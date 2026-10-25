#!/bin/bash
# macOS-runner pre_build: produce the verified-root evidence the kernel link
# needs before the board flips VERIFIED_ROOT_PROBE on.
#
# Everything runs in the UniXNU checkout (cwd of pre_build); the device
# repository is at $DEVICE_DIR. Products land in build/verified-root-{host,os,
# systemos,os-xnu-bundle}/ of the checkout, where the upload_verified_root
# workflow step picks them up. The kernel step in the same run is untouched
# (bring-up still links the refusing stub; the real archive is consumed by a
# later local build).
#
# Round 25: the two-volume bundle (OS + SystemOS cryptex) under ONE retained
# anchor. The RSA key rides in the device repository (keys/owner.pem, private
# repo) so every policy stays reproducible; round 21's ephemeral runner key
# died with the runner and froze the lane at the single-policy OS-only bundle,
# which put launchd's dyld on a volume without libSystem/dyld cache.
#
# macOS-only pieces: openssl + clang dylib build, hdiutil attach, diskutil.
set -euo pipefail
echo "== ci-owner-policy: resolve inputs"
# The rewritten workflow checks out without submodules; the kernel step fetches
# its own references later. NativePrelink stays a submodule; VerifiedRoot is
# REPLACED by the device fork (16 KiB verification blocks - the 100 MiB
# recovery_a payload cannot hold the 4 KiB manifests of both windows).
git submodule update --init kits/NativePrelink
rm -rf kits/VerifiedRoot
cp -r "$DEVICE_DIR/kits/VerifiedRoot" kits/VerifiedRoot
IPSW_URL=$(python3 - "$DEVICE_DIR/board.toml" <<'PY'
import sys, tomllib, pathlib
print(tomllib.loads(pathlib.Path(sys.argv[1]).read_text())['ipsw']['url'])
PY
)
echo "ipsw: ${IPSW_URL%%\?*}"
TV=".cache/firmware/target-volumes"
mkdir -p "$TV" build

if [ ! -f "$TV/044-76040-038.dmg" ] || [ ! -f "$TV/044-76034-038.dmg" ]; then
  echo "== downloading the IPSW"
  curl -fsSL --retry 3 -o /tmp/m2381-owner.ipsw "$IPSW_URL"
  for m in 044-76040-038.dmg 044-76034-038.dmg; do
    unzip -p /tmp/m2381-owner.ipsw "$m" > "$TV/$m"
  done
  rm -f /tmp/m2381-owner.ipsw
fi
echo "os dmg sha256:"; shasum -a 256 "$TV/044-76040-038.dmg"
echo "systemos dmg sha256:"; shasum -a 256 "$TV/044-76034-038.dmg"

echo "== host keys + verified-root.dylib"
HOST=build/verified-root-host
mkdir -p "$HOST/keys"
if [ -f "$DEVICE_DIR/keys/owner.pem" ]; then
  echo "anchor key: committed device key (stable across runs)"
  cp "$DEVICE_DIR/keys/owner.pem" "$HOST/keys/owner.pem"
  cp "$DEVICE_DIR/keys/owner-public.pem" "$HOST/keys/owner-public.pem"
elif [ ! -f "$HOST/keys/owner.pem" ]; then
  echo "anchor key: EPHEMERAL runner key — the two-volume lane requires the committed key" >&2
  exit 1
fi
SSL=$(brew --prefix openssl@3)
xcrun clang -std=c11 -Wall -Wextra -Werror -dynamiclib \
  -I kits/VerifiedRoot/include -I "$SSL/include" \
  kits/VerifiedRoot/src/verified_root.c kits/VerifiedRoot/tests/openssl_provider.c \
  -L "$SSL/lib" -lcrypto -o "$HOST/verified-root.dylib"

attach_volume () {  # $1 dmg  $2 wanted volume UUID  $3 mount-link name
  hdiutil attach -readonly -nobrowse -plist "$1" > "/tmp/attach-$3.plist"
  local DETACH=$(python3 -c '
import plistlib, sys
for e in plistlib.load(open(sys.argv[1], "rb"))["system-entities"]:
    if e.get("content-hint") == "GUID_partition_scheme":
        print(e["dev-entry"]); break
' "/tmp/attach-$3.plist")
  local MOUNTED=""
  local v u
  for v in /Volumes/*; do
    [ -d "$v" ] || continue
    u=$(diskutil info -plist "$v" | python3 -c 'import sys,plistlib;print(plistlib.loads(sys.stdin.buffer.read()).get("VolumeUUID",""))' 2>/dev/null || true)
    if [ "$u" = "$2" ]; then MOUNTED="$v"; break; fi
  done
  if [ -z "$MOUNTED" ]; then
    echo "volume $2 not found among mounts:" >&2
    for v in /Volumes/*; do
      [ -d "$v" ] || continue
      diskutil info -plist "$v" 2>/dev/null | python3 -c 'import sys,plistlib;d=plistlib.loads(sys.stdin.buffer.read());print("  ", d.get("VolumeUUID",""), d.get("MountPoint",""))' || true
    done >&2
    hdiutil detach "$DETACH" || true
    exit 1
  fi
  echo "$3 volume: $MOUNTED"
  rm -rf "$TV/$3"; ln -s "$MOUNTED" "$TV/$3"
  echo "$DETACH" > "/tmp/detach-$3"
}

attach_volume "$TV/044-76040-038.dmg" 04769D26-2CA0-4825-B443-E2E5F88300F2 os-mount

echo "== OS policy (real C signature + full block verification)"
python3 scripts/build-owner-os-policy.py

attach_volume "$TV/044-76034-038.dmg" 8846FE78-2910-4297-AF97-D59BB6F8FC16 systemos-mount

echo "== SystemOS policy (same committed anchor, full block verification)"
UNIXNU_CHECKOUT="$PWD" python3 "$DEVICE_DIR/scripts/build-owner-systemos-policy.py"

# The two-volume probe bundle is NOT built here: scripts/build-verified-root-probe.py
# compiles with the kernel's own compile recipe (build/xnu/ios-obj/...), which
# only exists after a kernel build. The artifact carries both policies; the
# maintainer's local kernel build produces the bundle via
# scripts/build-verified-root-if-evidenced.py (--include-systemos).

# Round 30 (stage 8): the RAM-backed Data seed. hdiutil formats a 32 MiB APFS
# image seeded from the original private/var (macOS-only). The scratch volume
# UUID is then forced OFFLINE to the kernel-pinned OWNER_DATA value — APFS has
# no public volume-UUID verb, so the patch walks the 4 KiB blocks, rewrites the
# uuid field (offset 56) of every APSB volume superblock plus any other
# occurrence of the generated UUID, and re-seals each modified block with the
# Fletcher64 checksum (self-tested against an unmodified superblock first).
# Finally the raw image is packed into the DBRDISK1 ramdisk the ESP carries
# (Payloads/scratch-data.img, loaded via the unixnu.toml initrd line into
# /chosen/memory-map PackedRAMDisk). Both forms travel in the same
# verified-root artifact.
echo "== Data seed (original var tree, pinned scratch volume UUID)"
python3 scripts/prepare-owner-data-fixture.py
python3 - "$DEVICE_DIR" <<'PY'
import hashlib
import sys
import uuid as uuidlib
from pathlib import Path

sys.path.insert(0, sys.argv[1] + '/scripts')
import packed_ramdisk

image = Path('build/owner-data-fixture/owner-data-32.cdr')
target = uuidlib.UUID('18AB5557-DC2D-469B-8758-855E60F5B0DF').bytes
data = bytearray(image.read_bytes())
BLOCK, HEADER, UUID_AT = 4096, 32, 56

def fletcher64(body):
    # Apple's APFS object checksum is not the classic Fletcher64: the sums
    # accumulate unreduced over the checksum-sized body, and the final words
    # come out of the Nakassis complement (linux-apfs-rw object.c; verified
    # byte-exact against the 21H461 OS container's real superblocks).
    sum1 = sum2 = 0
    for i in range(0, len(body), 4):
        sum1 += int.from_bytes(body[i:i + 4], 'little')
        sum2 += sum1
    c1 = 0xffffffff - (sum1 + sum2) % 0xffffffff
    c2 = 0xffffffff - (sum1 + c1) % 0xffffffff
    return (c2 << 32) | c1

def seal(block):
    stored = int.from_bytes(block[0:8], 'little')
    computed = fletcher64(block[8:])
    if stored not in (computed, 0):
        raise SystemExit('Fletcher64 self-test failed: stored %#x computed %#x' % (stored, computed))
    block[0:8] = computed.to_bytes(8, 'little')

patched = 0
current = None
for base in range(0, len(data), BLOCK):
    block = data[base:base + BLOCK]
    if block[HEADER:HEADER + 4] != b'APSB':
        continue
    seal(block)                      # self-test the checksum math before touching anything
    old = bytes(block[UUID_AT:UUID_AT + 16])
    if current is None:
        current = old
        print('scratch volume superblock uuid:', uuidlib.UUID(bytes=old))
    if old == target:
        continue
    block[UUID_AT:UUID_AT + 16] = target
    patched += 1

if current is None:
    raise SystemExit('no APSB volume superblock found in the seed image')
if current == target:
    print('volume already carries the pinned UUID')
else:
    # Rewrite every remaining occurrence of the generated UUID (checkpoint
    # copies keep their own APSB seal; other structures get re-sealed too).
    forms = {current, current[::-1]}
    for base in range(0, len(data), BLOCK):
        block = data[base:base + BLOCK]
        hit = False
        for form in forms:
            cursor = block.find(form)
            while cursor != -1:
                block[cursor:cursor + 16] = target
                hit = True
                cursor = block.find(form, cursor + 1)
        if hit:
            seal(block)
            patched += 1

for base in range(0, len(data), BLOCK):
    block = data[base:base + BLOCK]
    if block[HEADER:HEADER + 4] == b'APSB':
        seal(block)  # verifies every superblock re-seals to its own stored checksum
        if block[UUID_AT:UUID_AT + 16] != target:
            raise SystemExit('post-patch check: an APSB superblock does not carry the pinned UUID')

image.write_bytes(data)
print('patched blocks:', patched)
packed = packed_ramdisk.pack(str(image), 'build/owner-data-fixture/scratch-data.img')
print('packed ramdisk:', packed)
PY

hdiutil detach "$(cat /tmp/detach-os-mount)" || true
hdiutil detach "$(cat /tmp/detach-systemos-mount)" || true
echo "== ci-owner-policy: done"
ls -la build/verified-root-os build/verified-root-systemos
