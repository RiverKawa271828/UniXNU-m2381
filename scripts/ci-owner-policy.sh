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
# its own references later. XnuPrelink and VerifiedRoot are REPLACED by the
# device forks: XnuPrelink carries this port's 21H461 Libm literal pools and
# the fileset-KC rebinder body; VerifiedRoot carries the 16 KiB verification
# blocks (the 100 MiB recovery_a payload cannot hold the 4 KiB manifests of
# both windows). The schema v2 board.toml has no [ipsw] table — the OS
# profile in the UniXNU checkout owns the URL now.
git submodule update --init kits/XnuPrelink
rm -rf kits/XnuPrelink
cp -r "$DEVICE_DIR/kits/XnuPrelink" kits/XnuPrelink
git rm --cached -q kits/XnuPrelink
rm -rf kits/VerifiedRoot
cp -r "$DEVICE_DIR/kits/VerifiedRoot" kits/VerifiedRoot
# The device forks now sit where the checkout's gitlinks point at upstream;
# unregister them so the kernel step's submodule pass does not re-clone
# UniXNU/XnuPrelink and UniXNU/VerifiedRoot over the forks and abort.
git rm --cached -q kits/VerifiedRoot
IPSW_URL=$(python3 - "$DEVICE_DIR/board.toml" <<'PY'
import sys, pathlib, tomllib
board = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
if board.get('schema_version', 1) >= 2:
    root = next(p for p in pathlib.Path(sys.argv[1]).resolve().parents
                if (p / 'profiles/os').is_dir())
    profile = root / 'profiles/os' / board['board']['os_profile'] / 'profile.toml'
    print(tomllib.loads(profile.read_text())['ipsw']['url'])
else:
    print(board['ipsw']['url'])
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
BLOCK, HEADER = 4096, 32
UUID_AT = 240   # apfs_superblock volume UUID (offset 56 is the NXSB container layout)

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

def verifies(block):
    stored = int.from_bytes(block[0:8], 'little')
    return stored == 0 or stored == fletcher64(block[8:])

def reseal(block):
    block[0:8] = fletcher64(block[8:]).to_bytes(8, 'little')

current = None
verified = patched = skipped = 0
for base in range(0, len(data), BLOCK):
    block = data[base:base + BLOCK]
    if block[HEADER:HEADER + 4] != b'APSB':
        continue
    if not verifies(block):
        skipped += 1   # a byte-sequence coincidence, not a verifiable superblock
        continue
    verified += 1
    old = bytes(block[UUID_AT:UUID_AT + 16])
    if current is None:
        current = old
        print('scratch volume superblock uuid:', uuidlib.UUID(bytes=old))
    if old == target:
        continue
    block[UUID_AT:UUID_AT + 16] = target
    reseal(block)
    data[base:base + BLOCK] = block
    patched += 1

if not verified:
    raise SystemExit('no checksum-verifying APSB volume superblock in the seed image')
if current != target:
    # The generated UUID also lives in non-superblock structures; rewrite it
    # only where the block re-seals, and leave unverifiable blocks untouched.
    for base in range(0, len(data), BLOCK):
        block = data[base:base + BLOCK]
        hit = block.find(current)
        if hit == -1:
            continue
        if not verifies(block):
            continue
        touched = False
        while hit != -1:
            block[hit:hit + 16] = target
            touched = True
            hit = block.find(current, hit + 1)
        if touched:
            reseal(block)
            data[base:base + BLOCK] = block
            patched += 1

for base in range(0, len(data), BLOCK):
    block = data[base:base + BLOCK]
    if block[HEADER:HEADER + 4] == b'APSB' and verifies(block) and \
            bytes(block[UUID_AT:UUID_AT + 16]) != target:
        raise SystemExit('post-patch check: a verifiable APSB does not carry the pinned UUID')

image.write_bytes(data)
print('patched blocks:', patched)
packed = packed_ramdisk.pack(image, Path('build/owner-data-fixture/scratch-data.img'))
print('packed ramdisk:', packed)
PY

# Round 42 (STATE 0.23): the 32 MiB seed cannot hold the sheng-staged-apps copy
# (31 MiB and unfinished, so it refloods and ENOSPCs the boot policy every
# boot). Upstream pairs sheng-staged-apps=1 with seed-data-grow.py; the seed
# carries its store geometry and the kernel adapts (sparse-packed, sparse
# RAM), so growing here needs no kernel or board change. The grown seed
# replaces the base in build/owner-data-fixture/ and rides the verified-root
# artifact home for the local payload assembly (the payload itself never
# leaves the runner).
git submodule update --init --depth 1 drivers/DarwinBoot
python3 scripts/seed-data-grow.py --gib 16 \
  build/owner-data-fixture/scratch-data.img build/owner-data-fixture/scratch-data-16g.img
mv build/owner-data-fixture/scratch-data-16g.img build/owner-data-fixture/scratch-data.img
echo "== Data seed grown to 16 GiB: $(ls -l build/owner-data-fixture/scratch-data.img | awk '{print $5}') bytes packed"

hdiutil detach "$(cat /tmp/detach-os-mount)" || true
hdiutil detach "$(cat /tmp/detach-systemos-mount)" || true

# The kernel step reads the tree-relative paths (the schema v2 tree lives at
# out/<os-profile>/<board>/tree/ and tree/.cache/firmware symlinks into the
# device repository), so stage everything where the assembled tree will link
# it: the two policies via the device cache and the IPSW member volumes by a
# same-filesystem rename into the device repository.
echo "== ci-owner-policy: stage into the device repository"
mkdir -p "$DEVICE_DIR/.cache/firmware"
rm -rf "$DEVICE_DIR/.cache/firmware/verified-root-os" \
       "$DEVICE_DIR/.cache/firmware/verified-root-systemos" \
       "$DEVICE_DIR/.cache/firmware/target-volumes"
cp -r build/verified-root-os build/verified-root-systemos "$DEVICE_DIR/.cache/firmware/"
mv "$TV" "$DEVICE_DIR/.cache/firmware/target-volumes"

echo "== ci-owner-policy: done"
ls -la build/verified-root-os build/verified-root-systemos
