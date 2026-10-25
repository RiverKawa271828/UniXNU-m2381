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
# its own references later. The evidence build needs these two kits now.
git submodule update --init kits/VerifiedRoot kits/NativePrelink
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

echo "== cross-build two-volume probe bundle (OS + SystemOS, one anchor)"
python3 scripts/build-verified-root-probe.py --component os --include-systemos

hdiutil detach "$(cat /tmp/detach-os-mount)" || true
hdiutil detach "$(cat /tmp/detach-systemos-mount)" || true
echo "== ci-owner-policy: done"
ls -la build/verified-root-os build/verified-root-systemos build/verified-root-os-xnu-bundle
