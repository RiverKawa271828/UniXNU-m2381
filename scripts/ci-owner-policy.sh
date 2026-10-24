#!/bin/bash
# macOS-runner pre_build: produce the verified-root evidence the kernel link
# needs before the board flips VERIFIED_ROOT_PROBE on.
#
# Everything runs in the UniXNU checkout (cwd of pre_build); the device
# repository is at $DEVICE_DIR. Products land in build/verified-root-{host,os,
# os-xnu}/ of the checkout, where the upload_verified_root workflow step picks
# them up. The kernel step in the same run is untouched (bring-up still links
# the refusing stub; the real archive is consumed by a later local build).
#
# macOS-only pieces: openssl + clang dylib build, hdiutil attach, diskutil.
set -euo pipefail
echo "== ci-owner-policy: resolve inputs"
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

echo "== host keys + verified-root.dylib"
HOST=build/verified-root-host
mkdir -p "$HOST/keys"
if [ ! -f "$HOST/keys/owner.pem" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$HOST/keys/owner.pem"
  openssl pkey -in "$HOST/keys/owner.pem" -pubout -out "$HOST/keys/owner-public.pem"
fi
SSL=$(brew --prefix openssl@3)
xcrun clang -std=c11 -Wall -Wextra -Werror -dynamiclib \
  -I kits/VerifiedRoot/include -I "$SSL/include" \
  kits/VerifiedRoot/src/verified_root.c kits/VerifiedRoot/tests/openssl_provider.c \
  -L "$SSL/lib" -lcrypto -o "$HOST/verified-root.dylib"

echo "== attach the OS volume read-only"
hdiutil attach -readonly -nobrowse -plist "$TV/044-76040-038.dmg" > /tmp/attach.plist
DETACH=$(python3 -c '
import plistlib, sys
for e in plistlib.load(open("/tmp/attach.plist","rb"))["system-entities"]:
    if e.get("content-hint") == "GUID_partition_scheme":
        print(e["dev-entry"]); break
')
WANT=04769D26-2CA0-4825-B443-E2E5F88300F2
MOUNTED=""
for v in /Volumes/*; do
  [ -d "$v" ] || continue
  u=$(diskutil info -plist "$v" | python3 -c 'import sys,plistlib;print(plistlib.loads(sys.stdin.buffer.read()).get("VolumeUUID",""))' 2>/dev/null || true)
  if [ "$u" = "$WANT" ]; then MOUNTED="$v"; break; fi
done
if [ -z "$MOUNTED" ]; then
  hdiutil detach "$DETACH" || true
  echo "volume $WANT not found among mounts" >&2
  exit 1
fi
echo "root volume: $MOUNTED"
rm -rf "$TV/os-mount"; ln -s "$MOUNTED" "$TV/os-mount"

echo "== OS policy (real C signature + full block verification)"
python3 scripts/build-owner-os-policy.py

echo "== cross-build probe archive"
python3 scripts/build-verified-root-probe.py --component os

hdiutil detach "$DETACH" || true
echo "== ci-owner-policy: done"
ls -la build/verified-root-os build/verified-root-os-xnu
