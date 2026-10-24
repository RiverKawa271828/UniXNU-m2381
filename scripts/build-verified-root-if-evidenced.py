#!/usr/bin/env python3
"""Verified-root archive, adapted to what this host can prove.

With the macOS-produced OS policy staged (device .cache/firmware/
verified-root-os/, staged into build/ by stage-local-candidates.py), build the
real probe archive (scripts/build-verified-root-probe.py --component os) that
the owner defconfig links. Without evidence — a fresh CI runner — there is
nothing to prove yet: the build continues with the refusing stub merged into
libNativeUfs.a by build-verified-root-stub.py instead (and that defconfig keeps
VERIFIED_ROOT_PROBE off), so both hosts run the same board archive list.

The upstream two-volume bundle (which defines _verified_root_policies) needs a
SystemOS policy signed under the same anchor key; the anchor's private key
stays on the runner that produced the OS policy, so this port ships a
single-policy bundle for now: the OS manifest is the only root policy, which
is exactly the volume the board mounts (root-match 04769D26). When a runner
pass produces both policies under one fresh key, switch to
--include_systemos and drop this appendix.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
policy = ROOT / 'build/verified-root-os/verification.json'

if not policy.is_file():
    print('no verified-root evidence on this host: skipping the probe archive '
          '(the refusing stub in libNativeUfs.a is the root verifier)')
    sys.exit(0)

print('evidence staged: building the real verified-root probe archive')
# bsd_init.o's compile recipe references EXPORT_HDRS/libsa; this tree does
# not generate it (empty search dir is fine, missing one is -Werror).
(ROOT / 'build/xnu/ios-obj/EXPORT_HDRS/libsa').mkdir(parents=True, exist_ok=True)
failure = subprocess.run(['python3', ROOT / 'scripts/build-verified-root-probe.py',
                          '--component', 'os']).returncode
if failure:
    sys.exit(failure)

# Single-policy bundle appendix: give the kernel link the two data symbols
# NativeUfs's verified-block configuration reads.
manifest = ROOT / 'build/verified-root-os/manifest.bin'
archive = ROOT / 'build/verified-root-os-xnu/libVerifiedRootProbe.a'
out = ROOT / 'build/verified-root-os-xnu'
assembly = out / 'single-policy.S'
assembly.write_text(
    '.balign 8\n'
    '.globl _verified_root_policies, _verified_root_policy_count\n'
    '_verified_root_policies:\n'
    f'.quad _verified_root_manifest, {manifest.stat().st_size}\n'
    '_verified_root_policy_count:\n.quad 1\n')
subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0',
                '-c', assembly, '-o', out / 'single-policy.o'], check=True)
subprocess.run(['xcrun', 'ar', 'rcs', archive, out / 'single-policy.o'], check=True)
listing = subprocess.run(['xcrun', 'nm', '-g', str(archive)], capture_output=True, text=True).stdout
for symbol in ('_verified_root_policies', '_verified_root_policy_count', '_verified_root_manifest'):
    if symbol not in listing:
        raise SystemExit(f'{symbol} missing from the probe archive')
print('PASS: verified-root probe archive with the single OS root policy')
