#!/usr/bin/env python3
"""Verified-root archive, adapted to what this host can prove.

Round 25 (stage 7): with BOTH macOS-produced policies staged (device
.cache/firmware/verified-root-{os,systemos}/ — one committed anchor key),
build the upstream two-volume bundle (scripts/build-verified-root-probe.py
--component os --include-systemos) into
build/verified-root-os-xnu-bundle/libVerifiedRootProbe.a — the archive the
owner defconfig links now that the cryptex SystemOS window is published and
the owner cache mount unions it over "/". The bundle assembly already defines
_verified_root_policies with the count, so no appendix is appended.

With only the OS policy (a round-21-vintage cache), fall back to the
single-policy archive in build/verified-root-os-xnu/ plus the appendix. With
no evidence at all — a fresh runner — the refusing stub merged into
libNativeUfs.a stays the root verifier.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os_policy = ROOT / 'build/verified-root-os/verification.json'
systemos_policy = ROOT / 'build/verified-root-systemos/verification.json'

if not os_policy.is_file():
    print('no verified-root evidence on this host: skipping the probe archive '
          '(the refusing stub in libNativeUfs.a is the root verifier)')
    sys.exit(0)

# bsd_init.o's compile recipe references EXPORT_HDRS/libsa; this tree does
# not generate it (empty search dir is fine, missing one is -Werror).
(ROOT / 'build/xnu/ios-obj/EXPORT_HDRS/libsa').mkdir(parents=True, exist_ok=True)

if systemos_policy.is_file():
    print('two-policy evidence staged: building the OS+SystemOS verified-root bundle')
    sys.exit(subprocess.run(['python3', ROOT / 'scripts/build-verified-root-probe.py',
                             '--component', 'os', '--include-systemos']).returncode)

print('single-policy evidence staged: building the OS-only probe archive')
failure = subprocess.run(['python3', ROOT / 'scripts/build-verified-root-probe.py',
                          '--component', 'os']).returncode
if failure:
    sys.exit(failure)

# Single-policy appendix: give the kernel link the two data symbols
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
