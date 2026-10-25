#!/usr/bin/env python3
"""Stage the local evidence files the board audits read from inside the tree.

Two artifacts are pruned on every tree reassembly and must exist before the
audit archives run:

1. The decompressed original kernelcache at
   .cache/firmware/kernelcache.macho/ — the ApplePMGR contract audit reads the
   original component bytes from it. With a local --ipsw the driver keeps it
   in out/ipsw/<build>/ instead, so copy it in from there.
2. The prelink candidate pair in build/native-prelink/ — the storage audits
   require a candidate Mach-O plus its emit_prelink plan, with the plan's
   candidate_sha256 matching the Mach-O byte for byte. The previous build's
   clean prelink output (kernel.clean.macho + kernel.json) is exactly that
   pair; both audit alias names point at it.

Missing sources are skipped silently: the very first build on a fresh tree
runs its audits without them, and a later build restages what exists.
"""
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT.parent.parent          # tree -> <board> -> out

cache = ROOT / '.cache/firmware/kernelcache.macho'
for source in sorted((OUT / 'ipsw').glob('*/kernelcache.release.*.decompressed')):
    cache.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, cache / source.name)
    print(f'staged {source.name} from {source.relative_to(OUT)}')
    break

# The macOS-produced verified-root OS policy (verification.json, manifest.bin,
# trusted-key.bin) lives in the device firmware cache; the tree's build/ is
# fresh every assembly, so stage it for scripts/build-verified-root-probe.py.
policy = ROOT / '.cache/firmware/verified-root-os'
if (policy / 'verification.json').is_file():
    target = ROOT / 'build/verified-root-os'
    target.mkdir(parents=True, exist_ok=True)
    for name in ('verification.json', 'manifest.bin', 'trusted-key.bin',
                 'original-samples.bin'):
        if (policy / name).is_file():
            shutil.copyfile(policy / name, target / name)
    print('staged verified-root-os policy from the device firmware cache')
else:
    print('no verified-root-os policy in the device firmware cache (probe archive will fail if enabled)')

# Round 25 (stage 7): the SystemOS cryptex policy, same anchor — the second
# half of the two-volume bundle.
policy = ROOT / '.cache/firmware/verified-root-systemos'
if (policy / 'verification.json').is_file():
    target = ROOT / 'build/verified-root-systemos'
    target.mkdir(parents=True, exist_ok=True)
    for name in ('verification.json', 'manifest.bin', 'trusted-key.bin',
                 'original-samples.bin'):
        if (policy / name).is_file():
            shutil.copyfile(policy / name, target / name)
    print('staged verified-root-systemos policy from the device firmware cache')
else:
    print('no verified-root-systemos policy in the device firmware cache '
          '(single-policy fallback applies)')

kernel = OUT / 'm2381/kernel'
clean = kernel / 'kernel.clean.macho'
macho = clean if clean.is_file() else kernel / 'kernel.macho'
plan = kernel / 'kernel.json'
if macho.is_file() and plan.is_file():
    stage = ROOT / 'build/native-prelink'
    stage.mkdir(parents=True, exist_ok=True)
    for name in ('native-owner-ufs-cpu-desktop-m2381-candidate',
                 'native-apfs-load-positive'):
        shutil.copyfile(macho, stage / f'{name}.macho')
        shutil.copyfile(plan, stage / f'{name}.json')
    print(f"staged candidate pairs from {macho.name} ({plan.stat().st_size} B plan)")
else:
    print('no prelink products yet; candidate staging skipped')
