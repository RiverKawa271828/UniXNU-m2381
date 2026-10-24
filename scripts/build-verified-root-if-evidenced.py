#!/usr/bin/env python3
"""Verified-root archive, adapted to what this host can prove.

With the macOS-produced OS policy staged (device .cache/firmware/
verified-root-os/, staged into build/ by stage-local-candidates.py), build the
real probe archive (scripts/build-verified-root-probe.py --component os) that
the owner defconfig links. Without evidence — a fresh CI runner — there is
nothing to prove yet: the build continues with the refusing stub merged into
libNativeUfs.a by build-verified-root-stub.py instead (and that defconfig keeps
VERIFIED_ROOT_PROBE off), so both hosts run the same board archive list.
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
policy = ROOT / 'build/verified-root-os/verification.json'

if policy.is_file():
    print('evidence staged: building the real verified-root probe archive')
    sys.exit(subprocess.run(['python3', ROOT / 'scripts/build-verified-root-probe.py',
                             '--component', 'os']).returncode)
print('no verified-root evidence on this host: skipping the probe archive '
      '(the refusing stub in libNativeUfs.a is the root verifier)')
sys.exit(0)
