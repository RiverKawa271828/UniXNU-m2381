#!/usr/bin/env python3
"""Host tests of the audio DSP bring-up cores (package/tests/qcom_adsp_host.c): firmware image parsing, SMEM, SMP2P, GLINK, the
AOSS mailbox, cmd-db and RSC request encoding, SCM ids. Model tests only; nothing here touches hardware."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'kits/sheng' if (ROOT / 'kits/sheng').is_dir() else ROOT / 'package'
SOURCES = ['tests/qcom_adsp_host.c', 'QcomMdt.c', 'QcomSmem.c', 'QcomSmp2p.c', 'QcomGlink.c', 'QcomQmp.c', 'QcomRpmh.c']
# The kernel and the sheng CI compile this code with clang; gcc (the Linux
# default cc) additionally enables -Wimplicit-fallthrough under -Wextra and
# rejects the sources byte-for-byte identical to sheng's. Prefer clang when
# the host has one so the check tests the same dialect the kernel build uses.
CC = shutil.which('clang') or shutil.which('clang-24') or shutil.which('cc') or 'cc'

with tempfile.TemporaryDirectory() as tmp:
    exe = Path(tmp) / 'qcom-adsp-host'
    # -Wno-unused-but-set-variable: clang 21+ flags the sheng test harness's
    # kick counters (set for side-effect assertions only); the sheng CI clang
    # predates the warning.
    subprocess.run([CC, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-but-set-variable',
                    '-O1', '-g', '-fsanitize=address,undefined',
                    *[str(PACKAGE / s) for s in SOURCES], '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout.strip()
print(out)
sys.exit(0 if out.startswith('PASS') else 1)
