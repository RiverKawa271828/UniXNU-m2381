#!/usr/bin/env python3
"""Host tests of the Goodix Berlin protocol helpers and the board coordinate mapping (package/tests/goodix_host.c). Model tests only."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CC = shutil.which('clang') or shutil.which('clang-24') or shutil.which('cc') or 'cc'

with tempfile.TemporaryDirectory() as tmp:
    exe = Path(tmp) / 'goodix-host'
    subprocess.run([CC, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g', '-fsanitize=address,undefined',
                    str(ROOT / 'package/tests/goodix_host.c'), str(ROOT / 'package/GoodixBerlin.c'), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout.strip()
print(out)
sys.exit(0 if out.startswith('PASS') else 1)
