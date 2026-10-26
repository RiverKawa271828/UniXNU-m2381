#!/usr/bin/python3
"""Zero-value telemetry providers for the full BootProgress archive.

The real libBootProgress.a (BootProgress.o with its BootWatchdogPolicy.o,
built by build-boot-progress.py when XNU_BOOT_PROGRESS=1) reads the sheng
monitor surfaces: BootLog.c state, the legacy-display client counters, touch,
Adreno, cpufreq. This board leaves all of those off, and this ld64 (956)
errors on unresolved weak references where Apple's binds them to zero, so
BootProgressTelemetryDefs.c links the zeros in explicitly. The no-op
functions keep the weak callers on their NULL-guard paths. The legacy-display
topic replaces these with the qualified providers when it lands.
"""
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'build/boot-progress-telemetry'
OUT.mkdir(parents=True, exist_ok=True)
source = ROOT / 'kits/sheng/BootProgressTelemetryDefs.c'
obj = OUT / 'BootProgressTelemetryDefs.o'
sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
# The legacy-display zero-defs collide with the qualified providers/drivers once
# XNU_NATIVE_LEGACY_DISPLAY=y links libNativeLegacyDisplay.late.a; the defs file
# guards that block behind XNU_NATIVE_LEGACY_DISPLAY_QUALIFIED.
qualified = os.environ.get('XNU_NATIVE_LEGACY_DISPLAY') == '1'
flags = ['-DXNU_NATIVE_LEGACY_DISPLAY_QUALIFIED'] if qualified else []
subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-isysroot', sdk, '-ffreestanding',
                '-fno-common', '-Wall', '-Werror', *flags, '-c', str(source), '-o', str(obj)], check=True)
archive = OUT / 'libBootProgressTelemetry.a'
archive.unlink(missing_ok=True)
subprocess.run(['xcrun', 'ar', 'rcs', str(archive), str(obj)], check=True)
print('PASS: boot-progress telemetry zero-defs (legacy-display %s) -> %s'
      % ('excluded: the display lane provides them' if qualified else 'zeros linked', archive.name))
