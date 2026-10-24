#!/usr/bin/env python3
"""No-op boot_progress_poll for the bring-up storage lane.

NativeUfs declares boot_progress_poll() weak and calls it under a NULL guard;
the real implementation is the sheng BootProgress diagnostic, whose builder
needs the full owner-root/virtio stage this lane deliberately leaves off.
This ld64 (956) still errors on the weak undefined during the kernel link,
so supply a no-op definition in its own archive. Replace with
build-boot-progress.py when the progress UI stage comes up.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'build/boot-progress-stub'
OUT.mkdir(parents=True, exist_ok=True)
source = OUT / 'stub.c'
source.write_text('void boot_progress_poll(void) {}\n')
obj = OUT / 'stub.o'
subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-ffreestanding',
                '-Wall', '-Werror', '-c', str(source), '-o', str(obj)], check=True)
archive = OUT / 'libBootProgressStub.a'
archive.unlink(missing_ok=True)
subprocess.run(['xcrun', 'ar', 'rcs', str(archive), str(obj)], check=True)
print('PASS: no-op boot_progress_poll stub -> ' + archive.name)
