#!/usr/bin/env python3
"""Build the m2381 forensic log reader pair for the payload volume:
  - Payloads/forensic-kernel.efi  (Linux EFI-stub kernel PE, no initramfs inside)
  - Payloads/forensic-initrd.img  (gzip cpio: busybox + init + rebootbl)

plus the unixnu.toml [[entry]] lines to paste into the payload config (the
build prints them). The entry is type = "linux": UniXNUPkg Boot.c LoadImage()s
the kernel PE, publishes the initrd on LoadFile2 media, hands Entry->Args as
the command line, and StartImage()s it; when the reader exits, the boot menu
comes back. Nothing on UFS is written except by the XNU boot log itself.

Inputs (all outside Git; see FLASHING.md for the provenance):
  --kernel  Linux EFI-stub kernel PE proven on this board (nura ESP v71's
            BOOTAA64.EFI = pmOS r91 vmlinuz-efi, sha256 4aad92b3...; boots
            m2381 with UART+USB+UFS+configfs, root= unused by us)
  --busybox static aarch64 busybox (Ubuntu ports busybox-static 1.36.1)
  --rebootbl static aarch64 rebootbl (built from forensic/rebootbl.c)
usage: build-forensic-reader.py --kernel FILE --busybox FILE --rebootbl FILE --out-dir DIR
"""
import argparse
import gzip
import hashlib
import struct
import sys
from pathlib import Path

CMDLINE = ('earlycon=efifb console=tty1 loglevel=4 consoleblank=0 '
           'quiet logfuse=1')


def cpio(entries):
    """newc archive; entries are (path, mode, data) with directories first."""
    out = bytearray()
    ino = 0
    for name, mode, data in entries + [('TRAILER!!!', 0, b'')]:
        ino += 1
        path = name.encode() + b'\0'
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(path) - 1]
        out += b'070701' + b''.join(b'%08X' % v for v in fields) + path
        out += b'\0' * (-len(out) % 4) + data
        out += b'\0' * (-len(out) % 4)
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    for name in ('kernel', 'busybox', 'rebootbl'):
        ap.add_argument('--' + name, required=True, type=Path)
    ap.add_argument('--out-dir', required=True, type=Path)
    a = ap.parse_args()

    kernel = a.kernel.read_bytes()
    if kernel[:2] != b'MZ':
        sys.exit('kernel is not a PE image (EFI-stub kernel expected)')
    init = (Path(__file__).parent / 'init').read_bytes()

    dirs = ['bin', 'dev', 'proc', 'sys', 'run', 'tmp']
    entries = [(d, 0o40755, b'') for d in dirs]
    entries += [
        ('dev/console', 0o20600, b''),
        ('init', 0o100755, init),
        ('bin/busybox', 0o100755, a.busybox.read_bytes()),
        ('bin/rebootbl', 0o100755, a.rebootbl.read_bytes()),
    ]
    initrd = gzip.compress(cpio(entries), 9, mtime=0)

    a.out_dir.mkdir(parents=True, exist_ok=True)
    kp = a.out_dir / 'forensic-kernel.efi'
    ip = a.out_dir / 'forensic-initrd.img'
    kp.write_bytes(kernel)
    ip.write_bytes(initrd)
    for p, blob in ((kp, kernel), (ip, initrd)):
        print(f'BUILT {p} ({len(blob)} bytes) sha256 {hashlib.sha256(blob).hexdigest()}')
    print()
    print('# unixnu.toml additions (also pasted by payload tooling):')
    print('[[entry]]')
    print('id = "forensic"')
    print('title = "m2381 forensic log reader"')
    print('type = "linux"')
    print('path = "Payloads/forensic-kernel.efi"')
    print('initrd = "Payloads/forensic-initrd.img"')
    print(f'args = "{CMDLINE}"')


if __name__ == '__main__':
    main()
