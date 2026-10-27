#!/usr/bin/env python3
r"""Add the forensic log reader to a BUILT payload.img (FAT, no mounting):
copies Payloads/forensic-kernel.efi + Payloads/forensic-initrd.img in and
appends the type="linux" [[entry]] to \EFI\UniXNU\unixnu.toml. Run after
every ./unixnu payload; then copy the image to the flat payload-rNN-<sha>.img
name as usual. The entry sits behind "xnu" in the menu; booting it runs the
reader, exiting it (or /bin/rebootbl) returns to the UniXNU menu.

usage: add-forensic-entry.py <payload.img> [--kernel FILE] [--initrd FILE]
       (defaults: temp/forensic-esp/forensic-{kernel.efi,initrd.img})
"""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

ENTRY = (
    '\n[[entry]]\nid = "forensic"\ntitle = "m2381 forensic log reader"\n'
    'type = "linux"\npath = "Payloads/forensic-kernel.efi"\n'
    'initrd = "Payloads/forensic-initrd.img"\n'
    'args = "earlycon=efifb console=tty1 loglevel=4 consoleblank=0 quiet"\n'
)


def mcopy(image, local, target):
    subprocess.run(['mcopy', '-i', str(image), '-o', str(local), target],
                   check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('image', type=Path)
    ap.add_argument('--kernel', type=Path,
                    default=Path('temp/forensic-esp/forensic-kernel.efi'))
    ap.add_argument('--initrd', type=Path,
                    default=Path('temp/forensic-esp/forensic-initrd.img'))
    a = ap.parse_args()
    if not a.image.is_file():
        sys.exit(f'payload not found: {a.image}')
    for f in (a.kernel, a.initrd):
        if not f.is_file():
            sys.exit(f'missing {f}; run devices/m2381/unixnu-m2381/'
                     'forensic/build-forensic-reader.py first')

    with tempfile.TemporaryDirectory() as td:
        toml = Path(td) / 'unixnu.toml'
        subprocess.run(['mcopy', '-i', str(a.image),
                        '-s', '::/EFI/UNIXNU/UNIXNU~1.TOM', str(toml)],
                       check=True)
        text = toml.read_text()
        if 'id = "forensic"' in text:
            print('forensic entry already present; replacing files only')
        else:
            toml.write_text(text + ENTRY)
            mcopy(a.image, toml, '::/EFI/UNIXNU/UNIXNU~1.TOM')
        mcopy(a.image, a.kernel, '::/EFI/UNIXNU/PAYLOADS/FORENSIC~1.EFI')
        mcopy(a.image, a.initrd, '::/EFI/UNIXNU/PAYLOADS/FORENSIC~1.IMG')
    print(f'forensic entry added to {a.image}')


if __name__ == '__main__':
    main()
