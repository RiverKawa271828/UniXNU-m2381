#!/usr/bin/env python3
r"""Add the forensic log reader to a BUILT payload.img (FAT, no mounting):
copies Payloads/forensic-kernel.efi + Payloads/forensic-initrd.img in and
appends the type="linux" [[entry]] to \EFI\UniXNU\unixnu.toml. Run after
every ./unixnu payload; then copy the image to the flat payload-rNN-<sha>.img
name as usual. The entry sits behind "xnu" in the menu; booting it runs the
reader, exiting it (or /bin/rebootbl) returns to the UniXNU menu.

r55 lesson (do not regress): overwriting unixnu.toml through its 8.3 short
name (UNIXNU~1.TOM) destroys the LFN entry — Mu's FAT driver then cannot
open \EFI\UniXNU\unixnu.toml, drops the whole config and the menu falls
back to the built-in action list ("no boot entry found"). Always mdel the
old file and mcopy the new one under the LONG name; verify by reading the
file back through the LFN path before publishing.

usage: add-forensic-entry.py <payload.img> [--kernel FILE] [--initrd FILE]
       (defaults: temp/forensic-esp/forensic-{kernel.efi,initrd.img})
"""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

IMAGE_TOML = '::/EFI/UniXNU/unixnu.toml'
ENTRY = (
    '\n[[entry]]\nid = "forensic"\ntitle = "m2381 forensic log reader"\n'
    'type = "linux"\npath = "Payloads/forensic-kernel.efi"\n'
    'initrd = "Payloads/forensic-initrd.img"\n'
    'args = "earlycon=efifb console=tty1 loglevel=4 consoleblank=0 quiet"\n'
)


def run(*argv):
    subprocess.run(list(argv), check=True)


def read_toml(image):
    out = subprocess.run(['mcopy', '-i', str(image), '-s', IMAGE_TOML, '-'],
                         capture_output=True, check=True)
    return out.stdout.decode()


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
        toml.write_text(read_toml(a.image))
        if 'id = "forensic"' in toml.read_text():
            print('forensic entry already present; rewriting files only')
        else:
            # mdel first, then mcopy under the LONG name: overwriting in place
            # keeps the stale 8.3 entry and loses the LFN (r55 boot failure).
            run('mdel', '-i', str(a.image), IMAGE_TOML)
            run('mcopy', '-i', str(a.image), str(toml), IMAGE_TOML)
        # new files: LFN entries are created by mcopy automatically
        run('mcopy', '-i', str(a.image), '-o', str(a.kernel),
            '::/EFI/UniXNU/Payloads/forensic-kernel.efi')
        run('mcopy', '-i', str(a.image), '-o', str(a.initrd),
            '::/EFI/UniXNU/Payloads/forensic-initrd.img')

    # post-verify the way the boot manager reads it: LFN path
    text = read_toml(a.image)
    if 'id = "forensic"' not in text:
        sys.exit('post-verify failed: unixnu.toml not readable via LFN')
    print(f'forensic entry added to {a.image} (LFN read-back OK)')


if __name__ == '__main__':
    main()
