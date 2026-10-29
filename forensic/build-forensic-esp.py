#!/usr/bin/env python3
"""Build the m2381 forensic reader ESP image (the recovery_a swap-in):

A small FAT32 volume carrying ONLY the forensic reader entry, flashed to
recovery_a instead of the UniXNU payload for a forensic round (2026-10-30
split decision — the iOS payload no longer carries the reader, so the
growing fileset kernel.macho no longer squeezes it). The UniXNU menu still
runs from boot_b: this toml makes the reader the default entry (3 s
countdown) and keeps Restart/Power off on the menu; when the reader exits
the menu comes back.

Inputs (all in .cache/forensic/, outside Git; provenance in FLASHING.md §7):
  forensic-kernel.efi   the proven nura v71 reader kernel (4aad92b3…); the
                        benched 3.79 MiB minimal build (1512301a…) must not
                        be shipped until it has booted on this board
  forensic-initrd.img   busybox + init + rebootbl (13-field newc cpio)
  forensic.dtb          nura sm8550-meizu-20.dtb (the r55c dtb= contract)

usage: build-forensic-esp.py --cache-dir DIR --out FILE [--size-mib 64] (≥48 MiB: FAT32 needs ≥65525 data clusters, 32 MiB lands 1% short and the EDK2 Fat driver refuses the volume)
"""
import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

# The reader args are payload.py's nura-proven early-boot set (the r55e
# acceptance args): the EFI stub replaces the kernel's built-in command line
# when options are provided, so this carries the survival set minus root=
# and init= — this board's userdata is the iOS root and the reader must
# touch nothing but the log window.
ARGS = ('earlycon=efifb console=ttyMSM0,115200n8 qcom_geni_serial.con_enabled=1 '
        'console=tty1 loglevel=7 keep_bootcon fw_devlink=off clk_ignore_unused '
        'pd_ignore_unused icc-rpmh.qos_disable=1 icc_rpmh_qos_disable=1 '
        'sysrq_always_enabled no_console_suspend')

TRIO = ('forensic-kernel.efi', 'forensic-initrd.img', 'forensic.dtb')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cache-dir', required=True, type=Path)
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--size-mib', type=int, default=64)
    a = ap.parse_args()

    trio = {}
    for name in TRIO:
        path = a.cache_dir / name
        if not path.is_file():
            sys.exit(f'missing reader input: {path} (provenance: FLASHING.md §7)')
        trio[name] = path.read_bytes()

    image = a.out
    image.parent.mkdir(parents=True, exist_ok=True)
    sectors = a.size_mib * 2048
    env = {'PATH': '/usr/bin:/bin:/usr/local/bin'}
    subprocess.run(['mformat', '-C', '-F', '-T', str(sectors), '-v', 'M2381ESP',
                    '-N', '53484e47', '-i', str(image), '::'],
                   check=True, env=env, capture_output=True)
    for d in ('EFI', 'EFI/UniXNU', 'EFI/UniXNU/Payloads'):
        subprocess.run(['mmd', '-i', str(image), f'::/{d}'], check=True, env=env, capture_output=True)
    toml = ('version = 1\n'
            '[boot]\n'
            'timeout = 3\n'
            'default = "forensic"\n'
            '[kits]\n'
            'autoload = false\n'
            '[[entry]]\n'
            'id = "forensic"\n'
            'title = "m2381 forensic log reader"\n'
            'type = "linux"\n'
            'path = "Payloads/forensic-kernel.efi"\n'
            'initrd = "Payloads/forensic-initrd.img"\n'
            'dtb = "Payloads/forensic.dtb"\n'
            f'args = "{ARGS}"\n'
            '[[entry]]\n'
            'id = "reset"\n'
            'title = "Restart"\n'
            'type = "action"\n'
            'action = "reset"\n'
            '[[entry]]\n'
            'id = "shutdown"\n'
            'title = "Power off"\n'
            'type = "action"\n'
            'action = "shutdown"\n')
    work = image.with_suffix('.toml.tmp')
    work.write_text(toml)
    subprocess.run(['mcopy', '-i', str(image), str(work), '::/EFI/UniXNU/unixnu.toml'],
                   check=True, env=env, capture_output=True)
    work.unlink()
    for name, blob in trio.items():
        src = image.with_suffix(f'.{name}.tmp')
        src.write_bytes(blob)
        subprocess.run(['mcopy', '-i', str(image), str(src), f'::/EFI/UniXNU/Payloads/{name}'],
                       check=True, env=env, capture_output=True)
        src.unlink()

    listing = subprocess.run(['mdir', '-i', str(image), '-/', '::'],
                             check=True, env=env, capture_output=True, text=True).stdout
    total = sum(len(blob) for blob in trio.values()) + len(toml)
    if total > a.size_mib * 1024 * 1024 * 0.95:
        sys.exit(f'reader files take {total >> 20} MiB; raise --size-mib (now {a.size_mib})')
    print(f'BUILT {image} ({a.size_mib} MiB, content {total} bytes)')
    print(f'  sha256 {hashlib.sha256(image.read_bytes()).hexdigest()}')
    print(listing)


if __name__ == '__main__':
    main()
