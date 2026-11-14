#!/usr/bin/env python3
"""Inject a preferences plist into the packed Data seed (macOS hdiutil required).

r123 (s112): the BacklightServicesHost watchdog aborts SpringBoard on this
no-backlight board (r122: two SIGABRTs, same PC, BLSHWatchdogProvider
_fireWatchdogWithTimer -> _abortForWatchdogFire -> abort_with_payload). The
framework ships a user-default kill switch — domain com.apple.BacklightServices,
key backlightWatchdogsDisabled — registered as an observed default by
-[BLSHBacklightOSInterfaceProvider] (RE: cfstring 0x273b79e80, reader
BLSH+0x69908) and consumed by -[BLSHWatchdogProvider isWatchdogEnabled].

This tool performs seed surgery WITHOUT os-input involvement: unpack the
DBRDISK1 zero-page packing (lossless extents), self-verify the round trip,
attach the raw APFS container read-write, write the plist, detach, repack.
The volume UUID pin (OWNER_DATA 18AB5557-...) is untouched — only file blocks
change, and the APFS driver re-seals those object checksums on write.
"""
import argparse
import hashlib
import plistlib
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import packed_ramdisk


def unpack_to(packed: Path, raw: Path):
    blob = packed.read_bytes()
    logical, extents = packed_ramdisk.regions(blob)
    with raw.open('wb') as out:
        for offset, data in extents:
            out.seek(offset)
            out.write(data)
        out.truncate(logical)
    return logical


def repack_and_compare(raw: Path, packed: Path) -> bool:
    with tempfile.TemporaryDirectory() as td:
        probe = Path(td) / 'roundtrip.img'
        packed_ramdisk.pack(raw, probe)
        return hashlib.sha256(probe.read_bytes()).digest() == hashlib.sha256(packed.read_bytes()).digest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--seed', type=Path, required=True, help='packed DBRDISK1 seed (modified in place)')
    ap.add_argument('--domain', default='com.apple.BacklightServices')
    ap.add_argument('--bool', dest='bools', action='append', default=[], metavar='KEY=VALUE',
                    help='boolean user default to write (repeatable)')
    args = ap.parse_args()

    seed = args.seed.resolve()
    before = hashlib.sha256(seed.read_bytes()).hexdigest()
    work = seed.parent / f'{seed.stem}-work.cdr'
    logical = unpack_to(seed, work)
    print(f'unpacked logical bytes: {logical} ({logical / 2**30:.1f} GiB)')
    if not repack_and_compare(work, seed):
        raise SystemExit('roundtrip check FAILED — packing is not canonical for this seed, aborting')
    print('roundtrip check: byte-identical repack OK')

    mount = seed.parent / f'{seed.stem}-mnt'
    mount.mkdir(exist_ok=True)
    attached = plistlib.loads(subprocess.check_output(['hdiutil', 'attach', '-nobrowse', '-owners', 'off',
                                                       '-mountpoint', str(mount), '-plist', str(work)]))
    device = attached['system-entities'][0]['dev-entry']
    try:
        prefs = mount / 'mobile/Library/Preferences'
        prefs.mkdir(parents=True, exist_ok=True)
        payload = {key: value == 'true' for key, value in (b.split('=', 1) for b in args.bools)}
        target = prefs / f'{args.domain}.plist'
        with target.open('wb') as f:
            plistlib.dump(payload, f, fmt=plistlib.FMT_BINARY)
        print(f'wrote {target.relative_to(mount)}: {payload}')
    finally:
        subprocess.run(['hdiutil', 'detach', device], check=True)

    packed_ramdisk.pack(work, seed)
    work.unlink()
    mount.rmdir()
    after = hashlib.sha256(seed.read_bytes()).hexdigest()
    report = packed_ramdisk.inspect(seed)[0]
    print(f'seed sha256: {before} -> {after}')
    print(f'logical: {report["bytes"]}B packed: {report["encoded_bytes"]}B sha256(logical)={report["sha256"]}')


if __name__ == '__main__':
    main()
