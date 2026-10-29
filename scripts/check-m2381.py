#!/usr/bin/env python3
"""Preflight for the m2381 port.

Run by `unixnu build firmware` (see [firmware] preflight in board.toml) and safe
to run by hand at any time:

    python3 scripts/check-m2381.py
    python3 scripts/check-m2381.py --uefi ../uefi-sheng

Hard failures stop the build. Unmeasured placeholders (the [TODO] values of
board.toml) fail here rather than flowing into a written image — the nx729j
discipline. P2 will extend this with the UEFI memory map vs DTB reserved-region
comparison; only the board.toml sanity half is implemented so far.

Only the standard library is used, so it runs inside the build tree.
"""
from pathlib import Path
import argparse
import json
import os
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]

OK, WARN, FAIL = 'ok', 'warn', 'fail'
results = []


def record(status, name, detail):
    results.append((status, name, detail))


def load_merged_board(board_path):
    """Schema v2: merge the arch/OS profiles under the device board, so the
    checks below see [ipsw] and the payload policy the build will actually
    use (the v2 board carries neither — they live in the OS profile).

    The UniXNU checkout is found as the nearest ancestor with profiles/os/
    (the workflow checks the device out beside it). Without it — a standalone
    device branch — the plain board is checked and the identity check degrades
    to a warning rather than a false failure. The soc layer contributes none
    of the checked keys and is skipped (its pinned checkout may not exist
    locally; check-m2381 stays offline-only)."""
    board = tomllib.loads(board_path.read_text())
    if board.get('schema_version', 1) < 2:
        return board
    root = None
    for ancestor in [*Path(board_path).resolve().parents, Path.cwd(), *Path.cwd().parents]:
        if (ancestor / 'profiles/os').is_dir():
            root = ancestor
            break
    if root is None:
        # Standalone checkout: the build tree may live beside this repository
        # (the CI workflow also checks the device out beside the UniXNU tree).
        for sibling in sorted(Path(board_path).resolve().parent.parent.iterdir()):
            if (sibling / 'profiles/os').is_dir():
                root = sibling
                break
    if root is None:
        record(WARN, 'upstream checkout', 'no profiles/ ancestor or sibling found: checking the device board alone')
        return board

    def deep_merge(base, overlay):
        out = dict(base)
        for key, value in overlay.items():
            if isinstance(value, dict) and isinstance(out.get(key), dict):
                out[key] = deep_merge(out[key], value)
            else:
                out[key] = value
        return out

    def load(path):
        return tomllib.loads(path.read_text()) if path.is_file() else {}

    merged = load(root / 'profiles/arch/arm64/profile.toml')
    merged = deep_merge(merged, load(root / 'profiles/os' / board['board']['os_profile'] / 'profile.toml'))
    return deep_merge(merged, board)


def find_board(explicit):
    """Locate board.toml: explicit path, the device repo itself, or — when run
    from the build tree by `unixnu build firmware` — the device repository the
    unixnu state file remembers."""
    if explicit is not None:
        return explicit
    candidates = [ROOT / 'board.toml']
    if os.environ.get('UNIXNU_DEVICE'):
        candidates.append(Path(os.environ['UNIXNU_DEVICE']) / 'board.toml')
    for ancestor in [*ROOT.parents, Path.cwd(), *Path.cwd().parents]:
        state = ancestor / 'state.json'
        if state.is_file():
            try:
                device = json.loads(state.read_text()).get('device')
                if device:
                    candidates.append(Path(device) / 'board.toml')
            except ValueError:
                pass
            break
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise SystemExit('check-m2381: board.toml not found (pass --board)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--board', type=Path, default=None)
    parser.add_argument('--uefi', type=Path, default=None,
                        help='Root of the Mu-Silicium checkout (the --uefi argument of unixnu)')
    args = parser.parse_args()
    board_path = find_board(args.board)

    board = load_merged_board(board_path)

    # --- identity -----------------------------------------------------------
    ipsw = board.get('ipsw')
    if ipsw is None:
        record(WARN, 'ipsw identity', 'no [ipsw] visible: OS profile not merged (standalone board) — identity check skipped')
    elif (ipsw['product'], ipsw['build'], ipsw['device_class']) != ('iPhone10,3', '20H392', 'd22ap'):
        record(FAIL, 'ipsw identity', 'm2381 targets iPhone10,3 / 20H392 / d22ap (user decision 2026-10-29: the original cross-generation pairing, entropy/Image4 walls tamed on device at r11)')
    elif ipsw.get('chip_id') != 0x8015 or ipsw.get('board_id') != 6:
        record(FAIL, 'ipsw chip/board id', f"expected 0x8015/6 (d22ap BuildManifest), got {ipsw.get('chip_id')}/{ipsw.get('board_id')}")
    else:
        record(OK, 'ipsw identity', f"{ipsw['product']} {ipsw['version']} {ipsw['build']} chip {ipsw['chip_id']:#x} board {ipsw['board_id']}")

    # --- userdata geometry --------------------------------------------------
    ud = board['userdata']
    if ud['lba_bytes'] != 4096:
        record(FAIL, 'userdata lba_bytes', 'm2381 LUN 0 is 4 KiB; anything else writes at half/double density')
    span = ud['last_lba'] - ud['first_lba'] + 1
    gib = span * ud['lba_bytes'] / 2**30
    if not 400 < gib < 470:
        record(FAIL, 'userdata span', f'{span} LBAs = {gib:.1f} GiB, outside the measured ~463.7 GiB')
    else:
        record(OK, 'userdata span', f'first {ud["first_lba"]:#x} last {ud["last_lba"]:#x} = {gib:.1f} GiB @ {ud["lba_bytes"]} B')

    # --- payload volume fits recovery_a -------------------------------------
    payload = board['payload']
    if payload['volume'] != 'M2381ESP':
        record(FAIL, 'payload volume', 'label must be M2381ESP (≤11 chars, FAT limit)')
    if payload['size_mib'] > 96:
        record(FAIL, 'payload size', f"{payload['size_mib']} MiB does not fit recovery_a (100 MiB partition, FAT slack)")
    else:
        record(OK, 'payload volume', f'{payload["volume"]} {payload["size_mib"]} MiB on recovery_a, loader {payload["loader"]}')

    # --- placeholders that must be filled before an image is written --------
    adt = board['payload']['adt']
    uuid = adt.get('root_match_volume_uuid', '')
    # P2 builds the firmware only; nothing here writes a disk. The value is
    # the donor OS image root volume UUID, derived from the userdata OS
    # window's volume superblocks per donor.
    if not uuid or uuid.upper().startswith('TODO'):
        record(WARN, 'root_match_volume_uuid', 'still a placeholder; must be derived from the donor OS image before any payload/userdata image is written')
    else:
        record(OK, 'root_match_volume_uuid', uuid)

    width = len(max(results, key=lambda r: len(r[1]))[1])
    for status, name, detail in results:
        print(f'{status.upper():5s} {name.ljust(width)}  {detail}')
    failed = [r for r in results if r[0] == FAIL]
    print(f'\n{len(results) - len(failed)} ok, {len(failed)} fail')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
