#!/usr/bin/env python3
"""Wall-museum regression scan: run every closed wall's sentinel grep over a parsed window.

Per the R-CARD-TEMPLATE §2 rule — closed walls each carry one sentinel row and
the walls that "have not bitten for a long time" need them most (wall-42/76
PMGR: dormant r77-r118, then came back at r119/r120 through a kit-table loss,
not through anything AMFI-related). This automates the per-judgment first-grep
so a recurrence is flagged by the tool, not rediscovered by hand:

  python3 scripts/scan-wall-museum.py reader-rXXX/parsed-msg.txt [parsed-all.txt ...]
  python3 scripts/scan-wall-museum.py --registry walls.tsv parsed-msg.txt

Registry rows (name, expect, pattern, fixed-round): expect=absent → the
pattern must match ZERO lines (panic/wall text); expect=zero:N → capture
group N must be 0 in every match (counters); expect=present → the pattern
must match (milestones). Exit 1 if any absent/zero row trips.
"""
import argparse, re, sys
from pathlib import Path

# R-CARD-TEMPLATE.md §2 museum (2026-11-14 s108/s109 state)
# expect kinds:
#   absent   — window-verifiable wall: pattern must match zero lines
#   screen   — panic-text wall: the panic freezes the writer, so window absence
#              proves nothing; a hit is hard ALIVE evidence, a miss defers to the
#              screen photo (verify-panic-crc.py --msg)
#   zero:N   — capture group N must be 0 in every match
#   present  — milestone sentinel (needs the slots file, parsed-all.txt)
#   open     — wall known ALIVE on the current best face (fix in flight); state
#              is reported but does not fail the scan
REGISTRY = [
    # (name, expect, pattern, fixed-round, note)
    ('2s-fetch-abort', 'present', r'UFS TIME verify=', 'r118',
     'window proxy for ">10s survived": 2s-class deaths write no slot pages; '
     'screen-channel check = boot stage order past "kernel do post - done"'),
    ('wall42/76-amfi-no-pmgr', 'screen', r'No PMGR', 'r76 (24A446) / r119-r120 recurrence',
     'panic crc 0xf063fb5b; r119/r120 = emit kit lost TEXT_WORD_PATCHES, not AMFI'),
    ('launchd-p1-abort', 'zero:3', r'^p1 (\S+) status=(\S+) sig=(\d+)', 'r102+',
     'p1-only: group 3 = launchd death signal; daemon nonzeros are other walls'),
    ('sb-display-sig5', 'screen', r'CRASH.*SpringBoard', 'r115', ''),
    ('kqworkloops-quota', 'absent', r'caught allocating too many kqworkloops', 'r116', ''),
    ('watchdogd-cm-brk', 'screen', r'CRASH.*(watchdogd|containermanagerd)', 'r112', ''),
    ('entcopy-ret14', 'absent', r'ret=14\b', 'r111', 'probe telemetry line'),
    ('vnode-rele-underflow', 'screen', r'vnode_rele_ext.*underflow|underflow.*vnode_rele_ext', 'r118 (not seen since)', ''),
    ('liveactivitiesd-sig5', 'open', r'CRASH.*liveactivitiesd', 'OPEN until r122 (arg removal + de-mutex)', ''),
    # milestone sentinels (same first-grep discipline, inverted polarity)
    ('display-stage10', 'present', r'DISPLAY stage=10', 'r116', 'G0 display lane gate'),
    ('gop-mapping-nonzero', 'present', r'GOP actual mapping virtual=[0-9a-f]+ physical=[0-9a-f]+ bytes=[1-9]', 'r116', ''),
]


def scan(files, registry):
    text = '\n'.join(Path(f).read_text(errors='replace') for f in files)
    alive, ok, screen, open_w = [], [], [], []
    for name, expect, pattern, fixed, note in registry:
        rx = re.compile(pattern)
        hits = [m for m in rx.finditer(text)]
        bad = False
        detail = ''
        if expect == 'absent':
            bad = bool(hits)
            detail = hits[0].group(0)[:70] if hits else ''
        elif expect == 'screen':
            if hits:
                bad = True
                detail = hits[0].group(0)[:70]
            else:
                detail = 'not in window — screen photo is the authority (verify-panic-crc.py)'
        elif expect == 'open':
            detail = hits[0].group(0)[:70] if hits else 'not in window (fix still in flight)'
        elif expect == 'present':
            bad = not hits
            detail = hits[0].group(0)[:70] if hits else ''
        elif expect.startswith('zero:'):
            grp = int(expect.split(':')[1])
            bad = any(int(m.group(grp)) != 0 for m in hits)
            worst = max((int(m.group(grp)) for m in hits), default=0)
            detail = f'max={worst}'
        else:
            raise SystemExit(f'bad expect {expect!r} for {name}')
        row = (name, fixed, detail)
        if bad:
            alive.append(row)
        elif expect == 'screen':
            screen.append(row)
        elif expect == 'open':
            open_w.append(row)
        else:
            ok.append(row)
    return alive, ok, screen, open_w


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('parsed', nargs='+', help='parsed window text files')
    ap.add_argument('--registry', help='TSV override: name<TAB>expect<TAB>pattern<TAB>fixed<TAB>note')
    args = ap.parse_args()
    registry = REGISTRY
    if args.registry:
        registry = []
        for line in Path(args.registry).read_text().splitlines():
            if line.startswith('#') or not line.strip():
                continue
            name, expect, pattern, fixed, *note = line.split('\t')
            registry.append((name, expect, pattern, fixed, ' '.join(note)))
    alive, ok, screen, open_w = scan(args.parsed, registry)
    print(f'== wall museum: {len(ok)} dormant, {len(screen)} screen-channel, '
          f'{len(open_w)} open, {len(alive)} ALIVE ==')
    for name, fixed, detail in alive:
        print(f'  ALIVE   {name:26s} (closed {fixed})  {detail}')
    for name, fixed, detail in open_w:
        print(f'  OPEN    {name:26s} ({fixed})  {detail}')
    for name, fixed, detail in screen:
        print(f'  screen  {name:26s} (closed {fixed})  {detail}')
    for name, fixed, detail in ok:
        print(f'  dormant {name:26s} (closed {fixed})')
    if alive:
        print('\nVERDICT: FAIL — closed-wall sentinels tripped; judge as a recurrence '
              '(check: face audit station gate, args gate, kit copies) before blaming the wall domain')
        return 1
    print('\nVERDICT: PASS — no closed wall alive in this window')
    return 0


if __name__ == '__main__':
    sys.exit(main())
