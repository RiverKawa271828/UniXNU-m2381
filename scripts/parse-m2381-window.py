#!/usr/bin/env python3
"""Parse the m2381 UFS diagnostic window (package/BootLog.c version 4, SHLOG001) beyond the simple channel.

read-m2381-ufs-log.py stays the byte-parity simple channel (slot/msgbuf text); this tool adds what it does not do:
the header summary with boot_id (default), the residue generations (slots past slots_written, left by older boots),
death evidence (CRASH rows, exit-reason lines, nonzero exit-table rows) with a kernel/page clock-offset estimate,
a structured --json dump for diffing, and a semantic --diff of two windows (last page, census, exit table, msgbuf
tail, launchd exec stage sequence).

Window layout (4096-byte blocks): 0 header, 1..32 the kernel message buffer (oldest first), 33.. text slots of
slot_blocks (16) blocks in a ring (~509 slots ≈ 17 min). The header is written last in each round, so slots at or
past slots_written are residue from previous boots: each boot restarts the ring at slot 0 and the window is never
cleared, so the residue keeps older generations readable (no boot_id for them — the header only names the current
boot; generations are split where the page clock or the IRQ count regresses). boot_id is CNTPCT at writer start: a
hard power-off resets it, so it tells runs apart but does not order them.

Clocks (do not mix them): the page's time= line is the page clock; msgbuf "[   T]:" prefixes are the kernel clock,
about 21-22 s ahead of the page clock (per boot; --deaths/--json estimate the offset by pairing launchd boot-task
events with census first-start seconds by name); boot_id ticks are a third base.

usage: parse-m2381-window.py log.bin                default: header summary (boot_id, slots, clocks)
       parse-m2381-window.py log.bin --all|--msg|--page|--spawn   same output as read-m2381-ufs-log.py
       parse-m2381-window.py log.bin --residue      residue generations
       parse-m2381-window.py log.bin --deaths       CRASH / exit-reason / nonzero-exit evidence
       parse-m2381-window.py log.bin --json         structured slots for diffing
       parse-m2381-window.py log.bin --diff OTHER.bin  semantic diff against another window
"""
import argparse
import difflib
import json
import re
import struct
import sys

BLOCK = 4096
CNTFRQ_HZ = 19200000        # the page's CLK line: cntfrq=19200000

TIME_RE = re.compile(r'^time=(\d+)s idle=(\d+)s IRQ=(\d+) monitor=(\d+) lost=(\d+) root=(-?\d+) procs=(-?\d+) free=(-?\d+) spawn=(\d+) (\d+)/s')
UFS_RE = re.compile(r'^(?:OFFLINE VIRTIO|UFS) requests=(\d+) verified4K=(\d+) failures=(\d+) integrity=(\d+) published=(\d+)')
UFS_TIME_RE = re.compile(r'^UFS TIME verify=(\d+) ms read=(\d+) ms verified=(\d+) blocks')
EXITS_RE = re.compile(r'^ Process exits: total=(\d+) nonzero-status-or-reason=(\d+) dropped=(\d+)')
EXIT_ROW_RE = re.compile(r'^p(\d+) (\S+) status=(\S+) sig=(\d+) exit=(-?\d+) ns=(-?\d+) sub=(-?\d+)$')
CENSUS_ITEM_RE = re.compile(r'(\S+) (\d+)/(\d+)@(\d+)')
STAGE_ROW_RE = re.compile(r'^\s*\d+s ')
EXEC_ROW_RE = re.compile(r'^\s*(\d+)s (target pid=\d+ launchd exec .*)$')
SLOT_HEAD_RE = re.compile(r'^#slot (\d+) t=(\d+)s')
EVENT_RE = re.compile(r'\[Subsystem: launchd\] \[Event: ([^\]]+)\] Doing boot task')
MSG_TS_RE = re.compile(r'^\[\s*(\d+\.\d+)\]:')
EXIT_REASON_RE = re.compile(r'pid \d+ exited -- exit reason')


def parse_header(data):
    if len(data) < BLOCK:
        sys.exit(f'log window too short ({len(data)} bytes)')
    magic = data[0:8]
    if magic != b'SHLOG001':
        sys.exit(f'not a boot log window (magic {magic!r})')
    (version, header_bytes) = struct.unpack_from('<II', data, 8)
    (boot_id, first_lba) = struct.unpack_from('<QQ', data, 0x10)
    (window_blocks, msg_first, msg_blocks, msg_bytes, slot_first, slot_blocks, slot_count, slots_written,
     uptime_s, rounds, write_errors, gpt_open, gpt_last, state) = struct.unpack_from('<14I', data, 0x20)
    tag = data[0x58:0x78].split(b'\0')[0].decode('ascii', 'replace')
    (export_first, export_blocks, export_bytes, export_generation, export_below, diag_first, diag_bytes) = \
        struct.unpack_from('<7I', data, 0x78)
    return dict(version=version, header_bytes=header_bytes, boot_id=boot_id, first_lba=first_lba,
                window_blocks=window_blocks, msg_first=msg_first, msg_blocks=msg_blocks, msg_bytes=msg_bytes,
                slot_first=slot_first, slot_blocks=slot_blocks, slot_count=slot_count, slots_written=slots_written,
                uptime_s=uptime_s, rounds=rounds, write_errors=write_errors, gpt_open=gpt_open, gpt_last=gpt_last,
                state=state, tag=tag, export_first=export_first, export_blocks=export_blocks, export_bytes=export_bytes,
                export_generation=export_generation, export_below=export_below, diag_first=diag_first,
                diag_bytes=diag_bytes)


def slot_round(text):
    # "#slot %u t=%us tag=%s"
    for line in text.split("\n"):
        if line.startswith("#slot "):
            return int(line.split()[1])
    return None


def extract_section(text, start, stop=None):
    lines, keep, out = text.split("\n"), False, []
    for line in lines:
        if line.startswith("#slot "):
            out.append(line)
        elif line == start:
            keep = True
        elif stop and line == stop:
            keep = False
        elif keep and not line.startswith("["):
            out.append(line)
        elif keep and line.startswith("["):
            break
    return "\n".join(out)


def counted_slots(data, h, extract=None):
    """The slots the header counts, chronological: read-m2381-ufs-log.py's iteration and skip rules
    (with its --page/--spawn section extraction as the optional `extract`)."""
    counted = h['slots_written']
    truncated = counted <= h['slot_count']
    slots = []
    for index in range(h['slot_count'] if not truncated else counted):
        at = (h['slot_first'] + index * h['slot_blocks']) * BLOCK
        raw = data[at:at + h['slot_blocks'] * BLOCK]
        text = raw.decode('ascii', 'replace')
        if not text.startswith('#slot '):
            continue
        text = text.rstrip('\0')
        round_no = slot_round(text)
        if round_no is None:
            continue
        if extract is not None:
            text = extract(text)
        if text.strip():
            slots.append((round_no, text))
    slots.sort()
    return slots


def parse_exit_row(line):
    m = EXIT_ROW_RE.match(line)
    if not m:
        return None
    pid, name, status, sig, exit_, ns, sub = m.groups()
    return dict(row=line, pid=int(pid), name=name, status=status, sig=int(sig), exit=int(exit_),
                ns=int(ns), sub=int(sub), nonzero=any(v != '0' for v in (status, sig, exit_, ns, sub)))


def parse_slot(text):
    """One slot's text into its page clocks, UFS lines, stage rows, exit table, census and crash rows."""
    out = dict(round=None, t=None, page=None, ufs=[], stage=[], exits=[], exit_counts=None,
               census=[], census_names=None, census_dropped=None, crash=[], throw=[], reason=[], xpc=[])
    section, collecting = None, False
    for line in text.split('\n'):
        if line.startswith('#slot '):
            m = SLOT_HEAD_RE.match(line)
            if m:
                out['round'], out['t'] = int(m.group(1)), int(m.group(2))
            continue
        if line == '[page]':
            section, collecting = 'page', False
            continue
        if line == '[banner]':
            section, collecting = None, False
            continue
        if line == '[spawn]':
            section, collecting = 'spawn', False
            continue
        if line.startswith('['):          # [ext], [profile], [cryptex os] ... rows we do not parse
            section, collecting = 'other', False
            continue
        if section == 'page':
            m = TIME_RE.match(line)
            if m:
                t, idle, irq, mon, lost, root, procs, free, spawn, rate = m.groups()
                out['page'] = dict(raw=line, time=int(t), idle=int(idle), IRQ=int(irq), monitor=int(mon),
                                   lost=int(lost), root=int(root), procs=int(procs), free=int(free),
                                   spawn=int(spawn), rate=int(rate))
                collecting = False
                continue
            if UFS_RE.match(line) or UFS_TIME_RE.match(line):
                out['ufs'].append(line)
                collecting = False
                continue
            if line.startswith('stage +') or STAGE_ROW_RE.match(line):
                out['stage'].append(line.rstrip())
                collecting = False
                continue
            m = EXITS_RE.match(line)
            if m:
                out['exit_counts'] = dict(total=int(m.group(1)), nonzero=int(m.group(2)), dropped=int(m.group(3)))
                collecting = True
                continue
            if collecting:
                row = parse_exit_row(line)
                if row:
                    out['exits'].append(row)
                else:
                    collecting = False
            continue
        if section == 'spawn':
            if line.startswith('CRASH '):
                out['crash'].append(line)
                continue
            if line.startswith('THROW '):
                out['throw'].append(line)
                continue
            if line.startswith('REASON '):
                out['reason'].append(line)
                continue
            if line.startswith('xpcproxy exits:') or line.startswith('XPC '):
                out['xpc'].append(line)
                continue
            m = re.match(r'^names=(\d+) dropped=(\d+)', line)
            if m:
                out['census_names'], out['census_dropped'] = int(m.group(1)), int(m.group(2))
                continue
            for name, started, exited, first in CENSUS_ITEM_RE.findall(line):
                out['census'].append(dict(name=name, started=int(started), exited=int(exited), first=int(first)))
            continue
    out['census_by_name'] = {c['name']: c for c in out['census']}
    return out


def msgbuf_text(data, h):
    raw = data[h['msg_first'] * BLOCK:(h['msg_first'] + h['msg_blocks']) * BLOCK]
    return raw[:h['msg_bytes']].decode('ascii', 'replace')


def parse_msgbuf(text):
    lines = [l for l in text.split('\n') if l.strip()]
    events, exit_reasons, last_ts = {}, [], None
    for line in lines:
        m = MSG_TS_RE.match(line)
        if m:
            last_ts = float(m.group(1))
        ev = EVENT_RE.search(line)
        if ev and last_ts is not None and ev.group(1) not in events:
            events[ev.group(1)] = last_ts          # first boot-task event per name
        if EXIT_REASON_RE.search(line):
            exit_reasons.append((last_ts, line))
    last_line = lines[-1] if lines else None
    m = MSG_TS_RE.match(last_line or '')
    return dict(lines=lines, last_line=last_line, last_ts=float(m.group(1)) if m else last_ts,
                events=events, exit_reasons=exit_reasons)


def clock_offset(events, census):
    """kernel-clock minus page-clock, from launchd boot-task events (msgbuf kernel t) paired by name with the
    census first-start seconds (page clock); median over the pairs."""
    pairs = [(name, kt - census[name]['first']) for name, kt in events.items() if name in census]
    if not pairs:
        return None
    offsets = sorted(pairs, key=lambda p: p[1])
    vals = [o for _, o in offsets]
    n = len(vals)
    med = vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2
    return dict(offset_s=med, pairs=n, min_s=vals[0], max_s=vals[-1], per_pair=offsets)


def residue_generations(data, h):
    """The slots past slots_written, read in ring order (newest boot first), split into generations where the
    slot stamp, page time= or IRQ count regresses — a regression means the next older boot's slots began."""
    start = min(h['slots_written'], h['slot_count'])
    gens, cur, prev = [], None, None
    for index in range(start, h['slot_count']):
        at = (h['slot_first'] + index * h['slot_blocks']) * BLOCK
        raw = data[at:at + h['slot_blocks'] * BLOCK]
        text = raw.split(b'\0')[0].decode('ascii', 'replace')
        if not text.startswith('#slot '):
            if cur is not None:
                cur['notext'] += 1
            continue
        s = parse_slot(text)
        page = s.get('page') or {}
        clocks = (s['t'], page.get('time'), page.get('IRQ'))
        boundary = cur is not None and prev is not None and any(
            o is not None and new is not None and new < o for o, new in zip(prev, clocks))
        if cur is None or boundary:
            cur = dict(slots=[], notext=0)
            gens.append(cur)
        cur['slots'].append((index, s))
        if any(c is not None for c in clocks):
            prev = clocks
    return gens


def header_summary(path, h):
    boot_s = h['boot_id'] / CNTFRQ_HZ
    lines = [
        f'# log window: {path}',
        f"# tag='{h['tag']}' version={h['version']} header_bytes={h['header_bytes']} first_lba=0x{h['first_lba']:x} "
        f'window_blocks={h["window_blocks"]} ({h["window_blocks"] * BLOCK >> 20} MiB)',
        f"# boot_id=0x{h['boot_id']:x} = {h['boot_id']} ticks = {boot_s:.3f}s at cntfrq {CNTFRQ_HZ} Hz",
        f"# slots_written={h['slots_written']}/{h['slot_count']} (slot_blocks={h['slot_blocks']}) "
        f"uptime={h['uptime_s']}s rounds={h['rounds']} write_errors={h['write_errors']}",
        f"# gpt {h['gpt_open']}->{h['gpt_last']} state={h['state']} export_bytes={h['export_bytes']} "
        f"diag_bytes={h['diag_bytes']} msg_bytes={h['msg_bytes']}",
        "# clocks: page 'time=' (page-clock) vs msgbuf '[   T]:' (kernel-clock = page + ~21-22s, per boot) are two bases;",
        f"#         --deaths/--json estimate the real offset. boot_id = CNTPCT at writer start ({boot_s:.3f}s here):",
        '#         a hard power-off resets it, so it tells runs apart but does not order them.',
    ]
    residue_at = min(h['slots_written'], h['slot_count'])
    if residue_at < h['slot_count']:
        lines.append(f'# residue: ring slots {residue_at}..{h["slot_count"] - 1} still hold older boots (--residue to split generations)')
    print('\n'.join(lines))


def residue_report(path, h, data):
    start = min(h['slots_written'], h['slot_count'])
    if start >= h['slot_count']:
        print(f'# residue of {path}: none — slots_written={h["slots_written"]} covers the whole ring '
              f'(slot_count={h["slot_count"]}), nothing older survives')
        return
    gens = residue_generations(data, h)
    kept = sum(len(g['slots']) for g in gens)
    print(f'# residue of {path}: ring slots {start}..{h["slot_count"] - 1}, {len(gens)} generation(s), {kept} text slots '
          f'(ring order = newest boot first; residue boot_id is unknowable, the header only names the current boot)')
    for n, g in enumerate(gens, 1):
        slots = g['slots']
        i0, i1 = slots[0][0], slots[-1][0]
        rounds = [s['round'] for _, s in slots]

        def clk(s):
            p = s.get('page') or {}
            return (f"#slot {s['round']} t={s['t']}s time={p.get('time', '?')}s "
                    f"IRQ={p.get('IRQ', '?')} monitor={p.get('monitor', '?')}")
        last = slots[-1][1]
        crash_n = sum(len(s.get('crash', [])) for _, s in slots)
        head = ' '.join(f"{c['name']} {c['started']}/{c['exited']}@{c['first']}" for c in last.get('census', [])[:3])
        print(f'[gen {n}: boot_id unknown, 槽 {i0}..{i1}] slots={len(slots)} (no-text={g["notext"]}) '
              f'rounds {rounds[0]}..{rounds[-1]}')
        print(f'  first clock: {clk(slots[0][1])}')
        print(f'  last clock:  {clk(last)}')
        print(f'  last slot census: names={last.get("census_names")}'
              f'{f" [{head} ...]" if head else ""} CRASH rows in gen: {crash_n}')


def deaths_report(path, h, data):
    slots = counted_slots(data, h)
    parsed = [(r, parse_slot(t)) for r, t in slots]
    mb = parse_msgbuf(msgbuf_text(data, h))
    census = parsed[-1][1]['census_by_name'] if parsed else {}
    off = clock_offset(mb['events'], census)
    print(f'# deaths: {path} boot_id=0x{h["boot_id"]:x} ({h["boot_id"] / CNTFRQ_HZ:.3f}s) '
          f'slots_written={h["slots_written"]}/{h["slot_count"]}')
    if off:
        print(f'# offset: kernel-clock = page-clock + {off["offset_s"]:.2f}s '
              f'(median of {off["pairs"]} boot-task/census name pairs, spread {off["min_s"]:.2f}..{off["max_s"]:.2f})')
    else:
        print('# offset: unpaired (no launchd boot-task event matches a census name)')
    crash = [(r, p['t'], line) for r, p in parsed for line in p['crash']]
    print(f'CRASH rows: {len(crash)}')
    for r, t, line in crash:
        print(f'  slot {r} t={t}s {clip(line)}')
    print(f'msgbuf exit reasons: {len(mb["exit_reasons"])}')
    for ts, line in mb['exit_reasons']:
        print(f'  msgbuf (kernel-clock {ts if ts is not None else "?"}): {clip(line)}')
    nonzero = {}
    for r, p in parsed:
        for row in p['exits']:
            if row['nonzero'] and row['row'] not in nonzero:
                nonzero[row['row']] = (r, p['t'])
    counter = parsed[-1][1]['exit_counts'] if parsed else None
    counter_s = f'nonzero-status-or-reason={counter["nonzero"]}' if counter else 'no counted slots'
    print(f'exit-table nonzero rows: {len(nonzero)} distinct over the counted slots (last page counter: {counter_s})')
    for row, (r, t) in nonzero.items():
        print(f'  slot {r} t={t}s {clip(row)}')
    if not crash and not mb['exit_reasons'] and not nonzero:
        print('  (no death evidence in the counted slots)')


def clip(text, n=160):
    return text if len(text) <= n else text[:n] + '...'


def slot_json(p, round_no):
    page = p.get('page') or {}
    return dict(slot=round_no, t=p['t'],
                time=page.get('time'), IRQ=page.get('IRQ'), idle=page.get('idle'), monitor=page.get('monitor'),
                lost=page.get('lost'), procs=page.get('procs'), free=page.get('free'),
                spawn=page.get('spawn'), spawn_rate=page.get('rate'),
                UFS=p.get('ufs', []), stage=p.get('stage', []),
                exits=dict(counts=p.get('exit_counts'),
                           rows=[dict(pid=r['pid'], name=r['name'], status=r['status'], sig=r['sig'],
                                      exit=r['exit'], ns=r['ns'], sub=r['sub'], nonzero=r['nonzero'],
                                      row=r['row']) for r in p.get('exits', [])]),
                census=[dict(name=c['name'], started=c['started'], exited=c['exited'], first=c['first'])
                        for c in p.get('census', [])],
                census_names=p.get('census_names'), CRASH=p.get('crash', []), THROW=p.get('throw', []),
                REASON=p.get('reason', []))


def json_report(path, h, data):
    slots = counted_slots(data, h)
    parsed = [(r, parse_slot(t)) for r, t in slots]
    mb = parse_msgbuf(msgbuf_text(data, h))
    census = parsed[-1][1]['census_by_name'] if parsed else {}
    off = clock_offset(mb['events'], census)
    doc = dict(
        file=str(path),
        header={**h, 'boot_id_s': round(h['boot_id'] / CNTFRQ_HZ, 6)},
        clock_offset=dict(kernel_minus_page_s=round(off['offset_s'], 3), pairs=off['pairs'],
                          spread_s=[round(off['min_s'], 3), round(off['max_s'], 3)],
                          per_pair=sorted(((n, round(o, 3)) for n, o in off['per_pair']), key=lambda x: x[1]),
                          method='median of msgbuf launchd boot-task kernel t minus census first-start page t, by name')
        if off else dict(offset='unpaired', pairs=0),
        msgbuf=dict(msg_bytes=h['msg_bytes'], lines=len(mb['lines']), last_line=mb['last_line'],
                    last_timestamp_s=mb['last_ts'],
                    exit_reason_lines=[line for _, line in mb['exit_reasons']]),
        slots=[slot_json(p, r) for r, p in parsed],
    )
    print(json.dumps(doc, indent=1))


def exec_sequence(parsed_slots):
    seq, seen = [], set()
    for _, p in parsed_slots:
        for line in p.get('stage', []):
            m = EXEC_ROW_RE.match(line)
            if m and m.group(1) + ' ' + m.group(2) not in seen:
                seen.add(m.group(1) + ' ' + m.group(2))
                seq.append(f'{m.group(1)}s {m.group(2)}')
    return seq


def diff_items(items):
    for label, a, b in items:
        print(f'  {label}: A={a} B={b} {"SAME" if a == b else "DIFF"}')


def diff_report(mine_path, mine_h, mine_data, other_path):
    other_data = open(other_path, 'rb').read()
    oh = parse_header(other_data)
    a_slots = counted_slots(mine_data, mine_h)
    b_slots = counted_slots(other_data, oh)
    ap = parse_slot(a_slots[-1][1]) if a_slots else None
    bp = parse_slot(b_slots[-1][1]) if b_slots else None
    print(f'# diff A={mine_path} boot_id=0x{mine_h["boot_id"]:x} ({mine_h["boot_id"] / CNTFRQ_HZ:.3f}s) '
          f'slots_written={mine_h["slots_written"]}/{mine_h["slot_count"]} uptime={mine_h["uptime_s"]}s '
          f'rounds={mine_h["rounds"]}')
    print(f'#     B={other_path} boot_id=0x{oh["boot_id"]:x} ({oh["boot_id"] / CNTFRQ_HZ:.3f}s) '
          f'slots_written={oh["slots_written"]}/{oh["slot_count"]} uptime={oh["uptime_s"]}s '
          f'rounds={oh["rounds"]}')
    print('#     boot_id does not order runs (CNTPCT, reset by hard power-off): B is just the other window')
    print('== last page ==')
    for tag, p in (('A', ap), ('B', bp)):
        if p and p.get('page'):
            print(f'  {tag}: slot {p["round"]} (t={p["t"]}s)')
        else:
            print(f'  {tag}: no counted slots')
    if ap and bp and ap.get('page') and bp.get('page'):
        a, b = ap['page'], bp['page']
        diff_items([(k, a.get(k), b.get(k)) for k in
                    ('time', 'idle', 'IRQ', 'monitor', 'lost', 'procs', 'free', 'spawn', 'rate')])
        print('== last page UFS ==')
        au, bu = {}, {}
        for line in ap.get('ufs', []):
            m = UFS_RE.match(line) or UFS_TIME_RE.match(line)
            au['requests_raw'] = line if UFS_RE.match(line) else au.get('requests_raw')
            if UFS_RE.match(line):
                au.update(dict(zip(('requests', 'verified4K', 'failures', 'integrity', 'published'),
                                   map(int, UFS_RE.match(line).groups()))))
            if UFS_TIME_RE.match(line):
                au.update(dict(zip(('time_verify_ms', 'time_read_ms', 'time_verified_blocks'),
                                   map(int, UFS_TIME_RE.match(line).groups()))))
        for line in bp.get('ufs', []):
            if UFS_RE.match(line):
                bu.update(dict(zip(('requests', 'verified4K', 'failures', 'integrity', 'published'),
                                   map(int, UFS_RE.match(line).groups()))))
            if UFS_TIME_RE.match(line):
                bu.update(dict(zip(('time_verify_ms', 'time_read_ms', 'time_verified_blocks'),
                                   map(int, UFS_TIME_RE.match(line).groups()))))
        diff_items([(k, au.get(k), bu.get(k)) for k in
                    ('requests', 'verified4K', 'failures', 'integrity', 'published',
                     'time_verify_ms', 'time_read_ms', 'time_verified_blocks')])
        print('== last page census ==')
        an = [c['name'] for c in ap.get('census', [])]
        bn = [c['name'] for c in bp.get('census', [])]
        common = [n for n in an if n in set(bn)]
        only_a = [n for n in an if n not in set(bn)]
        only_b = [n for n in bn if n not in set(an)]
        print(f'  names: A={len(an)} (census_names={ap.get("census_names")}) B={len(bn)} (census_names={bp.get("census_names")}) '
              f'{"SAME" if set(an) == set(bn) else "DIFF"}')
        print(f'  common={len(common)}, only in A: {only_a if only_a else "(none)"}, only in B: {only_b if only_b else "(none)"}')
        print('== last page exit table ==')
        diff_items([('total', ap['exit_counts'] and ap['exit_counts']['total'], bp['exit_counts'] and bp['exit_counts']['total']),
                    ('nonzero-status-or-reason', ap['exit_counts'] and ap['exit_counts']['nonzero'],
                     bp['exit_counts'] and bp['exit_counts']['nonzero']),
                    ('dropped', ap['exit_counts'] and ap['exit_counts']['dropped'], bp['exit_counts'] and bp['exit_counts']['dropped'])])
        arows = [r['row'] for r in ap['exits'] if r['nonzero']]
        brows = [r['row'] for r in bp['exits'] if r['nonzero']]
        a_set, b_set = set(arows), set(brows)
        print(f'  nonzero rows on the page: A={len(arows)} B={len(brows)}')
        print(f'  common={len(a_set & b_set)}, only in A: {sorted(a_set - b_set) or "(none)"}, only in B: {sorted(b_set - a_set) or "(none)"}')
        print('  (the page keeps a 3-row FAIL ring plus the 4 most recent exits: one event can show twice)')
    amb = parse_msgbuf(msgbuf_text(mine_data, mine_h))
    bmb = parse_msgbuf(msgbuf_text(other_data, oh))
    print('== msgbuf ==')
    print(f'  A last [{amb["last_ts"]}]: {clip(amb["last_line"] or "")}')
    print(f'  B last [{bmb["last_ts"]}]: {clip(bmb["last_line"] or "")}')
    print(f'  last kernel-clock timestamp: A={amb["last_ts"]} B={bmb["last_ts"]} '
          f'{"SAME" if amb["last_ts"] == bmb["last_ts"] else "DIFF"}')
    print('== launchd exec stage sequence (deduped, chronological, all counted slots) ==')
    a_seq = exec_sequence([(r, parse_slot(t)) for r, t in a_slots])
    b_seq = exec_sequence([(r, parse_slot(t)) for r, t in b_slots])
    print(f'  A {len(a_seq)} rows, B {len(b_seq)} rows')
    only_a, only_b, common = [], [], 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a_seq, b_seq, autojunk=False).get_opcodes():
        if tag == 'equal':
            common += i2 - i1
        elif tag == 'delete':
            only_a += a_seq[i1:i2]
        elif tag == 'insert':
            only_b += b_seq[j1:j2]
        else:
            only_a += a_seq[i1:i2]
            only_b += b_seq[j1:j2]
    print(f'  common rows: {common}')
    for line in only_a:
        print(f'  only in A: {clip(line)}')
    for line in only_b:
        print(f'  only in B: {clip(line)}')
    if not only_a and not only_b:
        print('  sequences identical')


def text_channel(data, h, args):
    if args.msg:
        raw = data[h['msg_first'] * BLOCK:(h['msg_first'] + h['msg_blocks']) * BLOCK]
        sys.stdout.write(raw[:h['msg_bytes']].decode('ascii', 'replace'))
        return
    if args.page:
        extract = lambda text: extract_section(text, '[page]', '[banner]')  # noqa: E731
    elif args.spawn:
        extract = lambda text: extract_section(text, '[spawn]')  # noqa: E731
    else:
        extract = None
    for _, text in counted_slots(data, h, extract):
        sys.stdout.write(text + '\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('image', help='raw image of the 32 MiB log window (log.bin)')
    ap.add_argument('--page', action='store_true', help='only the [page] diagnostic snapshots (simple-channel output)')
    ap.add_argument('--spawn', action='store_true', help='only the [spawn] census sections (simple-channel output)')
    ap.add_argument('--msg', action='store_true', help='the kernel message buffer (simple-channel output)')
    ap.add_argument('--all', action='store_true', help='every counted slot, full text (simple-channel output)')
    ap.add_argument('--residue', action='store_true', help='split the slots past slots_written into generations')
    ap.add_argument('--deaths', action='store_true', help='CRASH rows, exit reasons, nonzero exit rows + clock offset')
    ap.add_argument('--json', action='store_true', help='structured slots on stdout, for diffing')
    ap.add_argument('--diff', metavar='OTHER', help='semantic diff of the last pages/census/exits/msgbuf/exec sequence vs OTHER log.bin')
    args = ap.parse_args()

    data = open(args.image, 'rb').read()
    h = parse_header(data)
    # The simple channel's stderr banner, kept so a redirected run still matches the parsed-*.txt files.
    shown = (f"tag={h['tag']} version={h['version']} rounds={h['rounds']} "
             f"slots_written={h['slots_written']}/{h['slot_count']} uptime={h['uptime_s']}s "
             f"write_errors={h['write_errors']} gpt {h['gpt_open']}->{h['gpt_last']} "
             f"state={h['state']} export_bytes={h['export_bytes']}")
    print(f'# log window: {shown}', file=sys.stderr)
    counted = h['slots_written']
    if counted <= h['slot_count'] and not args.msg:
        print(f'# truncating to the {counted} slots the header counts '
              f'(slots {counted}..{h["slot_count"] - 1} are residue from a previous boot)', file=sys.stderr)

    if args.msg or args.page or args.spawn or args.all:
        text_channel(data, h, args)
    elif not (args.residue or args.deaths or args.json or args.diff):
        header_summary(args.image, h)
    if args.residue:
        residue_report(args.image, h, data)
    if args.deaths:
        deaths_report(args.image, h, data)
    if args.json:
        json_report(args.image, h, data)
    if args.diff:
        diff_report(args.image, h, data, args.diff)


if __name__ == '__main__':
    main()
