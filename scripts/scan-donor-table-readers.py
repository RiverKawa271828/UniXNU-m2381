#!/usr/bin/env python3
"""Audit donor readers of the hybrid-kernel native function-pointer table.

Wall-40 root cause (session-48, 2026-11-04): the kernel entry's
__DATA_CONST is OUR native kernel, so every donor (kept-original) reader
that loads a function pointer through the gTable global and authenticates
it with a compiler-derived movk tag (movk x17, #imm16, lsl #48) hits our
slot's discriminator instead. Each such reader is an FPAC wall waiting for
its first execution; this tool enumerates ALL of them and diffs each
reader's tag against our node div at the same slot offset, so the whole
family can be cleared in one TEXT_WORD_PATCHES batch instead of one wall
per boot.

Reader pattern (canonical, as emitted by both Apple and our compilers):
    adrp  xG, g_page
    ldr   xG, [xG, #g_off]        ; table base
    add   xC, xG, #SLOT           ; context = slot address
    ldr   xT, [xG, #SLOT/8]       ; encoded fn pointer (imm12 scaled by 8!)
    mov   x17, xC
    movk  x17, #TAG, lsl #48
    blraa xT, x17

Encoding traps hit on the way (do not "simplify" these again):
  * LDR imm12 is SCALED by the access size (offset 0x2c0 encodes as 0x58);
    ADD imm12 is raw. Comparing raw-vs-scaled silently finds nothing.
  * BLRAA is not BLR: mask 0xD63F0900-style checks reject every real site.
    The tag+slot pairing is the evidence; do not gate on the branch word.

usage:
  python3 scan-donor-table-readers.py [--final kernel.macho]
Defaults: donor KC = this workspace's 23F84 decompressed cache; final =
the NEWEST kernel-*.macho archive in out/m2381/ (the Mac-build workflow
pulls archives back each round; the local tree kernel.macho is stale).
Name labels come only from a same-build snapshot: a sibling
<name>.map.json/<name>.json or the tree pair, accepted ONLY when the
snapshot's candidate_sha256 matches the audited image — mismatched
maps stay silent instead of printing wrong nearest-names.

Skews already covered by a kit TEXT_WORD_PATCHES entry (matched by the
movk donor VA) are annotated PATCHED and excluded from the actionable
count / exit code. Exit 1 = unpatched SKEW or NO-AUTH-NODE anomalies.
"""
import argparse
import bisect
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

WS = Path('/home/ri/work/unixnu-meizu')
DONOR = WS / 'ios-m2381-unixnu/out/ipsw/23F84/kernelcache.decompressed'
OUT_M2381 = WS / 'ios-m2381-unixnu/out/m2381'
TREE_KERNEL = WS / 'ios-m2381-unixnu/out/m2381/ipados-26.5.2-23F84/m2381/kernel/kernel.macho'
KIT_EMIT = WS / 'UniXNU-m2381/kits/XnuPrelink/fileset_emit.py'
TABLE_VA = 0xfffffe0007e07fd8          # donor global holding the table base
TABLE_PAGE = TABLE_VA & ~0xFFF
G_OFF = 0xfd8                          # offset of the global within its page
STRUCT_BASE_DONOR = 0xfffffe0007cfd410    # donor-space VA our native table is placed at
COLLECTION_SLIDE = 0x1f000000000          # donor -> rebased (final image) space


def load(path):
    data = Path(path).read_bytes()
    ncmds, = struct.unpack_from('<I', data, 16)
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from('<II', data, off)
        if cmd == 0x19:
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            if filesize:
                segs.append((vmaddr, filesize, fileoff))
        off += sz
    return data, segs


def fo(segs, va):
    for v, s, f in segs:
        if v <= va < v + s:
            return f + (va - v)
    return None


def kit_patched_movk_vas():
    """Donor VAs of movk words the kit already rewrites (TEXT_WORD_PATCHES)."""
    try:
        sys.path.insert(0, str(KIT_EMIT.parent))
        try:
            spec = importlib.util.spec_from_file_location('xnu_prelink_emit', KIT_EMIT)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return {va for va, _old, _new, _why in getattr(mod, 'TEXT_WORD_PATCHES', ())}
        finally:
            sys.path.pop(0)
    except (OSError, ImportError, AttributeError, ValueError):
        print(f'warning: cannot read kit patches from {KIT_EMIT}; '
              'PATCHED annotation unavailable', file=sys.stderr)
        return set()


def default_final():
    """Newest archived emit; the tree kernel.macho is stale in the Mac workflow."""
    archives = sorted(OUT_M2381.glob('kernel-*.macho'), key=lambda p: p.stat().st_mtime)
    return str(archives[-1]) if archives else str(TREE_KERNEL)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def name_source(final_path):
    """(map_functions, native_slide) from a sha-matched snapshot.

    Tries sibling <stem>.map.json/<stem>.json first (round snapshots kept
    next to the archive), then the tree pair. The snapshot's
    candidate_sha256 must match the image; a mismatched map stays silent
    instead of printing wrong nearest-names.

    The noctf->final placement slide is self-calibrated: histogram
    (node_target - map_native) over 0x4000-aligned candidates and take
    the clear winner (page-aligned placement makes noise ~zero; the
    slide must also collect >= MIN_PAIR exact pair hits). Hardcoding the
    slide would rot across builds — the -0x193F4 drift of session-47 is
    the precedent.
    """
    stem = Path(final_path).stem
    cand = [(OUT_M2381 / f'{stem}.map.json', OUT_M2381 / f'{stem}.json'),
            (TREE_KERNEL.parent / 'kernel.map.json', TREE_KERNEL.parent / 'kernel.json')]
    img_sha = sha256(final_path)
    for mapj, kjson in cand:
        try:
            kj = json.loads(kjson.read_text())
            if kj.get('candidate_sha256') != img_sha:
                continue
            return json.loads(mapj.read_text())['functions']
        except (OSError, KeyError, ValueError):
            continue
    print('note: no sha-matched map snapshot for this image; name labels off', file=sys.stderr)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--final', default=None,
                    help='emitted kernel.macho (default: newest archive in out/m2381/)')
    args = ap.parse_args()
    final_path = args.final or default_final()
    patched = kit_patched_movk_vas()

    data, segs = load(str(DONOR))
    fdata, fsegs = load(final_path)

    hits = {}
    for vm, sz, fo_ in segs:
        buf = data[fo_:fo_ + sz]
        n = len(buf) // 4
        words = struct.unpack_from('<%dI' % n, buf, 0)
        for i in range(n):
            w = words[i]
            # ldr xG, [xG, #G_OFF]
            if (w & 0xFFC00000) != 0xF9400000 or ((w >> 10) & 0xFFF) * 8 != G_OFF:
                continue
            g = (w >> 5) & 0x1F
            ok = False
            for u in range(max(0, i - 8), i):
                wa = words[u]
                if (wa & 0x9F000000) == 0x90000000 and (wa & 31) == g:
                    immlo = (wa >> 29) & 3
                    immhi = (wa >> 5) & 0x7FFFF
                    imm = (immhi << 2) | immlo
                    if imm & (1 << 20):
                        imm -= (1 << 21)
                    if ((vm + u * 4) + (imm << 12) & ~0xFFF) == TABLE_PAGE:
                        ok = True
            if not ok:
                continue
            # forward window: add xC, xG, #slot; ldr xT, [xG, slot/8]; movk x17
            for j in range(i + 1, min(n, i + 41)):
                wa = words[j]
                if (wa & 0xFF800000) != 0x91000000 or (wa >> 5) & 0x1F != g:
                    continue
                slot = (wa >> 10) & 0xFFF
                c = wa & 31
                if slot % 8 or slot == 0:
                    continue
                for t in range(j + 1, min(n, j + 7)):
                    wl = words[t]
                    if (wl & 0xFFC00000) == 0xF9400000 and (wl >> 5) & 0x1F == g \
                            and (wl >> 10) & 0xFFF == slot >> 3:
                        for mk in range(t + 1, min(n, t + 7)):
                            wmk = words[mk]
                            if (wmk & 0xFFE00000) == 0xF2E00000 and (wmk & 31) == 17:
                                hits[(vm + i * 4, slot)] = ((wmk >> 5) & 0xffff, vm + mk * 4)
                                break
                        break

    # our nodes: donor offset -> (div, final target); final image is rebased space
    def node_at(off):
        f = fo(fsegs, STRUCT_BASE_DONOR + COLLECTION_SLIDE + off)
        if f is None:
            return None
        v = struct.unpack_from('<Q', fdata, f)[0]
        if not (v >> 63):
            return None
        return ((v >> 32) & 0xffff, 0xfffffff007004000 + (v & 0x3fffffff))

    # native names from a sha-matched snapshot with a self-calibrated slide
    names = {}
    fns = name_source(final_path)
    if fns:
        nat = sorted((int(r['native'], 16) & 0xfffffffff, r.get('name', ''))
                     for r in fns.values() if r.get('native'))
        nkeys = [x[0] for x in nat]
        targets = [node_at(off)[1] & 0xfffffffff for off in range(0, 0x800, 8)
                   if node_at(off)]
        from collections import Counter
        hist = Counter()
        for t in targets:
            for n in nkeys:
                s = t - n
                if s > 0 and s % 0x4000 == 0:
                    hist[s] += 1
        slide = hist.most_common(1)[0][0] if hist else None
        if not slide or hist[slide] < 2:
            print('note: native placement slide ambiguous; name labels off', file=sys.stderr)
            slide = None
        else:
            print(f'native placement slide: {slide:#x} '
                  f'({hist[slide]} exact pair anchors)')
        if slide:
            def nm(final_target):
                t = (final_target & 0xfffffffff) - slide
                i = bisect.bisect_left(nkeys, t)
                if i < len(nkeys) and nkeys[i] == t:
                    return nat[i][1]
                j = max(0, i - 1)
                a, s2 = nat[j]
                return s2 + (f'+0x{t - a:x}' if t >= a else '?')
            for off in range(0, 0x800, 8):
                r = node_at(off)
                if r:
                    names[off] = nm(r[1])

    print(f'donor readers of gTable {TABLE_VA:#x}: {len(hits)}  '
          f'(final = {Path(final_path).name})')
    skews = no_node = 0
    for (site, slot), (tag, mksite) in sorted(hits.items()):
        r = node_at(slot)
        note = '  [PATCHED by kit]' if mksite in patched else ''
        if r is None:
            no_node += 1 if mksite not in patched else 0
            print(f'  site {site:#x}: slot +{slot:#x} tag {tag:#06x} — NO AUTH NODE in final{note}')
            continue
        div, tgt = r
        skewed = div != tag
        if skewed and mksite not in patched:
            skews += 1
        mark = ('PATCHED SKEW' if skewed else 'MATCH') if mksite in patched \
            else ('** SKEW **' if skewed else 'MATCH')
        label = names.get(slot, '')
        print(f'  site {site:#x}: slot +{slot:#x} tag {tag:#06x} ourdiv {div:#06x} {mark} {label}'
              f'  (movk at {mksite:#x}){note}')
    print(f'\nactionable anomalies: {skews} SKEW + {no_node} NO-NODE — each is a '
          'wall-in-waiting; add pinned movk swaps to TEXT_WORD_PATCHES in '
          'kits/XnuPrelink/fileset_emit.py')
    return 1 if (skews or no_node) else 0


if __name__ == '__main__':
    sys.exit(main())
