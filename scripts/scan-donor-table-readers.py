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
Default paths are this workspace's donor KC and the w40fix kernel; pass
--final to audit against a different emitted image.
"""
import argparse
import bisect
import json
import struct
import sys
from pathlib import Path

WS = Path('/home/ri/work/unixnu-meizu')
DONOR = WS / 'ios-m2381-unixnu/out/ipsw/23F84/kernelcache.decompressed'
MAPJ = WS / 'ios-m2381-unixnu/out/m2381/ipados-26.5.2-23F84/m2381/kernel/kernel.map.json'
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--final', default=None, help='emitted kernel.macho to read our nodes from')
    args = ap.parse_args()
    final_path = args.final or str(WS / 'ios-m2381-unixnu/out/m2381/kernel-w40fix-96422b08.macho')

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

    # native names from the pairing map; final targets -> noctf space via
    # noctf = (final - collection_base) + native_link_address
    names = {}
    try:
        kj = json.loads((WS / 'ios-m2381-unixnu/out/m2381/ipados-26.5.2-23F84/m2381/kernel/kernel.json').read_text())
        cbase = int(kj['collection_base'], 16)
        nbase = int(kj['native_link_address'], 16)
        fns = json.loads(MAPJ.read_text())['functions']
        nat = sorted((int(r['native'], 16) & 0xfffffffff, r.get('name', ''))
                     for r in fns.values() if r.get('native'))
        keys = [x[0] for x in nat]

        def nm(final_target):
            t = ((final_target - cbase) + nbase) & 0xfffffffff
            i = bisect.bisect_right(keys, t) - 1
            a, s = nat[i]
            return s + (f'+0x{t - a:x}' if t != a else '')
        for off in range(0, 0x800, 8):
            r = node_at(off)
            if r:
                names[off] = nm(r[1])
    except OSError:
        pass

    print(f'donor readers of gTable {TABLE_VA:#x}: {len(hits)}')
    print('(NOTE: this reads the PRISTINE donor, so skews already covered by a'
          ' TEXT_WORD_PATCHES entry still appear — cross-check the kit patch list)')
    skews = 0
    for (site, slot), (tag, mksite) in sorted(hits.items()):
        r = node_at(slot)
        if r is None:
            print(f'  site {site:#x}: slot +{slot:#x} tag {tag:#06x} — NO AUTH NODE in final')
            continue
        div, tgt = r
        mark = 'MATCH' if div == tag else '** SKEW **'
        if div != tag:
            skews += 1
        label = names.get(slot, '')
        print(f'  site {site:#x}: slot +{slot:#x} tag {tag:#06x} ourdiv {div:#06x} {mark} {label}'
              f'  (movk at {mksite:#x})')
    print(f'\nskews: {skews} — each is a wall-in-waiting; add pinned movk swaps to '
          'TEXT_WORD_PATCHES in kits/XnuPrelink/fileset_emit.py')
    return 1 if skews else 0


if __name__ == '__main__':
    sys.exit(main())
