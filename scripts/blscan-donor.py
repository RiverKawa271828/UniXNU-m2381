#!/usr/bin/env python3
"""Enumerate every word-aligned direct bl/b station in the donor KC that
targets given donor VAs (the dividend-accounting scanner; generalized from
the session-47 one-off, which proved the w38 pool = 5 bl + 1 GOT etc.).

usage:
  python3 blscan-donor.py 0xfffffe000a963a34 0xfffffe000a963aa0 ...
Requires /home/ri/work/tools/xnu27 on the path (kc.py KC for the donor image).
Output: one line per station `site  bl|b  target`, then a per-target tally.
"""
import struct
import sys

sys.path.insert(0, '/home/ri/work/tools/xnu27')
import kc as K  # noqa: E402


def sxt26(w):
    imm = w & 0x3FFFFFF
    if imm & 0x2000000:
        imm -= 0x4000000
    return imm


def main():
    targets = {}
    for a in sys.argv[1:]:
        v = int(a, 16)
        if v < 0x10000000000000:
            v |= 0xFFFFFE0000000000
        targets[v] = a
    k = K.KC()
    found = []
    for v, s, f in k.dsegs:
        n = s // 4
        words = struct.unpack_from(f'<{n}I', k.ddata, f)
        for i, w in enumerate(words):
            op = w >> 26
            if op == 0x25 or op == 0x05:  # bl / b
                tgt = v + i * 4 + sxt26(w) * 4
                if tgt in targets:
                    found.append((v + i * 4, tgt, 'bl' if op == 0x25 else 'b'))
    for site, tgt, kind in sorted(found):
        print(f'{site:#x}  {kind}  {tgt:#x}  {targets[tgt]}')
    print(f'total {len(found)} stations')
    from collections import Counter
    for tgt, n in Counter(t for _, t, _ in found).items():
        print(f'  {targets[tgt]}: {n}')


if __name__ == '__main__':
    main()
