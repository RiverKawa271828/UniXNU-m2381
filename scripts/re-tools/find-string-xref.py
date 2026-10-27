#!/usr/bin/env python3
"""Find C-string occurrences of a needle in the cache and xref them in
code (adrp+add / adrp+ldr producing the string VA).

Usage: find-string-xref.py 'displayIdentity'
The assert-message hunt pattern: the REASON text of an NSParameterAssert
names the condition; locating the condition string and its code xrefs
pins the assert site (see records/r55e-judgment.md for the worked
example).
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cachesym import Cache


def xref_code(c, target):
    hits = []
    for addr, size, foff, path in c.mappings:
        with path.open('rb') as f:
            f.seek(foff)
            data = f.read(size)
        lo_scan = max(addr, target - 0x1800000)
        start = lo_scan - addr
        code = data[start:start + min(size - start, 0x3000000)]
        for k in range(0, len(code) - 8, 4):
            w1 = struct.unpack_from('<I', code, k)[0]
            if (w1 & 0x9F000000) != 0x90000000:
                continue
            w2 = struct.unpack_from('<I', code, k + 4)[0]
            adrp_rd = w1 & 0x1f
            immlo = (w1 >> 29) & 0x3
            immhi = (w1 >> 5) & 0x7ffff
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            base = (lo_scan + k) & ~0xfff
            page = base + (imm << 12)
            if page > target:
                continue
            rn = (w2 >> 5) & 0x1f
            if rn != adrp_rd or adrp_rd == 31:
                continue
            if (w2 & 0x7F800000) == 0x91000000:
                off = (w2 >> 10) & 0xfff
            elif (w2 & 0xFFC00000) == 0xF9400000:
                off = ((w2 >> 10) & 0xfff) * 8
            else:
                continue
            if page + off == target:
                hits.append(lo_scan + k)
    return hits


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    needle = sys.argv[1].encode() + b'\0'
    c = Cache()
    occs = []
    for addr, size, foff, path in c.mappings:
        with path.open('rb') as f:
            f.seek(foff)
            data = f.read(size)
        start = 0
        while True:
            j = data.find(needle, start)
            if j < 0:
                break
            occs.append(addr + j)
            start = j + 1
    print(f'{len(occs)} occurrences of {needle[:-1]!r}')
    for o in occs[:40]:
        print(f'  str {o:#x}  {c.sym(o)}')
    for o in occs[:20]:
        hits = xref_code(c, o)
        if hits:
            print(f'--- str {o:#x}: {len(hits)} code xrefs')
            for h in hits[:20]:
                print(f'    ref {h:#x}  {c.sym(h)}')


if __name__ == '__main__':
    main()
