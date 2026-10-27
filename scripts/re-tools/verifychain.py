#!/usr/bin/env python3
"""Verify a SIGABRT/SIGSEGV backtrace frame by frame: decode the
instruction at (return-address - 4) of each frame and check it is a bl
into the next-inner frame's function.

Usage: verifychain.py PC LR BT1 [BT2 ...]   (unslid hex VAs, inner->outer)
A chain is alive when every frame's LR-4 decodes to a bl/blr whose
target matches the next-inner symbol region; frames that decode to
something else are stale or collapsed (exception paths through
dispatch_client_callout routinely drop the block/init frames between
the once-callout and the throwing site).
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cachesym import Cache


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    c = Cache()
    vas = [int(a, 16) for a in sys.argv[1:]]
    labels = ['PC', 'LR'] + [f'bt{i}' for i in range(1, len(vas) - 1)]
    print('=== per-frame bl verification (inner -> outer) ===')
    for i, va in enumerate(vas):
        line = f'{labels[i]:>4} {va:#x} {c.sym(va)}'
        raw = c.read_va(va - 4, 4) if i >= 1 else None
        if raw:
            ins = struct.unpack('<I', raw)[0]
            if (ins >> 26) == 0b100101:  # bl
                imm = ins & 0x3FFFFFF
                if imm & 0x2000000:
                    imm -= 0x4000000
                line += f'   <- bl {c.sym((va - 4) + imm * 4)}'
            elif (ins >> 26) == 0b000101:  # b (tail call)
                imm = ins & 0x3FFFFFF
                if imm & 0x2000000:
                    imm -= 0x4000000
                line += f'   <- b(tail) {c.sym((va - 4) + imm * 4)}'
            else:
                line += f'   <- inst {ins:08x}'
        print(line)


if __name__ == '__main__':
    main()
