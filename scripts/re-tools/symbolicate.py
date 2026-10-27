#!/usr/bin/env python3
"""Symbolicate unslid shared-cache VAs against the decoded 21H461 local
symbol table.

Usage: symbolicate.py VA [VA ...]   (hex, with or without 0x)
Strip the dyld slide first: unslid = addr - slide (the slide rides in
every CRASH line, e.g. `+a57c000`). Nearest-symbol-below is reported
plus a distance — treat big offsets on sparsely-symbolized images
(SpringBoard's anonymous stub/helper pools) as artifacts, not facts.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cachesym import Cache


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    c = Cache()
    for a in sys.argv[1:]:
        va = int(a, 16)
        print(f'{va:#x}  {c.sym(va)}')


if __name__ == '__main__':
    main()
