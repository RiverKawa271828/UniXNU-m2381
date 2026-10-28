#!/usr/bin/env python3
"""Disassemble at an unslid cache VA; resolve adrp+add string refs and
bl targets.

Usage: disasm.py LABEL VA [N_INS]
"""
import sys
from pathlib import Path

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cachesym import Cache


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    label = sys.argv[1]
    va = int(sys.argv[2], 16)
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 160
    c = Cache()
    fixups = [f for f in c.profile_fixups() if f['va'] is not None]
    print(f'=== {label} {va:#x} ({c.sym(va)}) [runtime: fixups applied] ===')
    code = c.read_run(va, n * 4)
    if code is None:
        print('  <unmapped>')
        return
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    adrp_reg = {}
    for ins in md.disasm(code, va):
        extra = ''
        if ins.mnemonic == 'adrp':
            ops = ins.op_str.split(', ')
            adrp_reg[ops[0]] = int(ops[1].split('#')[1], 0)
        elif ins.mnemonic == 'add' and len(ins.op_str.split(', ')) >= 3:
            parts = [p.strip() for p in ins.op_str.split(', ')]
            if parts[1] in adrp_reg and parts[2].startswith('#'):
                sva = adrp_reg[parts[1]] + int(parts[2][1:].split(' ')[0], 0)
                raw = c.read_va(sva, 96)
                if raw:
                    z = raw.find(b'\0')
                    if z > 0:
                        s = raw[:z].decode('utf-8', 'replace')
                        if all(32 <= ord(ch) < 127 or ch in '\n\t' for ch in s):
                            extra = f'   ; strref {sva:#x}: {s!r}'
        elif ins.mnemonic == 'bl':
            imm = int(ins.op_str.split('#')[1], 0)
            extra = f'   ; -> {c.sym(imm)}'
        for f in fixups:
            if f['va'] <= ins.address < f['va'] + f['size']:
                extra += f'   ; <<< FIXUP {f["where"]}'
        print(f'  {ins.address:#x}: {ins.mnemonic:8s} {ins.op_str}{extra}')


if __name__ == '__main__':
    main()
