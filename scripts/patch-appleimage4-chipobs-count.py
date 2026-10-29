#!/usr/bin/env python3
"""Patch the chip-observation entry-count consumer in AppleImage4 (r87).

r86 redirected the descriptor table pointer ([env+8]) at a demand-zero bss
page and the r86 screen capture confirmed it works exactly as designed: the
fault moved +0x78 bytes forward, with x19 = 0xfffffff009223000 (the adrp
target) live in a real register. The next consumer of the same missing
chip-observation layer is the entry-count pointer two instructions later:

    0xfffffff0046e4734: ldr  x9, [x0, #0x10]        ; 0xf9400809  -> x9 = NULL
    0xfffffff0046e4738: ldr  x8, [x9, #8]           ; data abort far=0x8, x9 = [env+0x10]

Same object, second unregistered pointer, same cure -- redirect at the same
demand-zero bss page (kernel __DATA bss tail 0xfffffff009223000, see the r86
script for the segment reasoning):

    0xfffffff0046e4734: ldr  x9, [x0, #0x10]  ->  adrp x9, 0xfffffff009223000

Static closure of the path after the patch: x8 = [zero+8] = 0 < 4 passes the
count guard at 0x46e473c, the count stores 0 into the globals page
(0x5cac356), the tail `bl 0x46f0e20` re-reads the (real) environment object
and its [x0+0x30] cbz gives a clean return.

Patch chain: kernel.macho -> r85 TXM short-circuit (patch-appleimage4-txm.py)
-> r86 zero table (patch-appleimage4-chipobs.py) -> this patch. Run this
script on kernel-r86-chipobs.macho; all three words coexist in the output.

The VA is the prelinked runtime VA (== the link VA in the prelinked macho; the
panic screen prints these identities). The file offset is re-derived from the
__PLK_TEXT_EXEC segment every run, and the patch refuses to write unless the
original word matches.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

PATCH_VA = 0xFFFFFFF0046E4734
ORIGINAL_WORD = 0xF9400809    # ldr x9, [x0, #0x10]
ZERO_TABLE_VA = 0xFFFFFFF009223000  # same demand-zero page as r86


def segment_for(data, va):
    """Return (segment_name, vmaddr, fileoff) of the LC_SEGMENT_64 covering va."""
    magic, _, _, _, ncmds, _, _ = struct.unpack_from("<IIIIIII", data, 0)
    if magic != 0xFEEDFACF:
        sys.exit(f"not a little-endian MH_MAGIC_64: {data[:4].hex()}")
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            name = data[off + 8:off + 24].split(b"\0")[0].decode(errors="replace")
            vmaddr, vmsize, fileoff, _ = struct.unpack_from("<QQQQ", data, off + 24)
            if vmaddr <= va < vmaddr + vmsize:
                return name, vmaddr, fileoff
        off += cmdsize
    sys.exit(f"no segment covers va 0x{va:x}")


def adrp(rd, pc, target):
    """Encode ADRP Xd, <target> for the 4 KiB page of target, and self-verify."""
    pc_page, tgt_page = pc & ~0xFFF, target & ~0xFFF
    delta = (tgt_page - pc_page) >> 12
    if not -(1 << 20) <= delta < (1 << 20):
        sys.exit(f"adrp delta {delta} pages out of range")
    imm21 = delta & 0x1FFFFF
    word = (1 << 31) | ((imm21 & 3) << 29) | (0b10000 << 24) | ((imm21 >> 2) << 5) | rd
    # decode back
    d_immlo = (word >> 29) & 3
    d_immhi = (word >> 5) & 0x7FFFF
    d_imm = (d_immhi << 2) | d_immlo
    if d_imm >= (1 << 20):
        d_imm -= 1 << 21
    if (pc_page + (d_imm << 12)) != tgt_page or (word & 0x9F000000) != 0x90000000 or (word & 0x1F) != rd:
        sys.exit(f"adrp self-check failed: 0x{word:08x}")
    return word


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kernel", type=Path, help="prelinked kernel Mach-O (TXM + r86 chipobs patched)")
    ap.add_argument("--output", type=Path,
                    help="patched copy path (default: patch the input in place)")
    args = ap.parse_args()

    data = bytearray(args.kernel.read_bytes())
    name, vmaddr, fileoff = segment_for(data, PATCH_VA)
    offset = fileoff + (PATCH_VA - vmaddr)
    word = struct.unpack_from("<I", data, offset)[0]
    if word != ORIGINAL_WORD:
        sys.exit(f"refusing: word at {name}+0x{PATCH_VA - vmaddr:x} (va 0x{PATCH_VA:x}) "
                 f"is 0x{word:08x}, expected the ldr 0x{ORIGINAL_WORD:08x}")
    replacement = adrp(9, PATCH_VA, ZERO_TABLE_VA)
    struct.pack_into("<I", data, offset, replacement)

    out = args.output or args.kernel
    out.write_bytes(data)
    record = {
        "patch": "appleimage4-chipobs-count-zero",
        "source_kernel_sha256": hashlib.sha256(args.kernel.read_bytes()).hexdigest()
                                if out != args.kernel else "(in place)",
        "patched_kernel_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
        "va": f"0x{PATCH_VA:x}",
        "segment": name,
        "file_offset": f"0x{offset:x}",
        "original_word": f"0x{ORIGINAL_WORD:08x}",
        "replacement_word": f"0x{replacement:08x}",
        "zero_table_va": f"0x{ZERO_TABLE_VA:x}",
        "rationale": "r87: the chip-observation entry-count pointer [env+0x10] is "
                     "NULL like the r86 table pointer (same unregistered layer); "
                     "the r86 screen capture proved the zero-page redirect works "
                     "(fault moved +0x78 with x19 = the adrp target live), so "
                     "redirect the second consumer at the same demand-zero bss "
                     "page: count reads 0, the >=4 guard passes, tail returns via "
                     "the [x0+0x30] cbz.",
    }
    sidecar = out.with_suffix(out.suffix + ".patch.json")
    sidecar.write_text(json.dumps(record, indent=2) + "\n")
    print(f"patched {PATCH_VA:#x} in {name}: 0x{ORIGINAL_WORD:08x} -> 0x{replacement:08x} "
          f"(adrp x9, {ZERO_TABLE_VA:#x})")
    print(f"wrote {out}")
    print(f"sha256 {record['patched_kernel_sha256']}")
    print(f"record {sidecar}")


if __name__ == "__main__":
    main()
