#!/usr/bin/env python3
"""Patch the 20H392 donor's AppleImage4 chip-observation descriptor load (r86).

r85 forced the AP-instantiation method onto its TXM short-circuit, which let
kext start advance to the next consumer of the missing chip-observation layer:
the descriptor loader at 0xfffffff0046e467c. It fetches the environment object
(bl 0xfffffff0046f0e20) and loads the chip-observation descriptor table from
[x0+8]. No Qualcomm chip driver ever registers one, so the field is NULL and
the first descriptor read faults:

    0xfffffff0046e46b4: ldr  x19, [x0, #8]          ; 0xf9400413  -> x19 = NULL
    0xfffffff0046e46c0: ldur q0, [x19, #0x18]       ; data abort far=0x18

The function is the safest possible consumer to satisfy with zeros: with a
zeroed table every path is structurally clean -- the 0x30-byte descriptor copy
writes zeros into the globals page, the entry count [x19+0x48] reads 0 and
passes the two panic guards (>=0x11 at 0x46e46f0 and, via the untouched real
environment object, >=4 at 0x46e473c), the [x19+8] sentinel compare falls to
its b.ne skip, and the tail [x0+0x30] check has its own cbz clean return. So
redirect the table pointer at a page of kernel bss that is demand-zero mapped
and unreferenced:

    0xfffffff0046e46b4: ldr  x19, [x0, #8]   ->  adrp x19, 0xfffffff009223000

Target = the last page of the kernel __DATA segment bss tail
(__DATA vm 0xfffffff0089ec000 + file 0x44000 -> bss 0xfffffff008a30000..
0xfffffff009224000, immediately before __BOOTDATA). Demand-zero pages read as
zeros, kext relocation never targets kernel bss, and the far end is the least
likely to be claimed by an early-boot static object. The adrp encoding is
computed from the live segment layout and decoded back as a self-check.

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

PATCH_VA = 0xFFFFFFF0046E46B4
ORIGINAL_WORD = 0xF9400413    # ldr x19, [x0, #8]
ZERO_TABLE_VA = 0xFFFFFFF009223000  # last page of kernel __DATA bss


def segment_for(data, va):
    """Return (segment_name, vmaddr, fileoff) of the LC_SEGMENT_64 covering va."""
    magic, _, _, _, ncmds, _, _ = struct.unpack_from("<IIIII I I", data, 0)
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
    ap.add_argument("kernel", type=Path, help="prelinked kernel Mach-O (TXM-patched)")
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
    replacement = adrp(19, PATCH_VA, ZERO_TABLE_VA)
    struct.pack_into("<I", data, offset, replacement)

    out = args.output or args.kernel
    out.write_bytes(data)
    record = {
        "patch": "appleimage4-chipobs-zero-table",
        "source_kernel_sha256": hashlib.sha256(args.kernel.read_bytes()).hexdigest()
                                if out != args.kernel else "(in place)",
        "patched_kernel_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
        "va": f"0x{PATCH_VA:x}",
        "segment": name,
        "file_offset": f"0x{offset:x}",
        "original_word": f"0x{ORIGINAL_WORD:08x}",
        "replacement_word": f"0x{replacement:08x}",
        "zero_table_va": f"0x{ZERO_TABLE_VA:x}",
        "rationale": "r86: the chip-observation descriptor table pointer [env+8] is "
                     "always NULL on Qualcomm (no chip driver registers one); redirect "
                     "the consumer at a demand-zero bss page so the loader runs its "
                     "zero-entry path instead of aborting on far=0x18.",
    }
    sidecar = out.with_suffix(out.suffix + ".patch.json")
    sidecar.write_text(json.dumps(record, indent=2) + "\n")
    print(f"patched {PATCH_VA:#x} in {name}: 0x{ORIGINAL_WORD:08x} -> 0x{replacement:08x} "
          f"(adrp x19, {ZERO_TABLE_VA:#x})")
    print(f"wrote {out}")
    print(f"sha256 {record['patched_kernel_sha256']}")
    print(f"record {sidecar}")


if __name__ == "__main__":
    main()
