#!/usr/bin/env python3
"""Patch the 20H392 donor's AppleImage4 kext to take its TXM short-circuit path (r85).

AppleImage4 kext start panics with "failed to get mix-n-match policy: 2": the AP
instantiation method queries the chip observation/policy layer (identifier 12,
vtable [self+0x38] -> internal list lookup) that no Qualcomm board provides, and
panics via its own _panic import slot on the non-zero return. The same method has
a built-in short-circuit: with bit 1 of [self+0x1a8] set it skips the whole
policy/manifest-properties/BNCH block, logs "system contains a TXM runtime", and
returns through the log tail-call. Its caller (the environment-object loop at
0xfffffff0046e4b2c) never checks the method's return value, so forcing the
short-circuit is return-safe. One instruction:

    0xfffffff0046e9924: tbnz w8, #1, #0xfffffff0046e9a44   ; 0x37080908
    replacement:        b    #0xfffffff0046e9a44   ; 0x14000048

The VA is the prelinked runtime VA (== the link VA in the prelinked macho; the
panic screen prints these identities). The file offset is re-derived from the
__PLK_TEXT_EXEC segment every run, and the patch refuses to write unless the
original word matches, so a rebuilt kernel with a different layout is left
alone loudly instead of corrupted quietly.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

PATCH_VA = 0xFFFFFFF0046E9924
ORIGINAL_WORD = 0x37080908   # tbnz w8, #1, #0xfffffff0046e9a44
REPLACEMENT_WORD = 0x14000048  # b #0xfffffff0046e9a44


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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kernel", type=Path, help="prelinked kernel Mach-O")
    ap.add_argument("--output", type=Path,
                    help="patched copy path (default: patch the input in place)")
    args = ap.parse_args()

    data = bytearray(args.kernel.read_bytes())
    name, vmaddr, fileoff = segment_for(data, PATCH_VA)
    offset = fileoff + (PATCH_VA - vmaddr)
    word = struct.unpack_from("<I", data, offset)[0]
    if word != ORIGINAL_WORD:
        sys.exit(f"refusing: word at {name}+0x{PATCH_VA - vmaddr:x} (va 0x{PATCH_VA:x}) "
                 f"is 0x{word:08x}, expected the tbnz 0x{ORIGINAL_WORD:08x}")
    struct.pack_into("<I", data, offset, REPLACEMENT_WORD)

    out = args.output or args.kernel
    out.write_bytes(data)
    record = {
        "patch": "appleimage4-txm-shortcircuit",
        "source_kernel_sha256": hashlib.sha256(args.kernel.read_bytes()).hexdigest()
                                if out != args.kernel else "(in place)",
        "patched_kernel_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
        "va": f"0x{PATCH_VA:x}",
        "segment": name,
        "file_offset": f"0x{offset:x}",
        "original_word": f"0x{ORIGINAL_WORD:08x}",
        "replacement_word": f"0x{REPLACEMENT_WORD:08x}",
        "rationale": "r85: force AppleImage4 AP-instantiation onto its TXM short-circuit; "
                     "chip observation identifier 12 is unregistered on Qualcomm and "
                     "panicked 'failed to get mix-n-match policy: 2'.",
    }
    sidecar = out.with_suffix(out.suffix + ".patch.json")
    sidecar.write_text(json.dumps(record, indent=2) + "\n")
    print(f"patched {PATCH_VA:#x} in {name}: 0x{ORIGINAL_WORD:08x} -> 0x{REPLACEMENT_WORD:08x}")
    print(f"wrote {out}")
    print(f"sha256 {record['patched_kernel_sha256']}")
    print(f"record {sidecar}")


if __name__ == "__main__":
    main()
