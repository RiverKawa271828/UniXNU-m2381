#!/usr/bin/env python3
"""Patch the AppleImage4 nonce manager's previous-stage-manifest-hash panic (r88).

r87 redirected the chip-observation entry-count pointer and the r87 screen
capture confirmed the whole descriptor loader now returns cleanly: the crash
moved out of 0x46e467c entirely, and kext start advanced into the next
consumer -- a *formatted* panic (progress: the wall grew text):

    failed to get previous stage manifest hash: 2
    frames 0xfffffff0046ed6a0 0xfffffff0046f1820 + the r84 kernel cluster

RE (this kernel, all VAs link == runtime):

  * frame2 return site 0x46f1820 calls 0x46ecc14 -- the nonce manager init.
    It zero-fills a 64-byte hash buffer at sp+0x460 on entry (0x46ecc50),
    reads "40A0DDD2-77F8-4392-B4A3-1E7304206516:nonce-seeds" via 0x46f06c0,
    then fetches the previous stage manifest hash through the environment
    object vtable slot [x19+0x50] (key 0xb) into that buffer.
  * The seeds query has Apple's own tolerance: ret==2 logs "nonce manager:
    error reading seeds: %d" and continues. The manifest-hash query has none:
    ret != 0 hits `cbnz w0` at

        0xfffffff0046ecd68: cbnz w0, 0x46ed690     ; 0x35004940 -> panic
        0x46ed690: str x0,[sp]; fmt "failed to get previous stage manifest
        hash: %d" (0x3e2035d); bl 0x46fa028 (panic)  <- frame 0x46ed6a0

  * On Qualcomm nothing passes a previous stage manifest (no iBoot chain),
    so the query always returns 2. The zero-filled buffer is already the
    correct "no previous stage" value: the tail paths publish exactly this
    buffer to the global state at 0x5caea42 (0x46ed308), and the sibling
    input (seeds) demonstrates the intended missing-value semantics
    (log and continue). So drop the branch:

        0xfffffff0046ecd68: cbnz w0 -> nop (0xd503201f)

  * The seeds-length mismatch paths after the patch point (0x46ecf64 /
    0x46ed2b0) are log-and-continue paths, not panics.

Patch chain: kernel.macho -> r85 TXM -> r86 chipobs zero table -> r87
chipobs count zero -> this patch. Run on kernel-r87-chipobs-count.macho; all
four words coexist in the output. The file offset is re-derived from
__PLK_TEXT_EXEC every run and the patch refuses to write unless the original
word matches.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

PATCH_VA = 0xFFFFFFF0046ECD68
ORIGINAL_WORD = 0x35004940    # cbnz w0, 0x46ed690
NOP = 0xD503201F


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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kernel", type=Path, help="prelinked kernel Mach-O (TXM + r86 + r87 patched)")
    ap.add_argument("--output", type=Path,
                    help="patched copy path (default: patch the input in place)")
    args = ap.parse_args()

    data = bytearray(args.kernel.read_bytes())
    name, vmaddr, fileoff = segment_for(data, PATCH_VA)
    offset = fileoff + (PATCH_VA - vmaddr)
    word = struct.unpack_from("<I", data, offset)[0]
    if word != ORIGINAL_WORD:
        sys.exit(f"refusing: word at {name}+0x{PATCH_VA - vmaddr:x} (va 0x{PATCH_VA:x}) "
                 f"is 0x{word:08x}, expected the cbnz 0x{ORIGINAL_WORD:08x}")
    struct.pack_into("<I", data, offset, NOP)

    out = args.output or args.kernel
    out.write_bytes(data)
    record = {
        "patch": "appleimage4-noncemgr-manifest-hash-continue",
        "source_kernel_sha256": hashlib.sha256(args.kernel.read_bytes()).hexdigest()
                                if out != args.kernel else "(in place)",
        "patched_kernel_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
        "va": f"0x{PATCH_VA:x}",
        "segment": name,
        "file_offset": f"0x{offset:x}",
        "original_word": f"0x{ORIGINAL_WORD:08x}",
        "replacement_word": f"0x{NOP:08x}",
        "rationale": "r88: the nonce manager init (0x46ecc14) panics when the "
                     "previous stage manifest hash query (vtable [x19+0x50], key "
                     "0xb) returns 2; nothing passes a previous stage manifest on "
                     "Qualcomm. The 64-byte hash buffer is zero-filled on entry "
                     "and is the published value (global 0x5caea42), and the "
                     "sibling seeds input already tolerates ret==2 with a log -- "
                     "so let the manifest-hash query take the same continue: "
                     "cbnz -> nop, the zero buffer stands for 'no previous stage'.",
    }
    sidecar = out.with_suffix(out.suffix + ".patch.json")
    sidecar.write_text(json.dumps(record, indent=2) + "\n")
    print(f"patched {PATCH_VA:#x} in {name}: 0x{ORIGINAL_WORD:08x} -> 0x{NOP:08x} (nop)")
    print(f"wrote {out}")
    print(f"sha256 {record['patched_kernel_sha256']}")
    print(f"record {sidecar}")


if __name__ == "__main__":
    main()
