#!/usr/bin/env python3
"""Squash the device's own split ADSP images (.mdt + .bNN) into the two blobs the kernel embeds.

Input:  .cache/firmware/adsp-src/{adsp.mdt,adsp.b01..,adsp_dtb.mdt,adsp_dtb.b01..} staged from the
        stock firmware harvest (vendor-fw-harvest/modem/image; the vendor firmware never enters git).
Output: .cache/firmware/adsp/{adsp.mbn,adsp_dtb.mbn} — one flat file per image: ELF header + program
        header table, then every segment with data (including the trailing hash segment, which this
        SoC's mdt carries behind the header table and the stock pil-squasher skips) concatenated in
        phdr order with p_offset/p_filesz rewritten. p_vaddr/p_paddr stay untouched, so the PAS/TZ-signed
        metadata (header + hash, the shape QcomMdt.c hands to SCM) is byte-identical to the stock pair.

The kernel-side consumer is package/AdspProbe.cpp + package/QcomMdt.c: qcom_mdt_metadata reads
ph[0].p_filesz (headers) plus the hash segment at its rewritten p_offset, and the segment loader
reads each PT_LOAD at its rewritten p_offset. Nothing in the consumer assumes the stock offsets.
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / '.cache/firmware/adsp-src'
DST = ROOT / '.cache/firmware/adsp'

TYPE_HASH = 2 << 24


def parse(mdt: bytes):
    if mdt[:4] != b'\x7fELF':
        raise SystemExit('not an ELF')
    ei_class = mdt[4]
    if ei_class == 1:
        hdr, ph, phsize = '<HHIIIIIHHHHHH', '<IIIIIIII', 32   # type off va pa filesz memsz flags align
        off_ix, filesz_ix, memsz_ix, flags_ix = 1, 4, 5, 6
    elif ei_class == 2:
        hdr, ph, phsize = '<HHIQQQIHHHHHH', '<IIQQQQQQ', 56   # type flags off va pa filesz memsz align
        off_ix, filesz_ix, memsz_ix, flags_ix = 2, 5, 6, 1
    else:
        raise SystemExit(f'bad EI_CLASS {ei_class}')
    e_phoff = struct.unpack_from(hdr, mdt, 16)[4]
    e_phentsize, e_phnum = struct.unpack_from('<HH', mdt, 42)
    if e_phentsize != phsize:
        raise SystemExit(f'phentsize {e_phentsize} != {phsize}')
    phdrs = [(e_phoff + i * phsize, list(struct.unpack_from(ph, mdt, e_phoff + i * phsize))) for i in range(e_phnum)]
    return ph, phdrs, off_ix, filesz_ix, memsz_ix, flags_ix


def squash(name: str) -> Path:
    mdt = (SRC / f'{name}.mdt').read_bytes()
    ph, phdrs, off_ix, filesz_ix, memsz_ix, flags_ix = parse(mdt)
    header_end = phdrs[0][1][filesz_ix]  # ph[0] (PT_NULL) covers ELF header + program header table
    if header_end < phdrs[-1][0] + (len(phdrs[0][1]) * 4):
        raise SystemExit(f'{name}: ph[0] too small for the header table')
    hash_tail = mdt[header_end:]  # the hash segment's bytes ride behind the header table in this SoC's mdt
    out = bytearray(mdt[:header_end])
    for index, (at, f) in enumerate(phdrs):
        filesz, memsz, flags = f[filesz_ix], f[memsz_ix], f[flags_ix]
        if index == 0 or filesz == 0:
            continue  # ph[0] stays at offset 0 (the metadata contract reads the header there); skip BSS-only segments
        piece = SRC / f'{name}.b{index:02d}'
        if piece.exists():
            data = piece.read_bytes()
        elif (flags & 0x7000000) >> 24 == TYPE_HASH >> 24:
            data, hash_source = hash_tail[:filesz], 'mdt tail'
            if len(data) != filesz:
                raise SystemExit(f'{name}: hash segment wants {filesz:#x} bytes, mdt tail has {len(data)}')
        else:
            raise SystemExit(f'{name}: missing {piece.name} (phdr wants {filesz:#x} bytes)')
        if len(data) != filesz:
            raise SystemExit(f'{name}: {piece.name} is {len(data)} bytes, phdr wants {filesz:#x}')
        f[off_ix] = len(out)    # p_offset: sequential placement
        f[filesz_ix] = len(data)
        out += data
    for at, f in phdrs:
        struct.pack_into(ph, out, at, *f)
    DST.mkdir(parents=True, exist_ok=True)
    dst = DST / f'{name}.mbn'
    dst.write_bytes(out)
    return dst


def main():
    if not SRC.is_dir():
        raise SystemExit(f'stage the stock split images first: {SRC} (see the file comment)')
    for name in ('adsp', 'adsp_dtb'):
        dst = squash(name)
        print(f'{dst}: {dst.stat().st_size} bytes')


if __name__ == '__main__':
    main()
