#!/usr/bin/env python3
"""r58 payload surgery: wall-57 (_IOFree) + same-family batch rebind.

Reads payload-r57, writes payload-r58 with:

  shims (native __text page padding after the r57 IOMalloc shim):
    shim_iofree   5 insns  IOFree(addr,size)         -> kfree_ext(KHEAP_DEFAULT, addr, size)
    shim_kfreevar 3 insns  kfree_type_var(view,ptr,size) -> kfree_ext(KHEAP_DEFAULT, ptr, size)
              (donor kt_view discarded; pairs with the r57 IOMalloc shim's
               KHEAP_DEFAULT allocations)

  slot rebinds (auth-GOT word 0x8011 << 48 | (va - 0x7004000)):
    donor _IOFree            0xfffffe000b441b54 -> shim_iofree         (132 slots)
    donor kfree_type_var     0xfffffe000b441c0c -> shim_kfreevar       ( 98 slots)
    donor kprintf            0xfffffe000b55c3e8 -> native _kprintf     ( 65 slots)
    donor mach_absolute_time 0xfffffe000aecef24 -> native twin         (133 slots)
    donor lck_mtx_alloc_init 0xfffffe000ad43134 -> native twin         (  8 slots)
    donor IOLockTryLock      0xfffffe000ad43db4 -> native twin         ( 10 slots)
    donor IOFreeAligned      0xfffffe000b441ba4 -> native _IOFreeAligned ( 7 slots)

  seal: HMAC-SHA256(key=b'\\0') over the com.apple.kernel entry's first
  __TEXT/__TEXT_EXEC __text section into __fips_hmacs (the
  scripts/seal-source-crypto-kernel.py contract), payload-offset aware.

Slot enumeration comes from the donor kernelcache (compressed GOT words,
low48 = VA - 0x7004000); every rewritten slot's pre-image must be the
donor word or the emitter sentinel word.
"""
import hashlib, hmac, json, struct
from pathlib import Path

PAY57 = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu/out/m2381/payload-r57-104bff44.img')
OUT = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu/out/m2381/payload-r58.img')
DON = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu/out/ipsw/24A446/kernelcache.decompressed')
KM = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu/temp/r57/kernel.macho')

KHEAD = 0x1c9800            # kernel.macho head inside the payload
BASE = 0x7004000            # GOT compression base
PAC = 0x8011
SENT_LO = 0x45a5c4c         # _unixnu_fileset_unmapped low48
KHEAP_DEFAULT_OFF = 0x7dec3e0   # VA low36 of our KHEAP_DEFAULT kheap view
KFREE_EXT = 0xfffffff00ace8d18  # native kfree_ext

SHIM_IOFREE = 0xfffffff00aef0820
SHIM_KFREEVAR = 0xfffffff00aef0838

NATIVE = {
    'kprintf': 0xfffffff00b514cb8,
    'mach_absolute_time': 0xfffffff00aefbfdc,
    'lck_mtx_alloc_init': 0xfffffff00aceffe8,
    'IOLockTryLock': 0xfffffff00acf0368,
    'IOFreeAligned': 0xfffffff00b4151dc,
}

REBINDS = [
    (0xfffffe000b441b54, 'IOFree', 'shim_iofree'),
    (0xfffffe000b441c0c, 'kfree_type_var', 'shim_kfreevar'),
    (0xfffffe000b55c3e8, 'kprintf', NATIVE['kprintf']),
    (0xfffffe000aecef24, 'mach_absolute_time', NATIVE['mach_absolute_time']),
    (0xfffffe000ad43134, 'lck_mtx_alloc_init', NATIVE['lck_mtx_alloc_init']),
    (0xfffffe000ad43db4, 'IOLockTryLock', NATIVE['IOLockTryLock']),
    (0xfffffe000b441ba4, 'IOFreeAligned', NATIVE['IOFreeAligned']),
]


def segs_of(data, header):
    ncmds, = struct.unpack_from('<I', data, header + 16)
    off, segs = header + 32, []
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from('<II', data, off)
        if cmd == 0x19:
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            if filesize:
                segs.append((vmaddr, filesize, fileoff))
        off += sz
    return segs


def fo(segs, va):
    for v, s, f in segs:
        if v <= va < v + s:
            return f + (va - v)


def adrp_word(pc, target_page, rd=0):
    delta = (target_page - (pc & ~0xfff)) >> 12
    assert -(1 << 20) <= delta < (1 << 20), hex(delta)
    imm = delta & 0x1fffff
    return 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | rd


def add_word(rn, rd, imm12):
    return 0x91000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd


def b_word(pc, target):
    delta = (target - pc) >> 2
    assert -(1 << 25) <= delta < (1 << 25), hex(delta)
    return 0x14000000 | (delta & 0x3ffffff)


def mov_reg(rd, rm):
    return 0xaa0003e0 | (rm << 16) | rd


def word_lo36(va):
    return ((va & 0xfffffffff) - BASE) & 0xffffffffffff


def main():
    pay = bytearray(PAY57.read_bytes())
    don = DON.read_bytes()
    km = KM.read_bytes()
    assert pay[KHEAD:KHEAD + 4] == km[:4] == b'\xcf\xfa\xed\xfe'
    ksegs = segs_of(km, 0)
    dsegs = segs_of(don, 0)
    report = {'shims': {}, 'rebinds': {}}

    # ---- donor slot enumeration ----
    faces = {}
    for stub_va, name, _ in REBINDS:
        lo = word_lo36(stub_va)
        slots = []
        for v, s, f in dsegs:
            for o in range(f, f + s - 8, 8):
                val, = struct.unpack_from('<Q', don, o)
                if (val & 0xffffffffffff) == lo:
                    slots.append((v + (o - f)) & 0xfffffffff)
        slots.sort()
        faces[stub_va] = slots
        print(f'{name}: {len(slots)} donor slots')

    # ---- shims ----
    # entry x0=addr x1=size  ->  kfree_ext(KHEAP_DEFAULT, addr, size)
    kheap_page = 0xfffffff007dec000
    shim_iofree = [mov_reg(2, 1),                    # mov x2, x1   (size)
                   mov_reg(1, 0),                    # mov x1, x0   (addr)
                   adrp_word(SHIM_IOFREE + 8, kheap_page),
                   add_word(0, 0, 0x3e0),
                   b_word(SHIM_IOFREE + 0x10, KFREE_EXT)]
    # entry x0=view(discarded) x1=ptr x2=size -> kfree_ext(KHEAP_DEFAULT, ptr, size)
    shim_kfreevar = [adrp_word(SHIM_KFREEVAR, kheap_page),
                     add_word(0, 0, 0x3e0),
                     b_word(SHIM_KFREEVAR + 8, KFREE_EXT)]
    shims = {SHIM_IOFREE: shim_iofree, SHIM_KFREEVAR: shim_kfreevar}
    for va, words in shims.items():
        o = fo(ksegs, va)
        assert o is not None, hex(va)
        po = KHEAD + o
        cur = struct.unpack_from(f'<{len(words)}I', pay, po)
        assert all(c == 0 for c in cur), f'shim site {va:#x} not padding: {[hex(c) for c in cur[:2]]}'
        struct.pack_into(f'<{len(words)}I', pay, po, *words)
        report['shims'][hex(va)] = [hex(x) for x in words]
        print(f'shim @ {va:#x}: {len(words)} insns')

    # ---- slot rebinds ----
    for stub_va, name, new in REBINDS:
        newva = {'shim_iofree': SHIM_IOFREE, 'shim_kfreevar': SHIM_KFREEVAR}.get(new, new)
        word = (PAC << 48) | word_lo36(newva)
        donor_lo = word_lo36(stub_va)
        raw = sent = prebound = 0
        prebound_to = set()
        for slot_lo36 in faces[stub_va]:
            va = 0xfffffff000000000 | slot_lo36
            o = fo(ksegs, va)
            assert o is not None, hex(va)
            po = KHEAD + o
            cur, = struct.unpack_from('<Q', pay, po)
            cur_lo = cur & 0xffffffffffff
            if cur_lo == donor_lo or cur_lo == SENT_LO:
                # donor stub (any pac) or emitter sentinel -> rewrite
                if cur_lo == donor_lo:
                    raw += 1
                else:
                    sent += 1
                struct.pack_into('<Q', pay, po, word)
            elif cur_lo == word_lo36(newva):
                prebound += 1          # already bound to the same target
            else:
                prebound += 1          # emitter already bound this slot natively
                prebound_to.add(hex(cur_lo + BASE))
        entry = {'slots': len(faces[stub_va]), 'rewritten_donor': raw,
                 'rewritten_sentinel': sent, 'kept_prebound': prebound,
                 'to': hex(newva), 'word': hex(word)}
        if prebound_to:
            entry['prebound_targets'] = sorted(prebound_to)
        report['rebinds'][name] = entry
        print(f'{name}: {len(faces[stub_va])} slots -> {newva:#x} '
              f'(donor {raw} + sentinel {sent} + prebound {prebound})')

    # ---- seal over the com.apple.kernel entry's __text ----
    # fileset entries share the collection's file-offset space: section
    # `offset` fields are already kernel-relative, so payload offset = KHEAD + off32.
    entry_hdr = None
    kind, = struct.unpack_from('<I', pay, KHEAD + 12)
    if kind == 12:  # kernel collection: descend into the com.apple.kernel entry
        offset = KHEAD + 32
        for _ in range(struct.unpack_from('<I', pay, KHEAD + 16)[0]):
            cmd, length = struct.unpack_from('<II', pay, offset)
            if cmd == 0x80000035:
                name_off = struct.unpack_from('<I', pay, offset + 24)[0]
                nm = bytes(pay[offset + name_off:pay.index(b'\0', offset + name_off)])
                if nm == b'com.apple.kernel':
                    entry_hdr = struct.unpack_from('<Q', pay, offset + 16)[0]
            offset += length
        assert entry_hdr is not None, 'no com.apple.kernel entry'
    kbase = KHEAD + (entry_hdr or 0)
    code = integrity = None
    ncmds, = struct.unpack_from('<I', pay, kbase + 16)
    offset = kbase + 32
    for _ in range(ncmds):
        cmd, length = struct.unpack_from('<II', pay, offset)
        if cmd == 0x19:
            nsects = struct.unpack_from('<I', pay, offset + 64)[0]
            for index in range(nsects):
                section = offset + 72 + index * 80
                sname, sgname = struct.unpack_from('<16s16s', pay, section)
                sname = sname.rstrip(b'\0')
                sgname = sgname.rstrip(b'\0')
                _addr, size, off32, _align = struct.unpack_from('<QQII', pay, section + 32)
                if sname == b'__text' and sgname in (b'__TEXT', b'__TEXT_EXEC') and code is None:
                    code = (KHEAD + off32, size, _addr)   # payload file offset
                if sname == b'__fips_hmacs':
                    assert size == 32
                    integrity = KHEAD + off32
        offset += length
    assert code and integrity is not None, 'seal sections not found'
    shim_fo = fo(ksegs, SHIM_IOFREE) + KHEAD
    assert code[0] <= shim_fo < code[0] + code[1], 'shim outside sealed __text'
    mac = hmac.digest(b'\0', bytes(pay[code[0]:code[0] + code[1]]), 'sha256')
    struct.pack_into('<32B', pay, integrity, *mac)
    report['seal'] = {'code_file_offset': hex(code[0]), 'code_bytes': hex(code[1]),
                      'hmac_file_offset': hex(integrity), 'hmac_sha256': mac.hex()}
    print(f'seal: __text {code[1]:#x}B @payload {code[0]:#x}, hmac {mac.hex()[:16]}...')

    OUT.write_bytes(bytes(pay))
    sha = hashlib.sha256(bytes(pay)).hexdigest()
    report['output'] = {'path': str(OUT), 'sha256': sha, 'size': len(pay)}
    OUT.with_suffix('.surgery.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'payload-r58 = {OUT} sha256 {sha[:8]}')


if __name__ == '__main__':
    main()
