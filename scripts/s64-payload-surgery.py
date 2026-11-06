#!/usr/bin/env python3
"""session-64 payload surgery: bind walls 62+63 (bsd_stubs cdevsw family).

Walls (statically pre-read at s63 close-out, confirmed by the r63 first
flash -- crc 0x68352ecd zero-correct 124B, panic from 0xfffffff00a41cb1c,
x0=0x1, x1=0xfffffff00bb65188 = the kext's own 112B cdevsw template; the
s63 forward-scan prediction bl 0xa41cb18 -> slot 0x83ae510 -> donor
0xb3d1d58 hit the rollback address exactly):

Wall-62: donor 0xb3d1d58 = cdevsw_add_with_bdev(int, const struct cdevsw*,
          dev_t bdev).  Body 316B: first bl 0xb3d1a98 = donor _cdevsw_add
          (kernel.map how=calls); bdev stored into chrtoblktab 0xb89bea4
          [major]; bdev out-of-range -> inline _cdevsw_remove rollback
          (five shared constants: cdevsw table 0xb89c6f0 / nocdev placeholder
          0x7ec2ae0 / flags 0xb9284f8 / devsw CAS lock 0xb9ce228 / memcmp
          0xae82458); returns index / -1.  s63's "native has no such symbol"
          is overturned: noctf-exact _cdevsw_add_with_bdev 0x79ebd74 (km
          0xB3A7D74, 228B) exists, body 1:1 with the donor (native calls
          _cdevsw_add 0xB3A7B3C then _chrtoblk_set 0xB3A0FEC; native cdevsw
          0xB855118 = 0xB854BD8 + 24*0x38 closure; chrtoblktab 0xB856D18).
          Source anchor xnu bsd_stubs.c:266-284: with_bdev = cdevsw_add +
          chrtoblk_set + failure rollback; cdevsw_remove_with_bdev does not
          exist in the tree; the only chrtoblktab reader chrtoblk() returns
          NODEV by design.  Sole donor caller _mdevadd+0x160; native caller
          _mdevadd+0x128.  Caller kext = IOStorageFamily (span fix verdict;
          registration fn [0xa41ca8c,0xa41ce70), call order isomorphic to
          memdev.c:665-673).

Wall-63: donor 0xb3d1894 = bdevsw_remove(int).  Triple geometric指纹 all
          hit: first cmp w0,#0x17 (nblkdev-1), stride 0x38 (56B bdevsw
          entry), table 0xb89c1b0; plus the devsw CAS lock 0xb9ce228,
          memcmp vs the kext template (56B), writes the empty-bdevsw
          placeholder 0x7ec2aa8 (q-reg 56B clear), returns major / -1 --
          the mirror of bdevsw_add (wall-61, 0xb3d1700).  Native twin
          noctf exact _bdevsw_remove 0x79eb968 (km 0xB3A7968, 196B): nblkdev
          global 0x71A07C8 (reads 24), table 0xB854BD8, lock 0xB996210,
          placeholder 0x7E4AF30; geometry closure 0xB854BD8 + 24*0x38 =
          0xB855118 = native cdevsw base (donor mirror +0x540 = 0xb89c6f0).
          Faces: 0x83ae490 (IOStorageFamily error-cleanup path of the
          registration fn + unload fn 0xa417f18) and 0x849f248 (apfs
          deregistration fn 0xaaedb8c, flag-guarded).  Erratum: earlier
          workorder said 0x849f240 -- that slot is wall-61's bdevsw_add
          face, already bound in r63.

Fix: bind the two donor imports to the noctf-exact native twins.  Faces are
enumerated dynamically: DC sentinel slots whose donor word decodes to one of
the two donor VAs.  Expected 1 + 2 = 3 faces.
"""
import hashlib, json, struct, sys
from pathlib import Path
sys.path.insert(0, '/home/ri/ubuntu/.local/lib/python3.14/site-packages')

ROOT = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu')
KHEAD, KBASE = 0x1c9800, 0x7004000
SENT_LO = 0x45a5c4c
FIPS_OFF = 0x4ec5fd

BINDINGS = [
    # (donor VA, donor name, native km VA, native symbol, noctf VA, expected faces)
    (0xb3d1d58, 'cdevsw_add_with_bdev', 0xB3A7D74, '_cdevsw_add_with_bdev', 0x79ebd74, 1),
    (0xb3d1894, 'bdevsw_remove',        0xB3A7968, '_bdevsw_remove',        0x79eb968, 2),
]

def segments(buf, base=0):
    segs = []
    ncmds, = struct.unpack_from('<I', buf, base + 16)
    at = base + 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', buf, at)
        if cmd == 0x19:
            name = buf[at + 8:at + 16].split(b'\0')[0].decode()
            vm, msz, fo, fsz = struct.unpack_from('<QQQQ', buf, at + 24)
            segs.append((name, vm & 0xFFFFFFFFF, msz, fo, fsz))
        at += size
    return segs

def cut_at_first_return(buf, segs, va):
    for name, vm, msz, fo, fsz in segs:
        if name == '__TEXT_E' and vm <= va < vm + msz:
            base = fo + (va - vm)
            break
    else:
        raise SystemExit(f'no __TEXT_E for 0x{va:x}')
    size = 0
    for k in range(0, 0x800, 4):
        w = struct.unpack_from('<I', buf, base + k)[0]
        if w in (0xD65F03C0, 0xD65F1BFF, 0xD65F1FFF):
            size = k + 4
            break
        if 0x14000000 <= w <= 0x17FFFFFF:
            imm = w & 0x3FFFFFF
            tgt = va + k + (imm - (1 << 26) if imm & (1 << 25) else imm) * 4
            if tgt < va or tgt > va + k:
                size = k + 4
                break
    return base, size

def main():
    pay = (ROOT / 'out/m2381/payload-r63.img').read_bytes()
    don = (ROOT / 'out/ipsw/24A446/kernelcache.decompressed').read_bytes()
    psegs, dsegs = segments(pay, KHEAD), segments(don)
    pdc = [s for s in psegs if s[0] == '__DATA_C'][0]
    ddc = [s for s in dsegs if s[0] == '__DATA_C'][0]
    assert (pdc[1], pdc[2]) == (ddc[1], ddc[2])

    # gate 1: native targets inside kernel __TEXT_E
    tex = [s for s in psegs if s[0] == '__TEXT_E'][0]
    for _, _, nv, sym, _, _ in BINDINGS:
        assert tex[1] <= nv < tex[1] + tex[2], f'native {sym} 0x{nv:x} not in __TEXT_E'
    print('gate1 native targets inside __TEXT_E OK')

    # gate 2: noctf names still exact (s53-noctf-syms.json, 0xfffffff0-prefixed)
    for _, _, nv, sym, noctf_va, _ in BINDINGS:
        assert nv == noctf_va + 0x39BC000, f'{sym}: km 0x{nv:x} != noctf 0x{noctf_va:x} + 0x39BC000'
    print('gate2 noctf->km delta OK')

    # enumerate faces dynamically: DC sentinel slots grouped by donor target
    by_dv = {b[0]: [] for b in BINDINGS}
    for i in range(0, pdc[2], 8):
        poff = KHEAD + pdc[3] + i
        w = struct.unpack_from('<Q', pay, poff)[0]
        if w & 0xFFFFFFFFFFFF != SENT_LO:
            continue
        dw = struct.unpack_from('<Q', don, ddc[3] + i)[0]
        dv = (dw & 0xFFFFFFFFFFFF) + KBASE
        if dv in by_dv:
            by_dv[dv].append((pdc[1] + i, poff, dw))
    total = sum(len(v) for v in by_dv.values())
    print(f'faces enumerated: {total}')
    for dv, dname, nv, sym, _, expect in BINDINGS:
        print(f'  donor 0x{dv:x} -> {sym} 0x{nv:x}: {len(by_dv[dv])} faces (expect {expect}) '
              + ' '.join(f'0x{s:x}' for s, _, _ in by_dv[dv]))
        assert len(by_dv[dv]) == expect, f'{dname}: {len(by_dv[dv])} faces != expected {expect}'

    edits = []
    for dv, dname, nv, sym, _, _ in BINDINGS:
        new_word = (0x8011 << 48) | (nv - KBASE)
        for slot, poff, dw in by_dv[dv]:
            pre = struct.unpack_from('<Q', pay, poff)[0]
            assert pre & 0xFFFFFFFFFFFF == SENT_LO, f'slot 0x{slot:x} not sentinel'
            assert (dw & 0xFFFFFFFFFFFF) + KBASE == dv
            edits.append((poff, slot, new_word, sym))

    seal_pre = pay[FIPS_OFF:FIPS_OFF + 16]
    buf = bytearray(pay)
    for poff, _, new_word, _ in edits:
        struct.pack_into('<Q', buf, poff, new_word)

    diffs = [i for i in range(len(buf)) if buf[i] != pay[i]]
    clusters = []
    for i in diffs:
        if clusters and i == clusters[-1][1] + 1:
            clusters[-1][1] = i
        else:
            clusters.append([i, i])
    exp_bytes = sum(1 for poff, _, new_word, _ in edits
                    for k in range(8)
                    if (struct.unpack_from('<Q', pay, poff)[0] >> (8 * k)) & 0xFF
                    != (new_word >> (8 * k)) & 0xFF)
    assert len(diffs) == exp_bytes, f'diff {len(diffs)}B != {exp_bytes}B'
    assert len(clusters) == len(edits), f'{len(clusters)} clusters != {len(edits)}'
    print(f'diff audit: {len(diffs)}B / {len(clusters)} clusters, zero stray OK')
    assert bytes(buf[FIPS_OFF:FIPS_OFF + 16]) == seal_pre, 'seal changed!'
    print('seal __fips_hmacs untouched OK')

    out = ROOT / 'out/m2381/payload-r64.img'
    out.write_bytes(bytes(buf))
    sha = hashlib.sha256(bytes(buf)).hexdigest()
    print(f'\nwrote {out} sha256 {sha[:8]}... ({len(buf)} B)')

    rec = {}
    for dv, dname, nv, sym, noctf_va, _ in BINDINGS:
        base, size = cut_at_first_return(don, dsegs, dv)
        body = don[base:base + size]
        rec[dname] = {'original': f'0xfffffe000{dv:07x}', 'original_size': size,
                      'original_sha256': hashlib.sha256(body).hexdigest(),
                      'native_symbol': sym, 'native_noctf': hex(noctf_va)}
        print(f'{dname}: donor body {size}B sha {rec[dname]["original_sha256"][:16]}')
    (ROOT / 'temp/s64-ledger-bodies.json').write_text(json.dumps(rec, indent=1))
    print('body records -> temp/s64-ledger-bodies.json')

if __name__ == '__main__':
    main()
