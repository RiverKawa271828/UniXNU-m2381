#!/usr/bin/env python3
"""session-63 payload surgery: bind the bdevsw family (wall-61).

Wall (payload-r62 first flash, crc 0xaf0e2d21, hit #1, t=1s):
  kext driver calls bdevsw_add(1, its_bdevsw_template) -> GOT thunk 0xa422054
  -> slot 0x83ae480 sentinel. Sentinel x0=0x1 (requested major), x1=0xbb651f8
  (kext's own 56B bdevsw template full of diversified-auth fn ptrs). Return
  compared with the requested major (bdevsw_add contract), then a second
  import bdevsw_isfree via slot 0x83ae488 (also sentinel).

Donor imports (TU = bsd/kern/bsd_stubs.c; donors export both):
  0xb3d1700 = bdevsw_add(int, const struct bdevsw*)
              devsw lock (CAS on 0xb9ce228 = devsw_lock_list_mtx state, same
              global donor _cdevsw_add/_cdevsw_remove/_devsw_unlock use) +
              per-cpu mtx stats + bounds (nblkdev=24) + memcmp vs the empty
              bdevsw placeholder 0x7ec2aa8 (6 eno_* ptrs + 0) + install.
  0xb3d161c = bdevsw_isfree(int)   unlocked probe, returns major or -1.
  Geometry proof: donor bdevsw[24 x 56B] @0xb89c1b0 abuts donor cdevsw[64 x
  112B] @0xb89c6f0 (donor _cdevsw_add: stride 0x70, bound 0x3f, key
  0x7ec2ae0) = conf.c layout bdevsw[] then cdevsw[].

Fix: noctf-exact native twins, body-verified (same arg shuffle, cmn/negs
overflow guards, native add calls lck_mtx_lock_spin):
  0xb3d1700 -> _bdevsw_add    noctf 0x79eb810, km 0xB3A7810
  0xb3d161c -> _bdevsw_isfree noctf 0x79eb700, km 0xB3A7700
Faces enumerated dynamically: DC sentinel slots whose donor word decodes to
one of the two donor VAs.
"""
import hashlib, json, struct, sys
from pathlib import Path
sys.path.insert(0, '/home/ri/ubuntu/.local/lib/python3.14/site-packages')

ROOT = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu')
KHEAD, KBASE = 0x1c9800, 0x7004000
SENT_LO = 0x45a5c4c
FIPS_OFF = 0x4ec5fd

BINDINGS = [
    # (donor VA, donor name, native km VA, native symbol, noctf VA)
    (0xb3d1700, 'bdevsw_add',    0xB3A7810, '_bdevsw_add',    0x79eb810),
    (0xb3d161c, 'bdevsw_isfree', 0xB3A7700, '_bdevsw_isfree', 0x79eb700),
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
    pay = (ROOT / 'out/m2381/payload-r62.img').read_bytes()
    don = (ROOT / 'out/ipsw/24A446/kernelcache.decompressed').read_bytes()
    psegs, dsegs = segments(pay, KHEAD), segments(don)
    pdc = [s for s in psegs if s[0] == '__DATA_C'][0]
    ddc = [s for s in dsegs if s[0] == '__DATA_C'][0]
    assert (pdc[1], pdc[2]) == (ddc[1], ddc[2])

    # gate 1: native targets inside kernel __TEXT_E
    tex = [s for s in psegs if s[0] == '__TEXT_E'][0]
    for _, _, nv, sym, _ in BINDINGS:
        assert tex[1] <= nv < tex[1] + tex[2], f'native {sym} 0x{nv:x} not in __TEXT_E'
    print('gate1 native targets inside __TEXT_E OK')

    # enumerate faces dynamically: DC sentinel slots grouped by donor target
    by_dv = {dv: [] for dv, _, _, _, _ in BINDINGS}
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
    for dv, _, nv, sym, _ in BINDINGS:
        print(f'  donor 0x{dv:x} -> {sym} 0x{nv:x}: {len(by_dv[dv])} faces '
              + ' '.join(f'0x{s:x}' for s, _, _ in by_dv[dv]))
        if not by_dv[dv]:
            # zero sentinel faces = the s61 696 batch already bound this import;
            # verify every donor word for this import in DC now holds the
            # expected native word (independent confirmation of the twin).
            exp = (0x8011 << 48) | (nv - KBASE)
            n_chk = 0
            for i in range(0, pdc[2], 8):
                dw = struct.unpack_from('<Q', don, ddc[3] + i)[0]
                if (dw & 0xFFFFFFFFFFFF) + KBASE == dv:
                    pw = struct.unpack_from('<Q', pay, KHEAD + pdc[3] + i)[0]
                    assert pw == exp, f'bound face 0x{pdc[1]+i:x} = 0x{pw:x} != expected 0x{exp:x}'
                    n_chk += 1
            print(f'    0 faces: already native-bound (s61); {n_chk} donor-word '
                  f'faces verified == 0x{exp:012x}')

    edits = []
    for dv, dname, nv, sym, noctf_va in BINDINGS:
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

    out = ROOT / 'out/m2381/payload-r63.img'
    out.write_bytes(bytes(buf))
    sha = hashlib.sha256(bytes(buf)).hexdigest()
    print(f'\nwrote {out} sha256 {sha[:8]}... ({len(buf)} B)')

    rec = {}
    for dv, dname, nv, sym, noctf_va in BINDINGS:
        base, size = cut_at_first_return(don, dsegs, dv)
        body = don[base:base + size]
        rec[dname] = {'original': f'0xfffffe000{dv:07x}', 'original_size': size,
                      'original_sha256': hashlib.sha256(body).hexdigest(),
                      'native_symbol': sym, 'native_noctf': hex(noctf_va)}
        print(f'{dname}: donor body {size}B sha {rec[dname]["original_sha256"][:16]}')
    (ROOT / 'temp/s63-ledger-bodies.json').write_text(json.dumps(rec, indent=1))
    print('body records -> temp/s63-ledger-bodies.json')

if __name__ == '__main__':
    main()
