#!/usr/bin/env python3
"""session-68 payload surgery: bind wall-67 (SecureDTLookupEntry).

Wall (payload-r67 first flash 2026-11-06, photo 22:39, crc 0xeb9fb8ca
autofix-f-only, hit #1, t=1s, stage +1s):
  fileset: original component called an unmapped kernel function from
  0xfffffff00924e6a0 (x0 0x0 x1 0xfffffff00763b99e) hit #1

r67 verdict (work-order B pass conditions all met):
  crc new (0xeb9fb8ca != 0x7a50a1ae), caller still inside the AMFI span,
  slot 0x8135d08 NOT one of r67's three bound slots (0x8136078 /
  0x8135f80 / 0x848d250) => all three r67 binds effective; wall 66
  cleared, wall advanced +0x58 inside the same AMFI policy-config
  caller (0x924e440, LocalSigning.cpp DT phase).

Judge chain (s66 prescan entry, body-verified this session):
  bl 0x924e69c -> thunk 0x9271338 -> slot 0x8135d08 sentinel -> donor
  0xb5be330.  Caller args: x0=0 (searchRoot), x1="/chosen"
  (@0x763b99e, byte-read), x2=&entry out-param; return compared ==1
  (kDTSuccess) then feeds DTGetProperty(entry, "darwinos-security-
  environment" @0x763e055, &ptr, &size) whose slot 0x8135d00 is ALREADY
  bound (r58) to native _SecureDTGetProperty 0xb5115e4.

Named: donor 0xb5be330 = _SecureDTLookupEntry (pexpert device_tree.c).
  Quadruple evidence:
  (1) donor body [0xb5be330,0xb5be5c8) 664B: init-flag ldr w8,[0x7f08000
      +0x330] cbz; NULL searchRoot -> csel from gDTRoot [x25+0x318]
      (bounds end [x24+0x328]); leading-'/' skip with empty-path -> root
      return (*entry=root, w0=1 @0xb5be534); 63-byte (w9=0x3f) path
      component copy loop; child walk bl 0xb5be11c (= matcher-verified
      _SecureDTGetPropertyInternal, fetching literal "name" @0x70cf529)
      + bl 0xb5bc51c name compare + bl 0xb5be5c8 next-child iterator;
      error blocks carry device_tree.c asserts (file string @0x70cef5d,
      lines 0x62=98 / 0x96=150, "Device tree pointer outside of device
      tree region" / "Device tree property overflow").
  (2) noctf exact _SecureDTLookupEntry 0xfffffff007b5522c (noctf36
      0x7b5522c, km 0xB51122C = +0x39BC000, inside payload __TEXT_E).
  (3) native body mirror (payload __TEXT_E at km 0xb51122c): block-for-
      block structural match (guard 0xb934000+0xb68, init flag
      [0x7e95000+0xfd8], root [..+0xfc0] csel, '/' skip, w9=0x3f loop,
      "name" @0x7274ede, bl 0xb511600 = _SecureDTGetPropertyInternal at
      EXACTLY its own noctf-slide km, bl 0xaeac450 compare, bl 0xb511998
      iterator, w0=-1 error returns, main retab 0xb511400).
  (4) source anchor pexpert/gen/device_tree.c (SecureDT* family; noctf
      26.5.2 uses Secure* naming; assert strings name the file).

NOTE (calibration): reading payload native bodies requires absolute file
offset KHEAD + (km - 0x7004000) -- forgetting KHEAD mislocates by 0x1c9800
and fabricated a fake "layout divergence" this session before the anchors
(lockdown/identity) caught it.

Faces: 5 sentinel slots image-wide carry donor target 0xb5be330:
  0x7f87218 0x80e17b8 0x8135d08 (AMFI, serves bl sites 0x924e69c +
  0x924f00c) 0x8479a60 0x848d0c8.
  -> 0x801100000450D22C = (0x8011 << 48) | (0xB51122C - 0x7004000).

Next-wall prediction (s69): site 0x924ec80 slot 0x8135e08 donor
0xb472cd8; further: 0x9250510/0xb262cd4, 0x9251108/0xad3e8e4 (work-order
batch candidate #1), 0x92515e4/0xb261374.
"""
import hashlib, json, struct, sys
from pathlib import Path

ROOT = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu')
KHEAD, KBASE = 0x1c9800, 0x7004000
SENT_LO = 0x45a5c4c
FIPS_OFF = 0x4ec5fd

BINDINGS = [
    # (donor VA, donor name, native km VA, native symbol, noctf36 VA,
    #  expected faces, donor body end VA)
    (0xb5be330, 'SecureDTLookupEntry', 0xB51122C,
     '_SecureDTLookupEntry', 0x7b5522c, 5, 0xb5be5c8),
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

def main():
    pay = (ROOT / 'out/m2381/payload-r67.img').read_bytes()
    don = (ROOT / 'out/ipsw/24A446/kernelcache.decompressed').read_bytes()
    psegs, dsegs = segments(pay, KHEAD), segments(don)
    pdc = [s for s in psegs if s[0] == '__DATA_C'][0]
    ddc = [s for s in dsegs if s[0] == '__DATA_C'][0]
    assert (pdc[1], pdc[2]) == (ddc[1], ddc[2])

    tex = [s for s in psegs if s[0] == '__TEXT_E'][0]
    for _, _, nv, sym, _, _, _ in BINDINGS:
        assert tex[1] <= nv < tex[1] + tex[2], f'native {sym} 0x{nv:x} not in __TEXT_E'
    print('gate1 native targets inside __TEXT_E OK')

    noctf = json.load(open(ROOT / 'temp/s53-noctf-syms.json'))
    names = {n: va for va, n in noctf}
    for _, _, nv, sym, noctf_va, _, _ in BINDINGS:
        assert sym in names and (names[sym] & 0xFFFFFFFFF) == noctf_va, \
            f'{sym} not noctf-exact at 0x{noctf_va:x}'
        assert nv == noctf_va + 0x39BC000, f'{sym}: km delta broken'
    print('gate2 noctf-exact + km delta OK')

    # gate3: native body entry sanity (pacibsp at km, KHEAD-corrected offset)
    for dv, dname, nv, sym, _, _, _ in BINDINGS:
        o = KHEAD + nv - KBASE
        assert struct.unpack_from('<I', pay, o)[0] == 0xd503237f, \
            f'native {sym} km 0x{nv:x} does not start with pacibsp'
    print('gate3 native body pacibsp entry OK')

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
    for dv, dname, nv, sym, _, expect, _ in BINDINGS:
        print(f'  donor 0x{dv:x} -> {sym} 0x{nv:x}: {len(by_dv[dv])} faces '
              f'(expect {expect}) ' + ' '.join(f'0x{s:x}' for s, _, _ in by_dv[dv]))
        assert len(by_dv[dv]) == expect, f'{dname}: {len(by_dv[dv])} faces != expected {expect}'

    edits = []
    for dv, dname, nv, sym, _, _, _ in BINDINGS:
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

    out = ROOT / 'out/m2381/payload-r68.img'
    out.write_bytes(bytes(buf))
    sha = hashlib.sha256(bytes(buf)).hexdigest()
    print(f'\nwrote {out} sha256 {sha[:8]}... ({len(buf)} B)')

    rec = {}
    for dv, dname, nv, sym, noctf_va, _, body_end in BINDINGS:
        base = dv - KBASE
        size = body_end - dv
        body = don[base:base + size]
        rec[dname] = {'original': f'0xfffffe000{dv:07x}', 'original_size': size,
                      'original_sha256': hashlib.sha256(body).hexdigest(),
                      'native_symbol': sym, 'native_noctf': hex(noctf_va),
                      'native_km': hex(nv)}
        print(f'{dname}: donor body {size}B sha {rec[dname]["original_sha256"][:16]}')
    (ROOT / 'temp/s68-ledger-bodies.json').write_text(json.dumps(rec, indent=1))
    print('body records -> temp/s68-ledger-bodies.json')

if __name__ == '__main__':
    main()
