#!/usr/bin/env python3
"""session-71 payload surgery: bind wall-71 AppleMatch kfree_data family
(donor 0xad3e8e4 _kfree_data + 0xad3e8fc _kfree_data_addr).

Wall (payload-r70 first flash 2026-11-07 01:48, photo 01:48, crc
0xb64e1097 zero-corrections single hit, hit #1, t=1s):
  fileset: original component called an unmapped kernel function from
  0xfffffff0092029c8 (x0 0xfffffff802dcc0c0 x1 0x35) hit #1

r70 verdict: site 0x92029c4 != wall-70's 0xaa75010 => same-payload-same-
site rule says r70's 7-slot bind (strncasecmp x4 + current_thread_ro x3)
EFFECTIVE, wall 70 cleared.  New span: com.apple.kext.AppleMatch text
[0x9200c20,0x92032a8) +0x1da4 (s64 kext-buckets) -- the regex/pattern
matching kext used by AMFI/sandbox entitlement evaluation, same
execution line as walls 69/70.  Caller args: x0 = 0xfffffff802dcc0c0
(KERNEL HEAP bank -- high32 0xfffffff8 vs text 0xfffffff0), x1 = 0x35 =
size 53 => kfree_data(addr, 53), freeing a 53-byte buffer.

Span census (s70-applematch-prescan.json, tracer over AppleMatch span):
51 bls, 8 sentinels collapsing to 2 donor targets:
  0xad3e8e4 x7 sites (slot 0x8126030)  -- ALSO s66-AMFI-census #2 target
      (12 AMFI sites, slot 0x8136108; s64-farm-report line 118 provisional
      _kfree_data topk 0.833, slot 0x83ae580)
  0xad3e8fc x1 site  (slot 0x8126038)
Both sit in the donor-map gap between _IOFreeTypeImpl 0xad3e894 and
_kfree_shared_data 0xad3e910.

Named: donor 0xad3e8e4 = _kfree_data, donor 0xad3e8fc = _kfree_data_addr.
Quadruple evidence:
  (1) donor bodies, instruction-exact family mirror:
      0xad3e8e4 (0x18B): bti c; mov x2,x1; mov x1,x0; adrp x0,<global>
      +0xe00; b 0xad3e43c  ==  native _kfree_data km 0xACE9360: bti c;
      mov x2,x1; mov x1,x0; adrp x0,<global> +0x3c0; b 0xace8d18
      (= noctf _kfree_ext)  -- kheap_free(KHEAP_DATA_BUFFERS, addr, size)
      tail-calling kfree_ext; only each build's own kheap global + branch
      target differ;
      0xad3e8fc (0x14B): bti c; mov x1,x0; adrp/add x0,<global>; b
      0xad3e684  ==  native _kfree_data_addr km 0xACE9378: same 5-ins
      wrapper tail-calling kfree_addr_ext (0xace9030);
  (2) family geometry IDENTICAL donor vs native: kfree_data +0x18
      kfree_data_addr +0x2c kfree_shared_data (+0x44 shared_addr), and
      donor map brackets the gap exactly (_IOFreeTypeImpl -0x50
      call-sites / _kfree_shared_data +0x2c reference-shape); donor
      kfree_data tail b 0xad3e43c = map-exact _kfree_ext (native km
      0xACE8D18 = same noctf symbol) -- geometric closure;
  (3) noctf exact _kfree_data 0x732d360 (km 0xACE9360) / _kfree_data_addr
      0x732d378 (km 0xACE9378) = +0x18, whole kfree family enumerated
      (kfree_ext 0x732cd18 / kfree_addr_ext 0x732d030 / kfree_shared_*
      ...); s64-farm topk 0.833 provisional match at the same native km;
  (4) source anchor osfmk/kern/kalloc.h:521
      #define kfree_data(elem, size) kheap_free(KHEAP_DATA_BUFFERS, elem, size)
      #define kfree_data_addr(elem)  kheap_free_addr(KHEAP_DATA_BUFFERS, elem)
      + kalloc.c:2866 kfree_data_external (same wrapper shape); callers
      across the tree: chunklist.c / kern_authorization.c /
      OSUnserializeXMLSharedImplementation.h (AMFI-adjacent).

Bind total: 6 slots image-wide (global __DATA_C sentinel enumeration):
  slots 0x80e1960 0x8126030 0x8136108 0x8333818 0x83ae580
       -> 0x8011000003CE5360 = (0x8011<<48)|(0xACE9360-0x7004000)
       (clears AppleMatch x7 + AMFI x12 + 3 other images' faces at once)
  slot  0x8126038
       -> 0x8011000003CE5378 = (0x8011<<48)|(0xACE9378-0x7004000)

Note: this wall marks the first AppleMatch-span hit; its remaining 1
sentinel face is bound in the same pass.  Sandbox census (s69) continues
in parallel: T3 0xb2aa3f8 x27 / T4 0xad45364 x25 / 0xadb7cbc x10 / ...
"""
import hashlib, json, struct
from pathlib import Path

ROOT = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu')
KHEAD, KBASE = 0x1c9800, 0x7004000
SENT_LO = 0x45a5c4c
FIPS_OFF = 0x4ec5fd

BINDINGS = [
    # (donor VA, body end VA, donor name, native km VA, native symbol,
    #  noctf36 VA, expected faces)
    (0xad3e8e4, 0xad3e8fc, '_kfree_data', 0xACE9360,
     '_kfree_data', 0x732d360, 5),
    (0xad3e8fc, 0xad3e910, '_kfree_data_addr', 0xACE9378,
     '_kfree_data_addr', 0x732d378, 1),
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
    pay = (ROOT / 'out/m2381/payload-r70.img').read_bytes()
    don = (ROOT / 'out/ipsw/24A446/kernelcache.decompressed').read_bytes()
    psegs, dsegs = segments(pay, KHEAD), segments(don)
    pdc = [s for s in psegs if s[0] == '__DATA_C'][0]
    ddc = [s for s in dsegs if s[0] == '__DATA_C'][0]
    assert (pdc[1], pdc[2]) == (ddc[1], ddc[2])

    tex = [s for s in psegs if s[0] == '__TEXT_E'][0]
    for _, _, _, nv, sym, _, _ in BINDINGS:
        assert tex[1] <= nv < tex[1] + tex[2], f'native {sym} 0x{nv:x} not in __TEXT_E'
    print('gate1 native targets inside __TEXT_E OK')

    noctf = json.load(open(ROOT / 'temp/s53-noctf-syms.json'))
    names = {n: va for va, n in noctf}
    for _, _, _, nv, sym, noctf_va, _ in BINDINGS:
        assert sym in names and (names[sym] & 0xFFFFFFFFF) == noctf_va, \
            f'{sym} not noctf-exact at 0x{noctf_va:x}'
        assert nv == noctf_va + 0x39BC000, f'{sym}: km delta broken'
    print('gate2 noctf-exact + km delta OK')

    # gate3: native body entry (bti c for these wrappers)
    for _, _, _, nv, sym, _, _ in BINDINGS:
        o = KHEAD + nv - KBASE
        w = struct.unpack_from('<I', pay, o)[0]
        assert w in (0xd503237f, 0xd503245f), \
            f'native {sym} km 0x{nv:x} bad entry word 0x{w:x}'
    print('gate3 native body entry OK (pacibsp/bti-c)')

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
    for dv, body_end, dname, nv, sym, _, expect in BINDINGS:
        print(f'  donor 0x{dv:x} -> {sym} 0x{nv:x}: {len(by_dv[dv])} faces '
              f'(expect {expect}) ' + ' '.join(f'0x{s:x}' for s, _, _ in by_dv[dv]))
        assert len(by_dv[dv]) == expect, f'{dname}: {len(by_dv[dv])} faces != expected {expect}'

    edits = []
    for dv, _, dname, nv, sym, _, _ in BINDINGS:
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

    out = ROOT / 'out/m2381/payload-r71.img'
    out.write_bytes(bytes(buf))
    sha = hashlib.sha256(bytes(buf)).hexdigest()
    print(f'\nwrote {out} sha256 {sha[:8]}... ({len(buf)} B)')

    rec = {}
    for dv, body_end, dname, nv, sym, noctf_va, _ in BINDINGS:
        base = dv - KBASE
        size = body_end - dv
        body = don[base:base + size]
        rec[sym] = {'original': f'0xfffffe000{dv:07x}', 'original_size': size,
                    'original_sha256': hashlib.sha256(body).hexdigest(),
                    'native_symbol': sym, 'native_noctf': hex(noctf_va),
                    'native_km': hex(nv)}
        print(f'{sym}: donor body {size}B sha {rec[sym]["original_sha256"][:16]}')
    (ROOT / 'temp/s71-ledger-bodies.json').write_text(json.dumps(rec, indent=1))
    print('body records -> temp/s71-ledger-bodies.json')

if __name__ == '__main__':
    main()
