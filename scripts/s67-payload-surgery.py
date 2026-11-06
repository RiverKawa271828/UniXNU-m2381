#!/usr/bin/env python3
"""session-67 payload surgery: bind wall-66 (get_lockdown_mode_state).

Wall (payload-r66 first flash, crc 0x7a50a1ae zero-corrected, hit #1, t=1s):
  fileset: original component called an unmapped kernel function from
  0xfffffff00924e648 (x0 0x0 x1 0x1).  x0/x1 are leftovers from the
  preceding slot call -- the real signature is (void).

Erratum first: session-66 claimed "AMFI import face cleared" from
temp/s66-amfi-prescan.json -- FALSE.  The prescan json stores calls under
'calls' with lowercase verdicts; the s66 judge parsed a nonexistent 'bls'
key + uppercase 'SENTINEL' substring and read the empty set as zero.
Re-parse: AMFI [0x92469c0,0x92721c8] still holds 114 sentinel calls over
35 distinct donor targets (top: 0xb226cc8 x24, 0xad3e8e4 x12, 0xaf21778
x11).  Wall 66 is caller #1 of that backlog, and it was in the prescan
all along (site 0x924e644 recorded, donor_target 0xb2a405c).

Judge chain (session-66 prescan entry, verified by body work):
  bl 0x924e644 -> thunk 0x9271a18 -> slot 0x8136078 sentinel -> donor
  0xb2a405c.  Caller = AMFI policy-config fn at 0x924e440 (boot-arg
  reads + 9x static registrations + PAC'd dict lookups); after the
  call: cmp w0,#0 / cset -> strb AMFI global 0x8130e58, and when
  non-zero three flag registrations 0x10000000/0x20000000/0x40000000
  -- the lockdown-mode enforcement bit fan-out.

Named: donor 0xb2a405c = _get_lockdown_mode_state
  (bsd/kern/lockdown_mode.c:87, exported via Private.exports:407).
  Quadruple evidence:
  (1) donor body [0xb2a405c,0xb2a4134) 216B (ceiling = next map symbol
      _disable_lockdown_mode; main-path retab 0xb2a40e4 + CAS-fail and
      release-retry tail blocks): inline CAS mutex on 0xb9cbaf8
      (= lck_mtx_lock compiled as casa loop), flag check 0xb9cbb00
      (= lockdown_mode_init_done), msleep call bl 0xb27b46c with
      (chan=&init_done, pri=0, wmesg=cstring 'get_lockdown_mode_state'
      @0x70a4d3d, timo=0, mtx=0xb9cbaf0), CAS release, return u32
      global 0xb910924 (= lockdown_mode_state).  The wmesg string IS
      the source's msleep literal -- names the function verbatim.
  (2) noctf exact _get_lockdown_mode_state 0x78bd4c4 (km 0xB2794C4 =
      noctf + 0x39BC000, gate2 dual-check).
  (3) native body mirror (kernel.macho __TEXT_E): identical prologue
      (pacibsp; stp x20,x19,[sp,#-0x20]!; stp x29,x30,[sp,#0x10];
      add x29,sp,#0x10), same structure with lck_mtx_lock/unlock as
      real calls (0xacf01b0/0xacf04bc), same msleep shape with the
      same wmesg string, returns lockdown_mode_state 0xb9137d8;
      donor compiles the mutex as inline CAS loops -- same op, two
      compile strategies.
  (4) source anchor lockdown_mode.c:87: lock / if (!init_done) msleep
      / unlock / return state -- instruction-for-instruction; map
      bracket _sys_panic_with_data 0xb2a3c38 < target <
      _disable_lockdown_mode 0xb2a4134 (lockdown_mode.c family).

Bonus bind (same session, pre-read census item #1): donor 0xb226cc8 =
  _csblob_get_identity -- codesign identity-string getter: guard byte
  [csb+0x20] bit0 -> find CSMAGIC 0xfade0c02 (CodeDirectory) via helper
  bl 0xb2c23dc (ptr=[csb+0x50], len=[csb+0x40], 0, magic) -> BE32 at
  dir+0x14 (= identOffset, byte-swapped) -> return dir+identOffset =
  the signing identity cstring; NULL paths both.  Twin: noctf exact
  _csblob_get_identity 0x7843cb4 (km 0xB1FFCB4); native body mirror =
  same find-magic walk + rev32 identOffset (native helper bl 0xb297ea8
  takes csb directly); disambiguated against the two neighbors by body:
  donor map _csblob_get_teamid 0xb226cbc = 3-insn leaf (ldr [x0,#0xb8])
  and map _csblob_get_cdhash 0xb226d2c = 3-insn cached getter
  (add x0,x0,#0x58) whose body is IDENTICAL to noctf _csblob_get_cdhash
  0xb1ffcf8 -- so the find-walker between them is identity, not cdhash.
  2 faces (AMFI slot 0x8135f80 serves 24 bl call sites per the prescan
  census + one sibling kext slot 0x848d250) ->
  0x80110000041FBCB4 = (0x8011 << 48) | (0xB1FFCB4 - 0x7004000).

Fix total: bind 3 faces to 2 native targets:
  slot 0x8136078 -> 0x80110000042754C4 = (0x8011<<48)|(0xB2794C4-0x7004000)
  slots 0x8135f80 + 0x848d250 -> 0x80110000041FBCB4.

userdata note: the 24A446 userdata (Mac AEA-chain build, 11-05 02:32,
sha256 b280f63e...) was NEVER flashed -- device still carries the 23F84
piece; user pulled it back this session for a manual flash alongside
payload-r67 (records corrected: s66 first-update wrongly inferred the
r52 flash carried it).
"""
import hashlib, json, struct, sys
from pathlib import Path
sys.path.insert(0, '/home/ri/ubuntu/.local/lib/python3.14/site-packages')

ROOT = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu')
KHEAD, KBASE = 0x1c9800, 0x7004000
SENT_LO = 0x45a5c4c
FIPS_OFF = 0x4ec5fd

BINDINGS = [
    # (donor VA, donor name, native km VA, native symbol, noctf VA,
    #  expected faces, body end VA or None)
    (0xb2a405c, 'get_lockdown_mode_state', 0xB2794C4,
     '_get_lockdown_mode_state', 0x78bd4c4, 1, 0xb2a4134),
    (0xb226cc8, 'csblob_get_identity', 0xB1FFCB4,
     '_csblob_get_identity', 0x7843cb4, 2, 0xb226d2c),
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
    pay = (ROOT / 'out/m2381/payload-r66.img').read_bytes()
    don = (ROOT / 'out/ipsw/24A446/kernelcache.decompressed').read_bytes()
    psegs, dsegs = segments(pay, KHEAD), segments(don)
    pdc = [s for s in psegs if s[0] == '__DATA_C'][0]
    ddc = [s for s in dsegs if s[0] == '__DATA_C'][0]
    assert (pdc[1], pdc[2]) == (ddc[1], ddc[2])

    # gate 1: native targets inside kernel __TEXT_E
    tex = [s for s in psegs if s[0] == '__TEXT_E'][0]
    for _, _, nv, sym, _, _, _ in BINDINGS:
        assert tex[1] <= nv < tex[1] + tex[2], f'native {sym} 0x{nv:x} not in __TEXT_E'
    print('gate1 native targets inside __TEXT_E OK')

    # gate 2: noctf names still exact (s53-noctf-syms.json, 0xfffffff0-prefixed)
    noctf = json.load(open(ROOT / 'temp/s53-noctf-syms.json'))
    names = {n: va for va, n in noctf}
    for _, _, nv, sym, noctf_va, _, _ in BINDINGS:
        assert sym in names and (names[sym] & 0xFFFFFFFFF) == noctf_va, \
            f'{sym} not noctf-exact at 0x{noctf_va:x}'
        assert nv == noctf_va + 0x39BC000, f'{sym}: km delta broken'
    print('gate2 noctf-exact + km delta OK')

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

    out = ROOT / 'out/m2381/payload-r67.img'
    out.write_bytes(bytes(buf))
    sha = hashlib.sha256(bytes(buf)).hexdigest()
    print(f'\nwrote {out} sha256 {sha[:8]}... ({len(buf)} B)')

    rec = {}
    for dv, dname, nv, sym, noctf_va, _, body_end in BINDINGS:
        base = dv - KBASE
        size = (body_end - dv) if body_end else 0
        body = don[base:base + size]
        rec[dname] = {'original': f'0xfffffe000{dv:07x}', 'original_size': size,
                      'original_sha256': hashlib.sha256(body).hexdigest(),
                      'native_symbol': sym, 'native_noctf': hex(noctf_va)}
        print(f'{dname}: donor body {size}B sha {rec[dname]["original_sha256"][:16]}')
    (ROOT / 'temp/s67-ledger-bodies.json').write_text(json.dumps(rec, indent=1))
    print('body records -> temp/s67-ledger-bodies.json')

if __name__ == '__main__':
    main()
