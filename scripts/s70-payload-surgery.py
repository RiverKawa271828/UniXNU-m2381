#!/usr/bin/env python3
"""session-70 payload surgery: bind wall-70 (strncasecmp) + prescan T2
(current_thread_ro via bti-c alias thunk).

Wall (payload-r69 first flash 2026-11-07, photo 01:10, crc 0xf53b30e2
zero-corrections single hit, hit #1, t=1s):
  fileset: original component called an unmapped kernel function from
  0xfffffff00aa75014 (x0 0xfffffff007d646a2 x1 0xfffffff007d67dbe) hit #1

r69 verdict: wall STILL IN sandbox span -- site 0xaa75010 belongs to
com.apple.security.sandbox (text span [0xaa46c70,0xaa81594)) => r69's
vnode_hold x4-slot + proc_get_syscall_filter_mask_size binds effective,
wall monotonic-advanced past wall 69.  Caller args are both donor strings:
  x0 = "ENTITLEMENT:com.apple.security.exception.iokit-user-client-class"
       @0x7d646a2
  x1 = "ENTITLEMENT:" @0x7d67dbe
=> sandbox/AMFI entitlement prefix matching at policy init.

Wall 70 judge chain: bl 0xaa75010 -> thunk 0xaa811a4 -> slot 0x848d698
sentinel (payload_word 0x80110000045a5c4c) -> donor 0xae825b8 (map-nearest
_strcasecmp +0x44 = the NEXT function; donor map lacks the symbol).
Second sandbox site 0xaa4aadc shares the slot (prescan).

Named: donor 0xae825b8 = _strncasecmp.  Quadruple evidence:
  (1) donor body 0x60B capstone: bti c; cbz x2 (n==0 -> 0); indexed loop
      ldrsb [x0,x9]/[x1,x9]; tolower inline ((unsigned)(c-0x41)<0x1a ?
      c|0x20 : c) x2; subs diff -> b.ne return; i++; ca==0 -> 0 (cmp
      w11,#0 + ccmp x10 + sub x10 + b.ne); exit mov w8,#0; ret
      (strncasecmp compiles alen==blen==n so the strbufcasecmp length
      tails compile out);
  (2) noctf exact _strncasecmp 0x74f0604 (km 0xAEAC604 = +0x39BC000);
      noctf family order = source order: _strcasecmp 0x74f05c0,
      _strncasecmp +0x44, _strbufcasecmp +0x74, _strlcasecmp +0xe4;
      donor geometry identical (donor _strcasecmp 0xae82574 = target-0x44);
  (3) native body mirror km 0xAEAC5C0: donor _strcasecmp 17 ins
      BYTE-IDENTICAL to native _strcasecmp; _strncasecmp 24 ins same
      instruction multiset, single adjacent transposition (donor: ldrsb
      w13,[x1,x9] before cmp w11,#0x1a; native: swapped) = scheduler
      difference, s67-lockdown precedent class;
  (4) source anchor osfmk/device/subrs.c: strncasecmp_impl(s1,s2,n) =
      strbufcasecmp_impl(s1,n,s2,n); tolower inline matches body line by
      line (ch>='A'&&ch<='Z' -> range check + |0x20).

Prescan T2 (28 sandbox sites, ALL through slot 0x848d6e8): donor
0xaf55418 = 2-ins bti-c alias thunk "bti c; b 0xadbafd4"; map-nearest
_vfs_64bitready(+0xac) is a bracket artifact.  Real callee 0xadbafd4:
Named: donor 0xadbafd4 = _current_thread_ro.  Quadruple evidence:
  (1) donor body 0x98B [0xadbafd4,0xadbb06c): mrs x0,tpidr_el1 (current
      thread; clobbers no-used x0 => zero-arg "current" flavor); ldr x1,
      [x0,#0x420] = thread->tro (donor struct offset); INLINE zone-
      element validation (tagged-ptr bounds vs [0x7df9f40] pair, 16K page
      arithmetic vs [0x7e00140], zone page-meta ldrh & 0x3ff == 3 via
      [0x7df9fa0], backpointer [ro]==thread) -> fail: bl 0xb59bd64 =
      _zone_id_require_ro_panic (map how=string) / next-fn tail
      ___thread_ro_circularity_panic; success: mov x0,x1; retab;
  (2) noctf exact _current_thread_ro 0x73add2c (km 0xAD69D2C); donor map
      bracket: _get_thread_ro -0x94 / _swap_task_map +0x690 /
      _get_threadtask +0x8bc = same thread-ro family;
  (3) native body semantic mirror km 0xAD69D2C: bl _current_thread
      (our build: tpidr-el1 3-ins leaf) -> ldr x19,[thr+0x4e8] (our
      struct offset) -> bl _zone_id_require(3, 0x38, ro) -> backpointer
      check -> return ro.  Same operation, two compilation strategies
      (donor inlines zone require; native calls the helper) -- s67
      lockdown precedent class; struct offsets 0x420/0x4e8 each
      internally consistent (donor _get_thread_ro also reads [th+0x420]);
  (4) source anchor osfmk/kern/bsd_kern.c:167:
      thread_ro_t current_thread_ro(void) { return
      get_thread_ro(current_thread()); }
  Faces: 3 slots (0x82da968 0x848d6e8 0x849fcf0) -- other images' GOT
  slots for the same thunk bound in the same pass.

Bind total: 7 slots across 2 targets (global sentinel enumeration over
__DATA_C, not just the sandbox span):
  slots 0x7f85788 0x836b580 0x848d698 0x849faa8
       -> 0x8011000003EA8604 = (0x8011<<48)|(0xAEAC604-0x7004000)
  slots 0x82da968 0x848d6e8 0x849fcf0
       -> 0x8011000003D65D2C = (0x8011<<48)|(0xAD69D2C-0x7004000)

Deferred farm queue (s69-sandbox-prescan.json, 57 targets left): T3
0xb2aa3f8 x27 (buffer space calc body, unnamed); T4 0xad45364 x25 =
lock_rw_old.c lck_rw family ("Taking non-sleepable RW lock with
preemption enabled" assert string, exact flavor TBD); 0xadb7cbc x10
(kfree_type_impl_internal neighborhood = s60 family); 0xb260110 x14 /
0xb26324c x10 / 0xad94128 x10.
"""
import hashlib, json, struct
from pathlib import Path

ROOT = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu')
KHEAD, KBASE = 0x1c9800, 0x7004000
SENT_LO = 0x45a5c4c
FIPS_OFF = 0x4ec5fd

BINDINGS = [
    # (bl_target donor VA, real body donor VA, donor name, native km VA,
    #  native symbol, noctf36 VA, expected faces, donor body end VA)
    (0xae825b8, 0xae825b8, '_strncasecmp', 0xAEAC604,
     '_strncasecmp', 0x74f0604, 4, 0xae82618),
    (0xaf55418, 0xadbafd4, '_current_thread_ro (via bti-c alias thunk)',
     0xAD69D2C, '_current_thread_ro', 0x73add2c, 3, 0xadbb06c),
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
    pay = (ROOT / 'out/m2381/payload-r69.img').read_bytes()
    don = (ROOT / 'out/ipsw/24A446/kernelcache.decompressed').read_bytes()
    psegs, dsegs = segments(pay, KHEAD), segments(don)
    pdc = [s for s in psegs if s[0] == '__DATA_C'][0]
    ddc = [s for s in dsegs if s[0] == '__DATA_C'][0]
    assert (pdc[1], pdc[2]) == (ddc[1], ddc[2])

    tex = [s for s in psegs if s[0] == '__TEXT_E'][0]
    for _, _, _, nv, sym, _, _, _ in BINDINGS:
        assert tex[1] <= nv < tex[1] + tex[2], f'native {sym} 0x{nv:x} not in __TEXT_E'
    print('gate1 native targets inside __TEXT_E OK')

    noctf = json.load(open(ROOT / 'temp/s53-noctf-syms.json'))
    names = {n: va for va, n in noctf}
    for _, _, _, nv, sym, noctf_va, _, _ in BINDINGS:
        assert sym in names and (names[sym] & 0xFFFFFFFFF) == noctf_va, \
            f'{sym} not noctf-exact at 0x{noctf_va:x}'
        assert nv == noctf_va + 0x39BC000, f'{sym}: km delta broken'
    print('gate2 noctf-exact + km delta OK')

    # gate3: native body entry (pacibsp 0xd503237f or bti c 0xd503245f)
    for _, _, _, nv, sym, _, _, _ in BINDINGS:
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
    for dv, body, dname, nv, sym, _, expect, _ in BINDINGS:
        print(f'  donor 0x{dv:x} -> {sym} 0x{nv:x}: {len(by_dv[dv])} faces '
              f'(expect {expect}) ' + ' '.join(f'0x{s:x}' for s, _, _ in by_dv[dv]))
        assert len(by_dv[dv]) == expect, f'{dname}: {len(by_dv[dv])} faces != expected {expect}'

    edits = []
    for dv, body, dname, nv, sym, _, _, _ in BINDINGS:
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

    out = ROOT / 'out/m2381/payload-r70.img'
    out.write_bytes(bytes(buf))
    sha = hashlib.sha256(bytes(buf)).hexdigest()
    print(f'\nwrote {out} sha256 {sha[:8]}... ({len(buf)} B)')

    rec = {}
    for dv, body, dname, nv, sym, noctf_va, _, body_end in BINDINGS:
        base = body - KBASE
        size = body_end - body
        b = don[base:base + size]
        rec[sym] = {'bl_target': f'0xfffffe000{dv:07x}',
                    'body_start': f'0xfffffe000{body:07x}',
                    'original_size': size,
                    'original_sha256': hashlib.sha256(b).hexdigest(),
                    'native_symbol': sym, 'native_noctf': hex(noctf_va),
                    'native_km': hex(nv)}
        print(f'{sym}: donor body {size}B sha {rec[sym]["original_sha256"][:16]}')
    (ROOT / 'temp/s70-ledger-bodies.json').write_text(json.dumps(rec, indent=1))
    print('body records -> temp/s70-ledger-bodies.json')

if __name__ == '__main__':
    main()
