#!/usr/bin/env python3
"""session-69 payload surgery: bind wall-69 (proc_get_syscall_filter_mask_size)
+ prescan head target (vnode_hold locking flavor).

Wall (payload-r68 first flash 2026-11-07, photo 23:55, crc 0x64d09506
zero-corrections, hit #1, t=1s):
  fileset: original component called an unmapped kernel function from
  0xfffffff00aa5a2e8 (x0 0x0 x1 0x0) hit #1

r68 verdict: wall LEFT THE AMFI SPAN -- site 0xaa5a2e4 belongs to
com.apple.security.sandbox (text span [0xaa46c70,0xaa81594)) => r68's
SecureDTLookupEntry bind effective, AMFI cleared, boot reached sandbox
init (the s43-era reference-lane milestone "崩点过AMFI进sandbox注册").

Wall 69 judge chain: bl 0xaa5a2e4 -> thunk 0xaa80e54 -> slot 0x848d4f0
sentinel -> donor 0xb26a124 (matcher: NOT matched; bracket _proc_pgrpid
0xb269ba4 < target < _proc_get_syscall_filter_mask 0xb26a158, kern_proc.c
family).  Caller (sandbox init): w0=0 / w0=1 two calls, results stored to
sandbox globals [0x84885d8]/[0x84885xx].
Named: donor 0xb26a124 = _proc_get_syscall_filter_mask_size
  (kern_proc.c:5289).  Quadruple evidence:
  (1) donor body 52B: switch(which): 0 -> const 0x22e (558 = nsysent,
      Apple release build compiles it as constant), 1 -> const 0x80
      (128 = mach_trap_count), 2 -> ldrsw global [0x7ea4830]
      (mach_kobj_count), default 0 -- exactly the source switch;
  (2) noctf exact _proc_get_syscall_filter_mask_size 0x78838a4 (km
      0xB23F8A4 = +0x39BC000), noctf neighborhood +0x14 proc_send_sync_
      EXC_RESOURCE / +0x50 proc_get_syscall_filter_mask;
  (3) native body mirror km 0xb23f8a4: same switch, which==0 loads
      nsysent global [0x719e670] (our build keeps it a variable);
  (4) source anchor kern_proc.c:5289 (read).

Prescan head (s69-sandbox-prescan.json, 267 sentinel calls / 59 donor
targets in sandbox span): top target donor 0xaf21778 x44 call sites.
Named: donor 0xaf21778 = vnode_hold (27.x locking flavor):
  (1) donor body: CAS [vp+8] 0 -> owner|0x30000000 (inline spin acquire
      of the vnode lock word, contended -> bl 0xad43344 slow path) ->
      ldadd 1 [vp+0xb4] (holdcount++, old->w8) -> w8==INT32_MAX ->
      panic block loading v_tag [vp+0x72] / v_type [vp+0x71] / v_flag
      [vp+0x54] with w11=0x180b (line 6155) and bl panic;
  (2) panic strings byte-read: "%s: vp %p holdcount overflow from : %d
      v_tag = %d, v_type = %d, v_flag = %x." @0x706e677,
      __FUNCTION__ "vnode_hold" @0x706e6cb, file "vfs_subr.c"
      @0x706e245 -- the panic names the function verbatim (wall-66
      wmesg lever class);
  (3) sibling leaf: donor 0xaf215f8 (matcher body-hash _vnode_hold) =
      ldadd [vp+0xb4] + INT32_MAX check, byte-shape IDENTICAL to native
      _vnode_hold km 0xAF5FE84 (bti c entry -- earlier "mid-function"
      reads were my own offadj double-subtracting KHEAD bug);
  (4) source anchor vfs_subr.c:6120 vnode_hold (inc_orig v_holdcount +
      INT32_MAX panic with v_tag/v_type/v_flag args).  The 27.x flavor
      adds lock+reconcile calls (put_internal_locked/drop_internal)
      absent from 26.5 source; binding to the native same-name KPI is
      the standing pattern -- our kernel's own hold model takes over.
  Faces: 4 slots (0x80e1b10 0x8136408 0x848d828 0x84a0008) serve the 44
  sandbox bl sites.

Bind total: 5 slots across 2 targets:
  slot 0x848d4f0 -> 0x801100000423B8A4 = (0x8011<<48)|(0xB23F8A4-0x7004000)
  slots 0x80e1b10/0x8136408/0x848d828/0x84a0008
       -> 0x8011000003F5BE84 = (0x8011<<48)|(0xAF5FE84-0x7004000)

Deferred to s70 farm batch (s69-sandbox-prescan.json): T2 0xaf55418 x28
= bti-c alias tail-branching to 0xadbafd4 (per-cpu range-check body,
unnamed); T3 0xb2aa3f8 x27 (buffer space calc body, unnamed); T4
0xad45364 x25 = lock_rw_old.c lck_rw family ("Taking non-sleepable RW
lock with preemption enabled" assert string, exact flavor TBD);
0xadb7cbc x10 (kfree_type_impl_internal neighborhood = s60 family).
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
    (0xb26a124, 'proc_get_syscall_filter_mask_size', 0xB23F8A4,
     '_proc_get_syscall_filter_mask_size', 0x78838a4, 1, 0xb26a158),
    (0xaf21778, 'vnode_hold (27.x locking flavor)', 0xAF5FE84,
     '_vnode_hold', 0x75a3e84, 4, 0xaf21850),
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
    pay = (ROOT / 'out/m2381/payload-r68.img').read_bytes()
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

    # gate3: native body entry (pacibsp 0xd503237f or bti c 0xd503245f)
    for dv, dname, nv, sym, _, _, _ in BINDINGS:
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

    out = ROOT / 'out/m2381/payload-r69.img'
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
    (ROOT / 'temp/s69-ledger-bodies.json').write_text(json.dumps(rec, indent=1))
    print('body records -> temp/s69-ledger-bodies.json')

if __name__ == '__main__':
    main()
