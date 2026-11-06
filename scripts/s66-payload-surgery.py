#!/usr/bin/env python3
"""session-66 payload surgery: bind wall-65 (os_log_create).

Wall (payload-r65 first flash, crc 0x992021fb per screen zero-corrected after
brute-force disambiguation, hit #1, t=1s):
  fileset: original component called an unmapped kernel function from
  0xfffffff00924f21c (x0 0xfffffff00763e445 x1 0xfffffff00763e463).
  Photo wrap-join noise defeated the naive transcription (crc 5c859dd0
  MISS); single-char 'f'->'8' flip in all three fields = the screen truth.
  Wall 64 dead (report point moved 0x925a148 -> 0x924f21c; OSDetached-
  Certificates/IOSurface ctor faces passed, boot advanced deeper into AMFI).

Judge chain (session-66, direct -- no agent dispatch, farm single-wall beat):
  caller bl 0x924f218 -> slot 0x8136200 sentinel -> donor 0xb41d998
  (temp/s64-tracer.py, caller fn = AMFI developer-mode daemon: neighbors
  _enable_developer_mode/_developer_mode_state/_disable_developer_mode/
  _IOLog all bound).
  Args: x0 = donor cstring "com.apple.MobileFileIntegrity" (AMFI bundle id,
  = os_log subsystem), x1 = donor cstring "library_validation_failure"
  (os_log category; pool also holds log fmt '\\n" @%s:%d' + developer-mode
  daemon + library-load-constraint strings).

Named: donor 0xb41d998 = _os_log_create (libkern/os/log.c; static
  os_log_create_impl inlined). Quadruple evidence:
  (1) signature: os_log_create(const char *subsystem, const char *category)
      -- log.h:161 -- matches the two-string arg pair exactly.
  (2) body mirror vs native km 0xB3EA19C (kernel.macho __TEXT_E): pacibsp +
      stp x28..x30 (donor frame 0x1a0 vs native 0x180, uniform +0x20 shift),
      global-copy guard stur [x29,#-0x60], os_log_disabled() byte-flag gate
      -> return NULL (donor reads 0x7ec4fc0 bit0, native 0x7e4d678 bit0),
      0x100/0x120 stack key-buffer memset, subsystem-then-category strlen +
      0x80 clamp with lens at [sp,#2]/[sp,#3].
  (3) donor map bracket: _os_log_hash @0xb41d788 (map body-hash -> native
      km 0xb3ea0f0) and __os_log_internal @0xb41df20 (call-sites -> km
      0xb3ea640); target is the only unplaced function between them and
      native _os_log_create is the only noctf function in the matching
      native bracket (_os_log_equ 0xb3ea13c < _oslog_try_get 0xb3ea190 <
      _os_log_create 0xb3ea19c < __os_log_internal 0xb3ea640).
  (4) source anchor log.c:613 os_log_create -> os_log_create_impl:556:
      if (os_log_disabled()) return OS_LOG_DISABLED; os_log_subsystem_init
      (pack subsystem/category + lens = the key-buffer build); cache
      find/insert = the _os_log_key_hash/_os_log_hash family nearby.
  Body [0xb41d998,0xb41df08) 1392B (exit block 0xb41decc -> retab
  0xb41df04; __os_log_internal starts 0xb41df20, no interposed function).

Fix: bind 5 faces (AMFI 0x8136200 + 4 sibling kext importers) to
  0x80110000043E619C = (0x8011 << 48) | (0xB3EA19C - 0x7004000).
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
    #  expected faces, body end VA or None for cut_at_first_return)
    (0xb41d998, 'os_log_create', 0xB3EA19C, '_os_log_create', 0x7a2e19c, 5,
     0xb41df08),
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
    pay = (ROOT / 'out/m2381/payload-r65.img').read_bytes()
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

    out = ROOT / 'out/m2381/payload-r66.img'
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
    (ROOT / 'temp/s66-ledger-bodies.json').write_text(json.dumps(rec, indent=1))
    print('body records -> temp/s66-ledger-bodies.json')

if __name__ == '__main__':
    main()
