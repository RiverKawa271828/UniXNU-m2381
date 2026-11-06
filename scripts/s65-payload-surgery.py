#!/usr/bin/env python3
"""session-65 payload surgery: bind wall-64 (OSMetaClass 6-arg zone ctor).

Wall (payload-r64 first flash, crc 0x785f87e4 per screen, hit #1, t=1s):
  fileset: original component called an unmapped kernel function from
  0xfffffff00925a148 (x0 0xfffffff00bac96e8 x1 0xfffffff007642b21).
  Walls 62/63 both dead (IOStorageFamily registration fn 22-call set all
  bound, boot advanced into AMFI) -- static pre-read strategy round 3.

Judge chain (session-65, direct -- no agent dispatch needed):
  caller bl 0x925a144 (com.apple.driver.AppleMobileFileIntegrity __TEXT_EXEC,
  via temp/s64-tracer.py) -> slot 0x8135d30 sentinel -> donor 0xb3d37ec.
  x1 = donor cstring "OSDetachedCertificates" (AMFI class name; string pool
  also holds zone name "iokit.OSDetachedCertificates" + ConstraintUtilities/
  CertManager strings); x0 = AMFI __DATA zeroed static = the metaclass
  storage being constructed.

Named: donor 0xb3d37ec = __ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t
  OSMetaClass::OSMetaClass(const char *inClassName, const OSMetaClass *inSuper,
  unsigned inClassSize, zone_t *inZone, const char *zone_name,
  zone_create_flags_t zflags) -- the zone_create variant, the first exported
  function after OSMetaClass::logError in libkern/c++/OSMetaClass.cpp.
  Evidence: (1) donor body [0xb3d37ec,0xb3d385c) 0x70B: pacibsp + 4x stp +
  save x3-x6/x0 to callee-saved (x1/x2 kept live) -> bl 0xb3cfcbc = donor
  3-arg core ctor __ZN11OSMetaClassC2EPKcPKS_j (delegation; map 0xb3cfca8
  "_unix_syscall" is a how=calls misname) -> adrp+ldrb+tbnz global bit gate
  = if (!(kIOTracking & gIOKitDebug)) -> orr zflags | ZC_ZFREE_CLEARMEM ->
  bl 0xadb3e94 = zone_create -> str x0,[x19] writes *inZone -> mov x0,x20
  (return this).  (2) native twin noctf exact 0x79ed4bc (km 0xB3A94BC):
  prologue byte-identical to donor (pacibsp a9bc5ff8 a90157f6 a9024ff4
  a9037bfd 9100c3fd aa0603f6); native layout mirrors donor order (3-arg C2
  0xB3A90EC < logError 0xB3A9360 (map how=body-hash exact) < 6-arg 0xB3A94BC).
  (3) source anchor OSMetaClass.cpp (feeds/xnu-b7545ced) lines 575-587:
  delegate to 3-arg then zone_create gate -- matches instruction for
  instruction.  Call context: AMFI static C++ init registering its
  OSDetachedCertificates class with a zone; IOSurface imports the same
  (zone-backed classes).

NOTE on reads: native bodies live in kernel.macho __TEXT_E (vm 0x8500000)
at km VAs = noctf + 0x39BC000; reading the payload's donor-layout segments
at km VAs gives the donor exec band bytes, NOT the native image -- always
verify native twins via kernel.macho (this bit the session-65 judge once).

Fix: bind 2 faces (0x8135d30 AMFI + 0x83b6148 IOSurface) to
  0x80110000043A54BC = (0x8011 << 48) | (0xB3A94BC - 0x7004000).
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
    (0xb3d37ec, 'OSMetaClassC2_zone6arg', 0xB3A94BC,
     '__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t', 0x79ed4bc, 2),
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
    pay = (ROOT / 'out/m2381/payload-r64.img').read_bytes()
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
    noctf = json.load(open(ROOT / 'temp/s53-noctf-syms.json'))
    names = {n: va for va, n in noctf}
    for _, _, nv, sym, noctf_va, _ in BINDINGS:
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
    for dv, dname, nv, sym, _, expect in BINDINGS:
        print(f'  donor 0x{dv:x} -> {sym.split("(")[0]} 0x{nv:x}: {len(by_dv[dv])} faces '
              f'(expect {expect}) ' + ' '.join(f'0x{s:x}' for s, _, _ in by_dv[dv]))
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

    out = ROOT / 'out/m2381/payload-r65.img'
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
    (ROOT / 'temp/s65-ledger-bodies.json').write_text(json.dumps(rec, indent=1))
    print('body records -> temp/s65-ledger-bodies.json')

if __name__ == '__main__':
    main()
