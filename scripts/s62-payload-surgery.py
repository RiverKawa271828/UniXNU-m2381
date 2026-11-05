#!/usr/bin/env python3
"""session-62 payload surgery: bind the erandom import family (wall-60).

Wall (payload-r61 first flash, crc 0xa9474625, hit #1, t=1s):
  AppleImage4 env-object callback adapter 0x902576c (ctx-drop tail:
  (ctx,buf,len)->(buf,len)) -> b GOT thunk 0x903a898 -> slot 0x80e1a40
  = sentinel -> _unixnu_fileset_unmapped. Sentinel x0/x1 = (buf, 0x10):
  a 16-byte random read (AppleImage4 nonce manager, post-corecrypto-start).

Donor imports (body forensics vs osfmk/prng/prng_random.c, the wall-55 TU):
  0xae9bc68 = read_erandom(void*, u_int)   - prng_ready gate [0x7dff0a80]
  0xae9bd20 = read_random_generate(void*, size_t) - prng_generate indirect
              call [0x7dff0a68], per-processor mutex, 0x100 chunks
  (sibling 0xae9bbac = read_erandom_generate: 16K PAGE_SIZE chunks, map
   how=string record -> native 0x7507818.)

Fix: native twin of read_erandom = _read_frandom (noctf-exact 0x7506bf8,
km 0xAEC2BF8): source read_frandom(buf,u_int){ read_erandom(buf,n); } with
read_erandom inlined = gate + (prng_ready ? PRNG path : DRBG path) - a
semantic superset of both donor imports, body-verified (gate + 0xedeb
per-cpu pacia global + 0x100 chunks, same shape as donor A/B).

Faces: 7 sentinel slots (A x1, B x6 incl AppleImage4 0x80e1a40).
Gates: pre-image whitelist (sentinel), donor word assert per slot, native
target inside kernel __TEXT_E, byte-diff audit (7 clusters / 56B, zero
stray), __fips_hmacs seal untouched.
"""
import hashlib, json, struct, sys
from pathlib import Path

ROOT = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu')
KHEAD, KBASE = 0x1c9800, 0x7004000
SENT_LO = 0x45a5c4c
FIPS_OFF = 0x4ec5fd

DON_VA_A = 0xae9bc68   # read_erandom
DON_VA_B = 0xae9bd20   # read_random_generate
NATIVE_VA = 0xAEC2BF8  # _read_frandom (noctf 0x7506bf8 + 0x39BC000)
NATIVE_SYM = '_read_frandom'

FACES = [
    # (slot VA, expected donor word target)
    (0x80e1a40, DON_VA_B),
    (0x8316e80, DON_VA_B),
    (0x833c2e8, DON_VA_B),
    (0x8479c28, DON_VA_B),
    (0x849fa18, DON_VA_B),
    (0x84ac9d8, DON_VA_B),
    (0x848d5e8, DON_VA_A),
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
    pay = (ROOT / 'out/m2381/payload-r61.img').read_bytes()
    don = (ROOT / 'out/ipsw/24A446/kernelcache.decompressed').read_bytes()
    psegs = segments(pay, KHEAD)
    dsegs = segments(don)
    ddc = [s for s in dsegs if s[0] == '__DATA_C'][0]
    pdc = [s for s in psegs if s[0] == '__DATA_C'][0]
    assert (pdc[1], pdc[2]) == (ddc[1], ddc[2]), 'DC mismatch'

    # gate 1: native target inside kernel __TEXT_E
    tex = [s for s in psegs if s[0] == '__TEXT_E'][0]
    assert tex[1] <= NATIVE_VA < tex[1] + tex[2], f'native 0x{NATIVE_VA:x} not in __TEXT_E'
    print(f'gate1 native {NATIVE_SYM} 0x{NATIVE_VA:x} inside __TEXT_E [0x{tex[1]:x},0x{tex[1]+tex[2]:x}) OK')

    new_word = (0x8011 << 48) | (NATIVE_VA - KBASE)
    edits = []
    for slot, dv in FACES:
        poff = KHEAD + pdc[3] + (slot - pdc[1])
        doff = ddc[3] + (slot - ddc[1])
        pre = struct.unpack_from('<Q', pay, poff)[0]
        dw = struct.unpack_from('<Q', don, doff)[0]
        assert pre & 0xFFFFFFFFFFFF == SENT_LO, f'slot 0x{slot:x} pre-image not sentinel: 0x{pre:x}'
        assert (dw & 0xFFFFFFFFFFFF) + KBASE == dv, \
            f'slot 0x{slot:x} donor word -> 0x{(dw & 0xFFFFFFFFFFFF) + KBASE:x} != 0x{dv:x}'
        edits.append((poff, slot, dv, pre))
        print(f'  slot 0x{slot:x}: sentinel -> 0x{new_word:012x}  (donor 0x{dv:x})')

    seal_pre = pay[FIPS_OFF:FIPS_OFF + 16]
    buf = bytearray(pay)
    for poff, *_ in edits:
        struct.pack_into('<Q', buf, poff, new_word)

    # diff audit
    diffs = [i for i in range(len(buf)) if buf[i] != pay[i]]
    clusters = []
    for i in diffs:
        if clusters and i == clusters[-1][1] + 1:
            clusters[-1][1] = i
        else:
            clusters.append([i, i])
    # sentinel word 0x8011_0000_0045a5c4c vs new word 0x8011_0000_03ebebf8
    # share the top 4 bytes (00 00 11 80), so each slot differs in 4 bytes
    assert len(diffs) == 4 * len(edits), f'diff {len(diffs)}B != {4*len(edits)}B'
    assert len(clusters) == len(edits), f'{len(clusters)} clusters != {len(edits)}'
    for [a, b] in clusters:
        assert any(a <= poff <= b for poff, *_ in edits), f'stray cluster at 0x{a:x}'
    print(f'diff audit: {len(diffs)}B / {len(clusters)} clusters, zero stray OK')

    assert bytes(buf[FIPS_OFF:FIPS_OFF + 16]) == seal_pre, 'seal changed!'
    print('seal __fips_hmacs @0x4ec5fd untouched OK')

    out = ROOT / 'out/m2381/payload-r62.img'
    out.write_bytes(bytes(buf))
    sha = hashlib.sha256(bytes(buf)).hexdigest()
    print(f'\nwrote {out} sha256 {sha[:8]}... ({len(buf)} B)')

    # ledger body records for the two donor imports (cut_at_first_return)
    rec = {}
    for label, va in (('read_erandom', DON_VA_A), ('read_random_generate', DON_VA_B)):
        for name, vm, msz, fo, fsz in dsegs:
            if name == '__TEXT_E' and vm <= va < vm + msz:
                base = fo + (va - vm)
                break
        size = 0
        for k in range(0, 0x800, 4):
            w = struct.unpack_from('<I', don, base + k)[0]
            top = w >> 24
            if w in (0xD65F03C0, 0xD65F1BFF, 0xD65F1FFF):  # ret/retaa/retab
                size = k + 4
                break
            if 0x14000000 <= w <= 0x17FFFFFF:  # b
                imm = w & 0x3FFFFFF
                tgt = va + k + (imm - (1 << 26) if imm & (1 << 25) else imm) * 4
                if tgt < va or tgt > va + k:
                    size = k + 4
                    break
        body = don[base:base + size]
        rec[label] = {'original': f'0xfffffe000{va:07x}', 'original_size': size,
                      'original_sha256': hashlib.sha256(body).hexdigest()}
        print(f'{label}: body 0x{va:x} size {size}B sha {rec[label]["original_sha256"][:16]}...')
    (ROOT / 'temp/s62-ledger-bodies.json').write_text(json.dumps(rec, indent=1))
    print('body records -> temp/s62-ledger-bodies.json')

if __name__ == '__main__':
    main()
