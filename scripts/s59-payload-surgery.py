#!/usr/bin/env python3
"""r59 payload surgery: wall-58 (IOLockAlloc) + OSObject default ctor batch.

Wall-58 screen (2026-11-06, crc 0xfcd9b111, hit #1, 139B):
  from 0xfffffff00a0aac38  x0 0xfffffff00bb3de18  x1 0xfffffff3facb9d20
  caller = com.apple.iokit.IOCryptoAcceleratorFamily ctor, bl 0xa0ab660
  (auth-GOT thunk) -> slot 0x8313b60 = sentinel -> donor import 0xb4424c4.

Reads payload-r58, writes payload-r59 with slot rebinds only (no shims,
no seal change - slots live in collection __DATA_CONST, outside the
fips-HMAC-covered com.apple.kernel entry __text):

  donor 0xb4424c4 (IOLockAlloc variant: bti; ldr x0,[0xb929330]; b
    lck_mtx_alloc_init 0xad43134 - discards args, uses kernel default
    lock group) 134 slots (118 donor-word + 16 sentinel)
      -> native _IOLockAlloc 0xb416a00
         (body-exact twin: adrp/ldr [0xb935450]; mov x1,#0; b native
          lck_mtx_alloc_init 0xaceffe8; noctf symbol-exact @0x7a5aa00)
  donor 0xb3d385c (OSObject default ctor, pacda-isa 0xcda1 context)
    292 slots (267 donor-word + 25 sentinel)
      -> native __ZN8OSObjectC2Ev 0xb3aba18
         (noctf 0x79efa18 + 0x39BC000; s45 wall-36 semantic precedent)
    NOTE: s57's "267 donor-copy slots alive" is OVERTURNED by byte
    compare - donor kernel exec is replaced by our native kernel in the
    payload, so donor-word slots pointed at native _OSKextFreeSite
    neighborhood code (0xb3d385c payload = fn @0xb3d382c). All 292 faces
    must rebind.

Slot word convention (r57/r58-proven): 0x8011 << 48 | (va - 0x7004000).
Every rewritten slot's pre-image must be the donor word or the emitter
sentinel word (0x8011<<48|0x45a5c4c); anything else aborts.
"""
import hashlib, json, struct, sys
from pathlib import Path

PAY58 = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu/out/m2381/payload-r58-ca755a65.img')
OUT = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu/out/m2381/payload-r59.img')
DON = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu/out/ipsw/24A446/kernelcache.decompressed')

BASE = 0x7004000            # GOT compression base (low48)
PAC = 0x8011
SENT_LO = 0x45a5c4c         # _unixnu_fileset_unmapped low48
KHEAD = 0x1c9800            # kernel.macho head inside the payload (s58 contract)
DC_VM, DC_FO, DC_SZ = 0xfffffe0007de4000, 0xde0000, 0x6d0000   # donor == km file offset
SLIDE = 0x1f000000000
SEAL_OFF, SEAL_SZ = 0x3e49800, 0x9e0e94   # fips-HMAC-covered entry __text (payload-absolute)

REBINDS = [
    # (donor_va, name, native_va, expect_donor, expect_sentinel)
    (0xb4424c4, 'IOLockAlloc', 0xb416a00, 118, 16),
    (0xb3d385c, 'OSObjectCtor', 0xb3aba18, 267, 25),
]


def word_of(va):
    return (PAC << 48) | (va - BASE)


def main():
    don = DON.read_bytes()
    full = bytearray(PAY58.read_bytes())
    pay = memoryview(full)[KHEAD:]          # km space view: all km-relative offsets below
    seal_before = bytes(full[SEAL_OFF:SEAL_OFF + SEAL_SZ])

    report = {'rebinds': {}, 'changed_offsets': []}
    total = 0
    for donor_va, name, native_va, exp_donor, exp_sent in REBINDS:
        tlo = donor_va - BASE
        donor_word = word_of(donor_va)
        new_word = word_of(native_va)
        n_donor = n_sent = 0
        offs = []
        for k in range(0, DC_SZ, 8):
            dw = struct.unpack_from('<Q', don, DC_FO + k)[0]
            if (dw >> 48) != PAC or (dw & 0xFFFFFFFFFFFF) != tlo:
                continue
            pre = struct.unpack_from('<Q', pay, DC_FO + k)[0]
            if pre == donor_word:
                n_donor += 1
            elif (pre >> 48) == PAC and (pre & 0xFFFFFFFFFFFF) == SENT_LO:
                n_sent += 1
            else:
                sys.exit(f'ABORT: slot {DC_VM + k:#x} unexpected pre-image {pre:#x}')
            struct.pack_into('<Q', pay, DC_FO + k, new_word)
            offs.append(KHEAD + DC_FO + k)   # payload-absolute
        if (n_donor, n_sent) != (exp_donor, exp_sent):
            sys.exit(f'ABORT: {name} counts {n_donor}/{n_sent} != expected {exp_donor}/{exp_sent}')
        report['rebinds'][name] = {
            'donor_va': hex(donor_va), 'native_va': hex(native_va),
            'slots': n_donor + n_sent, 'rewritten_donor': n_donor,
            'rewritten_sentinel': n_sent,
            'word': hex(new_word), 'slot_payload_offset_first': hex(offs[0]) if offs else None,
        }
        report['changed_offsets'] += offs
        total += n_donor + n_sent
        print(f'{name}: donor {donor_va:#x} -> native {native_va:#x}: '
              f'{n_donor} donor-word + {n_sent} sentinel = {n_donor + n_sent} slots')

    seal_after = bytes(full[SEAL_OFF:SEAL_OFF + SEAL_SZ])
    if seal_before != seal_after:
        sys.exit('ABORT: fips-sealed entry __text changed (must never happen in slot surgery)')
    report['seal_untouched'] = True

    # full-image diff audit vs pre-image: every changed byte must lie inside
    # one of the 8-byte slots we rewrote (payload-absolute)
    pre = PAY58.read_bytes()
    diffs = [i for i in range(len(full)) if pre[i] != full[i]]
    stray = [i for i in diffs if not any(o <= i < o + 8 for o in report['changed_offsets'])]
    clusters = []
    for i in diffs:
        if clusters and i == clusters[-1][1] + 1:
            clusters[-1][1] = i
        else:
            clusters.append([i, i])
    print(f'\naudit: {len(diffs)} bytes changed in {len(clusters)} clusters; '
          f'stray bytes = {len(stray)}')
    if stray:
        sys.exit('ABORT: diff outside rewritten slots')

    OUT.write_bytes(bytes(full))
    sha = hashlib.sha256(bytes(full)).hexdigest()
    report['output'] = {'path': str(OUT), 'sha256': sha, 'size': len(full),
                        'input': PAY58.name, 'input_sha256': hashlib.sha256(pre).hexdigest()}
    out_json = OUT.with_suffix('.img.surgery.json')
    out_json.write_text(json.dumps(report, indent=2) + '\n')
    print(f'\nwrote {OUT} sha256={sha[:8]} size={len(pay)}')
    print(f'journal {out_json}')


if __name__ == '__main__':
    main()
