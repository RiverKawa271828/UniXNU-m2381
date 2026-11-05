#!/usr/bin/env python3
"""r60 payload surgery: wall-59 (kalloc_type_impl_external) + 9 ledger-named imports.

Wall-59 screen (2026-11-06, crc 0x719ca2b6, hit #1, 124B):
  from 0xfffffff009023d34  x0 0xfffffff0080e16d0  x1 0x4
  caller = com.apple.security.AppleImage4 (ktv site.nonce_magazine_t at
  donor 0x80e16d0), bl 0x903a698 (auth-GOT thunk) -> slot 0x80e1940 =
  sentinel -> donor import 0xad3e380.
  x0 = kalloc_type_view (name "site.nonce_magazine_t" @0x751da8e, site
  bitmap "2211.." @0x751daa4, kt_size 0x64 @+0x2c, kt_flags 0xf8 @+0x28),
  w1 = 4 = zflags. Same wall family as the old 21H461 lane wall-10
  (AppleImage4 kalloc_type_view zflags=4).

Judgment (three proofs):
  1. noctf symbol-exact: _kalloc_type_impl_external @noctf 0x732cc8c
     (aliased with _kalloc_type_impl) -> km 0xace8c8c, immediately before
     the r58-proven _kfree_ext 0xace8d18 (same kalloc.c TU).
  2. Semantic body match donor 0xad3e380 vs native 0xace8c8c: identical
     0xd01000 immediate pair (mov w9,#0x1000; movk #0xd,lsl#16), zflags&7
     folded into it (orr w2,w10,w9 == bfxil w1,w8,#0,#3), ktv reads
     [+0](zone cache) / [+0x28] flags / [+0x2c] size&0xffffff, cold path
     tail into _kalloc_type_impl_internal (donor 0xadb2914 == native
     0xace9214, noctf alias confirmed).
  3. stubbed ledger: 0xfffffff00ad3e380 stubbed for BOTH
     com.apple.security.AppleImage4 and com.apple.driver.AppleMobileFileIntegrity
     - the rebind clears both callers' next wall.

The other 9 rebinds come straight from the matcher ledger
(kernel.map.json functions, how=body-hash, cross-checked symbol-exact
against the noctf table at native-0x39BC000; km VA = noctf + 0x39BC000,
convention confirmed by s57 kfree_ext 0xace8d18 and s58 IOLockAlloc
0xb416a00/noctf 0x7a5aa00).

Reads payload-r59, writes payload-r60 with slot rebinds only (no shims,
no seal change - slots live in collection __DATA_CONST, outside the fips
HMAC-covered com.apple.kernel entry __text).

Slot word convention (r57/r58/r59-proven): 0x8011 << 48 | (va - 0x7004000).
Every rewritten slot's pre-image must be the donor word or the emitter
sentinel word (0x8011<<48|0x45a5c4c); anything else aborts.
"""
import hashlib, json, struct, sys
from pathlib import Path

PAY59 = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu/out/m2381/payload-r59-72cc9ef4.img')
OUT = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu/out/m2381/payload-r60.img')
DON = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu/out/ipsw/24A446/kernelcache.decompressed')

BASE = 0x7004000            # GOT compression base (low48)
PAC = 0x8011
SENT_LO = 0x45a5c4c         # _unixnu_fileset_unmapped low48
KHEAD = 0x1c9800            # kernel.macho head inside the payload (s58 contract)
DC_VM, DC_FO, DC_SZ = 0xfffffe0007de4000, 0xde0000, 0x6d0000   # donor == km file offset
SEAL_OFF, SEAL_SZ = 0x3e49800, 0x9e0e94   # fips-HMAC-covered entry __text (payload-absolute)

REBINDS = [
    # (donor_va, name, native_km_va, expect_donor, expect_sentinel)
    (0xad3e380, 'kalloc_type_impl_external', 0xace8c8c, 6, 2),
    (0xb417188, 'OSUnserializeXML', 0xb3dfd78, 13, 5),
    (0xad3e894, 'IOFreeTypeImpl', 0xb415c84, 6, 2),
    (0xaec8c20, 'kauth_cred_nfs4domain2dsnode', 0xb1fcfd4, 2, 1),
    (0xb3d92e8, 'OSCollectionInit', 0xb3adddc, 0, 1),
    (0xaf0444c, 'buf_biowait', 0xaf45a94, 0, 1),
    (0xaf01774, 'buf_invalidateblks', 0xaf44968, 0, 1),
    (0xaf1581c, 'cluster_unlock_direct_read', 0xaf55a08, 0, 1),
    (0xaf1f698, 'vfs_iterate', 0xaf6294c, 0, 1),
    (0xaf2c560, 'vn_authorize_unlink', 0xaf6b8d0, 0, 1),
]


def word_of(va):
    return (PAC << 48) | (va - BASE)


def main():
    don = DON.read_bytes()
    full = bytearray(PAY59.read_bytes())
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
    pre = PAY59.read_bytes()
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
                        'input': PAY59.name, 'input_sha256': hashlib.sha256(pre).hexdigest()}
    out_json = OUT.with_suffix('.img.surgery.json')
    out_json.write_text(json.dumps(report, indent=2) + '\n')
    print(f'\nwrote {OUT} sha256={sha[:8]} size={len(full)}')
    print(f'journal {out_json}')


if __name__ == '__main__':
    main()
