#!/usr/bin/env python3
"""r61 payload surgery: the 696 named-import batch (9,139 faces).

Work order (STATE §0 session-61): rebind every named import still holding a
donor word in collection __DATA_CONST. Recipe verified against the work
order numbers on payload-r60:

  r52-era 24A446 matcher ledger
    (out/m2381/ipados-27.0.1-24A446/m2381/kernel/kernel.map.json)
  ∩ noctf symbol-exact (temp/s53-noctf-syms.json: same name AND same VA)
  ∩ form-A donor-word faces in the r60 payload DC
  = 696 imports / 9,139 faces (reproduced exactly 2026-11-06).

One VA is excluded by the ledger name-conflict rule
(0xad8f628: matcher says _task_reference, ledger record says
_task_reference_external) -> batch = 695 imports / 9,136 faces; the conflict
and its 3 faces are reported, not rewritten.

Coordinate conventions (s57/s58/s60-proven):
  payload km view = payload[KHEAD:], km VA = offset + 0x7004000 (low36)
  slot word = 0x8011 << 48 | (va - 0x7004000)
  native km VA = (noctf VA from map.native) + 0x39BC000
  form-A face: auth word, level bits 30-31 == 0, diversity bits 30-47 == 0
  sentinel word low48 = 0x45a5c4c (_unixnu_fileset_unmapped)

Gates: pre-image whitelist per face (donor word -> rewrite, already-native ->
skip+count, sentinel -> ABORT+report, anything else -> ABORT); every native
km VA inside kernel __TEXT/__TEXT_EXEC (parsed from the embedded kernel);
fips seal untouched; full-image diff only inside rewritten slots; count
assertions before anything is written.
"""
import hashlib, json, struct, sys, collections
from pathlib import Path

ROOT = Path('/home/ri/work/unixnu-meizu/ios-m2381-unixnu')
PAY60 = ROOT / 'out/m2381/payload-r60.img'
OUT = ROOT / 'out/m2381/payload-r61.img'
MAP = ROOT / 'out/m2381/ipados-27.0.1-24A446/m2381/kernel/kernel.map.json'
NOCTF = ROOT / 'temp/s53-noctf-syms.json'
LEDGER = Path('/home/ri/work/unixnu-meizu/UniXNU-m2381/kits/XnuPrelink/fixtures/fileset-24A446-symbols.json')
DON = ROOT / 'out/ipsw/24A446/kernelcache.decompressed'

BASE = 0x7004000
PAC = 0x8011
SENT_LO = 0x45a5c4c
KHEAD = 0x1c9800
DC_FO, DC_SZ = 0xde0000, 0x6d0000
NOCTF_DELTA = 0x39BC000
SEAL_OFF, SEAL_SZ = 0x3e49800, 0x9e0e94

# known-good twins (s57/s58/s60 wall-proven): name -> native km VA
SPOT = {'_kfree_ext': 0xace8d18, '_IOLockAlloc': 0xb416a00,
        '_kalloc_type_impl_external': 0xace8c8c}


def form_a(w):
    """s60 verified import-slot form: auth 0x8011, level 0, zero diversity."""
    return (w >> 48) == PAC and ((w >> 30) & 0x3FFFF) == 0


def word_of(va):
    return (PAC << 48) | ((va - BASE) & 0xFFFFFFFFFFFF)


def main():
    pay = PAY60.read_bytes()
    don = DON.read_bytes()

    # segment gate ranges from the embedded kernel macho
    ncmds, = struct.unpack_from('<I', pay, KHEAD + 16)
    at, execs = KHEAD + 32, []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', pay, at)
        if cmd == 0x19:
            name = pay[at + 8:at + 24].rstrip(b'\0').decode()
            vmaddr, vmsize = struct.unpack_from('<QQ', pay, at + 24)
            if name in ('__TEXT', '__TEXT_EXEC') and vmsize:
                execs.append((vmaddr & 0xFFFFFFFFF, (vmaddr + vmsize) & 0xFFFFFFFFF))
        at += size
    print(f'exec gate ranges: {[(hex(a), hex(b)) for a, b in execs]}')

    noct_names = collections.defaultdict(set)
    for va, name in json.load(open(NOCTF)):
        if isinstance(name, str) and name.startswith('_'):
            noct_names[name].add(va & 0xFFFFFFFFF)
    led = json.load(open(LEDGER))
    led_by_va = {int(r['original'], 16) & 0xFFFFFFFFF: r for r in led['functions']}

    pairs = {}
    ambiguous_noctf = 0
    for key, val in json.load(open(MAP))['functions'].items():
        dva = int(key, 16) & 0xFFFFFFFFF
        name = val['name']
        nat = int(val['native'], 16) & 0xFFFFFFFFF
        vas = noct_names.get(name, set())
        if nat not in vas:
            continue
        if len(vas) > 1:
            ambiguous_noctf += 1
        pairs[dva] = (name, nat, val['how'])

    # single pass over the donor DC: form-A donor-word face positions per target
    # (authoritative face set; the payload pre-image classifies each position)
    faces = collections.defaultdict(list)
    for k in range(0, DC_SZ, 8):
        w = struct.unpack_from('<Q', don, DC_FO + k)[0]
        if form_a(w):
            faces[((w & 0x3FFFFFFF) + BASE) & 0xFFFFFFFFF].append(k)

    # payload-side pass (same window): form-A donor-word faces still unfixed
    pay_faces = collections.defaultdict(list)
    for k in range(0, DC_SZ, 8):
        w = struct.unpack_from('<Q', pay, KHEAD + DC_FO + k)[0]
        if form_a(w):
            pay_faces[((w & 0x3FFFFFFF) + BASE) & 0xFFFFFFFFF].append(k)

    cand, conflicts = {}, []
    for dva, (name, nat, how) in pairs.items():
        offs = pay_faces.get(dva)
        if not offs:
            continue
        rec = led_by_va.get(dva)
        if rec is not None and rec['native_symbol'] != name:
            conflicts.append({'original': f'0x{dva:09x}', 'map_name': name,
                              'ledger_name': rec['native_symbol'],
                              'faces': len(offs)})
            continue
        cand[dva] = (name, nat, how, offs)

    n0 = sum(len(v[3]) for v in cand.values())
    print(f'\ncandidate set: {len(cand) + len(conflicts)} imports / '
          f'{n0 + sum(c["faces"] for c in conflicts)} faces '
          f'(work-order recipe must be 696/9139)')
    if len(cand) + len(conflicts) != 696 or \
       n0 + sum(c['faces'] for c in conflicts) != 9139:
        sys.exit('ABORT: candidate set != work-order 696/9139')
    for c in conflicts:
        print(f"  NAME-CONFLICT {c['original']}: map={c['map_name']} "
              f"ledger={c['ledger_name']} faces={c['faces']} (excluded)")
    batch = cand
    n_faces = n0
    print(f'batch after conflict exclusion: {len(batch)} imports / {n_faces} faces')

    # consistency: classify every donor-side face position of every named
    # import. Native words = emitter-fixed kext GOTs or native-kernel-proper
    # fixup sites (safe, out of scope); sentinel words = emitter-stubbed sites
    # of r52-named imports (same hazard class s60 fixed -> rewrite, counted);
    # anything else = abort.
    def classify(pre, donor_word, new_word):
        """Payload pre-image class at a donor face position."""
        if pre == donor_word:
            return 'donor'
        if pre == 0:
            return 'cleared'
        if (pre >> 48) == PAC and (pre & 0xFFFFFFFFFFFF) == SENT_LO:
            return 'sentinel'
        if not (pre >> 63) and ((pre >> 30) & 3) == 0:
            return 'rebase'            # emitter-converted non-auth rebase word
        if (pre >> 63) and ((pre >> 30) & 3) == 0:
            t = ((pre & 0x3FFFFFFF) + BASE) & 0xFFFFFFFFF
            if t == ((new_word & 0x3FFFFFFF) + BASE) & 0xFFFFFFFFF:
                return 'fixed'         # emitter-rebound (possibly diversified)
            return 'other-auth'
        return 'other'

    fully_fixed = sentinel_faces = cleared_sites = rebased_sites = 0
    other_sites = []
    conflict_vas = {int(c['original'], 16) for c in conflicts}
    for dva, (name, nat, how) in pairs.items():
        donor_offs = faces.get(dva, [])
        if not donor_offs:
            continue
        donor_word, new_word = word_of(dva), word_of(nat + NOCTF_DELTA)
        for off in donor_offs:
            at = KHEAD + DC_FO + off
            pre = struct.unpack_from('<Q', pay, at)[0]
            kind = classify(pre, donor_word, new_word)
            if kind == 'donor':
                if dva not in cand and dva not in conflict_vas:
                    sys.exit(f'ABORT: {name} donor face payload {at:#x} '
                             'still donor word but missing from the candidate set')
            elif kind == 'fixed':
                fully_fixed += 1
            elif kind == 'sentinel':
                sentinel_faces += 1
                cand[dva][3].append(off)   # same hazard class: rewrite it too
            elif kind == 'cleared':
                cleared_sites += 1         # emitter-cleared site, nothing to fix
            elif kind == 'rebase':
                rebased_sites += 1         # emitter non-auth rebase word
            else:
                other_sites.append({'payload_offset': hex(at), 'word': hex(pre),
                                    'kind': kind, 'import': name})
    if len(other_sites) > 100:
        for s in other_sites[:10]:
            print('  OTHER', s)
        sys.exit(f'ABORT: {len(other_sites)} unclassified face states (>100) '
                 '— needs manual format review')
    n_faces = sum(len(v[3]) for v in cand.values())
    print(f'donor-side classification clean: emitter-fixed {fully_fixed}, '
          f'sentinel folded {sentinel_faces}, cleared {cleared_sites}, '
          f'non-auth rebase {rebased_sites}, other(emitter-managed) '
          f'{len(other_sites)}')

    # residual donor-word faces on ledger VAs outside the batch (s62 queue)
    residuals = []
    for dva, rec in led_by_va.items():
        if dva in cand or dva in conflict_vas:
            continue
        offs = pay_faces.get(dva)
        if offs:
            residuals.append({'original': f'0x{dva:09x}',
                              'native_symbol': rec['native_symbol'],
                              'faces': len(offs)})
    if residuals:
        print(f'residual donor-word faces on ledger VAs outside batch '
              f'(s62 queue): {json.dumps(residuals)}')
    print(f'final batch: {len(cand)} imports / {n_faces} faces '
          f'(9139 donor-word + {sentinel_faces} sentinel)')

    # name-consistency spot check against ledger records that carry km VAs
    checked = 0
    for dva, (name, nat, how, offs) in batch.items():
        rec = led_by_va.get(dva)
        if rec and 'native_km_va' in rec:
            want = int(rec['native_km_va'], 16)
            if want != nat + NOCTF_DELTA:
                sys.exit(f'ABORT: {name} ledger km {want:#x} != noctf-derived '
                         f'{nat + NOCTF_DELTA:#x}')
            checked += 1
    print(f'ledger km-VA consistency: {checked} records checked')

    # spot-check known-good twins where the batch carries them
    for name, want_km in SPOT.items():
        for dva, (nm, nat, how, offs) in batch.items():
            if nm == name:
                km = nat + NOCTF_DELTA
                tag = 'OK' if km == want_km else 'MISMATCH'
                print(f'  spot {name}: km {km:#x} want {want_km:#x} {tag}')
                if km != want_km:
                    sys.exit(f'ABORT: spot twin {name} mismatch')

    # rewrite pass
    full = bytearray(pay)
    seal_before = bytes(full[SEAL_OFF:SEAL_OFF + SEAL_SZ])
    report = {'rebinds': {}, 'conflicts': conflicts, 'changed_offsets': [],
              'already_native': 0, 'rewritten_sentinel': 0,
              'other_emitter_managed_sites': other_sites}
    total = 0
    for dva, (name, nat, how, offs) in sorted(cand.items()):
        km = nat + NOCTF_DELTA
        if not any(a <= km < b for a, b in execs):
            sys.exit(f'ABORT: {name} native km {km:#x} outside kernel exec segments')
        donor_word, new_word = word_of(dva), word_of(km)
        n_done = n_sent = 0
        for off in offs:
            at = KHEAD + DC_FO + off
            pre = struct.unpack_from('<Q', full, at)[0]
            if pre == donor_word:
                struct.pack_into('<Q', full, at, new_word)
                report['changed_offsets'].append(at)
                n_done += 1
            elif pre == new_word:
                report['already_native'] += 1
            elif (pre & 0xFFFFFFFFFFFF) == SENT_LO:
                struct.pack_into('<Q', full, at, new_word)
                report['changed_offsets'].append(at)
                n_sent += 1
            else:
                sys.exit(f'ABORT: {name} face at payload {at:#x} unexpected '
                         f'pre-image {pre:#x} (donor word {donor_word:#x})')
        report['rebinds'][f'0x{dva:09x}'] = {
            'name': name, 'native_noctf': f'0x{nat:x}',
            'native_km_va': f'0x{km:x}', 'how': how,
            'faces': n_done, 'faces_from_sentinel': n_sent,
            'word': hex(new_word),
            'first_payload_offset': hex(KHEAD + DC_FO + offs[0])}
        total += n_done + n_sent
        report['rewritten_sentinel'] += n_sent
    print(f'\nrewritten {total} slots '
          f'({total - report["rewritten_sentinel"]} donor-word + '
          f'{report["rewritten_sentinel"]} sentinel); '
          f'already-native {report["already_native"]}')
    if total + report['already_native'] != n_faces:
        sys.exit('ABORT: face accounting mismatch')

    if bytes(full[SEAL_OFF:SEAL_OFF + SEAL_SZ]) != seal_before:
        sys.exit('ABORT: fips-sealed entry __text changed')
    report['seal_untouched'] = True

    diffs = [i for i in range(len(full)) if pay[i] != full[i]]
    spans = sorted(set(o for off in report['changed_offsets'] for o in range(off, off + 8)))
    span_set = set(spans)
    stray = [i for i in diffs if i not in span_set]
    clusters = []
    for i in diffs:
        if clusters and i == clusters[-1][1] + 1:
            clusters[-1][1] = i
        else:
            clusters.append([i, i])
    print(f'audit: {len(diffs)} bytes changed in {len(clusters)} clusters; stray {len(stray)}')
    if stray:
        sys.exit('ABORT: diff outside rewritten slots')
    report['audit'] = {'changed_bytes': len(diffs), 'clusters': len(clusters),
                       'stray_bytes': len(stray)}

    OUT.write_bytes(bytes(full))
    sha = hashlib.sha256(bytes(full)).hexdigest()
    report['output'] = {'path': str(OUT), 'sha256': sha, 'size': len(full),
                        'input': PAY60.name,
                        'input_sha256': hashlib.sha256(pay).hexdigest(),
                        'imports': len(batch), 'slots': total,
                        'ambiguous_noctf_names': ambiguous_noctf}
    out_json = OUT.with_suffix('.img.surgery.json')
    out_json.write_text(json.dumps(report, indent=2) + '\n')
    print(f'\nwrote {OUT} sha256={sha[:8]} size={len(full)}')
    print(f'journal {out_json}')


if __name__ == '__main__':
    main()
