#!/usr/bin/env python3
"""Bundle the two 20H392 Apple trust caches into the flat container DarwinBoot and the kernel consume.

The IPSW carries both caches as DER/IM4P ("IM4P"/"trst") files; "unixnu build payload" copies
--trust-cache byte for byte, and DarwinBoot's ValidTrustCaches only accepts the flat multi-module
container (count, offsets, version-2 modules). Same conversion as the upstream
scripts/build-original-system-trust.py: extract the inner modules unchanged, bundle
StaticTrustCache first then Cryptex1,SystemTrustCache, and self-check with the loader's rules."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('static_trustcache', type=Path, help='IPSW StaticTrustCache (IM4P, e.g. 087-86698-044.dmg.trustcache)')
parser.add_argument('system_trustcache', type=Path, help='IPSW Cryptex1,SystemTrustCache (IM4P, e.g. 087-86593-047.dmg.trustcache)')
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()

# board.toml [payload] trust_cache_sha256 pins the two IPSW inputs.
PINNED_INPUTS = {
    '63e01c03b31e1532a5581a24865490673f0b5c297b0199fe0095637c6100ef4b': 'StaticTrustCache',
    '9cc478fe3525e2683b5b9ea1eea0851eaebebdab21d206556233400e59d2e361': 'Cryptex1,SystemTrustCache',
}


def der(data, at):
    if at + 2 > len(data):
        raise ValueError('Truncated DER')
    tag, size = data[at:at + 2]
    at += 2
    if size & 128:
        count = size & 127
        if not 0 < count <= 4 or at + count > len(data):
            raise ValueError('Invalid DER length')
        size = int.from_bytes(data[at:at + count], 'big')
        at += count
    if at + size > len(data):
        raise ValueError('DER exceeds original input')
    return tag, data[at:at + size], at + size


def im4p_payload(path):
    original = path.read_bytes()
    tag, sequence, end = der(original, 0)
    if tag != 0x30 or end != len(original):
        raise SystemExit(f'{path.name}: not a single DER sequence')
    fields, cursor = [], 0
    while cursor < len(sequence):
        kind, data, cursor = der(sequence, cursor)
        fields.append((kind, data))
    if [kind for kind, _ in fields] != [0x16, 0x16, 0x16, 4] or fields[0][1] != b'IM4P' or fields[1][1] not in (b'trst', b'trcs'):
        raise SystemExit(f'{path.name}: require an IM4P trust cache, got {[k for k, _ in fields]} {fields[0][1]!r} {fields[1][1]!r}')
    return original, fields[3][1]


def check_module(data, name):
    version, = struct.unpack_from('<I', data)
    entries, = struct.unpack_from('<I', data, 20)
    if version != 2 or len(data) != 24 + entries * 24:
        raise SystemExit(f'{name}: require a complete exact version-2 module (version={version}, len={len(data)}, entries={entries})')
    for entry in range(entries):
        at = 24 + entry * 24
        if not 1 <= data[at + 20] <= 4:
            raise SystemExit(f'{name}: entry {entry} hash category {data[at + 20]}')
        if entry and data[at - 24:at - 4] >= data[at:at + 20]:
            raise SystemExit(f'{name}: entry {entry} not ascending')
    return entries


modules, inputs = [], []
for path, name in ((args.static_trustcache, 'StaticTrustCache'), (args.system_trustcache, 'Cryptex1,SystemTrustCache')):
    original, module = im4p_payload(path)
    digest = hashlib.sha256(original).hexdigest()
    if digest not in PINNED_INPUTS:
        raise SystemExit(f'{path.name}: sha256 {digest} is not one of the pinned 20H392 trust caches')
    entries = check_module(module, name)
    print(f'{name}: {len(module)} bytes, {entries} entries, input sha256 {digest[:16]}... pinned')
    modules.append(module)
    inputs.append({'name': name, 'im4p_sha256': digest, 'module_sha256': hashlib.sha256(module).hexdigest(), 'entries': entries})

bundle = struct.pack('<3I', 2, 12, 12 + len(modules[0])) + b''.join(modules)


def valid_like_the_loader(data):
    count = struct.unpack_from('<I', data)[0]
    if not 0 < count <= 128:
        return False
    for index in range(count):
        start = struct.unpack_from('<I', data, 4 + 4 * index)[0]
        end = struct.unpack_from('<I', data, 8 + 4 * index)[0] if index + 1 < count else len(data)
        if start < 4 + 4 * count or start & 3 or end > len(data) or end - start < 24 or struct.unpack_from('<I', data, start)[0] != 2:
            return False
        entries = struct.unpack_from('<I', data, start + 20)[0]
        if end - start != 24 + entries * 24:
            return False
        for entry in range(entries):
            at = start + 24 + entry * 24
            if not 1 <= data[at + 20] <= 4 or (entry and data[at - 24:at - 4] >= data[at:at + 20]):
                return False
    return True


if not valid_like_the_loader(bundle):
    raise SystemExit('The trust bundle would be refused by the boot loader')
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_bytes(bundle)
(args.output.with_suffix('.json')).write_text(json.dumps({
    'bundle_sha256': hashlib.sha256(bundle).hexdigest(), 'modules': inputs,
    'original_modules_modified': False, 'own_code_entries_added': False,
    'purpose': 'm2381 boot trust cache: both unchanged 20H392 modules'}, indent=2) + '\n')
print('PASS: 20H392 trust bundle (StaticTrustCache + Cryptex1,SystemTrustCache)', hashlib.sha256(bundle).hexdigest())
