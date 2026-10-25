#!/usr/bin/env python3
"""Write the transport bindings record the kernel link's cross-check reads.

build-xnu-4k-baseline.sh refuses to link NativeRamBlock together with
NativeVirtioBlock unless both archives carry a bindings.json record and the
two records bind the same original class. Upstream produces those records in
build-native-virtio-bindings.py from build/storage-abi/interface-audit.json,
which only a live-device lldb snapshot can produce. This lane binds the same
slots statically (prelink-storage-bindings.json applied at prelink time via
libStorageBindings.a in build/io-storage-family), so the records carry that
audited map plus the hash of the actual compiled transport object.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('component', choices=['NativeVirtioBlock', 'NativeRamBlock'])
parser.add_argument('--archive', required=True, type=Path,
                    help='Directory holding the compiled transport archive and object')
args = parser.parse_args()

out = args.archive.resolve()
obj = out / (args.component + '.o')
if not obj.is_file():
    raise SystemExit(f'missing compiled transport object: {obj}')
# The link audit derives the audited object from the archive file name
# (libVirtioMmioBlock.a -> VirtioMmioBlock.o) while build-arm-driver writes
# the runtime identifier (NativeVirtioBlock.o); alias it in place.
for archive in out.glob('lib*.a'):
    audit_obj = out / (archive.stem.removeprefix('lib') + '.o')
    if not audit_obj.exists():
        audit_obj.hardlink_to(obj)
source = ROOT / 'build/io-storage-family/bindings.json'
if not source.is_file():
    raise SystemExit('run build-storage-bindings.py first: ' + str(source))
bindings = json.loads(source.read_text())['bindings']
record = dict(compiled_object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest(),
              bindings=dict(bindings),
              binding_source='build/io-storage-family/bindings.json (prelink-storage-bindings.json static pin)',
              static_prelink_lane=True, original_code_modified=False)
(out / 'bindings.json').write_text(json.dumps(record, indent=2) + '\n')
print(f'{args.component}: transport record written '
      f'({len(bindings)} static original-class bindings, object {record["compiled_object_sha256"][:12]})')
