#!/usr/bin/env python3
"""Local production of both 16 KiB policies from the flashed userdata image.

The CI lane (ci-owner-policy.sh) attaches the restore dmg volumes on macOS;
this lane proves the very same bytes on any host with aead-decoded userdata:
userdata-root.img carries the OS and SystemOS windows byte for byte (the image
manifest pins both digests), so the manifests are made over the window streams
and every block is verified by the same real C/RSA pass (local verified-root +
openssl provider). The committed anchor key (device keys/owner.pem) signs both
policies.

Generalized 2026-11-05 (session-52, 24A446 lane switch): windows, volume UUIDs
and image digests are read from the userdata step's own report
(userdata-root.json) and the OS profile's [root] pins instead of the
23F84-era hardcoded WINDOWS table, and the policies land in the combined
firmware-cache layout build-sheng-source-storage.py consumes
(.cache/firmware/verified-root-<build>/{OS,SystemOS}/).

Usage: build-owner-policies-local.py <userdata-root.img> <fw-cache-dir> <profile.toml>
  fw-cache-dir = e.g. .cache/firmware/verified-root-24A446 (OS/ SystemOS/ inside)
"""
import ctypes
import hashlib
import importlib.util
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if len(sys.argv) != 4:
    raise SystemExit(__doc__)
image = Path(sys.argv[1])
fw = Path(sys.argv[2])
profile_path = Path(sys.argv[3])
keys = ROOT / 'keys'
profile = tomllib.loads(profile_path.read_text())
root_pins = profile['root']
LANES = {'OS': ('os_volume_uuid', 'os_image_sha256'),
         'SystemOS': ('systemos_volume_uuid', 'systemos_image_sha256')}
report = json.loads(image.with_suffix('.json').read_text())
WINDOWS = []
for entry in report['windows']:
    uuid_key, sha_key = LANES[entry['name']]
    WINDOWS.append(dict(name=entry['name'], offset=entry['offset'], size=entry['size'],
                        uuid=root_pins[uuid_key].upper(), sha=root_pins[sha_key]))
for window in WINDOWS:
    if window['sha'] != report['windows'][[e['name'] for e in report['windows']].index(window['name'])]['sha256']:
        raise SystemExit(f'{window["name"]}: profile [root] sha and userdata report disagree')
if not image.is_file():
    raise SystemExit(f'Require the dual-window userdata image: {image}')
digest = hashlib.sha256()
with image.open('rb') as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
print(f'userdata image sha256 {digest.hexdigest()[:16]}… ({image.stat().st_size} bytes)')

spec = importlib.util.spec_from_file_location('verified_manifest', ROOT / 'kits/VerifiedRoot/tools/manifest.py')
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)


class Window:
    """A seekable read-only view of one window inside the userdata image."""

    def __init__(self, stream, offset, size):
        self.stream, self.offset, self.size = stream, offset, size
        self.position = 0

    def seek(self, n, whence=0):
        self.position = n if whence == 0 else self.position + n

    def read(self, n=-1):
        if self.position >= self.size:
            return b''
        n = self.size - self.position if n < 0 else min(n, self.size - self.position)
        self.stream.seek(self.offset + self.position)
        data = self.stream.read(n)
        self.position += len(data)
        return data


class View(ctypes.Structure):
    _fields_ = [('hashes', ctypes.c_void_p), ('image_bytes', ctypes.c_uint64), ('block_count', ctypes.c_uint64),
                ('generation', ctypes.c_uint64), ('volume_uuid', ctypes.c_uint8 * 16), ('image_sha256', ctypes.c_uint8 * 32)]


dylib = ROOT / 'build/verified-root-host/verified-root.dylib'
if not dylib.is_file():
    raise SystemExit(f'missing {dylib}: build it once per host (xcrun clang verified_root.c + openssl_provider.c, '
                     'see ci-owner-policy.sh host section) or copy the local one')
native = ctypes.CDLL(str(dylib))
native.vr_host_open.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(View)]
native.vr_host_block.argtypes = [ctypes.POINTER(View), ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]

for window in WINDOWS:
    out = fw / window['name']
    out.mkdir(parents=True, exist_ok=True)
    with image.open('rb') as raw:
        stream = Window(raw, window['offset'], window['size'])
        record = manifest.make(stream, window['size'], keys / 'owner.pem', keys / 'owner-public.pem',
                               window['uuid'], 1, out)
    encoded = ctypes.create_string_buffer((out / 'manifest.bin').read_bytes())
    anchor = ctypes.create_string_buffer((out / 'trusted-key.bin').read_bytes())
    view = View()
    if native.vr_host_open(encoded, len(encoded) - 1, anchor, 1, ctypes.byref(view)) or bytes(view.volume_uuid) != bytes(bytearray.fromhex(window['uuid'].replace('-', ''))):
        raise SystemExit(f'{window["name"]}: real C signature/volume authentication failed')
    complete = hashlib.sha256()
    indices = [0, 1, view.block_count // 2, view.block_count - 1]
    samples, lengths = [], []
    block_bytes = record['block_bytes']
    with image.open('rb') as raw:
        raw.seek(window['offset'])
        for index in range(view.block_count):
            block = raw.read(min(block_bytes, view.image_bytes - index * block_bytes))
            if native.vr_host_block(ctypes.byref(view), index, block, len(block)) != 0:
                raise SystemExit(f'{window["name"]}: actual C block verification failed at {index}')
            complete.update(block)
            if index in indices:
                samples.append(block)
                lengths.append(len(block))
    if complete.hexdigest() != window['sha'] or complete.digest() != bytes(view.image_sha256):
        raise SystemExit(f'{window["name"]}: complete window digest differs from the pinned original')
    (out / 'original-samples.bin').write_bytes(b''.join(samples))
    report_out = dict(image_bytes=view.image_bytes, blocks_verified=view.block_count, image_sha256=complete.hexdigest(),
                      volume_uuid=window['uuid'], generation=view.generation, block_bytes=block_bytes,
                      source_compressed_sha256=complete.hexdigest(), source_format='userdata window',
                      host_bus_protocol='local file', host_media_writable=False,
                      trusted_key_sha256=record['trusted_key_sha256'], actual_sample_indices=indices,
                      actual_sample_lengths=lengths, real_c_signature_and_block_verification=True,
                      original_image_modified=False, host_only=True, boot_root_authenticated=False,
                      qemu_tested=False, hardware_tested=False)
    (out / 'verification.json').write_text(json.dumps(report_out, indent=2) + '\n')
    print(f'PASS: {window["name"]} signature and every {view.block_count} block verified by real C/RSA')
print('PASS: both 16 KiB policies produced under the committed anchor')
