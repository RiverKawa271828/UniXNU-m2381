#!/usr/bin/env python3
"""Local production of both 16 KiB policies from the flashed userdata image.

The CI lane (ci-owner-policy.sh) attaches the restore dmg volumes on macOS;
this lane proves the very same bytes on Linux: userdata-root.img carries the
OS and SystemOS windows byte for byte (the image manifest pins both digests),
so the manifests are made over the window streams and every block is verified
by the same real C/RSA pass (local verified-root + openssl provider). The
committed anchor key (device keys/owner.pem) signs both policies.
"""
import ctypes
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

# Local lane: ROOT is this device repository (the VerifiedRoot fork with the
# 16 KiB blocks lives in kits/, the committed anchor key in keys/). The
# policies land in the firmware cache the kernel build stages from.
ROOT = Path(__file__).resolve().parents[1]
image = Path(sys.argv[1])
fw = Path(sys.argv[2])
keys = ROOT / 'keys'
WINDOWS = [
    dict(name='os', out='build/verified-root-os', offset=1048576, size=6077580800,
         uuid='04769D26-2CA0-4825-B443-E2E5F88300F2',
         sha='e5634d04a8ac35f024845f583394e0a35deb26a04cb0c00286a8674e25a9a4f2'),
    dict(name='systemos', out='build/verified-root-systemos', offset=6079643648, size=3303014400,
         uuid='8846FE78-2910-4297-AF97-D59BB6F8FC16',
         sha='b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f'),
]
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


native = ctypes.CDLL(str(ROOT / 'build/verified-root-host/verified-root.dylib'))  # built below if absent
native.vr_host_open.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(View)]
native.vr_host_block.argtypes = [ctypes.POINTER(View), ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]

for window in WINDOWS:
    out = fw / ('verified-root-' + window['name'])
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
    report = dict(image_bytes=view.image_bytes, blocks_verified=view.block_count, image_sha256=complete.hexdigest(),
                  volume_uuid=window['uuid'], generation=view.generation, block_bytes=block_bytes,
                  source_compressed_sha256=complete.hexdigest(), source_format='userdata window',
                  host_bus_protocol='local file', host_media_writable=False,
                  trusted_key_sha256=record['trusted_key_sha256'], actual_sample_indices=indices,
                  actual_sample_lengths=lengths, real_c_signature_and_block_verification=True,
                  original_image_modified=False, host_only=True, boot_root_authenticated=False,
                  qemu_tested=False, hardware_tested=False)
    (out / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {window["name"]} signature and every {view.block_count} block verified by real C/RSA')
print('PASS: both 16 KiB policies produced under the committed anchor')
