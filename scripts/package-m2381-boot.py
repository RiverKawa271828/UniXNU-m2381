#!/usr/bin/env python3
"""Pack the m2381 boot image: gzip(BootShim + UEFI FD) in an Android boot v4 header.

The upstream `unixnu bootimg` step emits the sheng shape (header v0/v2, device
tree appended to the kernel member). The m2381 ABL needs the nura-proven
shape instead, per docs/BOOT-CHAIN-RE.md §4.2 and the running nura chain:

  * header v4 (Flyme stock shape), with os_version / os_patch_level;
  * kernel member = gzip(BootShim + FD) with NO appended device tree — the
    stock vendor_boot DTB passes BoardDtMatch and feeds the ABL, the FV's
    FdtBlob feeds the UEFI;
  * the shim carries the ARM64 kernel header (requires_kernel_header) and
    disables the inherited Gunyah VM watchdog (SMC 0x86000005) — both baked
    into the overlaid BootShim.S (devices/m2381/uefi/BootShim).
  * a 5-byte ramdisk placeholder; this ABL ignores the boot ramdisk entirely.

Firmware append (m2381 charging lane, 2026-10-29): with --adsp-mbn/--adsp-dtb-mbn
the ADSP firmware rides AFTER the boot image inside boot_b, in a self-describing
segment the kernel's AdspProbe reads through the ShengUfs native_ufs_part_find/read
exports (the ESP cannot hold 30.5 MiB). The segment starts at the first 4 KiB
boundary past the finished boot image — the exact offset AdspProbe recomputes
from the v4 header fields — and its header carries boot_image_bytes so a layout
drift refuses loudly instead of reading garbage. The ABL only consumes the boot
image proper (it computes the same extent from the header), so trailing bytes
are inert to it; first-flash evidence is the gate for that assumption.

Segment layout (all little-endian):
    u8[8]  magic  "M2381FW\x01"
    u32    header_size  (4096)
    u32    entry_count
    u64    boot_image_bytes (the boot image this segment follows)
    u64    reserved (0)
    entries at 32, 48 B each: u64 offset (from segment start, 4 KiB aligned),
                              u64 size, u8[32] sha256 (forensics only — the
                              kernel does not verify; PAS authentication gates)
    payloads at their offsets, each padded to 4 KiB.

Usage:
    python3 scripts/package-m2381-boot.py --uefi out/m2381/uefi \
        [--fd out/m2381/uefi/Build/m2381Pkg/DEBUG_CLANGPDB/FV/SILICIUM_UEFI.fd] \
        [--adsp-mbn .cache/firmware/adsp/adsp.mbn --adsp-dtb-mbn .cache/firmware/adsp/adsp_dtb.mbn] \
        [--out out/m2381/boot/boot.img]

Deterministic: the gzip stream carries mtime=0. Verified by unpacking the
result and round-tripping every member (and every segment entry).
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[1]

SEGMENT_MAGIC = b'M2381FW\x01'
SEGMENT_HEADER_SIZE = 4096
SEGMENT_ENTRY_SIZE = 48
BOOT_PARTITION_BYTES = 96 * 1024 * 1024  # boot_b on this board (FLASHING.md red line)


def build_segment(members, boot_image_bytes):
    """members: [(name, bytes)] in fixed order; returns the 4 KiB-aligned segment."""
    count = len(members)
    header = bytearray(SEGMENT_HEADER_SIZE)
    header[0:8] = SEGMENT_MAGIC
    struct.pack_into('<IIQQ', header, 8, SEGMENT_HEADER_SIZE, count, boot_image_bytes, 0)
    offset = SEGMENT_HEADER_SIZE
    payloads = []
    for index, (name, data) in enumerate(members):
        entry_at = 32 + index * SEGMENT_ENTRY_SIZE
        struct.pack_into('<QQ', header, entry_at, offset, len(data))
        header[entry_at + 16:entry_at + 48] = hashlib.sha256(data).digest()
        pad = -len(data) % 4096
        payloads.append(data + b'\x00' * pad)
        offset += len(data) + pad
    return bytes(header) + b''.join(payloads)


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    if result.returncode:
        sys.exit(f'package-m2381-boot: {" ".join(map(str, command))} failed:\n{result.stderr.strip()}')


def compile_shim(uefi, base, size, scratch):
    """Compile the overlaid BootShim.S with the m2381 flags and check its shape."""
    clang = __import__('shutil').which('clang')
    objcopy = __import__('shutil').which('llvm-objcopy')
    nm = __import__('shutil').which('llvm-nm')
    for tool, hint in ((clang, 'clang'), (objcopy, 'llvm'), (nm, 'llvm')):
        if not tool:
            sys.exit(f'package-m2381-boot: {hint} tooling not found on PATH')
    obj = scratch / 'shim.o'
    run([clang, '--target=aarch64-none-elf', '-c',
         f'-DFD_BASE={base}', f'-DFD_SIZE={size}',
         '-DREQUIRES_KERNEL_HEADER=1', '-DDISABLE_GUNYAH_WATCHDOG=1',
         str(uefi / 'BootShim/BootShim.S'), '-o', str(obj)])
    run([objcopy, '-O', 'binary', str(obj), str(scratch / 'shim.bin')])
    shim = (scratch / 'shim.bin').read_bytes()
    symbols = subprocess.run([nm, '-n', str(obj)], capture_output=True, text=True).stdout
    payload = next((int(line.split()[0], 16) for line in symbols.splitlines() if line.endswith(' _Payload')), None)
    if payload != len(shim):
        sys.exit('package-m2381-boot: a literal pool or padding separates _Payload from the firmware volume')
    if shim[56:60] != b'ARM\x64':
        sys.exit('package-m2381-boot: the shim lacks the ARM64 image magic the ABL checks')
    image_size = struct.unpack_from('<Q', shim, 16)[0]
    if image_size != int(size, 0):
        sys.exit(f'package-m2381-boot: shim image_size {image_size:#x} != FD size {int(size, 0):#x}')
    return shim


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uefi', type=Path, required=True, help='Mu-Silicium checkout (m2381 overlay applied)')
    parser.add_argument('--fd', type=Path, default=None, help='built SILICIUM_UEFI.fd (default: the DEBUG one of this checkout)')
    parser.add_argument('--out', type=Path, default=ROOT / 'build/m2381/boot/boot.img')
    parser.add_argument('--adsp-mbn', type=Path, default=None,
                        help='squashed ADSP firmware to append inside boot_b (with --adsp-dtb-mbn)')
    parser.add_argument('--adsp-dtb-mbn', type=Path, default=None,
                        help='squashed ADSP DTB firmware to append inside boot_b (with --adsp-mbn)')
    parser.add_argument('--max-image-bytes', type=lambda x: int(x, 0), default=BOOT_PARTITION_BYTES,
                        help='refuse to build past this many bytes (default: boot_b size)')
    parser.add_argument('--boot-sha256', default=None, help='expected sha256 of the finished image (recorded in boot.json)')
    args = parser.parse_args()
    if bool(args.adsp_mbn) != bool(args.adsp_dtb_mbn):
        sys.exit('package-m2381-boot: --adsp-mbn and --adsp-dtb-mbn go together')

    import tomllib
    config = tomllib.loads((args.uefi / 'Resources/Configs/m2381.toml').read_text())
    boot_image = config['boot_image']
    if boot_image.get('header_version') != 4:
        sys.exit('package-m2381-boot: m2381.toml must request header_version 4')
    if config['boot_image_kernel'].get('append_dtb'):
        sys.exit('package-m2381-boot: m2381.toml must set append_dtb=false (the stock vendor_boot DTB feeds the ABL)')
    kernel_compression = config['boot_image_kernel'].get('kernel_compression')
    if kernel_compression != 'gzip':
        sys.exit(f'package-m2381-boot: unsupported kernel_compression {kernel_compression!r}')

    fd = args.fd or args.uefi / 'Build/m2381Pkg/DEBUG_CLANGPDB/FV/SILICIUM_UEFI.fd'
    if not fd.is_file():
        sys.exit(f'package-m2381-boot: firmware volume not found: {fd}')
    firmware = fd.read_bytes()
    fd_config = config['uefi_fd']
    base, size = fd_config['base'], fd_config['size']
    if len(firmware) != size:
        sys.exit(f'package-m2381-boot: FD is {len(firmware):#x} bytes, m2381.toml says {size:#x}')

    mkbootimg = args.uefi / 'Resources/Scripts/mkbootimg.py'
    if not mkbootimg.is_file():
        sys.exit(f'package-m2381-boot: {mkbootimg} missing')

    with tempfile.TemporaryDirectory(prefix='m2381-boot-') as scratch_name:
        scratch = Path(scratch_name)
        shim = compile_shim(args.uefi, hex(base), hex(size), scratch)
        combined = shim + firmware
        kernel = scratch / 'Image.gz'
        kernel.write_bytes(gzip.compress(combined, mtime=0))
        ramdisk = scratch / 'ramdisk'
        ramdisk.write_bytes((args.uefi / 'Resources/ramdisk').read_bytes())

        args.out.parent.mkdir(parents=True, exist_ok=True)
        command = ['python3', str(mkbootimg), '--kernel', str(kernel), '--ramdisk', str(ramdisk), '-o', str(args.out)]
        for key in ('header_version', 'os_version', 'os_patch_level', 'base', 'kernel_offset', 'tags_offset', 'pagesize', 'cmdline'):
            if key in boot_image and boot_image[key] is not None:
                command += [f'--{key}', str(boot_image[key])]
        run(command)

        # Verify: unpack and round-trip every member against its input.
        data = args.out.read_bytes()
        if data[:8] != b'ANDROID!':
            sys.exit('package-m2381-boot: output is not a boot image')
        kernel_size, ramdisk_size, os_version, header_size = struct.unpack_from('<4I', data, 8)
        header_version = struct.unpack_from('<I', data, 40)[0]
        if header_version != 4:
            sys.exit(f'package-m2381-boot: header_version={header_version}, expected 4')
        page = 4096
        start = page * (1 + -(-kernel_size // page))
        unpacker = zlib.decompressobj(16 + zlib.MAX_WBITS)
        if unpacker.decompress(data[page:page + kernel_size]) != combined or not unpacker.eof or unpacker.unused_data:
            sys.exit('package-m2381-boot: gzip(shim+FD) does not round-trip')
        if data[start:start + ramdisk_size] != ramdisk.read_bytes():
            sys.exit('package-m2381-boot: ramdisk bytes differ')
        kernel_sha256 = hashlib.sha256(kernel.read_bytes()).hexdigest()
        boot_image_sha256 = hashlib.sha256(data).hexdigest()
        boot_image_bytes = len(data)

        # Firmware append: the ADSP segment rides after the boot image inside boot_b. Verified by
        # re-reading the file and checking the magic, the recorded boot_image_bytes cross-check and
        # every entry's payload against its sha256.
        segment_report = None
        if args.adsp_mbn:
            adsp = args.adsp_mbn.read_bytes()
            adsp_dtb = args.adsp_dtb_mbn.read_bytes()
            segment = build_segment([('adsp', adsp), ('adsp_dtb', adsp_dtb)], len(data))
            if len(data) + len(segment) > args.max_image_bytes:
                sys.exit(f'package-m2381-boot: boot image {len(data)} + segment {len(segment)} '
                         f'exceeds the partition budget {args.max_image_bytes}')
            with open(args.out, 'ab') as out:
                out.write(segment)
            full = args.out.read_bytes()
            if full[:len(data)] != data:
                sys.exit('package-m2381-boot: boot image changed under the append')
            appended = full[len(data):]
            if appended != segment:
                sys.exit('package-m2381-boot: appended segment does not round-trip')
            if appended[0:8] != SEGMENT_MAGIC:
                sys.exit('package-m2381-boot: segment magic missing at the append offset')
            _, header_size, count, recorded_boot, _ = struct.unpack_from('<8sIIQQ', appended, 0)
            if recorded_boot != len(data) or header_size != SEGMENT_HEADER_SIZE or count != 2:
                sys.exit(f'package-m2381-boot: segment header inconsistent (boot={recorded_boot}, '
                         f'header={header_size}, count={count})')
            entries = []
            for index, (name, payload) in enumerate((('adsp', adsp), ('adsp_dtb', adsp_dtb))):
                offset, size = struct.unpack_from('<QQ', appended, 32 + index * SEGMENT_ENTRY_SIZE)
                digest = appended[32 + index * SEGMENT_ENTRY_SIZE + 16:32 + index * SEGMENT_ENTRY_SIZE + 48].hex()
                if appended[offset:offset + size] != payload or hashlib.sha256(payload).hexdigest() != digest:
                    sys.exit(f'package-m2381-boot: segment entry {name} does not round-trip')
                entries.append({'name': name, 'offset': offset, 'size': size, 'sha256': digest})
            segment_report = {'bytes': len(segment), 'boot_image_bytes': len(data), 'entries': entries}
            data = full
            print(f"package-m2381-boot: ADSP segment appended ({len(segment)} bytes, "
                  f"boot image {recorded_boot} + segment)")

    report = {'kernel_sha256': kernel_sha256, 'fd_sha256': hashlib.sha256(firmware).hexdigest(),
              'image_sha256': hashlib.sha256(data).hexdigest(), 'image_bytes': len(data),
              'boot_image_sha256': boot_image_sha256, 'boot_image_bytes': boot_image_bytes,
              'segment': segment_report,
              'header_version': 4, 'os_version': boot_image.get('os_version'), 'os_patch_level': boot_image.get('os_patch_level'),
              'shim_bytes': len(shim), 'fd_bytes': len(firmware), 'hardware_tested': False}
    if args.boot_sha256 and report['image_sha256'] != args.boot_sha256:
        sys.exit(f"package-m2381-boot: image sha {report['image_sha256']} != expected {args.boot_sha256}")
    (args.out.parent / 'boot.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"package-m2381-boot: {args.out} ({len(data)} bytes)")
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
