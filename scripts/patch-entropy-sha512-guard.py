#!/usr/bin/env python3
"""Guard entropy_init's eager SHA512_Init against an unregistered g_crypto_funcs.

The source base (xnu-10063.141.1, iOS 17.6 generation) requires the
corecrypto dispatch table before the PRNG install: entropy_init ->
SHA512_Init dispatches through g_crypto_funcs. The 20H392 (iOS 16.7)
corecrypto kext installed the kernel PRNG *before* it called
register_crypto_functions — an ordering its own iOS 16 kernel tolerated and
the iOS 17 kexts (21H461, and the 21H16 train this board now pairs with) do
not have. The 2026-10-23/24 device rounds panicked with a data abort at
SHA512_Init+0x10 (FAR 0x40, g_crypto_funcs == NULL) inside the kext's
register_and_init_prng.

The digest context is only consumed through entropy_provide, which runs when
the PRNG first generates — after that same kext start has completed the
registration. So the eager init is deferred: entropy_init skips SHA512_Init
while g_crypto_funcs is still NULL (the later startup-table run, and every
later consumer, see the registered table and behave like upstream).

Patch shape: entropy_init's `bl _SHA512_Init` is redirected to a guard
trampoline placed in the corecrypto kext's __TEXT_EXEC udf#0 padding (dead
space; branch range ~64 MiB, inside the ±128 MiB limit)."""
import argparse
import shutil
import struct
import subprocess
from pathlib import Path

ENTROPY_INIT = None   # resolved from the symbol table
SHA512_INIT = None
GUARD_SITE_OFFSET = 0x1c          # entropy_init+0x1c = `bl _SHA512_Init`
# [TODO kernel step] donor-specific: the trampoline sits in the prelinked
# corecrypto kext's __TEXT_EXEC udf#0 padding. 0x...46D8B3C was derived from
# the 20H392 prelinked image; with the 21H16 donor the corecrypto kext lands
# elsewhere, so re-derive from the new prelinked kernel before running the
# guard. The empty-padding probe below makes a stale value fail loudly, but a
# coincidental zero region of another component would be corrupted — derive,
# do not guess.
TRAMPOLINE_VA = 0xFFFFFFF0046D8B3C
TRAMPOLINE_BYTES = 0x94           # udf#0 region observed through +0x8c28


def kernel_symbols(path):
    nm = shutil.which('llvm-nm') or 'llvm-nm'
    table = {}
    for line in subprocess.run([nm, '-n', path], capture_output=True, text=True, check=True).stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in 'tTsSdDbBrR':
            table.setdefault(int(parts[0], 16), parts[2])
    return table


def parse_macho(data):
    count = struct.unpack_from('<I', data, 16)[0]
    off, segs, syms = 32, [], {}
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == 0x19:
            vmaddr, vmsize, fo, fs = struct.unpack_from('<QQQQ', data, off + 24)
            if vmsize:
                segs.append((vmaddr, vmsize, fo, fs))
        elif cmd == 0x2:
            symoff, nsyms, stroff, _ = struct.unpack_from('<IIII', data, off + 8)
            for i in range(nsyms):
                n_strx, _, _, _, n_value = struct.unpack_from('<IBBBI', data, symoff + i * 16)
                end = data.index(b'\x00', stroff + n_strx)
                name = data[stroff + n_strx:end].decode('ascii', 'replace')
                if n_value:
                    syms.setdefault(n_value, name)
        off += size
    return segs, syms


def file_offset(segs, va):
    for vmaddr, vmsize, fo, fs in segs:
        if vmaddr <= va < vmaddr + min(vmsize, fs):
            return fo + (va - vmaddr)
    raise SystemExit(f'{va:#x} is not file-backed')


def branch(from_va, to_va):
    delta = (to_va - from_va) // 4
    if (to_va - from_va) % 4 or not -(1 << 25) <= delta < (1 << 25):
        raise SystemExit(f'branch {from_va:#x}->{to_va:#x} out of range')
    return 0x94000000 | (delta & 0x3FFFFFF)


def adrp_add_pages(va, target):
    """(adrp encoding helper) page pair for adrp x8 + add x8, #off."""
    page = target & ~0xFFF
    d = (page - (va & ~0xFFF)) >> 12
    if not -(1 << 20) <= d < (1 << 20):
        raise SystemExit('adrp out of range')
    enc = (0x90000000 | ((d & 0x3) << 29) | (((d >> 2) & 0x7FFFF) << 5) | 8)
    return enc, target & 0xFFF


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('kernel', type=Path, help='kernel Mach-O, patched in place')
    args = p.parse_args()
    data = bytearray(args.kernel.read_bytes())
    segs, _ = parse_macho(data)
    syms = kernel_symbols(args.kernel)
    entropy_init = next((va for va, n in syms.items() if n == '_entropy_init'), None)
    sha512_init = next((va for va, n in syms.items() if n == '_SHA512_Init'), None)
    gcf = next((va for va, n in syms.items() if n == '_g_crypto_funcs'), None)
    if not (entropy_init and sha512_init and gcf):
        raise SystemExit('require _entropy_init, _SHA512_Init and _g_crypto_funcs symbols')
    site = entropy_init + GUARD_SITE_OFFSET
    fo = file_offset(segs, site)
    word, = struct.unpack_from('<I', data, fo)
    if word != branch(site, sha512_init):
        raise SystemExit(f'{site:#x} holds {word:#010x}, expected bl _SHA512_Init; not this kernel')

    # free trampoline space must be udf#0
    tfo = file_offset(segs, TRAMPOLINE_VA)
    probe, = struct.unpack_from('<I', data, tfo)
    if probe != 0:
        raise SystemExit(f'trampoline space at {TRAMPOLINE_VA:#x} is not empty padding')

    gcf_adrp, gcf_off = adrp_add_pages(TRAMPOLINE_VA + 4, gcf)
    code = [
        0xA9BF7BFD,                                   # stp x29, x30, [sp, #-16]!
        gcf_adrp,                                     # adrp x8, <g_crypto_funcs page>
        0x91000000 | ((gcf_off & 0xFFF) << 10) | 0x108,   # add x8, x8, #(gcf & 0xFFF)
        0xF9400108,                                   # ldr x8, [x8]
        0xB4000068,                                   # cbz x8, +3 -> ldp (skip the init)
        0xAA1303E0,                                   # mov x0, x19
        branch(TRAMPOLINE_VA + 0x18, sha512_init),    # bl _SHA512_Init
        0xA8C17BFD,                                   # ldp x29, x30, [sp], #16
        0xD65F03C0,                                   # ret
    ]
    for k, ins in enumerate(code):
        struct.pack_into('<I', data, tfo + 4 * k, ins)
    struct.pack_into('<I', data, fo, branch(site, TRAMPOLINE_VA))
    args.kernel.write_bytes(data)
    print(f'patched {args.kernel.name}: entropy_init bl -> guard trampoline at {TRAMPOLINE_VA:#x} '
          f'(g_crypto_funcs={gcf:#x}, SHA512_Init={sha512_init:#x})')


if __name__ == '__main__':
    main()
