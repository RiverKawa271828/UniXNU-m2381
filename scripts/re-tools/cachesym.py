#!/usr/bin/env python3
"""Shared loader for the 21H461 dyld shared cache RE tools.

Exposes mappings (VA -> file,offset) for every subcache file, a symbol
table (the decoded .symbols local-symbols nlist, 10.2M entries) and
helpers: sym(), read_va(), file_offset(). The cache directory defaults
to <workspace>/temp/cache-extract (override with UNIXNU_CACHE_EXTRACT
or --cache).
"""
import bisect
import mmap
import os
import struct
import sys
from pathlib import Path

CACHE_ENV = 'UNIXNU_CACHE_EXTRACT'


def cache_dir(override=None):
    if override:
        return Path(override)
    env = os.environ.get(CACHE_ENV)
    if env:
        return Path(env)
    # workspace root = six levels up (re-tools -> scripts -> unixnu-m2381
    # -> m2381 -> devices -> workspace)
    here = Path(__file__).resolve()
    ws = here.parents[5]
    return ws / 'temp' / 'cache-extract'


class Cache:
    def __init__(self, cache_path=None):
        base = cache_dir(cache_path)
        self.cache_dir = base
        self.sym_path = base / 'dec-symbols'
        self.cache_files = base / 'System' / 'Library' / 'Caches' / 'com.apple.dyld'
        self.mappings = []  # (start_va, size, file_offset, Path)
        for path in sorted(self.cache_files.iterdir()):
            with path.open('rb') as f:
                head = f.read(0x1000)
            magic = head[:4]
            if not (magic.startswith(b'dyld') or magic.startswith(b'cach')):
                continue
            mo, mc = struct.unpack_from('<2I', head, 0x10)
            for i in range(mc):
                addr, size, foff, maxp, initp = struct.unpack_from('<3Q2I', head, mo + i * 32)
                if size:
                    self.mappings.append((addr, size, foff, path))
        self.mappings.sort()
        f = self.sym_path.open('rb')
        self.syms = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        lo, _ = struct.unpack_from('<2Q', self.syms, 0x48)
        no, nc, so, ss, eo, ec = struct.unpack_from('<6I', self.syms, lo)
        nl = lo + no
        lst = []
        for i in range(nc):
            n_strx, _, _, _, n_value = struct.unpack_from('<IBBHQ', self.syms, nl + i * 16)
            if n_value:
                lst.append((n_value, n_strx))
        lst.sort()
        self._lst = lst
        self._vals = [v for v, _ in lst]
        self._lo, self._so = lo, so

    def sym(self, va):
        idx = bisect.bisect_right(self._vals, va) - 1
        if idx < 0:
            return '<none>'
        v, strx = self._lst[idx]
        pos = self._lo + self._so + strx
        name = self.syms[pos:self.syms.find(b'\0', pos)].decode('utf-8', 'replace')
        d = va - v
        return f'{name}+{d:#x}' if d else name

    def sym_exact(self, va):
        """Symbol name only if it starts exactly at va (no nearest-hit guess)."""
        idx = bisect.bisect_left(self._vals, va)
        if idx < len(self._vals) and self._vals[idx] == va:
            v, strx = self._lst[idx]
            pos = self._lo + self._so + strx
            return self.syms[pos:self.syms.find(b'\0', pos)].decode('utf-8', 'replace')
        return None

    def read_va(self, va, n):
        for addr, size, foff, path in self.mappings:
            if addr <= va < addr + size:
                with path.open('rb') as f:
                    f.seek(foff + (va - addr))
                    return f.read(n)
        return None

    def file_offset(self, va):
        """(subcache filename, offset within that file) for a VA."""
        for addr, size, foff, path in self.mappings:
            if addr <= va < addr + size:
                return path.name, foff + (va - addr)
        return None, None

    def untag(self, stored):
        """Strip the chained-fixup VA tag (0x400_00000000, bit 42)."""
        TAG = 0x40000000000
        return stored & ~TAG

    def profile_fixups(self):
        """The OS profile's text_fixups resolved to unslid VAs.

        Returns dicts {va, size, expected, replacement, where}; va is None
        for fixups outside the cache (BTAudioHALPlugin lives in its own
        driver file). The kernel overlays expected with replacement at
        boot, so raw read_va is the BUILD state — any crash-chain
        disassembly must read through read_run instead (r69: 6 of 25
        fixups sat inside the functions being analyzed, and the applied
        patch at +[UIScreen mainScreen] flipped the whole judgment).
        """
        import re
        ws = self.cache_dir.parents[1]
        out = []
        for prof in sorted(ws.glob('profiles/os/*/profile.toml')):
            text = prof.read_text()
            m = re.search(r'"text_fixups"\s*=\s*\[(.*?)\]\n', text, re.S)
            if not m:
                continue
            for item in re.findall(r'"([^"]+)"', m.group(1)):
                where, off, expected, replacement = item.split(',')
                off = int(off, 16)
                exp = bytes.fromhex(expected)
                rep = bytes.fromhex(replacement)
                va = None
                for addr, size, foff, path in self.mappings:
                    if path.name == where and foff <= off < foff + size:
                        va = addr + (off - foff)
                        break
                out.append({'va': va, 'size': len(exp), 'expected': exp,
                            'replacement': rep, 'where': f'{where}+{off:x}'})
            break
        return out

    def read_run(self, va, n):
        """read_va with the applied text_fixups overlaid (the RUN state)."""
        data = self.read_va(va, n)
        if data is None:
            return None
        buf = bytearray(data)
        for f in self.profile_fixups():
            if f['va'] is None:
                continue
            s, e = f['va'], f['va'] + f['size']
            if e > va and s < va + n:
                for i in range(min(f['size'], len(f['replacement']))):
                    pos = s + i - va
                    if 0 <= pos < len(buf):
                        buf[pos] = f['replacement'][i]
        return bytes(buf)


def main():
    c = Cache(sys.argv[1] if len(sys.argv) > 1 else None)
    print(f'cache: {c.cache_dir} mappings={len(c.mappings)} symbols={len(c._vals)}')


if __name__ == '__main__':
    main()
