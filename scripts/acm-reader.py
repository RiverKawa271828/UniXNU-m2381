#!/usr/bin/env python3
"""Host-side driver for the m2381 forensic log reader USB ACM shell (ttyACM0).

probe        — open, hush echo, show /run/reader.log + /run/log.bin state
cmd 'CMDS'   — run shell command(s) on the reader, print output
fetch OUT    — sha256sum on device, then base64-pull /run/log.bin, verify sha
fetchchunk OUT — same, 2MiB chunks with a fresh ACM session per chunk; use
               when fetch stalls around ~13MiB (r56 observed twice)
"""
import base64
import hashlib
import os
import select
import sys
import termios
import time
import tty

PORT = '/dev/ttyACM0'
END = b'___DONE___'
B64END = b'___B64END___'


class Acm:
    def __init__(self):
        self.fd = os.open(PORT, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        self.old = termios.tcgetattr(self.fd)
        tty.setraw(self.fd)

    def _read_some(self, wait):
        r, _, _ = select.select([self.fd], [], [], wait)
        if not r:
            return b''
        try:
            return os.read(self.fd, 262144)
        except OSError:
            return b''

    def drain(self, seconds):
        acc = bytearray()
        end = time.time() + seconds
        while time.time() < end:
            acc += self._read_some(0.1)
        return bytes(acc)

    def send(self, text):
        os.write(self.fd, text.encode() + b'\n')

    def until(self, marker, timeout):
        acc = bytearray()
        end = time.time() + timeout
        while time.time() < end:
            data = self._read_some(0.2)
            if data:
                acc += data
                if marker in acc:
                    return bytes(acc[:acc.index(marker)]), True
        return bytes(acc), False

    def close(self):
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)
        os.close(self.fd)


def run(acm, cmds, timeout=15):
    acm.send(f'echo ___RUN___\n')
    acm.drain(0.3)
    acm.send(f'{cmds}\n')
    acm.send(f'echo {END.decode()}\n')
    out, ok = acm.until(END, timeout)
    return out.decode('utf-8', errors='replace'), ok


def cmd_mode(cmds, timeout):
    acm = Acm()
    boot = acm.drain(1.5)
    acm.send('stty -echo\n')
    acm.drain(0.3)
    out, ok = run(acm, cmds, timeout)
    print(out)
    if not ok:
        print(f'--- TIMEOUT after {timeout}s (partial output above)', file=sys.stderr)
        sys.exit(2)
    acm.close()


def fetch_mode(out_path):
    acm = Acm()
    boot = acm.drain(1.5)
    acm.send('stty -echo\n')
    acm.drain(0.3)
    dev_sha, ok = run(acm, 'sha256sum /run/log.bin; wc -c < /run/log.bin', 180)
    print('--- device side:', dev_sha.strip(), '(complete)' if ok else '(TIMEOUT)')
    if not ok:
        sys.exit(2)
    print(f'--- pulling /run/log.bin via base64 -> {out_path}')
    acm.send('base64 /run/log.bin; echo ___B64END___\n')
    acc = bytearray()
    t0 = time.time()
    last = 0
    while time.time() - t0 < 540:
        data = acm._read_some(0.2)
        if data:
            acc += data
            now = len(acc)
            if now - last > 4 * 1024 * 1024:
                last = now
                print(f'--- {now >> 20} MiB raw stream, {time.time() - t0:.0f}s elapsed', flush=True)
            if B64END in acc:
                break
    else:
        print(f'--- TIMEOUT at {len(acc)} raw bytes', file=sys.stderr)
        sys.exit(2)
    head, _, tail = bytes(acc).partition(B64END)
    lines = []
    for line in head.replace(b'\r', b'\n').split(b'\n'):
        line = line.strip()
        if not line or b'___' in line or line.startswith(b'base64 '):
            continue
        if not all(43 <= c <= 122 for c in line):  # base64: + / 0-9 = A-Z a-z
            continue
        lines.append(line)
    blob = base64.b64decode(b''.join(lines) + b'===')
    with open(out_path, 'wb') as f:
        f.write(blob)
    sha = hashlib.sha256(blob).hexdigest()
    dev_line = ''
    for l in dev_sha.splitlines():
        if len(l) >= 64 and all(c in '0123456789abcdef' for c in l[:64]):
            dev_line = l[:64]
    print(f'--- pulled {len(blob)} bytes, host sha256 {sha}')
    print(f'--- device sha256      {dev_line}')
    print('--- SHA MATCH' if dev_line and sha == dev_line else '--- SHA MISMATCH!', file=sys.stderr)
    acm.close()


def fetchchunk_mode(out_path):
    """2MiB chunked pull, one fresh ACM session per chunk.

    The single-shot base64 stream deterministically stalls around ~13MiB
    decoded (two r55e fetches died the same way; fresh sessions per chunk
    fully avoid it — 16/16 chunks + SHA MATCH, 31s). Device sha is queried
    first; chunks are re-tried up to 3x before giving up.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location('acm_reader', __file__)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    acm0 = mod.Acm()
    acm0.drain(1.5)
    acm0.send('stty -echo\n')
    acm0.drain(0.3)
    dev_sha, ok = run(acm0, 'sha256sum /run/log.bin; wc -c < /run/log.bin', 180)
    acm0.close()
    if not ok:
        print('--- device sha query TIMEOUT', file=sys.stderr)
        sys.exit(2)
    dev_line = ''
    total = 0
    for l in dev_sha.splitlines():
        if len(l) >= 64 and all(c in '0123456789abcdef' for c in l[:64]):
            dev_line = l[:64]
        elif l.strip().isdigit():
            total = int(l.strip())
    if total <= 0:
        print('--- device size query failed', file=sys.stderr)
        sys.exit(2)
    chunk_mb = 2
    nchunks = (total + chunk_mb * 1024 * 1024 - 1) // (chunk_mb * 1024 * 1024)
    sha = hashlib.sha256()
    t0 = time.time()
    with open(out_path, 'wb') as f:
        for i in range(nchunks):
            skip = i * chunk_mb
            blob, ok = None, False
            for attempt in range(3):
                blob, ok = chunk_pull(skip, chunk_mb)
                if ok and len(blob) == min(chunk_mb * 1024 * 1024, total - skip * 1024 * 1024):
                    break
                print(f'--- chunk {i}: attempt {attempt + 1} bad (ok={ok}, {len(blob)} bytes), retrying',
                      flush=True)
            else:
                print(f'--- chunk {i}: FAILED after 3 attempts', file=sys.stderr)
                sys.exit(2)
            f.write(blob)
            sha.update(blob)
            print(f'--- chunk {i:2d}/{nchunks - 1} ok, {len(blob)} bytes, '
                  f'{time.time() - t0:.0f}s', flush=True)
    got = sha.hexdigest()
    print(f'--- host   sha256 {got}')
    print(f'--- device sha256 {dev_line}')
    print('--- SHA MATCH' if dev_line and got == dev_line else '--- SHA MISMATCH!', file=sys.stderr)
    sys.exit(0 if dev_line and got == dev_line else 1)


def chunk_pull(skip_mb, count_mb):
    acm = Acm()
    try:
        acm.drain(1.0)
        acm.send('stty -echo\n')
        acm.drain(0.3)
        cmd = (f'dd if=/run/log.bin bs=1048576 skip={skip_mb} count={count_mb} '
               f'2>/dev/null | base64')
        out_txt, ok = run(acm, cmd, 120)
    finally:
        acm.close()
    lines = []
    for line in out_txt.replace('\r', '\n').split('\n'):
        line = line.strip()
        if not line or '___' in line or line.startswith('dd ') or line.startswith('base64 '):
            continue
        if not all(43 <= ord(c) <= 122 for c in line):  # base64: + / 0-9 = A-Z a-z
            continue
        lines.append(line)
    blob = base64.b64decode(''.join(lines) + '===')
    return blob, ok


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    mode = sys.argv[1]
    if mode == 'probe':
        cmd_mode('cat /run/reader.log; ls -l /run/log.bin; uname -a', 15)
    elif mode == 'cmd':
        cmd_mode(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 15)
    elif mode == 'fetch':
        fetch_mode(sys.argv[2])
    elif mode == 'fetchchunk':
        fetchchunk_mode(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
