#!/usr/bin/env python3
"""Host-side driver for the m2381 forensic log reader USB ACM shell (ttyACM0).

probe        — open, hush echo, show /run/reader.log + /run/log.bin state
cmd 'CMDS'   — run shell command(s) on the reader, print output
fetch OUT    — sha256sum on device, then base64-pull /run/log.bin, verify sha
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
        if not all(48 <= c <= 122 for c in line):
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
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
