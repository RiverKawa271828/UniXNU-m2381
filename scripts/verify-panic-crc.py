#!/usr/bin/env python3
"""First-boot panic-screen CRC verifier (the per-round transcription check).

The panic screen appends crc= over the PANIC_TEXT message copy:
    zlib.crc32 over the panic() format expansion of
    fileset-unmapped-call.patch:
    "fileset: original component called an unmapped kernel function from %p (x0 0x%llx x1 0x%llx) hit #%u"
    (no trailing newline; %p renders as 0x%016lx on the kernel console).

2026-11-07 (r76): the general format is now pinned — osfmk/kern/panic_call.h:46
(XNU_KERNEL_PRIVATE) defines panic as a macro expanding every call to
    (panic)(fmt " @%s:%d", ##__VA_ARGS__, __FILE_NAME__, __LINE__)
so the covered bytes are ALWAYS: expanded fmt + " @" + basename + ":" + line,
literal bytes, no trailing newline (\t/\n inside a fmt become spaces via the
screen's put(), but the assert-style quoted forms carry a LITERAL backslash-n
which stays two ASCII chars). Calibration pairs (all zero-correction):
  w38: --from 0xfffffff0084ca3bc --x0 0xfffffff2d947bb00 --x1 0xfffffff00b4afe88 --crc 0x8a2bf81e
  w39: --from 0xfffffff0084ca524 --x0 0x1 --x1 0x10001 --crc 0x50d36e66
  w74: --msg 'SourceStorage: root policy handoff or authentication failed @SourceStorage.cpp:102' --crc 0x2960355a
  w75: --msg 'NATIVE_UFS smmu: conflicting UFS stream mapping slot=2 smr=80000060 s2cr=2 @NativeUfs.cpp:402' --crc 0xa8b5d477
  w76: --msg '"AMFI: No PMGR?\\n" @ConfigurationSettings.cpp:392' --crc 0xf063fb5b

For non-wall messages use --msg with the fully expanded string.

Photo transcription loses leading 'f's (every round since wall 36). With
--autofix the tool re-inserts dropped f's one at a time on the address and
x0/x1 until the CRC hits; zero corrections = transcription was exact.

usage:
  python3 verify-panic-crc.py --from 0xfffffff0084ca524 --x0 0x1 --x1 0x10001 \
      --hit 1 --crc 0x50d36e66 [--autofix]
  python3 verify-panic-crc.py --msg 'expanded message' --crc 0x2960355a
"""
import argparse
import zlib

FMT = ("fileset: original component called an unmapped kernel function "
       "from %s (x0 %s x1 %s) hit #%u")


def fmt_p(a):
    """kernel %p renders 0x%016lx (zero-padded to 16 hex digits)."""
    a = a.lower().removeprefix('0x')
    return f"0x{a:0>16}"


def fmt_llx(a):
    """kernel %llx renders unpadded lowercase hex."""
    a = a.lower().removeprefix('0x').lstrip('0') or '0'
    return '0x' + a


def crc_for(froma, x0, x1, hit):
    msg = FMT % (fmt_p(froma), fmt_llx(x0), fmt_llx(x1), hit)
    return zlib.crc32(msg.encode()), len(msg.encode())


def variants(a):
    yield a.lower()
    stripped = a.lower().removeprefix('0x')
    for k in range(1, 4):
        yield '0x' + 'f' * k + stripped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--from', dest='froma')
    ap.add_argument('--x0')
    ap.add_argument('--x1')
    ap.add_argument('--hit', type=int, default=1)
    ap.add_argument('--msg', help='fully expanded message bytes (walls 74/75/76 style)')
    ap.add_argument('--crc', required=True)
    ap.add_argument('--autofix', action='store_true')
    args = ap.parse_args()
    want = int(args.crc, 16)

    if args.msg:
        got = zlib.crc32(args.msg.encode())
        print(f'HIT crc={got:08x} len={len(args.msg.encode())}B (zero corrections)'
              if got == want else
              f'MISS: crc={got:08x} (want {want:08x}) for {args.msg!r}')
        return

    if not args.froma or not args.x0 or not args.x1:
        ap.error('--from/--x0/--x1 required without --msg')

    cands = [(args.froma, args.x0, args.x1)]
    if args.autofix:
        for f in variants(args.froma):
            for a0 in variants(args.x0):
                for a1 in variants(args.x1):
                    cands.append((f, a0, a1))
    for f, a0, a1 in cands:
        got, ln = crc_for(f, a0, a1, args.hit)
        if got == want:
            fixed = (f, a0, a1) != (args.froma.lower(), args.x0.lower(), args.x1.lower())
            print(f'HIT crc={got:08x} len={ln}B  '
                  f'from={fmt_p(f)} x0={fmt_llx(a0)} x1={fmt_llx(a1)}'
                  + ('  (autofix applied)' if fixed else '  (zero corrections)'))
            return
    got, ln = crc_for(args.froma, args.x0, args.x1, args.hit)
    print(f'MISS: transcription crc={got:08x} (want {want:08x}), len={ln}B — '
          'photo transcription diverges beyond f-correction; re-read the screen')


if __name__ == '__main__':
    main()
