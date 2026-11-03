#!/usr/bin/env python3
"""Emit static gate for Mac-built kernels (replaces the temp/ w35-gate, lost 2026-11-04).

Two counters over the whole macho (word-aligned, calibrated on archived builds):
- resign fingerprint  : adjacent triple xpaci x17 (0xDAC143F1) + movz x16,#0 (0xD2800010)
                        + pacia1716 (0xD503211F) -> Mac builds must have 0.
                        (The donor-resign patch is compiled out under __apple_build_version__;
                        >0 means the zero-modifier resign loop leaked back in = wall-35 class
                        regression. Fingerprint words extracted from the on-device resign-era
                        kernel 0b607b2a in session 44; old w35-gate read 1 hit there, 0 on
                        every post-fix Mac build.)
- 2abe dispatch pairs : movz x17,#0x2abe (0xD28557D1) immediately followed by blraa x8,x17
                        (0xD73F0911) -> flat count (371 baseline on w37/w39 builds;
                        drift = collateral text mutation).

usage: python3 emit-static-gate.py <kernel.macho> [more.macho ...]
"""
import struct
import sys

FP_XPACI_X17 = 0xDAC143F1
FP_MOVZ_X16_0 = 0xD2800010
FP_PACIA1716 = 0xD503211F
DP_MOVZ_X17_2ABE = 0xD28557D1
DP_BLRAA_X8_X17 = 0xD73F0911


def gate(path):
    data = open(path, 'rb').read()
    n = len(data) // 4
    words = struct.unpack_from(f'<{n}I', data, 0)
    resign = 0
    dispatch = 0
    for i in range(2, n - 1):
        w0, w1, w2 = words[i - 2], words[i - 1], words[i]
        if w0 == FP_XPACI_X17 and w1 == FP_MOVZ_X16_0 and w2 == FP_PACIA1716:
            resign += 1
        if w1 == DP_MOVZ_X17_2ABE and w2 == DP_BLRAA_X8_X17:
            dispatch += 1
    return resign, dispatch


if __name__ == '__main__':
    for p in sys.argv[1:]:
        r, d = gate(p)
        print(f'{p}: resign={r} dispatch={d}')
