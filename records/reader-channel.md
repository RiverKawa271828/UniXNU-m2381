# Forensic reader channel (r55e/r56, 2026-10-27)

Read-only UFS forensics without adb/nura: the recovery_a payload carries
a `type = "linux"` menu entry ("m2381 forensic log reader") that boots a
pmOS EFI-stub kernel + busybox initrd, dd's the 32 MiB SHLOG tail window
of userdata into RAM and serves a USB CDC ACM shell. The payload's xnu
entry stays the menu default.

## Channel bring-up (r55e, payload b060b512)

- Host: `lsusb` shows `1d6b:0104`; udev rule `99-m2381-reader.rules`
  grants ttyACM0 MODE=0666.
- Probe: `m2381 forensic log reader 7.3.0 / usb: acm on a600000.usb /
  userdata=sda22 sectors=972326040 log=33554432 bytes magic=SHLOG001`
  (nura kernel names partitions sdaNN; the init greps PARTNAME).
- Write-readback closed inside the reader shell (first time without
  adb): `dd if=/dev/sde27 bs=1M count=96 | sha256sum` == the flashed
  payload image sha byte for byte.

## Tool findings (r56 round)

1. `acm-reader.py fetch` line filter used `48 <= c <= 122`, which drops
   every base64 line containing `+` (43) or `/` (47) — the pulled blob
   was silently corrupted. Fixed to `43..122`.
2. The single-shot base64 stream deterministically stalls around 13 MiB
   decoded (two consecutive fetches died the same way; device-side sha
   stayed stable). `fetchchunk` added: 2 MiB chunks, one fresh ACM
   session per chunk, per-chunk retry x3, host-side total sha check.
   Measured 16/16 chunks + SHA MATCH in 31 s.

## iOS boot time standard (BootLog.c mechanism)

BootLog writes one 8 KiB slot every 2 s; slot_count ~= 509, so the
32 MiB window wraps after ~17 minutes and overwrites the earliest
applied/fixup evidence. Standard run: 8-15 min with a stable screen
shape, +2-3 min, then a long-press hard power-off; never exceed ~17 min.

## Round loop

flash recovery_a (only, while the iOS chain is resident) -> boot the
menu default xnu 8-15 min -> hard power-off -> power on and pick the
reader within the 3 s menu timeout -> `acm-reader.py fetchchunk` ->
`read-m2381-ufs-log.py --all`. Tools:
`devices/m2381/unixnu-m2381/scripts/acm-reader.py` (probe/cmd/fetch/
fetchchunk), `read-m2381-ufs-log.py` (header slots_written contract,
wraparound-safe).
