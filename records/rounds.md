# Round index (r51-r56, workspace commits carry the full detail)

Round naming: rNN = one payload image + one device verdict. Images land
at `out/m2381/payload-rNN-<sha8>.img` (flat path mandatory, r49).

| round | payload sha8 | verdict |
|---|---|---|
| r51 | 22f8f0bd | Upstream sync + research closure; =y display lane built (kernel 3ab2ace4) |
| r52 | 22f8f0bd | =y first stage all-green on device (PE handoff, real display config, swap, screen self-stable); SB crash loop pinned to BannerKit |
| r53 | 04f4d803 | fixup 11 effective (applied 5->6); SB advanced to BLSHBacklightHost brk wall |
| r54 | 1ef5eb63 | fixup 12 (BLSHBacklightHost entry ret-nil); judgment deferred by reader debugging |
| r55a-c | fb2c5dd1 -> 69538b41 | Reader triple failure: LFN destroyed by short-name toml overwrite -> entry missing dtb instant exit -> ENABLE_SECUREBOOT=1 signature rejection (boot_b swapped to 289614ba) |
| r55d | 087f9ca3 | Survival cmdline verdict: kernel always starts (penguin, full UFS enumeration); death = hand-written 12-field newc cpio (13-field contract) -> damaged header -> root panic -> no USB, one root cause |
| r55e | b060b512 | Reader channel live (1d6b:0104, magic=SHLOG001); in-shell flash readback closed; first full iOS judgment: applied=7, real swaps W1-W3, wall = displayIdentity assert |
| r56 | db3a7392 | fixup 9 (SBSystemGestureManager _initWithDisplayIdentity: entry ret); fetchchunk promoted; flashed 2026-10-27 |

Current resident set: boot_b 289614ba + recovery_a = latest round
payload + userdata fd43e70 (CI iOS root). Rollback images live only in
the nura repository (workspace red line 6).

ABL facts (r55d/r55e): same-slot consecutive boot failures exhaust the
retry budget and drop to fastboot; recovery = `fastboot --set-active=b`
(stays on b, resets budget). `rebootbl` inside the reader reboots but
does not land in ABL fastboot on this chain.
