# Round index (r51-r59, workspace commits carry the full detail)

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
| r56 | db3a7392 | WASTED ROUND: build missing --data-ramdisk/--trust-cache -> ESP without Data seed/initrd line/trustcache -> Data mount ENOENT panic (t=1s), applied=0; recipe red line entered (three flags mandatory, ESP four-item check) |
| r57 | 1e7ea60b | displayIdentity wall BROKEN: applied=8 (fixup 9 executed), real swaps W1-W3 pulled forward to t=85s, 178 procs / 907 spawns, SpringBoard drew the boot-progress flower on the panel; new wall = XBApplicationController.m:120 assert 'invalid mainDisplay configuration' (SIGABRT x560 from t=66s, isMainDisplay==0 -> cbz/cbnz pair into handleFailureInMethod); in-reader flash readback == image sha | flashed + judged 2026-10-27 |
| r58 | d27c4f36 | XB assert wall BROKEN (applied=11, SpringBoard sig6 = 0); SB started loading the application library (SBApplicationController init -> launch-image ingestion); new wall = SIGSEGV x588 at +[UIScreen _mainScreenThreadSafeTraitCollection]+0x2c derefing garbage x19=0xf00 (FAR 0xfe0; 12-frame bl-target-verified chain); in-reader flash readback == image sha | flashed + judged 2026-10-27 |
| r59 | a9144765 | fixup 13a/13b: +[UIScreen mainScreen] entry + _mainScreenThreadSafeTraitCollection entry both mov x0,#0;ret (return nil, r49 getter shape; .03,3255d40/341e6d8; 13a takes over the dormant r46 fixup 7 semantics) -> 20 fixups; full-table validation, ADT f60ecf0c, ESP four-item check all green; NOT YET FLASHED (recovery_a only + set_active b) | built 2026-10-27 |

Current resident set: boot_b 289614ba + recovery_a = r58 d27c4f36
(readback verified) + userdata fd43e70 (CI iOS root); next flash = r59
a9144765 recovery_a only. Rollback images live only in
the nura repository (workspace red line 6).

ABL facts (r55d/r55e): same-slot consecutive boot failures exhaust the
retry budget and drop to fastboot; recovery = `fastboot --set-active=b`
(stays on b, resets budget). `rebootbl` inside the reader reboots but
does not land in ABL fastboot on this chain.
