# Round index (r51-r62, workspace commits carry the full detail)

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
| r59 | a9144765 | UIScreen SIGSEGV wall SEALED (applied=13, sig11 = 0); new wall = traitCollection-nil assert x573 (__UIGetCurrentFallbackTraitCollection line 117; REASON string -> CFString slot -> sole xref pinned the raiser; SBCoverSheetPresentationManager/SBWallpaperController chain bl-target verified); in-reader flash readback == image sha | flashed + judged 2026-10-27 |
| r60 | edabbafd | traitCollection-nil wall BROKEN (applied=14, 'returned nil' zero occurrences); new wall = same getter's second raise block (+0x124): "unspecified values" x758 — fixup 14's _backgroundThreadFallbackTraitCollection is deliberately all-unspecified (scale 0.0); in-reader flash readback == image sha | flashed + judged 2026-10-27 |
| r61 | 169f160c | fixup 15a/15b effective (applied=70, 'unspecified' assert zero occurrences, all scale raise blocks dead); SB advanced deep into wallpaper UI construction; new wall = SIGSEGV garbage-pointer family x684 (retain fast-path FAR=0xf1 inside bgTC, same disease as r58's 0xf00 — UIKit cached-singleton globals go garbage in displayless env); **USER VERDICT: stop per-site fixups, switch to the systematic route — next session researches upstream (sheng/fuxi fixup lists) and other forks first** | flashed + judged 2026-10-27 |
| r62 | 0854ea5e | **Research verdict + systematic round built (NOT yet flashed)**: upstream device catalog surveyed (f85b5a6->0fc0fc1); wall-crossing boards carry NO display-family fixups (sheng 4 baseline entries, fuxi 0). The template: (a) AppleKeyStore stand-in — asteroids T20-T29: SpringBoard never finishes booting without it (component AppleKeyStoreState / legacy name NativeKeyStoreEvents); (b) sheng-vsync (144/120/60 on sheng/asteroids/oneplus13t); (c) offline-mobile-graphics-client off (asteroids =0; the r52 "mfb C0 sel6" suspect was this kernel probe client, NOT backboardd). oneplus13t reached the LOCK SCREEN GPU-less on the CPU framebuffer. Gaps closed: KeyStoreProbe.cpp (sheng verbatim) + AppleKeyStoreState compiled into the display archive (b6daee99, seven members; probe call restored in native_legacy_display_late_probe; gates offline-key-events=1 + sheng-aks=1 + persistent Data pre-existing), sheng-vsync=120 (publishes IOMFBDisplayRefresh above 60), client 1->0; all 23 fixups kept as safety net + laziness oracle (applied expected to drop below 14 if the environment heals). kernel 542300ca / probe-patched 158adedb / trust 7416ca4f / seed d04a0153; ADT b5b4a172 (same 23 fixups; sha moved = per-build random-seed, byte-diff verified against the r58 image); ESP four-item check passed | built 2026-10-28, awaiting flash |
| r62 flash | 0854ea5e | **Flashed 2026-10-28** (fastboot log: getvar current-slot=b OK, set_active b OKAY, sha256 gate 0854ea5e...db1a matched, Sending/Writing recovery_a 98304KB OKAY, reboot); user reports the device did NOT come up ("还是起不来", details pending window); readback verify and window judgment deferred to the next session — reader first act: dd recovery_a sha == 0854ea5e, then fetchchunk, then the six-item judgment (AKS row / vsync / C0 probe gone / applied < 14? / revived walls / SEGV family); check header rounds first (run duration unrecorded, wrap possible) | flashed 2026-10-28, judgment pending |

Current resident set: boot_b 289614ba + recovery_a = **r62 0854ea5e**
(flashed 2026-10-28, readback verify pending) + userdata fd43e70 (CI iOS
root); next session = reader (dd verify == 0854ea5e → fetchchunk →
six-item judgment). Rollback images live only in
the nura repository (workspace red line 6).

ABL facts (r55d/r55e): same-slot consecutive boot failures exhaust the
retry budget and drop to fastboot; recovery = `fastboot --set-active=b`
(stays on b, resets budget). `rebootbl` inside the reader reboots but
does not land in ABL fastboot on this chain.
