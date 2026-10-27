# r55e forensic window judgment (2026-10-27)

First full iOS boot judged through the SHLOG forensic reader channel.
Device: Meizu 20 Classic (m2381), recovery_a = payload-r55e-b060b512
(fixups 1-15 of the OS profile), userdata = CI iOS root fd43e70 build,
boot_b = 289614ba (no-SecureBoot UEFI).

## Window

- 32 MiB SHLOG tail window of userdata, pulled over the ACM reader:
  header `rounds=314 slots_written=314/509 uptime=628s write_errors=0`
  (xnu ran ~10.5 min before the operator hard-powered-off; no wraparound,
  earliest evidence intact).

## Judged milestones

1. `applied=7` in the last slots (`[text fixup] parsed=15 applied=7`):
   the display-family and backlight-family text fixups (5, 6, 7, 8a, 8b,
   11, 12) all fired; the lazy-application oracle holds.
2. Real display swaps: `[swap timeline] W1 t=243.275s done=1410ms / W2
   t=244.712s done=188ms / W3 t=245.286s done=207ms`; GOP mapping
   `physical=b8000000 bytes=10368000` (1080x2400 ARGB8888). On-panel
   observation matches: boot diagnostics page, then a steady Apple logo.
3. Full userland ecology: 173 processes resident, 881 spawns total
   (configd, sleepd, mDNSResponder, akd, analyticsd, ...); launchd pid 1
   on the native UFS root; cryptex OS stage=5 status=0.
4. New wall: SpringBoard SIGABRT crash loop from t=68s (p27 -> p195 ->
   ... -> p254 relaunch chain), 552 crashes with byte-identical
   PC/LR/backtrace (slide +a57c000). REASON x276: `*** Terminating app
   due to uncaught exception 'NSInternalInconsistencyException', reason:
   'Invalid parameter not satisfying: displayIdentity'`.

## Crash chain (symbolicated against the 21H461 local symbol table,
bl-verified at every frame)

```
-[UIApplication _handleDelegateCallbacksWithOptions:isSuspended:restoreState:] +0x198
-[SpringBoard applicationDidFinishLaunching:] +0x888
+[SBProximityBacklightPolicyFactory createNewProximityBacklightPolicyWithBacklightController:sensorModeController:] +0x8c
+[SBMainDisplaySystemGestureManager sharedInstance]  (dispatch_once block)
-[SBMainDisplaySystemGestureManager _init]
  -> objc_msgSendSuper2 -[SBSystemGestureManager _initWithDisplayIdentity:]
     identity = +[FBDisplayManager mainIdentity] == nil
     (mainIdentity = sharedInstance ivar@8; nothing registers it on a
      displayless lane)
  -> NSParameterAssert fires (SBSystemGestureManager.m:119)
```

RE notes:
- `-[SBMainDisplaySystemGestureManager _initWithDisplayIdentity:]`
  (0x1cfe90ac0) is a trap ("unallowed initializer", same file :53) that
  always raises; sharedInstance deliberately goes through `super` to skip
  it. Patch the base class, never the trap.
- `+[FBDisplayManager mainIdentity]` = `[sharedInstance mainIdentity]` =
  returns ivar@8 with a retain.

## Resulting fixup 9 (r56)

`dyld_shared_cache_arm64.25,1e64f10,ff8301d1f85f02a9,c0035fd6f85f02a9`
= `-[SBSystemGestureManager _initWithDisplayIdentity:]` entry `ret`
(returns self; same shape as fixup 8b). Verified present verbatim in the
ADT of payload-r56-db3a7392.

Parser output for this round: workspace
`temp/r55e-parse.txt` (83k lines, full 314-slot dump); raw window
`out/m2381/reader-r55e-log.bin` sha256
3c29c83f0b0fc62aa9ad0899ecc109bef176e67ffd0a107b0f6bc6ea8c69a942.
