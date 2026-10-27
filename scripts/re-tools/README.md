# re-tools — 21H461 dyld shared cache RE kit

Symbolication and crash-chain verification for the SpringBoard fixup
iteration. Everything works against the decoded cache at the workspace
`temp/cache-extract/` (override with `UNIXNU_CACHE_EXTRACT`): the
52-subcache `dyld_shared_cache_arm64` tree plus `dec-symbols` (the
LZBITMAP-decoded local-symbols file, 10.2M nlist entries — decode
method in the workspace memory `dyld-cache-symbolication`).

## The loop (from a SHLOG crash line to a fixup)

1. A CRASH line gives `PC.. LR.. +slide bt ..` — subtract the slide
   from every address (r55e: slide `a57c000`).
2. `symbolicate.py <unslid VAs...>` — first-pass picture.
3. `verifychain.py PC LR BT1 BT2 ...` — the only trustable pass: each
   frame's LR-4 must decode to a `bl` into the next-inner function.
   Stale frames (exception paths through `dispatch_client_callout`
   collapse the block/init frames) get filtered by eye here; the
   verified tail names the true thrower.
4. `disasm.py <label> <va> [n]` — read the throwing function; adrp+add
   string refs and bl targets resolve inline. NSAssertionHandler raise
   blocks carry file/line CFStrings (strip the chained-fixup tag
   `0x40000000000` from stored pointers before resolving).
5. `find-string-xref.py 'conditionText'` — pin assert sites by hunting
   the NSParameterAssert condition string and its code xrefs.

## Text fixups

Crash → base VAs → patch spec
`dyld_shared_cache_arm64.<NN>,<file-offset>,<expected-8-bytes>,<replacement-8-bytes>`
in the OS profile `text_fixups` (workspace
`profiles/os/ipados-17.7.11-21H461/profile.toml`). `cachesym.Cache.
file_offset(va)` gives the file/offset pair; lazy page-in application
makes the `applied` counter an execution oracle.

## Pitfalls (all paid for in r52-r56)

- Nearest-symbol-below hits on sparsely-symbolized regions (SpringBoard
  anonymous stub/helper pools, the high subcache area) are artifacts:
  `dispatch_once` stubs can report as `_resetState.cold.1+0x3218`;
  cross-check with `sym_exact` and by decoding instructions.
- Chained-fixup stored pointers carry the VA tag `0x400_00000000`
  (bit 42) — `Cache.untag` strips it; mis-stripping points you 8 TB
  outside the cache.
- dispatch_once helper indirection: the sharedInstance pattern is
  token at `-1` fast path + block literal; resolve block invokes by
  untagging the block's `invoke` field, not by trusting adjacent
  symbols.
- ObjC classref slots need the real bind resolution or symbol-table
  pairing; `objc_msgSendSuper2` compiles to `stp self,cls,[sp]; mov
  x0,sp` — a super call, not a receiver pair for `alloc`.
- A subclass may define a trap initializer (r55e:
  `SBMainDisplaySystemGestureManager._initWithDisplayIdentity:` always
  raises "unallowed initializer") while the real init lives in the base
  class — symbol name similarity is not call-graph evidence.
