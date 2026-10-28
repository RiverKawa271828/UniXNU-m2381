# Agent instructions

This repository owns m2381 (Meizu 20 Classic, Qualcomm SM8550) board
configuration, peripherals, firmware selection, partition layout, power
policy, and device-side packaging. Shared SM8550 resources belong to
`UniXNU-sm8550-common`; the build tree, component catalog, and docs site
belong to `UniXNU`. The working narrative, per-round verdicts, and
flashing discipline live in the
[ios-m2381-unixnu workspace](https://github.com/RiverKawa271828/ios-m2381-unixnu)
(`AGENTS.md`, `docs/STATE.md`, `docs/FLASHING.md`) — that workspace
remains the source of truth for process and history; this repository
carries board values and device-side code.

Conventions carried over from the workspace:

- Evidence over assertion: measured values cite their source
  (`porting.toml`, `records/`).
- Nothing Apple-derived enters this repository (no IPSW contents, no
  donor images).
- Signing keys under `keys/` stay local-only (`*.pem` is gitignored).
- Run `python3 scripts/check-m2381.py` before claiming a buildable
  tree; hard failures stop the build by design.
