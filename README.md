# UniXNU m2381

Device support for the **Meizu 20 Classic** (`m2381`, Qualcomm SM8550
phone): UniXNU 4K kernel + an OS profile selecting
`ipados-17.7.11-21H461` (iPad7,1 donor — the same donor as sheng) plus a
board profile that drives the unixnu build tree. Developed inside the
[ios-m2381-unixnu](https://github.com/RiverKawa271828/ios-m2381-unixnu)
workspace (branch `m2381`; this directory is mirrored to the orphan
branch `device-m2381` for CI).

**Status (2026-10-27, after round r55e / payload r56 db3a7392):** the
full iOS chain runs on hardware — UEFI → XNU → launchd → a 173-process
userland with real IOMFB swaps on the panel (W1-W3, 1080x2400 @ GOP
0xb8000000) — currently iterating SpringBoard text fixups against a
displayIdentity assertion. Diagnostics run over an in-payload forensic
reader (read-only ACM shell into the userdata tail window), so every
round is judged without adb.

# Structure

| path | contents |
|---|---|
| `porting.toml` | subsystem inputs / findings / evidence — the authoritative porting record |
| `board.toml` | device configuration (schema v2: sm8550 source pin + ipados-17.7.11-21H461 profile) |
| `feeds.toml` | pinned SoC source (UniXNU-sm8550-common) |
| `configs/m2381_defconfig` | kernel defconfig |
| `dts/m2381.dts` | board DTS feeding the ADT generator |
| `patches/xnu/series` | board XNU patch order |
| `package/` | device package (incl. `OriginalLegacyFramebufferABI.h`) |
| `drivers/ShengUfs`, `kits/XnuPrelink`, `kits/VerifiedRoot` | board-owned driver/component forks |
| `forensic/` | forensic log reader builder + artifacts (kernel PE, 13-field newc initrd) |
| `scripts/` | build/forensics tooling (acm-reader, SHLOG parser, ADT/trust builders, ci-owner-policy) |
| `records/` | per-round evidence notes referenced from `porting.toml` |

# Development record

`porting.toml` is updated with every subsystem change and records
hardware findings, evidence and completion criteria; `records/*.md`
carry the per-round detail (round index r51-r56, the r55e forensic
judgment, reader-channel mechanics). The workspace
[docs/STATE.md](https://github.com/RiverKawa271828/ios-m2381-unixnu/blob/m2381/docs/STATE.md)
is the live work order; every round's full verdict also lives in the
workspace commit messages.

# Build

All outputs land under `out/m2381/ipados-17.7.11-21H461/m2381/`.

```bash
./unixnu defconfig
./unixnu fetch
./unixnu status
./unixnu kernel      # Linux lane proven locally; CI uses macos.yml
./unixnu firmware    # m2381Pkg (Mu-Silicium) builds in devices/m2381/uefi
UNIXNU_UNIQUE_CHIP_ID=<seed> ./unixnu payload
./unixnu bootimg
```

Flash policy: only `recovery_a` per round while the iOS chain is
resident (`fastboot --set-active=b` first — resets the ABL retry
budget); three-partition flashes only after nura covers the chain.
Verify every flash by dd-readback inside the forensic reader shell.

# Documentation

- [Device guide](https://unixnu.com/zh/devices) — the org device pages (generated from `porting.toml`)
- [Porting records spec](https://unixnu.com/zh/porting/records) — record format this repo follows
- [Building](https://unixnu.com/zh/porting/building) and [device-repository spec](https://unixnu.com/zh/porting/device-repository)
- Workspace docs: `AGENTS.md`, `docs/STATE.md`, `docs/FLASHING.md` (flashing + reader loop §7), `docs/HARDWARE-m2381.md`
