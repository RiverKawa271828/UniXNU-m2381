# UniXNU SM8550 support

> **Local copy of UniXNU-sm8550-common@`23b2049fcd9e30356161def84231334fb55ecca9`**
> (its `main` tip as of 2026-10-29), resolved by `local = "soc/sm8550"` in
> this repository's `feeds.toml`. Carried because the feed's
> `native-smp-secondary.patch` no longer applies on the xnu-12377 arch
> series: its hunk 1 (`board_config.h` MAX_CPUS 4→8) was written against the
> xnu-10063-era arch layer, and the xnu-12377
> `bcm2837-machine-config.patch` already creates the BCM2837 block with
> `MAX_CPUS 8` / `MAX_CPU_CLUSTERS 2` — that hunk is dropped here. Hunk 2
> (`start.s` MPIDR Affinity1 core numbering) is still required because the
> new `pexpert/arm64/BCM2837.h` does not define `HAS_CLUSTER` and SM8550
> numbers cores in Affinity1; it is carried unchanged. **Revert to the
> upstream pin** (delete `local` from `feeds.toml`, delete this directory)
> as soon as upstream updates UniXNU-sm8550-common for the xnu-12377 series.

Shared Qualcomm SM8550 support for UniXNU: CPU topology, GICv3, UFS and
Adreno 740 resources, GMU operations, GPU SMMU integration, and XNU patches.

`soc.toml` selects `Adreno740` and `AdrenoMetal`. Device repositories supply
memory layout, peripherals, firmware, power policy, and packaging.
`kits/Sm8550Platform` preserves its `ShengGmu*` and `ShengGpuSmmu*` source
filenames and exported symbols. Generated headers supply the selected
device's firmware and power inputs.

Hardware descriptions use the SM8550 DTS at revision
`42f3b40c702abbc37c3a04c95af008cd283aeaf3` of
[sm8550-mainline](https://github.com/ianchb/sm8550-mainline).

Build through the [UniXNU CLI](https://unixnu.com/building).
Read the [device repository specification](https://unixnu.com/porting/device-repository),
[device-tree specification](https://unixnu.com/porting/device-tree),
and [component catalog](https://unixnu.com/reference/components).

## Contents

| Path | Contents |
| --- | --- |
| `soc.toml` | SoC profile and component selection |
| `configs/` | Kernel configuration fragments |
| `dts/sm8550.dtsi` | Shared hardware resources |
| `patches/xnu/series` | Ordered SoC patches |
| `kits/Sm8550Platform/` | GMU, command database, GPU SMMU operations |

Build verification and hardware observations are recorded separately.
sheng is the initial device integration.
