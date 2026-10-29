# 读者专用最小内核需求（转告 nura 用，2026-10-30）

> 交付通道：**用户口头转告**（2026-10-30 拍板：nura 仓零接触，不发工单文档）。
> 本文件 = 需求在我方的留档与验收依据；nura 出件后把 kernel PE 摆进
> `.cache/forensic/`（同现役三件的位），board.toml `forensic` 翻回 `true`。

## 背景

UniXNU payload ESP（recovery_a，**100 MiB 分区**）原本携带 SHLOG 读者三件
（forensic-kernel.efi + forensic-initrd.img + forensic.dtb）。现役读者内核 =
nura ESP v71 整机内核直接复用（13,885,952 B PE32+ AArch64，全量驱动）。
26.5.2 fileset 车道 payload 内核 Mach-O 涨到 85.2 MiB，三件放不下，首轮
payload 已摘读者。nura 之前出过 nura-min 整套，这次只需要一个精简内核。

## 需求

1. **源码**：pmos_linux 现役主线树即可；出**专用 config**。预算：**PE ≤ 4 MiB**。
2. **必保**（读者初始化与读回全链）：
   - EFI stub（PE32+ AArch64 应用；initramfs 走 LoadFile2 **外部投递**，
     不打进内核——契约 = 本仓 `forensic/build-forensic-reader.py`）；
   - UART console（reader shell 输出）；
   - USB：dwc3 + NCM/gadget + configfs（reader shell 的 USB 网络通道，
     同 nura-min 读回形态）；
   - UFS（dd 直读 userdata 尾窗 SHLOG 与分区对拍）；
   - devtmpfs/cpio initramfs 解包（现役 busybox init 直接跑）。
3. **必删**：DRM/GPU 全家（msm_drm/Adreno/panel/backlight）、ALSA、
   Wi-Fi/BT（ath11k/wcn）、modem/qrtr 全家、多余 cpufreq governor、ftrace/kprobe
   可选删、不用的文件系统。
4. **交付**：kernel PE 一个文件 + `.config` 一份（nura 仓留档）；busybox 与
   initramfs 沿用现役（`forensic/init`、1,914,704 B busybox 不动）。

## 验收（我方执行）

1. `file` = PE32+ executable (EFI application) Aarch64，≤ 4 MiB。
2. 拼回 payload stage（85.2 MiB 内核 + 本件 + initrd + dtb + scratch-data +
   trustcache）后 unixnu payload 步零告警、卷余量 ≥ 2 MiB。
3. 实机从 payload 菜单进 reader 项：UART 出 shell、UFS 块设备可见、NCM 起来
   后宿主 reader shell dd recovery_a 前 96 MiB 对拍（= nura-min 现行验收同款）。

## 已知事实

- initramfs 解包 = 13 hex 字段 110 字节头（cpio）；现役内核已证可解，换
  config 后必须复测 "Initramfs unpacking" 不回归。
- 读回红线：只读不写；recovery_a 前 96 MiB sha 对拍（主树 FLASHING.md §2）。
- 现役件参考：`.cache/forensic/forensic-kernel.efi`（13.9 MiB）= 功能基线。
