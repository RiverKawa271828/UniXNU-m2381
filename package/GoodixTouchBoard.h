// SPDX-License-Identifier: BSD-2-Clause-Patent
// m2381 (SM8550) Goodix GT9916 ("Berlin-D") board facts and the pure helpers around them. Every constant states its
// source; nothing here touches hardware. Host-tested by tests/GoodixTouchBoardTests.c.
//
// Sources (all of them agree on the bus, the pins and the geometry):
//   * stock dtbo entry 9 (ro.boot.dtbo_idx=9, the overlay this board boots): fragment@19/@87/@88 put a
//     goodix-berlin@5d on target <&qupv3_se4_i2c>, reset-gpio = <&tlmm 0x18> (24), irq-gpio = <&tlmm 0x19> (25,
//     IRQ_TYPE_EDGE_FALLING), panel-max-x 0x438 (1080), panel-max-y 0x960 (2400), firmware-name
//     goodix_firmware_i2c.bin, config-name goodix_cfg_group_i2c.bin, avdd/iovdd from the LDO rails (two hardware
//     variants exist in the overlay: avdd = L14B in fragment@19, L9B in fragment@87; both name L12B for iovdd).
//     Decompiled copies: meizu20-m1/dts/factory-first/corpus/dtbo_b.entry9.dts:2586-2620.
//   * mainline sm8550.dtsi: i2c4 = i2c@a90000 (GENI SE4, gcc_qupv3_wrap1_s4_clk, GIC SPI 357) with
//     pinctrl qup_i2c4_data_clk = gpio44 (SDA) / gpio45 (SCL), function qup1_se4, drive-strength 2, 2200 pull-up.
//   * docs/hardware/sm8550-meizu-20.dts (this repository's mainline port, working on the device): the same node with
//     touchscreen-size 1080x2400, avdd vreg_l14b_3p2, vddio vreg_l12b_1p8.
//   * nura's reader kernel (goodix_berlin_core.c/goodix_berlin_i2c.c + this node) is the protocol reference;
//     24A446 iPadOS is the OS side.
#ifndef M2381_GOODIX_TOUCH_BOARD_H
#define M2381_GOODIX_TOUCH_BOARD_H
#include <stdint.h>

// GENI SE4 (the i2c4 engine). The wrapper is the same qup1 wrapper sheng's SPI4 lives in: QUPV3 HW version register
// at wrapper + 0x4, apps-SMMU stream 0xa3 (sm8550.dtsi geniqup@ac0000 iommus; sheng's TouchBoard.h used the same pair
// for the SPI SE4 on the same wrapper).
#define GX_SE_BASE 0x00a90000ULL
#define GX_SE_SIZE 0x4000ULL
#define GX_QUP_WRAPPER_BASE 0x00ac0000ULL
#define GX_QUP_SMMU_SID 0xa3

// I2C target: the Goodix Berlin part answers at 0x5d on SE4.
#define GX_I2C_ADDRESS 0x5d
// The stock node runs this bus at 400 kHz (touchscreen's i2c4 node: clock-frequency 400000).
#define GX_I2C_HZ 400000u

// GCC (clock-controller@100000). The vote/halt registers and the S4 RCG are the SM8550 values sheng's TouchBoard.h
// records for the same SE4 branch; the I2C engine wants a 19.2 MHz serial clock (the counter table's source), which
// is the TCXO source of this RCG.
#define GX_GCC_BASE 0x00100000ULL
#define GX_GCC_VOTE_ENABLE 0x52008       // enable_reg of every QUP branch below (bit set = voted on)
#define GX_GCC_VOTE_CORE_2X (1u << 18)   // gcc_qupv3_wrap1_core_2x_clk, halt 0x23294
#define GX_GCC_VOTE_CORE (1u << 19)      // gcc_qupv3_wrap1_core_clk, halt 0x23284
#define GX_GCC_VOTE_M_AHB (1u << 20)     // gcc_qupv3_wrap_1_m_ahb_clk, halt 0x2327c
#define GX_GCC_VOTE_S_AHB (1u << 21)     // gcc_qupv3_wrap_1_s_ahb_clk, halt 0x23280
#define GX_GCC_VOTE_S4 (1u << 26)        // gcc_qupv3_wrap1_s4_clk, halt 0x184e4
#define GX_GCC_VOTE_ALL (GX_GCC_VOTE_CORE_2X | GX_GCC_VOTE_CORE | GX_GCC_VOTE_M_AHB | GX_GCC_VOTE_S_AHB | GX_GCC_VOTE_S4)
#define GX_HALT_CORE_2X 0x23294
#define GX_HALT_CORE 0x23284
#define GX_HALT_M_AHB 0x2327c
#define GX_HALT_S_AHB 0x23280
#define GX_HALT_S4 0x184e4
#define GX_CBCR_CLK_OFF (1u << 31)
#define GX_S4_RCG 0x184f0                // gcc_qupv3_wrap1_s4_clk_src
#define GX_RCG_CMD 0x0
#define GX_RCG_CFG 0x4
#define GX_RCG_SRC_TCXO 0u               // gcc_parent_map_0: 0 = TCXO, 19.2 MHz (sheng's tb_src_hz)
#define GX_SE_SRC_HZ 19200000u

// I2C timing for 19.2 MHz (mainline i2c-qcom-geni.c geni_i2c_clk_map_19p2mhz, 400 kHz row): clk_div 2, t_high 5,
// t_low 11, t_cycle 22. The fields go to SE_GENI_CLK_CFG (div << 4 | SER_CLK_EN) and SE_I2C_SCL_COUNTERS
// (high << 20 | low << 10 | cycle).
#define GX_I2C_CLK_DIV 2u
#define GX_I2C_T_HIGH 5u
#define GX_I2C_T_LOW 11u
#define GX_I2C_T_CYCLE 22u

// TLMM (pinctrl@f100000, pinctrl-sm8550.c PINGROUP: ctl = 0x1000*id, io = ctl+4, mux bit 2, pull bits 1:0 (3 = up),
// drive at bit 6, output enable at bit 9, output value at io bit 1, input level at io bit 0; pin interrupts:
// intr_cfg bit 0 enable, target bits 7:5 (3 = APSS), polarity bit 1, detection bits 3:2 (2 = falling), raw bit 4).
#define GX_TLMM_BASE 0x0f100000ULL
#define GX_GPIO_STRIDE 0x1000u
#define GX_GPIO_SDA 44                   // qup_i2c4_data_clk: gpio44 SDA, gpio45 SCL (sm8550.dtsi)
#define GX_GPIO_SCL 45
#define GX_GPIO_RESET 24                 // goodix,reset-gpio = <&tlmm 0x18 0>, active low
#define GX_GPIO_IRQ 25                   // goodix,irq-gpio = <&tlmm 0x19 0x2008> (falling)
#define GX_FUNC_GPIO 0u
#define GX_FUNC_QUP1_SE4 1u              // the function index "qup1_se4" in pinctrl-sm8550's PINGROUP lists
#define GX_DRIVE_2MA 0u                  // drive-strength = <2>: (2/2)-1
#define GX_DRIVE_8MA 3u                  // drive-strength = <8> on the reset/irq pins in the stock overlay
#define GX_PULL_UP 3u
#define GX_PULL_NONE 0u

// Panel and panel coordinate space. Goodix Berlin reports 0.1 px units (the reference driver's resolution is 10/ mm
// and ruby's GT9916R reported ABS 10800x24000 for the same 1080x2400 panel), so the raw maxima are 10x the pixels.
#define GX_PANEL_PX_X 1080u
#define GX_PANEL_PX_Y 2400u
#define GX_RAW_X 10800u
#define GX_RAW_Y 24000u

// The HID producer (ShengHidInput's NativeHidInput.cpp) normalises the published finger set against a long axis of
// 30480 and a short axis of 20320 in 0.1 px units -- the sheng panel's maxima. The values are denominators only
// (transformCoordinate maps them to 0..32767), so the board publishes its own fractions against those maxima and the
// HID layer needs no change.
#define GX_HID_LONG 30480u
#define GX_HID_SHORT 20320u

static inline uint32_t gx_tlmm_ctl(unsigned gpio) {return gpio * GX_GPIO_STRIDE;}
static inline uint32_t gx_tlmm_io(unsigned gpio) {return gpio * GX_GPIO_STRIDE + 4u;}
// Function, drive strength, pull and output enable for a pin's CTL register (the stock overlay's reset/irq pins are
// pull-up, drive 8; the I2C pins are drive 2 with the 2200 pull-up, which pinctrl-msm encodes as PULL_UP here).
static inline uint32_t gx_pin_ctl(unsigned func, unsigned drive, unsigned pull, int output) {
    return ((func & 0xfu) << 2) | ((drive & 0x7u) << 6) | ((pull & 0x3u) << 0) | (output ? (1u << 9) : 0u);
}
// A GPIO's output value sits at io bit 1 (pinctrl-sm8550.c out_bit), the level read back at io bit 0 (in_bit): the
// IO register is read-modify-written so the input bit is left alone.
#define GX_IO_OUT_BIT (1u << 1)

// Published coordinate for HID: raw 0.1 px -> 0.1 px of the long/short axis the HID producer assumes. `mirror` counts
// from the far edge (the axis maximum - 1, the same convention sheng's publish() uses for its panel).
static inline int gx_publish_x(int raw, int mirror_x) {
    if (raw < 0) raw = 0;
    if ((unsigned)raw > GX_RAW_X - 1) raw = (int)(GX_RAW_X - 1);
    int value = (int)((uint32_t)raw * GX_HID_LONG / GX_RAW_X);
    if (mirror_x) value = (int)(GX_HID_LONG - 1 - (uint32_t)value);
    return value;
}
static inline int gx_publish_y(int raw, int mirror_y) {
    if (raw < 0) raw = 0;
    if ((unsigned)raw > GX_RAW_Y - 1) raw = (int)(GX_RAW_Y - 1);
    if (mirror_y) raw = (int)(GX_RAW_Y - 1 - (uint32_t)raw);
    return (int)((uint32_t)raw * GX_HID_SHORT / GX_RAW_Y);
}
// Swapped axes (a panel mounted rotated against the UI's orientation) are published by the caller swapping the raw
// values before either helper runs; the raw maxima differ, so the scale is applied after the swap.
static inline int gx_publish_x_from_y(int raw_y, int mirror_x) {
    if (raw_y < 0) raw_y = 0;
    if ((unsigned)raw_y > GX_RAW_Y - 1) raw_y = (int)(GX_RAW_Y - 1);
    int value = (int)((uint32_t)raw_y * GX_HID_LONG / GX_RAW_Y);
    if (mirror_x) value = (int)(GX_HID_LONG - 1 - (uint32_t)value);
    return value;
}
static inline int gx_publish_y_from_x(int raw_x, int mirror_y) {
    if (raw_x < 0) raw_x = 0;
    if ((unsigned)raw_x > GX_RAW_X - 1) raw_x = (int)(GX_RAW_X - 1);
    if (mirror_y) raw_x = (int)(GX_RAW_X - 1 - (uint32_t)raw_x);
    return (int)((uint32_t)raw_x * GX_HID_SHORT / GX_RAW_X);
}
#endif
