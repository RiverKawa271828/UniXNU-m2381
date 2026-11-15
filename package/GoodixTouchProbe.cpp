// SPDX-License-Identifier: BSD-2-Clause-Patent
// m2381 (SM8550) Goodix GT9916 ("Berlin-D") touch bring-up, staged and default-off. `touch=<n>`:
//   1  read-only snapshot: GCC QUP branch/CBCR state, the S4 RCG source select, the GENI engine identity
//      (protocol, clock enable, SCL counters), the TLMM state of SDA/SCL/reset/IRQ and the IRQ pin level
//   2  vote the qupv3_wrap1 branches, program the S4 RCG to TCXO (19.2 MHz) and the I2C counters for 400 kHz,
//      mux gpio44/45 as qup1_se4, and initialise the engine (FIFO mode, packing, interrupts)
//   3  reset the part over gpio24, device-confirm it, read the ROM/patch version and the IC info (identity and
//      the runtime touch-data address)
//   4  start the frame thread: the interrupt pin says when to read, every valid frame is published to the HID
//      sink (ShengHidInput's NativeHidInput when `offline-hid-input=1 touch-hid=1`)
// Every stage reports on the diagnostic page (native_touch_rows) and in BootLog; the first failure stops the
// sequence and records its step. Board constants and their sources: GoodixTouchBoard.h. Protocol: GoodixBerlin.c.
// Coordinates are published in the same 0.1 px convention as sheng's producer (0..30479 along the long axis,
// 0..20319 along the short one, see GoodixTouchBoard.h) because NativeHidInput normalises against those maxima;
// touch-mirror-x / touch-mirror-y flip an axis and touch-swap-xy swaps them, for a panel mounted against the UI.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLocks.h>
#include <pexpert/pexpert.h>
#include <libkern/c++/OSSharedPtr.h>
#include <kern/thread.h>
#include <mach/mach_time.h>
#include <string.h>
extern "C" {
#include "GeniI2c.h"
#include "GoodixBerlin.h"
#include "GoodixTouchBoard.h"
}
extern "C" {
char native_touch_rows[4][120];
volatile uint32_t native_touch_loop_step;
volatile uint32_t native_touch_stage_req, native_touch_stage_done, native_touch_step, native_touch_frames,
    native_touch_valid, native_touch_contacts, native_touch_hid_reports;
volatile int native_touch_error;
volatile int native_touch_last_x = -1, native_touch_last_y = -1;
// The finger set the HID layer consumes: sequence odd while being written (NativeHidInput reads it with a seqlock).
volatile uint32_t native_touch_seq;
volatile uint32_t native_touch_count;
volatile int native_touch_xs[12], native_touch_ys[12], native_touch_ids[12];
// Finished strokes as published: {start ms, duration ms, first x, first y, last x, last y, frames} and the extent
// every published contact reached {min x, max x, min y, max y}. BootLog.c prints both.
volatile int32_t native_touch_strokes[16][7];
volatile uint32_t native_touch_stroke_count;
volatile int32_t native_touch_extent[4] = {0x7fffffff, -1, 0x7fffffff, -1};
// Where the thread's time goes: [0] wakes, [1] pin-polled with no frame, [2] reads, [3] bad headers, [4] points
// published, then microseconds in [5] reads and [6] publishing.
volatile uint32_t native_touch_cost[9];
// Transfer counters: [0] reads, [1] writes, [2] read failures, [3] write failures, [4] the engine's last M_IRQ error
// status, [5] engine timeouts, [6] the GENI status when the last transfer ended.
volatile uint32_t native_touch_bus_stats[8];
int armcpu_spi_attach(uint32_t, bool, void (*)(void *), void *, uint32_t *, uint64_t *) __attribute__((weak_import));
}

namespace {
struct Region {OSSharedPtr<IOMemoryMap> keep; uintptr_t va = 0;};

bool mapRegion(uint64_t phys, uint64_t length, Region &region) {
    IODeviceMemory *memory = IODeviceMemory::withRange(phys, length);
    if (!memory) return false;
    region.keep = OSSharedPtr<IOMemoryMap>(memory->map(kIOMapAnywhere | kIOMapInhibitCache), OSNoRetain);
    memory->release();
    region.va = region.keep ? static_cast<uintptr_t>(region.keep->getVirtualAddress()) : 0;
    return region.va != 0;
}
uint32_t rd32(uintptr_t base, uint32_t reg) {return *reinterpret_cast<volatile uint32_t *>(base + reg);}
void wr32(uintptr_t base, uint32_t reg, uint32_t value) {
    *reinterpret_cast<volatile uint32_t *>(base + reg) = value;
    __asm__ volatile("dsb sy" ::: "memory");
}
void rmwSet(uintptr_t base, uint32_t reg, uint32_t bits) {wr32(base, reg, rd32(base, reg) | bits);}

uint32_t geniIoRead(void *ctx, uint32_t reg) {return rd32(reinterpret_cast<uintptr_t>(ctx), reg);}
void geniIoWrite(void *ctx, uint32_t reg, uint32_t value) {wr32(reinterpret_cast<uintptr_t>(ctx), reg, value);}

struct Session {
    Region gccLow, gccS4, gccHalt, gccVote, tlmmBus, tlmm, wrapper, se;
    GeniI2c engine;
    int lastError;
    uint32_t regs[16];
    uint8_t version[GX_VERSION_LEN];
    uint8_t icInfo[GX_IC_INFO_MAX];
    GxIdentity identity;
    GxVersion parsed;
    unsigned reads, writes;
    // The frame thread's scratch: header + two points + checksum, the continuation, and the assembled point block.
    uint8_t head[GX_FRAME_HEAD_LEN];
    uint8_t tail[(GX_MAX_TOUCH - 2) * GX_POINT_LEN + GX_CHECKSUM_LEN];
    uint8_t points[GX_MAX_TOUCH * GX_POINT_LEN + GX_CHECKSUM_LEN];
    GxContact contacts[GX_MAX_TOUCH];
    int mirrorX, mirrorY, swapXY;
    struct {int id, x0, y0, x1, y1, frames; uint32_t t0;} strokes[12];
    unsigned strokeCount;
};

Session *gSession;

void mark(unsigned step) {native_touch_step = step;}
void fail(unsigned step, int code) {native_touch_loop_step = 0; native_touch_error = code; mark(step);}
uint32_t touchMs() {
    uint32_t frequency = 0;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    return (uint32_t)(mach_absolute_time() / ((frequency ? frequency : 19200000u) / 1000u));
}

// ---- I2C transport (GeniI2c) -------------------------------------------------------------------------------------
// One transfer's deadline: 26 bytes at 400 kHz is ~0.7 ms; a 5 ms budget tells a slow part from a hung engine.
constexpr unsigned kTransferBudgetUs = 5000;

int waitEngine(Session *s) {
    for (unsigned elapsed = 0; elapsed < kTransferBudgetUs; ++elapsed) {
        const int state = geni_i2c_poll(&s->engine);
        if (state == GeniDone) return 0;
        if (state == GeniFailed) {
            native_touch_bus_stats[4] = s->engine.error_status;
            return -1;
        }
        IODelay(1);
    }
    const int state = geni_i2c_timeout(&s->engine);
    for (unsigned spin = 0; spin < 200 && state == GeniPending; ++spin) {
        if (geni_i2c_poll(&s->engine) != GeniPending) break;
        IODelay(1);
    }
    native_touch_bus_stats[4] = s->engine.error_status;
    return -2;
}

int busRead(void *ctx, uint32_t addr, uint8_t *data, uint32_t len) {
    Session *s = static_cast<Session *>(ctx);
    const uint8_t command[4] = {(uint8_t)(addr >> 24), (uint8_t)(addr >> 16), (uint8_t)(addr >> 8), (uint8_t)addr};
    ++s->reads;
    native_touch_bus_stats[0] = s->reads;
    if (geni_i2c_start_read_buffer(&s->engine, command, sizeof command, data, len)) {
        ++s->lastError;
        native_touch_bus_stats[2] = native_touch_bus_stats[2] + 1;
        return -1;
    }
    const int result = waitEngine(s);
    if (result) native_touch_bus_stats[2] = native_touch_bus_stats[2] + 1;
    return result;
}

int busWrite(void *ctx, uint32_t addr, const uint8_t *data, uint32_t len) {
    Session *s = static_cast<Session *>(ctx);
    uint8_t buffer[4 + 8];
    if (len > sizeof buffer - 4) return -1;
    buffer[0] = (uint8_t)(addr >> 24); buffer[1] = (uint8_t)(addr >> 16);
    buffer[2] = (uint8_t)(addr >> 8); buffer[3] = (uint8_t)addr;
    memcpy(buffer + 4, data, len);
    ++s->writes;
    native_touch_bus_stats[1] = s->writes;
    if (geni_i2c_start_write_buffer(&s->engine, buffer, 4 + len)) {
        native_touch_bus_stats[3] = native_touch_bus_stats[3] + 1;
        return -1;
    }
    const int result = waitEngine(s);
    if (result) native_touch_bus_stats[3] = native_touch_bus_stats[3] + 1;
    return result;
}

void gxDelay(void *, unsigned microseconds) {IODelay(microseconds);}

// ---- Stage 1: read-only snapshot ----------------------------------------------------------------------------------
bool snapshot(Session &s) {
    mark(1);
    if (!mapRegion(GX_GCC_BASE + 0x0000, 0x1000, s.gccLow) || !mapRegion(GX_GCC_BASE + 0x18000, 0x1000, s.gccS4) ||
        !mapRegion(GX_GCC_BASE + 0x23000, 0x1000, s.gccHalt) || !mapRegion(GX_GCC_BASE + 0x52000, 0x1000, s.gccVote) ||
        !mapRegion(GX_TLMM_BASE + gx_tlmm_ctl(GX_GPIO_SDA), 4 * GX_GPIO_STRIDE, s.tlmmBus) ||
        !mapRegion(GX_QUP_WRAPPER_BASE, 0x2000, s.wrapper) || !mapRegion(GX_SE_BASE, GX_SE_SIZE, s.se)) {
        fail(1, -12);
        return false;
    }
    uint32_t *v = s.regs;
    v[0] = rd32(s.gccVote.va, GX_GCC_VOTE_ENABLE & 0xfff);
    v[1] = rd32(s.gccHalt.va, GX_HALT_CORE_2X & 0xfff);
    v[2] = rd32(s.gccHalt.va, GX_HALT_CORE & 0xfff);
    v[3] = rd32(s.gccHalt.va, GX_HALT_M_AHB & 0xfff);
    v[4] = rd32(s.gccHalt.va, GX_HALT_S_AHB & 0xfff);
    v[5] = rd32(s.gccS4.va, GX_HALT_S4 & 0xfff);
    v[6] = rd32(s.gccS4.va, (GX_S4_RCG + GX_RCG_CFG) & 0xfff);
    v[7] = rd32(s.tlmmBus.va, gx_tlmm_ctl(GX_GPIO_SDA));
    v[8] = rd32(s.tlmmBus.va, gx_tlmm_ctl(GX_GPIO_SCL));
    mark(2);
    return true;
}

// ---- Stage 2: clocks, pins, engine ---------------------------------------------------------------------------------
bool enable(Session &s) {
    mark(2);
    wr32(s.gccVote.va, GX_GCC_VOTE_ENABLE & 0xfff, rd32(s.gccVote.va, GX_GCC_VOTE_ENABLE & 0xfff) | GX_GCC_VOTE_ALL);
    // The S4 RCG: TCXO (19.2 MHz) with no divider, as the I2C counter table assumes. CFG's source select is bits 10:8,
    // mode bits 13:12; mode 0 is bypass, so the output is the selected source.
    wr32(s.gccS4.va, (GX_S4_RCG + GX_RCG_CFG) & 0xfff, (GX_RCG_SRC_TCXO & 7u) << 8);
    wr32(s.gccS4.va, (GX_S4_RCG + GX_RCG_CMD) & 0xfff, rd32(s.gccS4.va, (GX_S4_RCG + GX_RCG_CMD) & 0xfff) | 1u);
    // A branch with hardware clock gating (bit 1) reads CLK_OFF while idle and wakes on access; only a branch without
    // that bit must have CLK_OFF clear.
    auto running = [](uint32_t cbcr) {return !(cbcr & GX_CBCR_CLK_OFF) || (cbcr & 2u);};
    bool ok = false;
    for (unsigned i = 0; i < 2000 && !ok; ++i) {
        ok = running(rd32(s.gccHalt.va, GX_HALT_M_AHB & 0xfff)) && running(rd32(s.gccHalt.va, GX_HALT_S_AHB & 0xfff)) &&
             !(rd32(s.gccHalt.va, GX_HALT_CORE & 0xfff) & GX_CBCR_CLK_OFF) &&
             !(rd32(s.gccHalt.va, GX_HALT_CORE_2X & 0xfff) & GX_CBCR_CLK_OFF) &&
             !(rd32(s.gccS4.va, GX_HALT_S4 & 0xfff) & GX_CBCR_CLK_OFF);
        if (!ok) IODelay(10);
    }
    s.regs[10] = rd32(s.gccVote.va, GX_GCC_VOTE_ENABLE & 0xfff);
    s.regs[11] = rd32(s.gccHalt.va, GX_HALT_CORE & 0xfff);
    s.regs[12] = rd32(s.gccS4.va, GX_HALT_S4 & 0xfff);
    if (!ok) {fail(2, -110); return false;}      // never touch the engine without running clocks
    // gpio44 SDA / gpio45 SCL as qup1_se4, drive 2, pull-up (the stock overlay's 2200 ohm pull); no output enable.
    const uint32_t i2cPin = gx_pin_ctl(GX_FUNC_QUP1_SE4, GX_DRIVE_2MA, GX_PULL_UP, 0);
    wr32(s.tlmmBus.va, gx_tlmm_ctl(GX_GPIO_SDA), i2cPin);
    wr32(s.tlmmBus.va, gx_tlmm_ctl(GX_GPIO_SCL), i2cPin);
    s.regs[7] = rd32(s.tlmmBus.va, gx_tlmm_ctl(GX_GPIO_SDA));
    s.regs[8] = rd32(s.tlmmBus.va, gx_tlmm_ctl(GX_GPIO_SCL));
    mark(3);
    return true;
}

// geni_se_init equivalent for I2C: the sequence spi-geni-qcom/i2c-qcom-geni run before the first command. The engine's
// protocol is a bootloader/platform configuration (qcom-geni-se.c), so it is read, not written; a wrong protocol ends
// the stage with that state reported on the diagnostic page.
bool engineInit(Session &s) {
    mark(4);
    uintptr_t se = s.se.va;
    const uint32_t fw = rd32(se, GENI_FW_REVISION);
    s.regs[13] = fw;
    s.regs[14] = rd32(se, GENI_IF_DISABLE);
    s.regs[15] = s.wrapper.va ? rd32(s.wrapper.va, 0x4) : 0;
    if (((fw >> 8) & 0xffu) != GENI_PROTO_I2C) {fail(4, -(int)(0x100 | ((fw >> 8) & 0xffu))); return false;}
    wr32(se, GENI_M_IRQ_CLEAR, 0xffffffffu);
    wr32(se, 0x648, 0xffffffffu);      // SE_GENI_S_IRQ_CLEAR
    wr32(se, 0xc44, 0xffffffffu);      // SE_DMA_TX_IRQ_CLR
    wr32(se, 0xd44, 0xffffffffu);      // SE_DMA_RX_IRQ_CLR
    wr32(se, 0xe1c, 0);                // SE_IRQ_EN off while the engine is set up
    rmwSet(se, 0x28, 0x7fu);           // SE_GENI_CGC_CTRL
    rmwSet(se, 0xe30, 0x0fu);          // SE_DMA_GENERAL_CFG: all four AHB/DMA gate enables
    wr32(se, 0x24, 0x7fu);             // GENI_OUTPUT_CTRL
    wr32(se, 0x20, 1u);                // GENI_FORCE_DEFAULT
    wr32(se, 0xe18, 0);                // SE_GSI_EVENT_EN
    wr32(se, GENI_DMA_MODE, rd32(se, GENI_DMA_MODE) & ~1u);   // FIFO (PIO) mode
    // I2C serial clock: source select 0 (19.2 MHz), divider and the 400 kHz counters.
    wr32(se, 0x7c, 0);                                               // SE_GENI_CLK_SEL
    wr32(se, GENI_CLK_CFG, ((GX_I2C_CLK_DIV & 0xfffu) << 4) | 1u);   // GENI_SER_M_CLK_CFG / SER_CLK_EN
    wr32(se, GENI_SCL_COUNTERS, (GX_I2C_T_HIGH << 20) | (GX_I2C_T_LOW << 10) | GX_I2C_T_CYCLE);
    wr32(se, 0xe1c, GENI_SE_M_IRQ_EN);   // SE_IRQ_EN: the M (master) interrupt line
    const struct GeniIo io = {geniIoRead, geniIoWrite, reinterpret_cast<void *>(se)};
    uint32_t config = 0;
    if (geni_i2c_prepare(&s.engine, &io, GX_I2C_ADDRESS, &config)) {fail(5, -1); return false;}
    s.regs[9] = config;
    mark(6);
    return true;
}

// ---- Stage 3: reset, confirm, identity ------------------------------------------------------------------------------
bool identify(Session &s) {
    mark(7);
    // Two pages cover reset (24) and IRQ (25): pins are 0x1000 apart, gpio25's registers sit one page above gpio24's.
    if (!mapRegion(GX_TLMM_BASE + gx_tlmm_ctl(GX_GPIO_RESET), 2 * GX_GPIO_STRIDE, s.tlmm)) {fail(7, -12); return false;}
    Region &tlmm = s.tlmm;
    // reset gpio24: function gpio (0), drive 8, pull-up, output enable. Physical low asserts the part's reset (the node's
    // GPIO_ACTIVE_LOW), physical high releases it; the pin is read back after every write.
    const uint32_t resetCtl = gx_pin_ctl(GX_FUNC_GPIO, GX_DRIVE_8MA, GX_PULL_UP, 1);
    wr32(tlmm.va, gx_tlmm_ctl(GX_GPIO_RESET), resetCtl);
    uint32_t io = rd32(tlmm.va, gx_tlmm_io(GX_GPIO_RESET));
    wr32(tlmm.va, gx_tlmm_io(GX_GPIO_RESET), (io & ~GX_IO_OUT_BIT));          // low = asserted
    IODelay(10000);
    io = rd32(tlmm.va, gx_tlmm_io(GX_GPIO_RESET));
    wr32(tlmm.va, gx_tlmm_io(GX_GPIO_RESET), io | GX_IO_OUT_BIT);             // high = released
    IODelay(100000);
    // irq gpio25: function gpio, pull-up, input; the level (io bit 0) is polled by the frame thread, no pin interrupt.
    wr32(tlmm.va, gx_tlmm_ctl(GX_GPIO_IRQ), gx_pin_ctl(GX_FUNC_GPIO, GX_DRIVE_8MA, GX_PULL_UP, 0));
    s.regs[2] = rd32(tlmm.va, gx_tlmm_ctl(GX_GPIO_RESET));
    s.regs[3] = rd32(tlmm.va, gx_tlmm_io(GX_GPIO_RESET));
    s.regs[4] = rd32(tlmm.va, gx_tlmm_ctl(GX_GPIO_IRQ));
    s.regs[5] = rd32(tlmm.va, gx_tlmm_io(GX_GPIO_IRQ));
    GxTransport transport = {busRead, busWrite, &s};
    mark(8);
    const int confirm = gx_dev_confirm(&transport, GX_DEV_CONFIRM_TRIES, 5000, gxDelay, nullptr);
    if (confirm) {fail(8, -200 + confirm); return false;}
    mark(9);
    const int version = gx_read_version(&transport, &s.parsed);
    memcpy(s.version, &s.parsed, sizeof s.parsed);
    if (version) {fail(9, -210 + version); return false;}
    mark(10);
    const int identity = gx_read_identity(&transport, GX_IC_INFO_ADDR, &s.identity);
    if (identity) {fail(10, -220 + identity); return false;}
    mark(11);
    return true;
}

// ---- Stage 4: frames -----------------------------------------------------------------------------------------------
// The HID consumer registers here (NativeHidInput's start, touch-hid=1); it is called after a frame is published.
void (*gTouchSink)(void *);
void *gTouchSinkContext;

void publish(Session *s, unsigned count) {
    int ids[12], xs[12], ys[12];
    for (unsigned i = 0; i < count && i < 12; ++i) {
        const GxContact &c = s->contacts[i];
        ids[i] = c.id;
        if (s->swapXY) {
            xs[i] = gx_publish_x_from_y(c.y, s->mirrorX);
            ys[i] = gx_publish_y_from_x(c.x, s->mirrorY);
        } else {
            xs[i] = gx_publish_x(c.x, s->mirrorX);
            ys[i] = gx_publish_y(c.y, s->mirrorY);
        }
    }
    // Stroke bookkeeping (BootLog's [touch] row): a contact's first and last published position and its frame count.
    const uint32_t now = touchMs();
    for (unsigned i = 0; i < count && i < 12; ++i) {
        if (xs[i] < native_touch_extent[0]) native_touch_extent[0] = xs[i];
        if (xs[i] > native_touch_extent[1]) native_touch_extent[1] = xs[i];
        if (ys[i] < native_touch_extent[2]) native_touch_extent[2] = ys[i];
        if (ys[i] > native_touch_extent[3]) native_touch_extent[3] = ys[i];
        unsigned k = 0;
        while (k < s->strokeCount && s->strokes[k].id != ids[i]) ++k;
        if (k == s->strokeCount) {
            if (s->strokeCount == 12) continue;
            s->strokes[s->strokeCount++] = {ids[i], xs[i], ys[i], xs[i], ys[i], 0, now};
        }
        s->strokes[k].x1 = xs[i]; s->strokes[k].y1 = ys[i]; ++s->strokes[k].frames;
    }
    for (unsigned k = 0; k < s->strokeCount;) {
        bool live = false;
        for (unsigned i = 0; i < count && !live; ++i) live = ids[i] == s->strokes[k].id;
        if (live) {++k; continue;}
        volatile int32_t *row = native_touch_strokes[native_touch_stroke_count & 15];
        row[0] = (int32_t)s->strokes[k].t0; row[1] = (int32_t)(now - s->strokes[k].t0);
        row[2] = s->strokes[k].x0; row[3] = s->strokes[k].y0;
        row[4] = s->strokes[k].x1; row[5] = s->strokes[k].y1; row[6] = s->strokes[k].frames;
        native_touch_stroke_count = native_touch_stroke_count + 1;
        s->strokes[k] = s->strokes[--s->strokeCount];
    }
    native_touch_seq = native_touch_seq + 1;
    __asm__ volatile("dmb ish" ::: "memory");
    native_touch_count = count;
    for (unsigned i = 0; i < count; ++i) {
        native_touch_xs[i] = xs[i];
        native_touch_ys[i] = ys[i];
        native_touch_ids[i] = ids[i];
    }
    __asm__ volatile("dmb ish" ::: "memory");
    native_touch_seq = native_touch_seq + 1;
    if (count) {
        native_touch_last_x = xs[0];
        native_touch_last_y = ys[0];
        ++native_touch_contacts;
    }
    if (void (*sink)(void *) = __atomic_load_n(&gTouchSink, __ATOMIC_ACQUIRE)) sink(gTouchSinkContext);
}

// One frame: header, then the points (a continuation read when more than two fingers are down), then the status clear.
// Returns 0 when the frame was valid and published (or was an empty/status-only frame), -1 on a bus error.
int serviceFrame(Session *s) {
    ++native_touch_cost[2];
    const uint64_t readAt = mach_absolute_time();
    if (busRead(s, s->identity.touch_data_addr, s->head, sizeof s->head)) return -1;
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(mach_absolute_time() - readAt, &ns);
    native_touch_cost[5] = native_touch_cost[5] + (uint32_t)(ns / 1000);
    if (!s->head[0]) return 0;                        // no frame yet: the status byte is 0 until the controller has data
    uint8_t status = 0;
    if (gx_header_status(s->head, &status)) {
        ++native_touch_cost[3];
        const uint8_t zero = 0;
        busWrite(s, s->identity.touch_data_addr, &zero, 1);                 // a bad header is still acknowledged
        return 0;
    }
    ++native_touch_frames;
    const unsigned count = gx_frame_count(s->head[2]);
    if ((status & GX_TOUCH_EVENT) && count <= GX_MAX_TOUCH) {
        uint32_t points = 0;
        memcpy(s->points, s->head + GX_HEADER_LEN, 2 * GX_POINT_LEN);
        points = 2 * GX_POINT_LEN;
        if (count > 2) {
            const uint32_t extraLen = (count - 2) * GX_POINT_LEN;
            const uint64_t extraAt = mach_absolute_time();
            if (busRead(s, s->identity.touch_data_addr + GX_FRAME_HEAD_LEN, s->tail, extraLen)) return -1;
            absolutetime_to_nanoseconds(mach_absolute_time() - extraAt, &ns);
            native_touch_cost[5] = native_touch_cost[5] + (uint32_t)(ns / 1000);
            memcpy(s->points + points, s->tail, extraLen);
            points += extraLen;
        }
        if (count && !gx_points_valid(s->points, count)) {
            ++native_touch_cost[3];
        } else if (!count || gx_points_valid(s->points, count)) {
            const uint64_t publishAt = mach_absolute_time();
            const int contacts = gx_parse_points(s->points, count, s->contacts, GX_MAX_TOUCH);
            if (contacts >= 0) {
                ++native_touch_valid;
                ++native_touch_cost[4];
                publish(s, (unsigned)contacts);
            }
            absolutetime_to_nanoseconds(mach_absolute_time() - publishAt, &ns);
            native_touch_cost[6] = native_touch_cost[6] + (uint32_t)(ns / 1000);
        }
    } else if (status & GX_REQUEST_EVENT) {
        if (s->head[2] == GX_REQUEST_RESET) {   // the controller asks for a reset: release it again
            ++native_touch_bus_stats[5];
            IODelay(2000);
        }
    }
    const uint8_t zero = 0;
    busWrite(s, s->identity.touch_data_addr, &zero, 1);                      // clear the frame status
    return 0;
}

void frameThread(void *, wait_result_t) {
    Session *s = gSession;
    native_touch_stage_done = 4;
    for (;;) {
        native_touch_loop_step = 1;
        ++native_touch_cost[0];
        // The interrupt pin is active low while the controller has a frame (the stock node's IRQ_TYPE_EDGE_FALLING, level
        // polled here: no pin interrupt is configured for the bring-up). A quiet pin sleeps 1 ms.
        if (rd32(s->tlmm.va, gx_tlmm_io(GX_GPIO_IRQ)) & 1u) {
            ++native_touch_cost[1];
            IOSleep(1);
            continue;
        }
        native_touch_loop_step = 2;
        for (unsigned burst = 0; burst < 8; ++burst) {
            if (serviceFrame(s)) {fail(12, -300); goto done;}
            if (rd32(s->tlmm.va, gx_tlmm_io(GX_GPIO_IRQ)) & 1u) break;
        }
    }
done:
    thread_terminate(current_thread());
}

}  // namespace

extern "C" void native_touch_set_sink(void (*sink)(void *), void *context) {
    gTouchSinkContext = context;
    __atomic_store_n(&gTouchSink, sink, __ATOMIC_ACQUIRE);
}

extern "C" void native_goodix_touch_probe(void) {
    unsigned stage = 0;
    if (!PE_parse_boot_argn("touch", &stage, sizeof stage) || stage < 1 || native_touch_stage_req) return;
    if (stage > 4) stage = 4;
    native_touch_stage_req = stage;
    Session *s = new Session();
    if (!s) {native_touch_error = -12; return;}
    gSession = s;
    if (!snapshot(*s)) {native_touch_stage_done = 1; return;}
    if (stage >= 2) {
        native_touch_stage_done = 1;
        if (!enable(*s) || !engineInit(*s)) {native_touch_stage_done = 2; return;}
        native_touch_stage_done = 2;
    }
    if (stage >= 3) {
        if (!identify(*s)) {native_touch_stage_done = 3; return;}
        native_touch_stage_done = 3;
    }
    unsigned mirrorX = 0, mirrorY = 0, swap = 0;
    PE_parse_boot_argn("touch-mirror-x", &mirrorX, sizeof mirrorX);
    PE_parse_boot_argn("touch-mirror-y", &mirrorY, sizeof mirrorY);
    PE_parse_boot_argn("touch-swap-xy", &swap, sizeof swap);
    s->mirrorX = mirrorX != 0; s->mirrorY = mirrorY != 0; s->swapXY = swap != 0;
    if (stage >= 4) {
        thread_t thread = nullptr;
        if (kernel_thread_start(frameThread, nullptr, &thread) != KERN_SUCCESS) {fail(13, -12); return;}
        thread_deallocate(thread);
        native_touch_stage_done = 4;
    }
}
