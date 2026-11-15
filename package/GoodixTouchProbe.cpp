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
#include "QcomRpmh.h"
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
    Region gccLow, gccS4, gccHalt, gccVote, tlmmBus, tlmm, wrapper, se, rsc, cmdDb;
    QcomRscLayout rscLayout;
    GeniI2c engine;
    int lastError;
    // Stage 2's engine readbacks: GENI_IF_DISABLE (bit 0 = the SE's boot firmware has no FIFO interface) and the result of
    // the address-only probe transfer that follows the setup.
    uint32_t ifd;
    int probeResult;
    uint32_t probeIrq;
    // The engine's state right after a failed probe, and whether the pins have been taken over as open-drain GPIOs.
    uint32_t engStatus, engCommand, engTxFifo, engIrq;
    bool gpioBus = false;
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
    // The panel's own report axes (IC info misc +52/+54) and the rails the identity stage found; 0 = the board's constants.
    uint32_t maxX = GX_RAW_X, maxY = GX_RAW_Y;
    char railIov[8], railAvdd[8];
    uint32_t railMv;
    int railResult;
    struct {int id, x0, y0, x1, y1, frames; uint32_t t0;} strokes[12];
    unsigned strokeCount;
};

Session *gSession;

// The page's summary row (row 0) is the one touch line a reader window always carries, so a stopped stage's step and code
// ride on it: the per-stage rows are only written once their stage gets far enough to format them.
void appendRow(unsigned row, const char *text) {
    char *r = native_touch_rows[row];
    const size_t used = strlen(r), room = sizeof native_touch_rows[row] - used;
    if (used < sizeof native_touch_rows[row] && room > 1) snprintf(r + used, room, "%s", text);
}

void mark(unsigned step) {native_touch_step = step;}
void fail(unsigned step, int code) {
    native_touch_loop_step = 0; native_touch_error = code; mark(step);
    char note[40];
    snprintf(note, sizeof note, " fail=s%u/c%d", step, code);
    appendRow(0, note);
}
uint32_t touchMs() {
    uint32_t frequency = 0;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    return (uint32_t)(mach_absolute_time() / ((frequency ? frequency : 19200000u) / 1000u));
}

// ---- I2C transport (GeniI2c) -------------------------------------------------------------------------------------
// One transfer's deadline: 26 bytes at 400 kHz is ~0.7 ms; a 5 ms budget tells a slow part from a hung engine.
constexpr unsigned kTransferBudgetUs = 5000;
// The application processor's RSC (DRV 2) and the AOP command database: the same windows the ADSP lane votes lcx/lmx with
// (AdspProbe.cpp). The rails a Goodix panel hangs on are PMIC LDOs whose RPMh resource names come from the command database.
constexpr uint64_t kRscDrv = 0x17a20000, kRscSize = 0x10000, kRscTcs = 0xd00;
constexpr uint64_t kCmdDbBase = 0x81c60000, kCmdDbSize = 0x20000;
constexpr unsigned kRailTcs = 2;            // active TCS 0/1 belong to the WiFi/ADSP votes; the panel gets its own
// The TLMM regions are mapped at the first pin's own page, so every access is relative to that page.
constexpr uint32_t kResetCtl = 0, kResetIo = 4, kIrqCtl = GX_GPIO_STRIDE, kIrqIo = GX_GPIO_STRIDE + 4;

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

// ---- GPIO open-drain transport ----------------------------------------------------------------------------------------
// The SE4 firmware on this board is the GSI/DMA variant (GENI_IF_DISABLE bit 0 set): its FIFO interface is reported dead by
// every transfer (r130 stage 3: probe p=to, error_status 0, device confirm -2). The same pins can carry the same bus as
// open-drain GPIOs, which is what the device-verified GENI I2C component does in that case (unixnu-nativegenii2c, SM-T733).
// Only the pins change: START/repeated START/ACK/NACK/STOP and clock stretching are done here, <= 100 kHz at 5 us a phase.
constexpr unsigned kBitUs = 5;          // one phase; a bit is two phases, so ~100 kHz with the pull-up rise
constexpr unsigned kStretchSpins = 200; // a stretched clock gets 200 us before the transfer is abandoned
bool gxLine(Session &s, unsigned gpio) {return (rd32(s.tlmmBus.va, (gpio - GX_GPIO_SDA) * GX_GPIO_STRIDE + 4u) & 1u) != 0;}
// Open drain: driving low enables the output with a zero; releasing turns the output off and the pin's pull-up lifts the line.
void gxDrive(Session &s, unsigned gpio, bool low) {
    wr32(s.tlmmBus.va, (gpio - GX_GPIO_SDA) * GX_GPIO_STRIDE, gx_pin_ctl(GX_FUNC_GPIO, GX_DRIVE_2MA, GX_PULL_UP, low ? 1 : 0));
    if (low) {
        const uint32_t io = rd32(s.tlmmBus.va, (gpio - GX_GPIO_SDA) * GX_GPIO_STRIDE + 4u);
        wr32(s.tlmmBus.va, (gpio - GX_GPIO_SDA) * GX_GPIO_STRIDE + 4u, io & ~GX_IO_OUT_BIT);
    }
}
bool gxClockHigh(Session &s) {
    for (unsigned spin = 0; spin < kStretchSpins; ++spin) {
        if (gxLine(s, GX_GPIO_SCL)) return true;
        IODelay(1);
    }
    return false;
}
// START (or a repeated START when a transfer is already open): both lines idle high, SDA falls first.
int gxStart(Session &s) {
    gxDrive(s, GX_GPIO_SDA, false);
    gxDrive(s, GX_GPIO_SCL, false);
    if (!gxClockHigh(s) || !gxLine(s, GX_GPIO_SDA)) return -3;   // a held line means someone else owns the bus
    IODelay(kBitUs);
    gxDrive(s, GX_GPIO_SDA, true);
    IODelay(kBitUs);
    gxDrive(s, GX_GPIO_SCL, true);
    IODelay(kBitUs);
    return 0;
}
// STOP: SDA rises while SCL is high. Best effort: a stretched or held clock must not leave the pins mid-transfer.
void gxStop(Session &s) {
    gxDrive(s, GX_GPIO_SDA, true);
    IODelay(kBitUs);
    gxDrive(s, GX_GPIO_SCL, false);
    gxClockHigh(s);
    IODelay(kBitUs);
    gxDrive(s, GX_GPIO_SDA, false);
    IODelay(kBitUs);
}
// 0 on ACK, -1 on NACK, -2 when the slave holds the clock, -3 when the bus cannot be taken.
int gxWriteByte(Session &s, uint8_t byte, bool first) {
    if (first) {
        const int started = gxStart(s);
        if (started) return started;
    }
    for (int bit = 7; bit >= 0; --bit) {
        gxDrive(s, GX_GPIO_SDA, !((byte >> bit) & 1u));
        IODelay(kBitUs);
        gxDrive(s, GX_GPIO_SCL, false);
        if (!gxClockHigh(s)) return -2;
        IODelay(kBitUs);
        gxDrive(s, GX_GPIO_SCL, true);
    }
    gxDrive(s, GX_GPIO_SDA, false);          // the ninth clock: the slave drives ACK
    IODelay(kBitUs);
    gxDrive(s, GX_GPIO_SCL, false);
    if (!gxClockHigh(s)) return -2;
    const bool ack = !gxLine(s, GX_GPIO_SDA);
    IODelay(kBitUs);
    gxDrive(s, GX_GPIO_SCL, true);
    return ack ? 0 : -1;
}
int gxReadByte(Session &s, uint8_t *out, bool last) {
    uint8_t value = 0;
    gxDrive(s, GX_GPIO_SDA, false);          // the slave drives the data; the host acknowledges after it
    for (int bit = 7; bit >= 0; --bit) {
        IODelay(kBitUs);
        gxDrive(s, GX_GPIO_SCL, false);
        if (!gxClockHigh(s)) return -2;
        value = (uint8_t)((value << 1) | (gxLine(s, GX_GPIO_SDA) ? 1 : 0));
        gxDrive(s, GX_GPIO_SCL, true);
    }
    gxDrive(s, GX_GPIO_SDA, !last);          // ACK everything but the final byte
    IODelay(kBitUs);
    gxDrive(s, GX_GPIO_SCL, false);
    if (!gxClockHigh(s)) return -2;
    IODelay(kBitUs);
    gxDrive(s, GX_GPIO_SCL, true);
    gxDrive(s, GX_GPIO_SDA, false);
    *out = value;
    return 0;
}
// The Berlin register is a 32-bit address: write {address, data} or write the address, repeated START, read the data.
int gxTransferRead(Session &s, uint32_t addr, uint8_t *data, uint32_t len) {
    int result = gxWriteByte(s, (uint8_t)(GX_I2C_ADDRESS << 1), true);
    for (unsigned i = 0; !result && i < 4; ++i) result = gxWriteByte(s, (uint8_t)(addr >> (24 - 8 * i)), false);
    if (!result) result = gxWriteByte(s, (uint8_t)((GX_I2C_ADDRESS << 1) | 1u), true);
    for (uint32_t i = 0; !result && i < len; ++i) result = gxReadByte(s, data + i, i + 1 == len);
    gxStop(s);
    return result;
}
int gxTransferWrite(Session &s, uint32_t addr, const uint8_t *data, uint32_t len) {
    int result = gxWriteByte(s, (uint8_t)(GX_I2C_ADDRESS << 1), true);
    for (unsigned i = 0; !result && i < 4; ++i) result = gxWriteByte(s, (uint8_t)(addr >> (24 - 8 * i)), false);
    for (uint32_t i = 0; !result && i < len; ++i) result = gxWriteByte(s, data[i], false);
    gxStop(s);
    return result;
}
// Take the pins off the SE and put the bus in a known idle state. Nine clock pulses release a slave that a dead transfer
// left part-way through a byte (the reference driver's recovery), then START/STOP leaves the bus idle.
void gxEnterGpio(Session &s) {
    gxDrive(s, GX_GPIO_SDA, false);
    gxDrive(s, GX_GPIO_SCL, false);
    for (unsigned pulse = 0; pulse < 9 && !gxLine(s, GX_GPIO_SDA); ++pulse) {
        gxDrive(s, GX_GPIO_SCL, true);
        IODelay(kBitUs);
        gxDrive(s, GX_GPIO_SCL, false);
        gxClockHigh(s);
    }
    if (!gxStart(s)) gxStop(s);
    s.gpioBus = true;
}

int busRead(void *ctx, uint32_t addr, uint8_t *data, uint32_t len) {
    Session *s = static_cast<Session *>(ctx);
    ++s->reads;
    native_touch_bus_stats[0] = s->reads;
    if (s->gpioBus) {
        const int result = gxTransferRead(*s, addr, data, len);
        if (result) native_touch_bus_stats[2] = native_touch_bus_stats[2] + 1;
        return result;
    }
    const uint8_t command[4] = {(uint8_t)(addr >> 24), (uint8_t)(addr >> 16), (uint8_t)(addr >> 8), (uint8_t)addr};
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
    if (s->gpioBus) {
        const int result = gxTransferWrite(*s, addr, data, len);
        if (result) native_touch_bus_stats[3] = native_touch_bus_stats[3] + 1;
        return result;
    }
    if (geni_i2c_start_write_buffer(&s->engine, buffer, 4 + len)) {
        native_touch_bus_stats[3] = native_touch_bus_stats[3] + 1;
        return -1;
    }
    const int result = waitEngine(s);
    if (result) native_touch_bus_stats[3] = native_touch_bus_stats[3] + 1;
    return result;
}

void gxDelay(void *, unsigned microseconds) {IODelay(microseconds);}

// The engine's own registers after a probe that produced no event: was the command latched (M_CMD0 readback), did the
// address byte reach the FIFO (TX_FIFO_STATUS), is the engine still busy (GENI_STATUS bit 0)? That separates a FIFO the
// boot firmware disabled from a sequence that never got as far as the command register.
void engineState(Session &s) {
    constexpr uint32_t kGeniStatus = 0x40;      // SE_GENI_STATUS: bit 0 = a command is in progress
    s.engStatus = rd32(s.se.va, kGeniStatus);
    s.engCommand = rd32(s.se.va, GENI_M_CMD0);
    s.engTxFifo = rd32(s.se.va, GENI_TX_FIFO_STATUS);
    s.engIrq = rd32(s.se.va, GENI_M_IRQ_STATUS);
    snprintf(native_touch_rows[3], sizeof native_touch_rows[3],
             "TCHE st=%08x cmd=%08x tx=%08x irq=%08x", s.engStatus, s.engCommand, s.engTxFifo, s.engIrq);
}

// One register read of address 0 with the rails as the boot left them, over whichever transport is active. The slave may
// NACK (unpowered until stage 3 votes IOVDD/AVDD); what the result separates is the transport from the slave:
//   ok    the slave answered                  -> bus and part both alive
//   nack  the slave refused its address       -> bus works, part not powered/not out of reset yet
//   to    no completion at all (engine) / stretched clock (GPIO) -> the transport itself is the problem
//   busy  the pins could not be taken         -> something else owns the bus
// Observational: the stage continues either way and the result rides on the page row under its tag.
bool busProbe(Session &s, const char *tag) {
    uint8_t byte = 0;
    if (s.gpioBus) {
        s.probeResult = gxTransferRead(s, 0x00, &byte, 1);
        s.probeIrq = 0;
    } else {
        s.probeResult = geni_i2c_start_read(&s.engine, 0x00) ? -10 : waitEngine(&s);
        s.probeIrq = s.engine.error_status;
    }
    const char *state = s.probeResult == 0 ? "ok"
        : s.probeResult == -1 ? ((s.probeIrq & (1u << 9)) ? "nack" : "berr")
        : s.probeResult == -2 ? "to"
        : s.probeResult == -3 ? "busy" : "start";
    char note[40];
    if (s.probeIrq) snprintf(note, sizeof note, " %s=%s/%08x", tag, state, s.probeIrq);
    else snprintf(note, sizeof note, " %s=%s", tag, state);
    appendRow(0, note);
    return s.probeResult == 0;
}

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
    // The bus page is mapped at gpio44's own page (GX_TLMM_BASE + 44 * stride); offsets are relative to that base.
    v[7] = rd32(s.tlmmBus.va, 0);
    v[8] = rd32(s.tlmmBus.va, GX_GPIO_STRIDE);
    // Row 0 is the page's summary row (BootProgress.c line 42) and the first row a reader window carries; rows 1..3 are
    // BootLog's [touch 1..3]. Every stage refreshes its row before the next one can fail.
    snprintf(native_touch_rows[0], sizeof native_touch_rows[0],
             "TCH1 gcc=%08x c2x=%08x core=%08x mahb=%08x sahb=%08x s4=%08x rcg=%08x",
             v[0], v[1], v[2], v[3], v[4], v[5], v[6]);
    snprintf(native_touch_rows[1], sizeof native_touch_rows[1],
             "TCH1p sda=%08x scl=%08x (TLMM CTL; qup1_se4 func = 1, OE bit 9)", v[7], v[8]);
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
    wr32(s.tlmmBus.va, 0, i2cPin);                       // gpio44 SDA: the mapping's own base
    wr32(s.tlmmBus.va, GX_GPIO_STRIDE, i2cPin);          // gpio45 SCL: one page up
    s.regs[7] = rd32(s.tlmmBus.va, 0);
    s.regs[8] = rd32(s.tlmmBus.va, GX_GPIO_STRIDE);
    // The interface-disable bit is the one the stage-2 window could not show: prepare() used to stop on it before any row
    // was written. It stays reported, and whether the engine still runs is settled by busProbe's first command.
    s.ifd = rd32(s.se.va, GENI_IF_DISABLE);
    snprintf(native_touch_rows[1], sizeof native_touch_rows[1],
             "TCH2 vote=%08x core=%08x s4=%08x rcg=%08x sda=%08x scl=%08x ifd=%08x",
             s.regs[10], s.regs[11], s.regs[12], rd32(s.gccS4.va, (GX_S4_RCG + GX_RCG_CFG) & 0xfff), s.regs[7], s.regs[8],
             s.ifd);
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
    // Row first: the engine identity reaches the window even when the protocol check or the engine setup stops the stage.
    // The stage-2 build wrote this row only on success, so a stopped stage left no engine evidence at all.
    snprintf(native_touch_rows[2], sizeof native_touch_rows[2],
             "TCH3a fw=%08x ifd=%08x whv=%08x", fw, s.regs[14], s.regs[15]);
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
    const GeniIo io = {geniIoRead, geniIoWrite, reinterpret_cast<void *>(se)};
    uint32_t config = 0;
    if (geni_i2c_prepare(&s.engine, &io, GX_I2C_ADDRESS, &config)) {fail(5, -1); return false;}
    s.regs[9] = config;
    snprintf(native_touch_rows[2], sizeof native_touch_rows[2],
             "TCH3 fw=%08x ifd=%08x whv=%08x cfg=%08x clk=%08x scl=%08x addr=%02x",
             s.regs[13], s.regs[14], s.regs[15], config, rd32(se, GENI_CLK_CFG), rd32(se, GENI_SCL_COUNTERS), GX_I2C_ADDRESS);
    mark(6);
    return true;
}

// ---- Stage 3: rails, reset, confirm, identity -------------------------------------------------------------------------
// One PMIC LDO through an active-only RPMh request: {address, mV}, {address+4, 1} (enable), {address+8, 7} (high-power mode).
bool railVote(Session &s, uint32_t address, uint32_t millivolts) {
    if (!address) return false;
    const uint32_t addresses[3] = {address, address + 4, address + 8};
    const uint32_t values[3] = {millivolts, 1, 7};
    QcomRpmhWrite writes[16];
    const unsigned n = qcom_rpmh_active_request(&s.rscLayout, kRailTcs, addresses, values, 3, writes, sizeof writes / sizeof writes[0]);
    if (!n) return false;
    const uint32_t bit = 1u << kRailTcs;
    wr32(s.rsc.va, kRscTcs + s.rscLayout.irq_clear, bit);
    wr32(s.rsc.va, kRscTcs + s.rscLayout.irq_status, 0);   // the status bit is write-one-to-clear on this layout
    for (unsigned i = 0; i < n; ++i) wr32(s.rsc.va, kRscTcs + writes[i].offset, writes[i].value);
    bool done = false;
    for (unsigned i = 0; i < 2000 && !done; ++i) {
        if (rd32(s.rsc.va, kRscTcs + s.rscLayout.irq_status) & bit) done = true;
        else IODelay(50);
    }
    const unsigned m = qcom_rpmh_finish(&s.rscLayout, kRailTcs, writes, sizeof writes / sizeof writes[0]);
    for (unsigned i = 0; i < m; ++i) wr32(s.rsc.va, kRscTcs + writes[i].offset, writes[i].value);
    return true;                            // a request whose done bit is not seen still takes effect on this platform
}

// The panel's rails by their PMIC resource names, in the order the reference driver uses: IOVDD first, then AVDD.
// The stock overlay names L14B (fragment@19) or L9B (fragment@87) for AVDD and L12B for IOVDD; the command database
// decides which of those this boot actually has.
bool railsOn(Session &s) {
    const char *iovCandidates[] = {"ldob12", "ldol12"};
    const char *avddCandidates[] = {"ldob14", "ldol14", "ldob9", "ldol9"};
    if (!mapRegion(kRscDrv, kRscSize, s.rsc) || !mapRegion(kCmdDbBase, kCmdDbSize, s.cmdDb)) return false;
    s.rscLayout = qcom_rsc_layout(rd32(s.rsc.va, 0));
    QcomRpmhResource iov = {}, avdd = {};
    for (const char *name : iovCandidates) if (!qcom_cmd_db_find(reinterpret_cast<const uint8_t *>(s.cmdDb.va), kCmdDbSize, name, &iov)) {strlcpy(s.railIov, name, sizeof s.railIov); break;}
    for (const char *name : avddCandidates) if (!qcom_cmd_db_find(reinterpret_cast<const uint8_t *>(s.cmdDb.va), kCmdDbSize, name, &avdd)) {strlcpy(s.railAvdd, name, sizeof s.railAvdd); break;}
    if (!s.railIov[0] || !s.railAvdd[0]) {s.railResult = -1; return false;}
    // L14B is the DT's 3.2 V rail; the L9B variant is the stock overlay's ~2.96 V. Both are accepted by the part; the
    // voltage follows the rail the database actually has.
    s.railMv = s.railAvdd[4] == '9' ? 2960u : 3200u;
    if (!railVote(s, iov.address, 1800u)) {s.railResult = -2; return false;}
    IODelay(3000);
    if (!railVote(s, avdd.address, s.railMv)) {s.railResult = -3; return false;}
    IODelay(15000);
    s.railResult = 1;
    return true;
}

// ---- Stage 3: reset, confirm, identity ------------------------------------------------------------------------------
bool identify(Session &s) {
    mark(7);
    // Two pages cover reset (24) and IRQ (25): the mapping starts at gpio24's own page (GX_TLMM_BASE + 24 * stride).
    if (!mapRegion(GX_TLMM_BASE + gx_tlmm_ctl(GX_GPIO_RESET), 2 * GX_GPIO_STRIDE, s.tlmm)) {fail(7, -12); return false;}
    Region &tlmm = s.tlmm;
    // reset gpio24: function gpio (0), drive 8, pull-up, output enable. Physical low asserts the part's reset (the node's
    // GPIO_ACTIVE_LOW), physical high releases it; the pin is read back after every write.
    // The page is mapped at gpio24's own base: reset is +0 (ctl) / +4 (io), irq is one page up.
    const uint32_t resetCtl = gx_pin_ctl(GX_FUNC_GPIO, GX_DRIVE_8MA, GX_PULL_UP, 1);
    wr32(tlmm.va, kResetCtl, resetCtl);
    uint32_t io = rd32(tlmm.va, kResetIo);
    wr32(tlmm.va, kResetIo, (io & ~GX_IO_OUT_BIT));          // low = asserted
    IODelay(10000);
    io = rd32(tlmm.va, kResetIo);
    wr32(tlmm.va, kResetIo, io | GX_IO_OUT_BIT);             // high = released
    IODelay(100000);
    // irq gpio25: function gpio, pull-up, input; the level (io bit 0) is polled by the frame thread, no pin interrupt.
    wr32(tlmm.va, kIrqCtl, gx_pin_ctl(GX_FUNC_GPIO, GX_DRIVE_8MA, GX_PULL_UP, 0));
    s.regs[2] = rd32(tlmm.va, kResetCtl);
    s.regs[3] = rd32(tlmm.va, kResetIo);
    s.regs[4] = rd32(tlmm.va, kIrqCtl);
    s.regs[5] = rd32(tlmm.va, kIrqIo);
    GxTransport transport = {busRead, busWrite, &s};
    mark(8);
    int confirm = gx_dev_confirm(&transport, GX_DEV_CONFIRM_TRIES, 5000, gxDelay, nullptr);
    if (confirm && railsOn(s)) {
        // The part did not answer with the rails as the boot left them: power IOVDD/AVDD through RPMh, release reset
        // again and re-confirm (the reference driver's order: probe, then supply, then reset, then probe).
        mark(12);
        io = rd32(s.tlmm.va, kResetIo);
        wr32(s.tlmm.va, kResetIo, io & ~GX_IO_OUT_BIT);
        IODelay(10000);
        io = rd32(s.tlmm.va, kResetIo);
        wr32(s.tlmm.va, kResetIo, io | GX_IO_OUT_BIT);
        IODelay(100000);
        confirm = gx_dev_confirm(&transport, GX_DEV_CONFIRM_TRIES, 5000, gxDelay, nullptr);
    }
    if (confirm) {fail(8, -200 + confirm); return false;}
    mark(9);
    const int version = gx_read_version(&transport, &s.parsed);
    memcpy(s.version, &s.parsed, sizeof s.parsed);
    if (version) {fail(9, -210 + version); return false;}
    mark(10);
    const int identity = gx_read_identity(&transport, GX_IC_INFO_ADDR, &s.identity);
    if (identity) {fail(10, -220 + identity); return false;}
    // The panel advertises its own report axes; they supersede the board constants when present.
    if (s.identity.max_x && s.identity.max_y) {s.maxX = s.identity.max_x; s.maxY = s.identity.max_y;}
    snprintf(native_touch_rows[3], sizeof native_touch_rows[3],
             "TCH4 rst=%08x iox=%08x irq=%08x pid=%.6s/%d addr=%x axes=%ux%u rail=%s/%umV(%d)",
             s.regs[2], s.regs[3], s.regs[5], (const char *)s.parsed.patch_pid, s.parsed.sensor_id, s.identity.touch_data_addr,
             s.maxX, s.maxY, s.railAvdd[0] ? s.railAvdd : "-", s.railMv, s.railResult);
    mark(11);
    return true;
}

// ---- Stage 4: frames -----------------------------------------------------------------------------------------------
// Published coordinates: raw report units scaled against the panel's own axes (IC info) onto the long/short maxima the
// HID producer normalises by; the board constants are the fallback when the firmware does not advertise axes.
int scaleLong(const Session *s, int raw, uint32_t maxRaw, int mirror) {
    if (raw < 0) raw = 0;
    if (!maxRaw) maxRaw = GX_RAW_X;
    if ((uint32_t)raw >= maxRaw) raw = (int)(maxRaw - 1);
    int value = (int)((long long)raw * GX_HID_LONG / maxRaw);
    return mirror ? (int)(GX_HID_LONG - 1 - (uint32_t)value) : value;
}
int scaleShort(const Session *s, int raw, uint32_t maxRaw, int mirror) {
    (void)s;
    if (raw < 0) raw = 0;
    if (!maxRaw) maxRaw = GX_RAW_Y;
    if ((uint32_t)raw >= maxRaw) raw = (int)(maxRaw - 1);
    int value = (int)((long long)raw * GX_HID_SHORT / maxRaw);
    return mirror ? (int)(GX_HID_SHORT - 1 - (uint32_t)value) : value;
}
// The HID consumer registers here (NativeHidInput's start, touch-hid=1); it is called after a frame is published.
void (*gTouchSink)(void *);
void *gTouchSinkContext;

void publish(Session *s, unsigned count) {
    int ids[12], xs[12], ys[12];
    for (unsigned i = 0; i < count && i < 12; ++i) {
        const GxContact &c = s->contacts[i];
        ids[i] = c.id;
        if (s->swapXY) {
            xs[i] = scaleLong(s, c.y, s->maxY, s->mirrorX);
            ys[i] = scaleShort(s, c.x, s->maxX, s->mirrorY);
        } else {
            xs[i] = scaleLong(s, c.x, s->maxX, s->mirrorX);
            ys[i] = scaleShort(s, c.y, s->maxY, s->mirrorY);
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
        memcpy(s->points, s->head + GX_HEADER_LEN, 2 * GX_POINT_LEN);
        if (count > 2) {
            // The head read only took the first two points; re-read the whole point area (count * 8 bytes) together
            // with its trailing checksum in one transfer, as the reference Berlin drivers do.
            const uint32_t pointsLen = count * GX_POINT_LEN + GX_CHECKSUM_LEN;
            const uint64_t extraAt = mach_absolute_time();
            if (busRead(s, gx_frame_points_addr(s->identity.touch_data_addr), s->points, pointsLen)) return -1;
            absolutetime_to_nanoseconds(mach_absolute_time() - extraAt, &ns);
            native_touch_cost[5] = native_touch_cost[5] + (uint32_t)(ns / 1000);
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
        if (rd32(s->tlmm.va, kIrqIo) & 1u) {
            ++native_touch_cost[1];
            IOSleep(1);
            continue;
        }
        native_touch_loop_step = 2;
        for (unsigned burst = 0; burst < 8; ++burst) {
            if (serviceFrame(s)) {fail(12, -300); goto done;}
            if (rd32(s->tlmm.va, kIrqIo) & 1u) break;
        }
    }
done:
    thread_terminate(current_thread());
}

}  // namespace

extern "C" void native_touch_set_sink(void (*sink)(void *), void *context) {
    gTouchSinkContext = context;
    __atomic_store_n(&gTouchSink, sink, __ATOMIC_RELEASE);
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
        const bool engineOk = busProbe(*s, "p");
        engineState(*s);
        // This board's SE4 runs the GSI/DMA firmware (no FIFO interface), so a silent engine means the same pins must carry
        // the bus as open-drain GPIOs; every later transfer then goes through gxTransferRead/gxTransferWrite.
        if (!engineOk) {
            gxEnterGpio(*s);
            appendRow(0, " bus=gpio");
            busProbe(*s, "pg");
        }
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
