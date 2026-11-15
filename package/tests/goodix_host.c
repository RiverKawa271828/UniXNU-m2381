// SPDX-License-Identifier: BSD-2-Clause-Patent
// Host tests of the Goodix Berlin protocol helpers and the board coordinate mapping. Model tests only: no IO.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../GoodixBerlin.h"
#include "../GoodixTouchBoard.h"

static unsigned checks;

static void check(int condition, const char *what) {
    if (!condition) {
        printf("FAIL: %s\n", what);
        exit(1);
    }
    ++checks;
}

// A register file behind the transport: 64 KiB, byte addressed. The walker records the last address it served.
struct fake {
    unsigned char mem[0x20000];
    int reads, writes, failWrite, failRead;
    uint32_t lastAddr;
};

static int fakeRead(void *ctx, uint32_t addr, uint8_t *data, uint32_t len) {
    struct fake *f = ctx;
    f->lastAddr = addr;
    ++f->reads;
    if (f->failRead) return -1;
    if (addr + len > sizeof f->mem) return -1;
    memcpy(data, f->mem + addr, len);
    return 0;
}

static int fakeWrite(void *ctx, uint32_t addr, const uint8_t *data, uint32_t len) {
    struct fake *f = ctx;
    f->lastAddr = addr;
    ++f->writes;
    if (f->failWrite) return -1;
    if (addr + len > sizeof f->mem) return -1;
    memcpy(f->mem + addr, data, len);
    return 0;
}

static void put16(unsigned char *p, uint16_t v) {p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);}
static void put32(unsigned char *p, uint32_t v) {p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);}

// A copy of the writer's buffer, for the echo transport.
static uint8_t lastWrite[64];
static uint32_t lastWriteLen;

static int echoWrite(void *ctx, uint32_t addr, const uint8_t *data, uint32_t len) {
    struct fake *f = ctx;
    (void)addr;
    if (len > sizeof lastWrite) return -1;
    memcpy(lastWrite, data, len);
    lastWriteLen = len;
    ++f->writes;
    return 0;
}
static int echoRead(void *ctx, uint32_t addr, uint8_t *data, uint32_t len) {
    (void)ctx; (void)addr;
    if (len != lastWriteLen) return -1;
    memcpy(data, lastWrite, len);
    return 0;
}

// Builds a version block at GX_VERSION_ADDR with the given identity and a correct checksum.
static void putVersion(struct fake *f) {
    unsigned char *v = f->mem + GX_VERSION_ADDR;
    memset(v, 0, GX_VERSION_LEN);
    memcpy(v + 0, "BERLIN", 6);
    memcpy(v + 10, "9916R\0\0\0", 8);
    v[23] = 0xff;
    put16(v + 26, gx_sum16(v, 26));
}

// Builds an IC info record with one value in each variable list and the touch-data address at the misc offset.
static uint32_t putIcInfo(struct fake *f, uint32_t touchDataAddr) {
    unsigned char rec[GX_IC_INFO_MAX];
    memset(rec, 0, sizeof rec);
    memcpy(rec + 2, "BERLIN", 6);
    memcpy(rec + 2 + 10, "9916R\0\0\0", 8);
    rec[2 + 23] = 0xff;
    uint32_t offset = 2 + 16 + 10 + 4;
    for (unsigned list = 0; list < 5; ++list) {
        rec[offset++] = 1;                // one 16-bit value per list
        rec[offset++] = 0x34; rec[offset++] = 0x12;
    }
    // The misc block: the touch-data address sits 44 bytes in.
    put32(rec + offset + 44, touchDataAddr);
    const uint32_t length = offset + 44 + 4 + 40;   // a little tail so the length is plausible
    put16(rec, (uint16_t)length);
    put16(rec + length - 2, gx_sum16(rec, length - 2));
    memcpy(f->mem + GX_IC_INFO_ADDR, rec, length);
    return length;
}

static void testChecksums(void) {
    const unsigned char block[6] = {1, 2, 3, 0, 6, 0};       // sum 6, little-endian at the end
    check(gx_sum16(block, 4) == 6, "sum of four bytes");
    check(gx_checksum_valid(block, sizeof block) == 1, "checksum accepts a correct block");
    unsigned char bad[6];
    memcpy(bad, block, sizeof bad);
    bad[1] = 9;
    check(gx_checksum_valid(bad, sizeof bad) == 0, "checksum rejects a changed block");
    const unsigned char zeros[8] = {0};
    check(gx_dummy(zeros, sizeof zeros) == 1, "all zero is dummy");
    const unsigned char ones[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    check(gx_dummy(ones, sizeof ones) == 1, "all 0xff is dummy");
    unsigned char live[8] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff};
    live[3] = 0x42;
    check(gx_dummy(live, sizeof live) == 0, "one real byte is not dummy");
}

// A part that swallows writes and reads back zeros: the silent bus a missing controller leaves behind.
static int nullWrite(void *ctx, uint32_t addr, const uint8_t *data, uint32_t len) {
    struct fake *f = ctx;
    (void)addr; (void)data; (void)len;
    ++f->writes;
    return f->failWrite ? -1 : 0;
}

static void testDevConfirm(void) {
    struct fake f;
    memset(&f, 0, sizeof f);
    GxTransport echo = {echoRead, echoWrite, &f};
    check(gx_dev_confirm(&echo, 3, 0, NULL, NULL) == 0, "an echoing part confirms");
    check(lastWriteLen == 8 && lastWrite[0] == 0xaa && lastWrite[7] == 0xaa, "confirm writes eight 0xaa");
    struct fake silent;
    memset(&silent, 0, sizeof silent);                        // reads return zeros: no echo
    GxTransport noecho = {fakeRead, nullWrite, &silent};
    check(gx_dev_confirm(&noecho, 3, 0, NULL, NULL) == -1, "a silent part does not confirm");
    silent.failWrite = 1;
    check(gx_dev_confirm(&noecho, 3, 0, NULL, NULL) == -2, "a bus error is reported as such");
}

static void testVersion(void) {
    struct fake f;
    memset(&f, 0, sizeof f);
    putVersion(&f);
    GxTransport t = {fakeRead, fakeWrite, &f};
    GxVersion version;
    memset(&version, 0, sizeof version);
    check(gx_read_version(&t, &version) == 0, "version block reads");
    check(!memcmp(version.rom_pid, "BERLIN", 6), "ROM pid");
    check(!memcmp(version.patch_pid, "9916R", 3), "patch pid");
    check(version.sensor_id == 0xff, "sensor id");
    f.mem[GX_VERSION_ADDR + 3] ^= 1;                          // breaks the checksum
    check(gx_read_version(&t, &version) == -4, "a bad version checksum is rejected");
    memset(&f, 0xff, sizeof f.mem);                           // dummy bus
    check(gx_read_version(&t, &version) == -3, "dummy data is rejected");
}

static void testIcInfo(void) {
    struct fake f;
    memset(&f, 0, sizeof f);
    const uint32_t length = putIcInfo(&f, 0x10308);
    check(length > 60 && length < GX_IC_INFO_MAX, "record length is plausible");
    GxTransport t = {fakeRead, fakeWrite, &f};
    GxIdentity identity;
    memset(&identity, 0, sizeof identity);
    check(gx_read_identity(&t, GX_IC_INFO_ADDR, &identity) == 0, "IC info reads");
    check(identity.touch_data_addr == 0x10308, "touch-data address");
    check(!memcmp(identity.rom_pid, "BERLIN", 6), "identity ROM pid");
    check(identity.sensor_id == 0xff, "identity sensor id");
    f.mem[GX_IC_INFO_ADDR + 40] ^= 0x10;                      // breaks the record checksum
    check(gx_read_identity(&t, GX_IC_INFO_ADDR, &identity) == -4, "a bad IC info checksum is rejected");
    check(gx_parse_ic_info(f.mem + GX_IC_INFO_ADDR, 10, &identity) == -5, "a short record is rejected");
}

static void testFrames(void) {
    unsigned char head[GX_FRAME_HEAD_LEN];
    memset(head, 0, sizeof head);
    head[0] = GX_TOUCH_EVENT;            // status
    head[2] = 2;                         // request_type low nibble = two fingers
    put16(head + 6, gx_sum16(head, 6));
    uint8_t status = 0;
    check(gx_header_status(head, &status) == 0 && status == GX_TOUCH_EVENT, "touch header accepted");
    check(gx_frame_count(head[2]) == 2, "frame count");
    head[6] ^= 0xff;
    check(gx_header_status(head, &status) == -1, "a bad header checksum is rejected");
    put16(head + 6, gx_sum16(head, 6));
    check(gx_frame_count(GX_REQUEST_EVENT | GX_REQUEST_RESET) == GX_REQUEST_RESET, "request code in the low nibble");

    unsigned char points[3 * GX_POINT_LEN + GX_CHECKSUM_LEN];
    memset(points, 0, sizeof points);
    points[0] = 0x11;                    // id 1, type 1? type 1 is a hovering stylus: skipped
    points[8] = 0x02;                    // id 0, type 2 (a finger)
    put16(points + 8 + 2, 5400);         // x = 540 px
    put16(points + 8 + 4, 12000);        // y = 1200 px
    put16(points + 8 + 6, 30);           // w
    put16(points + 2 * GX_POINT_LEN + GX_CHECKSUM_LEN - 2, 0);   // replaced below
    put16(points + 3 * GX_POINT_LEN, gx_sum16(points, 3 * GX_POINT_LEN));
    check(gx_points_valid(points, 3) == 1, "three points with a correct checksum");
    GxContact contacts[GX_MAX_TOUCH];
    const int used = gx_parse_points(points, 3, contacts, GX_MAX_TOUCH);
    check(used == 2, "stylus types are skipped");
    check(contacts[0].id == 0 && contacts[0].x == 5400 && contacts[0].y == 12000 && contacts[0].w == 30, "point values");
    points[3 * GX_POINT_LEN] ^= 1;
    check(gx_points_valid(points, 3) == 0, "a bad point checksum is rejected");
    // Two fingers: the header read alone (two points) carries the checksum.
    unsigned char two[2 * GX_POINT_LEN + GX_CHECKSUM_LEN];
    memset(two, 0, sizeof two);
    two[0] = 0x00; put16(two + 2, 10799); put16(two + 4, 23999);
    put16(two + 2 * GX_POINT_LEN, gx_sum16(two, 2 * GX_POINT_LEN));
    check(gx_points_valid(two, 2) == 1, "two points");
    check(gx_parse_points(two, 2, contacts, 1) == -1, "a contact array that is too small is refused");
    check(GX_FRAME_HEAD_LEN == 26, "the head read is 26 bytes");
    check(gx_frame_extra_addr(0x10308, 3) == 0x10308 + 26, "the continuation starts at +26");
}

static void testPublish(void) {
    check(gx_publish_x(0, 0) == 0, "x origin");
    check(gx_publish_x(5400, 0) == GX_HID_LONG / 2, "x middle");
    check(gx_publish_x(10799, 0) == 30477, "x last unit (10799 * 30480 / 10800)");
    check(gx_publish_x(20000, 0) == 30477, "x beyond the panel is clamped to the last unit");
    check(gx_publish_y(0, 0) == 0, "y origin");
    check(gx_publish_y(12000, 0) == GX_HID_SHORT / 2, "y middle");
    check(gx_publish_y(23999, 0) == GX_HID_SHORT - 1, "y last unit");
    check(gx_publish_y(0, 1) == GX_HID_SHORT - 1, "mirrored y origin is the far edge");
    check(gx_publish_x(0, 1) == GX_HID_LONG - 1, "mirrored x origin is the far edge");
    // Fractions are preserved: the HID layer normalises by the axis maximum, so a quarter of the panel is a quarter.
    const int quarter = gx_publish_x(2700, 0) * 4;
    check(quarter >= (int)GX_HID_LONG - 2 && quarter <= (int)GX_HID_LONG + 2, "x quarter");
    check(gx_publish_y_from_x(5400, 0) == GX_HID_SHORT / 2, "swapped y from x");
    check(gx_publish_x_from_y(12000, 0) == GX_HID_LONG / 2, "swapped x from y");
}

static void testBoardEncoding(void) {
    check(gx_pin_ctl(GX_FUNC_GPIO, GX_DRIVE_8MA, GX_PULL_UP, 1) == ((3u << 6) | 3u | (1u << 9)), "reset pin CTL");
    check(gx_pin_ctl(GX_FUNC_QUP1_SE4, GX_DRIVE_2MA, GX_PULL_UP, 0) == ((1u << 2) | 3u), "I2C pin CTL");
    check(gx_tlmm_ctl(GX_GPIO_RESET) == 24u * 0x1000u, "reset pin page");
    check(gx_tlmm_io(GX_GPIO_IRQ) - gx_tlmm_ctl(GX_GPIO_RESET) < 2u * GX_GPIO_STRIDE, "IRQ pin is in the two mapped pages");
    check((GX_I2C_T_HIGH << 20 | GX_I2C_T_LOW << 10 | GX_I2C_T_CYCLE) == 0x00502c16u, "400 kHz counter word");
    check(((GX_I2C_CLK_DIV & 0xfffu) << 4 | 1u) == 0x21u, "SE clock config word");
}

int main(void) {
    testChecksums();
    testDevConfirm();
    testVersion();
    testIcInfo();
    testFrames();
    testPublish();
    testBoardEncoding();
    printf("PASS goodix host: %u checks\n", checks);
    return 0;
}
