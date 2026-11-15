// SPDX-License-Identifier: BSD-2-Clause-Patent
// Goodix "Berlin" (GT9916) register protocol, transport-agnostic and pure (no MMIO, no IOKit), so the parsing and the
// checksum rules are host-testable. Protocol facts (offsets, record layout, checksum rules, event semantics) follow the
// Berlin driver's published register map and the device's own dtbo node (firmware-name goodix_firmware_i2c.bin,
// config-name goodix_cfg_group_i2c.bin, compatible goodix,gt9916 = Berlin revision D address map):
//   * register writes/reads carry a 32-bit big-endian register address (i2c-qcom-geni/regmap reg_bits = 32, endianness
//     default big); a read writes the address without a stop condition, then reads the payload.
//   * boot option window 0x10000: 8 x 0xAA writes, read back identical = the part is up ("device confirm").
//   * firmware/ROM version window 0x10014, 28 bytes ending in a little-endian 16-bit sum of the first 26.
//   * IC info window 0x10070: a 16-bit little-endian length, then the record, checksummed like the version block; its
//     misc section carries the runtime touch-data address.
//   * touch data: 8-byte header (status, reserved, request_type, 3 reserved, LE16 sum of the first 6) followed by 8-byte
//     points and a trailing LE16 sum of the points. Counter 0 of the *frame* word (request_type) is in request_type's
//     low nibble; status bit 7 = a touch frame, bit 6 = a request frame (code 3 = the controller asks for a reset).
//     Reading the header plus two points (26 bytes) covers one and two fingers; more fingers continue at +26.
// Writes of the status byte 0 to the touch-data address clear it (that is the frame acknowledgement).
#ifndef M2381_GOODIX_BERLIN_H
#define M2381_GOODIX_BERLIN_H
#include <stdint.h>

#define GX_BOOTOPTION_ADDR 0x10000u
#define GX_VERSION_ADDR 0x10014u         // Berlin revision D / gt9916 (mainline GOODIX_BERLIN_FW_VERSION_INFO_ADDR_D)
#define GX_IC_INFO_ADDR 0x10070u         // Berlin revision D / gt9916 (GOODIX_BERLIN_IC_INFO_ADDR_D)

#define GX_BOOTOPTION_VALUE 0xAAu
#define GX_DEV_CONFIRM_TRIES 3
#define GX_VERSION_LEN 28u
#define GX_IC_INFO_MAX 1024u
#define GX_HEADER_LEN 8u
#define GX_POINT_LEN 8u
#define GX_CHECKSUM_LEN 2u
#define GX_MAX_TOUCH 10u
// Header + two points + checksum: the single read every frame starts with (26 bytes).
#define GX_FRAME_HEAD_LEN (GX_HEADER_LEN + 2u * GX_POINT_LEN + GX_CHECKSUM_LEN)
// Header + ten points + checksum: the largest frame a full read needs.
#define GX_FRAME_MAX_LEN (GX_HEADER_LEN + GX_MAX_TOUCH * GX_POINT_LEN + GX_CHECKSUM_LEN)

#define GX_TOUCH_EVENT 0x80u
#define GX_REQUEST_EVENT 0x40u
#define GX_REQUEST_RESET 3u
#define GX_TOUCH_COUNT_MASK 0x0fu
#define GX_POINT_TYPE_MASK 0x0fu
#define GX_POINT_TYPE_STYLUS_HOVER 1u
#define GX_POINT_TYPE_STYLUS 3u
#define GX_POINT_ID_MASK 0xf0u

// One register transport: len bytes at a 32-bit register address. Both return 0 on success.
typedef struct {
    int (*read)(void *ctx, uint32_t addr, uint8_t *data, uint32_t len);
    int (*write)(void *ctx, uint32_t addr, const uint8_t *data, uint32_t len);
    void *ctx;
} GxTransport;

typedef struct {
    uint8_t rom_pid[6];
    uint8_t rom_vid[3];
    uint8_t rom_vid_reserved;
    uint8_t patch_pid[8];
    uint8_t patch_vid[4];
    uint8_t patch_vid_reserved;
    uint8_t sensor_id;
    uint8_t reserved[2];
    uint16_t checksum;                   // little-endian on the wire
} __attribute__((packed)) GxVersion;

typedef struct {
    uint8_t status;                      // frame word
    uint8_t reserved1;
    uint8_t request_type;                // low nibble: touch count on a touch frame, request code on a request frame
    uint8_t reserved2[3];
    uint16_t checksum;                   // little-endian sum of the six bytes above
} __attribute__((packed)) GxHeader;

typedef struct {
    uint8_t status;                      // high nibble: id, low nibble: type (1/3 are stylus)
    uint8_t reserved;
    uint16_t x;                          // little-endian, 0.1 px
    uint16_t y;
    uint16_t w;
} __attribute__((packed)) GxPoint;

// What the probe needs out of the IC info record: the identity strings and the runtime touch-data address.
typedef struct {
    uint8_t rom_pid[6];
    uint8_t patch_pid[8];
    uint8_t sensor_id;
    uint32_t touch_data_addr;
} GxIdentity;

typedef struct {
    uint8_t id;
    uint8_t type;
    uint16_t x, y, w;
} GxContact;

// 16-bit sum of size bytes (the checksum rule of every Berlin block).
uint16_t gx_sum16(const uint8_t *data, uint32_t size);
// 1 when the last two bytes of the block are the little-endian sum of the rest.
int gx_checksum_valid(const uint8_t *data, uint32_t size);
// 1 when every byte is 0x00 or 0xff: the bus's idle level, i.e. nothing answered (a checksum can still pass on it).
int gx_dummy(const uint8_t *data, uint32_t size);

// Device confirm: write 8 x 0xAA to the boot-option window and read them back, `tries` times with `delay_us` between
// attempts. 0 on success, -1 when the part answers with something else, -2 on a transport error.
typedef void (*GxDelay)(void *ctx, unsigned microseconds);
int gx_dev_confirm(const GxTransport *t, unsigned tries, unsigned delay_us, GxDelay delay, void *delay_ctx);

// Firmware/ROM version block at GX_VERSION_ADDR. 0 on success, -2 transport, -3 dummy data, -4 checksum.
int gx_read_version(const GxTransport *t, GxVersion *version);

// IC info at GX_IC_INFO_ADDR: reads the length word, the record, checks it and extracts the identity. -5 when the
// record is too short or its offset arithmetic runs past the length, -6 when the touch-data address is zero.
int gx_read_identity(const GxTransport *t, uint32_t ic_info_addr, GxIdentity *identity);

// Parse an IC info record of `length` bytes (as read from ic_info_addr, length word included).
int gx_parse_ic_info(const uint8_t *record, uint32_t length, GxIdentity *identity);

// Header checksum / frame classification. 0 = valid touch or request frame in *status, -1 = header checksum bad.
int gx_header_status(const uint8_t *frame_head, uint8_t *status);
static inline unsigned gx_frame_count(uint8_t request_type) {return request_type & GX_TOUCH_COUNT_MASK;}
// The address the continuation of a frame with more than two fingers sits at (header + two points + the two checksum
// bytes the head read takes as extra data when more points follow). extra = GX_FRAME_HEAD_LEN.
static inline uint32_t gx_frame_extra_addr(uint32_t touch_addr, unsigned count) {
    (void)count;
    return touch_addr + GX_FRAME_HEAD_LEN;
}

// Point checksum over `count` points starting at points[0] and the trailing two bytes. 1 when it matches.
int gx_points_valid(const uint8_t *points, unsigned count);
// Extract the points. `points` holds count * 8 bytes followed by the two checksum bytes. Returns the number of contacts
// written (stylus types are skipped) or -1 when the buffer does not hold count points plus the checksum.
int gx_parse_points(const uint8_t *points, unsigned count, GxContact *contacts, unsigned max_contacts);
#endif
