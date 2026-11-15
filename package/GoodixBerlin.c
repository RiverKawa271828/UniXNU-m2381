// SPDX-License-Identifier: BSD-2-Clause-Patent
// Goodix Berlin protocol core: pure functions only, see GoodixBerlin.h for the register map and the sources of every
// rule. Nothing here performs IO by itself; the transport is the caller's.
#include "GoodixBerlin.h"
#include <stddef.h>
#include <string.h>

// The IC info record's fixed prefix and variable middle (the published Berlin layout, as the reference driver parses it):
// a 16-bit length, the version block, the feature block, four single-byte counts, then five variable lists of
// count x 16-bit values, then the misc block. Only the misc block's touch-data address is needed at runtime.
typedef struct {
    uint8_t info_customer_id;
    uint8_t info_version_id;
    uint8_t ic_die_id;
    uint8_t ic_version_id;
    uint32_t config_id;
    uint8_t config_version;
    uint8_t frame_data_customer_id;
    uint8_t frame_data_version_id;
    uint8_t touch_data_customer_id;
    uint8_t touch_data_version_id;
    uint8_t reserved[3];
} __attribute__((packed)) GxIcInfoVersion;

typedef struct {
    uint16_t freqhop_feature;
    uint16_t calibration_feature;
    uint16_t gesture_feature;
    uint16_t side_touch_feature;
    uint16_t stylus_feature;
} __attribute__((packed)) GxIcInfoFeature;

typedef struct {
    uint32_t cmd_addr;
    uint16_t cmd_max_len;
    uint32_t cmd_reply_addr;
    uint16_t cmd_reply_len;
    uint32_t fw_state_addr;
    uint16_t fw_state_len;
    uint32_t fw_buffer_addr;
    uint16_t fw_buffer_max_len;
    uint32_t frame_data_addr;
    uint16_t frame_data_head_len;
    uint16_t fw_attr_len;
    uint16_t fw_log_len;
    uint8_t pack_max_num;
    uint8_t pack_compress_version;
    uint16_t stylus_struct_len;
    uint16_t mutual_struct_len;
    uint16_t self_struct_len;
    uint16_t noise_struct_len;
    uint32_t touch_data_addr;            // +44
    uint16_t header_len;                 // +48
    uint16_t point_len;                  // +50
    uint16_t max_x;                      // +52
    uint16_t max_y;                      // +54
} __attribute__((packed)) GxIcInfoMisc;

static uint16_t le16(const uint8_t *p) {return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));}
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint16_t gx_sum16(const uint8_t *data, uint32_t size)
{
    uint32_t sum = 0;
    for (uint32_t i = 0; i < size; ++i) sum += data[i];
    return (uint16_t)sum;
}

int gx_checksum_valid(const uint8_t *data, uint32_t size)
{
    if (size < GX_CHECKSUM_LEN) return 0;
    return gx_sum16(data, size - GX_CHECKSUM_LEN) == le16(data + size - GX_CHECKSUM_LEN);
}

int gx_dummy(const uint8_t *data, uint32_t size)
{
    for (uint32_t i = 0; i < size; ++i)
        if (data[i] != 0x00 && data[i] != 0xff) return 0;
    return 1;
}

int gx_dev_confirm(const GxTransport *t, unsigned tries, unsigned delay_us, GxDelay delay, void *delay_ctx)
{
    uint8_t tx[8], rx[8];
    memset(tx, GX_BOOTOPTION_VALUE, sizeof tx);
    for (unsigned attempt = 0; attempt < tries; ++attempt) {
        if (t->write(t->ctx, GX_BOOTOPTION_ADDR, tx, sizeof tx)) return -2;
        if (t->read(t->ctx, GX_BOOTOPTION_ADDR, rx, sizeof rx)) return -2;
        if (!memcmp(tx, rx, sizeof tx)) return 0;
        if (delay && attempt + 1 < tries) delay(delay_ctx, delay_us);
    }
    return -1;
}

int gx_read_version(const GxTransport *t, GxVersion *version)
{
    uint8_t raw[GX_VERSION_LEN];
    if (t->read(t->ctx, GX_VERSION_ADDR, raw, sizeof raw)) return -2;
    if (gx_dummy(raw, sizeof raw)) return -3;
    if (!gx_checksum_valid(raw, sizeof raw)) return -4;
    memcpy(version, raw, sizeof *version);
    return 0;
}

int gx_parse_ic_info(const uint8_t *record, uint32_t length, GxIdentity *identity)
{
    const uint32_t header = (uint32_t)sizeof(uint16_t) + (uint32_t)sizeof(GxIcInfoVersion) + (uint32_t)sizeof(GxIcInfoFeature);
    uint32_t offset = header;
    if (length < header + 4u) return -5;
    offset += 4u;                         // drv_num, sen_num, button_num, force_num
    for (unsigned list = 0; list < 5; ++list) {
        if (offset >= length) return -5;
        const uint32_t count = record[offset++];
        if (offset + count * 2u >= length) return -5;
        offset += count * 2u;
    }
    // The record must at least carry the misc block through the touch-data address; the report ABI and the real axes
    // follow it and are read when the firmware includes them (Berlin-D does; a shorter record leaves them zero).
    if (offset + offsetof(GxIcInfoMisc, touch_data_addr) + 4 > length) return -5;
    const GxIcInfoMisc *misc = (const GxIcInfoMisc *)(record + offset);
    const uint32_t touch_data_addr = le32((const uint8_t *)&misc->touch_data_addr);
    if (!touch_data_addr) return -6;
    const int with_axes = offset + sizeof(GxIcInfoMisc) <= length;
    memset(identity, 0, sizeof *identity);
    memcpy(identity->rom_pid, record + 2 + offsetof(GxVersion, rom_pid), sizeof identity->rom_pid);
    memcpy(identity->patch_pid, record + 2 + offsetof(GxVersion, patch_pid), sizeof identity->patch_pid);
    identity->sensor_id = record[2 + offsetof(GxVersion, sensor_id)];
    identity->touch_data_addr = touch_data_addr;
    identity->command_addr = le32((const uint8_t *)&misc->cmd_addr);
    if (with_axes) {
        identity->header_len = le16((const uint8_t *)&misc->header_len);
        identity->point_len = le16((const uint8_t *)&misc->point_len);
        identity->max_x = le16((const uint8_t *)&misc->max_x);
        identity->max_y = le16((const uint8_t *)&misc->max_y);
    }
    return 0;
}

int gx_read_identity(const GxTransport *t, uint32_t ic_info_addr, GxIdentity *identity)
{
    uint8_t length_raw[2];
    if (t->read(t->ctx, ic_info_addr, length_raw, sizeof length_raw)) return -2;
    const uint32_t length = le16(length_raw);
    if (length < 4u || length > GX_IC_INFO_MAX) return -5;
    uint8_t record[GX_IC_INFO_MAX];
    if (t->read(t->ctx, ic_info_addr, record, length)) return -2;
    if (gx_dummy(record, length)) return -3;
    if (!gx_checksum_valid(record, length)) return -4;
    return gx_parse_ic_info(record, length, identity);
}

int gx_header_status(const uint8_t *frame_head, uint8_t *status)
{
    if (!gx_checksum_valid(frame_head, GX_HEADER_LEN)) return -1;
    *status = frame_head[0];
    return 0;
}

int gx_points_valid(const uint8_t *points, unsigned count)
{
    if (count > GX_MAX_TOUCH) return 0;
    return gx_checksum_valid(points, count * GX_POINT_LEN + GX_CHECKSUM_LEN);
}

int gx_parse_points(const uint8_t *points, unsigned count, GxContact *contacts, unsigned max_contacts)
{
    if (count > GX_MAX_TOUCH) return -1;
    unsigned used = 0;
    for (unsigned i = 0; i < count; ++i) {
        const uint8_t *p = points + i * GX_POINT_LEN;
        const uint8_t type = p[0] & GX_POINT_TYPE_MASK;
        if (type == GX_POINT_TYPE_STYLUS || type == GX_POINT_TYPE_STYLUS_HOVER) continue;
        if (used >= max_contacts) return -1;
        contacts[used].id = (uint8_t)(p[0] >> 4);
        contacts[used].type = type;
        contacts[used].x = le16(p + 2);
        contacts[used].y = le16(p + 4);
        contacts[used].w = le16(p + 6);
        ++used;
    }
    return (int)used;
}
