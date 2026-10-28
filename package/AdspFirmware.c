// SPDX-License-Identifier: BSD-2-Clause-Patent
// Firmware files for the remote processors, read by the kernel from the mounted Data volume (the device's own adsp.mbn and
// adsp_dtb.mbn, installed by the owner below /private/var/firmware; they are never part of the build). Plain VFS reads on the caller's
// thread: the ADSP thread is the only caller and it runs no interrupt work, so a slow read only delays that bring-up.
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <IOKit/IOLib.h>

int sheng_fw_open(const char *path, void **handle, uint64_t *size);
int sheng_fw_read(void *handle, uint64_t offset, void *to, size_t length);
void sheng_fw_close(void *handle);
int sheng_fw_ufs_read(void *handle, uint64_t offset, void *to, size_t length);
void sheng_fw_ufs_close(void *handle);
static int sheng_fw_ufs_open_image(const char *image, void **handle, uint64_t *out_size);

int sheng_fw_open(const char *path, void **handle, uint64_t *size)
{
    if (!strncmp(path, "boot_b:", 7) || !strncmp(path, "boot_a:", 7))
        return sheng_fw_ufs_open_image(path + 7, handle, size);
    vfs_context_t ctx = vfs_context_kernel();
    vnode_t vp = NULLVP;
    struct vnode_attr va;
    int error = vnode_open(path, FREAD, 0, 0, &vp, ctx);
    if (error) return error;
    VATTR_INIT(&va);
    VATTR_WANTED(&va, va_data_size);
    if ((error = vnode_getattr(vp, &va, ctx)) || !VATTR_IS_SUPPORTED(&va, va_data_size) || !va.va_data_size) {
        vnode_close(vp, FREAD, ctx);
        return error ? error : EFTYPE;
    }
    *handle = vp;
    *size = va.va_data_size;
    return 0;
}

int sheng_fw_read(void *handle, uint64_t offset, void *to, size_t length)
{
    vfs_context_t ctx = vfs_context_kernel();
    uint8_t *out = (uint8_t *)to;
    while (length) {
        const int want = length > (1u << 30) ? (1 << 30) : (int)length;
        int resid = want;
        const int error = vn_rdwr(UIO_READ, (vnode_t)handle, (caddr_t)out, want, (off_t)offset, UIO_SYSSPACE, IO_NOAUTH,
                                  vfs_context_ucred(ctx), &resid, vfs_context_proc(ctx));
        if (error) return error;
        if (resid == want) return EIO;  /* end of file before the bytes asked for */
        out += want - resid;
        offset += (uint64_t)(want - resid);
        length -= (size_t)(want - resid);
    }
    return 0;
}

void sheng_fw_close(void *handle)
{
    if (handle) vnode_close((vnode_t)handle, FREAD, vfs_context_kernel());
}

// ---- the embedded form (m2381): scripts/make-adsp-firmware.py squashes the device's own split ADSP images
// (modem_a image/ .mdt + .bNN, harvested from the stock firmware) into two blobs and the boot-progress build
// stages AdspFirmwareBlob.c from .cache/firmware/adsp; the vendor firmware never enters git. A zero-size blob
// (nothing staged) makes the probe fall back to the VFS sources above.
struct ShengFwMem {const uint8_t *data; uint64_t size;};

int sheng_fw_mem_open(const void *data, uint64_t size, void **handle, uint64_t *out_size)
{
    if (!data || !size) return ENOENT;
    struct ShengFwMem *m = (struct ShengFwMem *)IOMalloc(sizeof *m);
    if (!m) return ENOMEM;
    m->data = (const uint8_t *)data;
    m->size = size;
    *handle = m;
    *out_size = size;
    return 0;
}

int sheng_fw_mem_read(void *handle, uint64_t offset, void *to, size_t length)
{
    const struct ShengFwMem *m = (const struct ShengFwMem *)handle;
    if (!m || offset > m->size || length > m->size - offset) return EIO;
    memcpy(to, m->data + offset, length);
    return 0;
}

void sheng_fw_mem_close(void *handle)
{
    if (handle) IOFree(handle, sizeof(struct ShengFwMem));
}

// ---- the boot_b segment form (m2381): the squashed images ride in a self-describing segment
// appended after the boot image inside boot_b (scripts/package-m2381-boot.py --adsp-mbn/--adsp-dtb-mbn),
// read in place through the ShengUfs partition exports, so the 30.5 MiB firmware never has to fit
// the payload's ESP. Entries are positional (0 = adsp, 1 = adsp_dtb; the script's fixed order).
// Weak imports: with ShengUfs absent or the segment not flashed the source reports ENXIO and the
// probe falls through to the other sources. The header's sha256 fields are forensics only — the
// kernel does not verify them; PAS authentication stays the integrity gate.
extern int native_ufs_part_find(const char *name, uint32_t *lun, uint64_t *first, uint64_t *blocks) __attribute__((weak_import));
extern int native_ufs_part_read(uint32_t lun, uint64_t lba, uint32_t blocks, void *dst) __attribute__((weak_import));

struct ShengFwUfs {
    uint32_t lun;
    uint64_t first;   // partition first LBA (4096 B units, as native_ufs_part_find returned it)
    uint64_t win;     // window start, bytes from the partition start
    uint64_t size;    // window bytes
    uint64_t cached;  // LBA held in block[] (~(uint64_t)0: none)
    uint8_t *block;
};

static int sheng_fw_ufs_open_image(const char *image, void **handle, uint64_t *out_size)
{
    if (!native_ufs_part_find || !native_ufs_part_read) return ENXIO;
    const unsigned entry_index = !strcmp(image, "adsp") ? 0 : !strcmp(image, "adsp_dtb") ? 1 : 2;
    if (entry_index == 2) return ENOENT;
    static const char *const slots[2] = {"boot_b", "boot_a"};
    uint8_t *page = (uint8_t *)IOMalloc(4096);
    if (!page) return ENOMEM;
    int rc = ENXIO;
    for (unsigned slot = 0; slot < 2 && rc == ENXIO; ++slot) {
        uint32_t lun = 0;
        uint64_t first = 0, blocks = 0;
        if (!native_ufs_part_find(slots[slot], &lun, &first, &blocks)) continue;
        if (native_ufs_part_read(lun, first, 1, page) != 1) {rc = EIO; continue;}
        if (memcmp(page, "ANDROID!", 8) || memcmp(page + 40, "\4\0\0\0", 4)) continue;  // boot image v4
        uint32_t kernel_size, ramdisk_size;
        memcpy(&kernel_size, page + 8, 4);
        memcpy(&ramdisk_size, page + 12, 4);
        // The segment follows the finished boot image: header page + kernel pages + ramdisk pages +
        // the v4 signature page — the same extent the ABL computes, mirrored from the packaging script.
        const uint64_t seg = 4096ull * (2 + ((uint64_t)kernel_size + 4095) / 4096 + ((uint64_t)ramdisk_size + 4095) / 4096);
        if ((seg >> 12) + 1 >= blocks) {rc = EFTYPE; continue;}
        if (native_ufs_part_read(lun, first + (seg >> 12), 1, page) != 1) {rc = EIO; continue;}
        if (memcmp(page, "M2381FW\x01", 8)) continue;  // not flashed (plain boot image): try the other slot
        uint64_t recorded_boot = 0;
        uint32_t header_size = 0, count = 0;
        memcpy(&header_size, page + 8, 4);
        memcpy(&count, page + 12, 4);
        memcpy(&recorded_boot, page + 16, 8);
        if (header_size != 4096 || count != 2 || recorded_boot != seg) {rc = EFTYPE; continue;}
        uint64_t offset = 0, bytes = 0;
        memcpy(&offset, page + 32 + entry_index * 48, 8);
        memcpy(&bytes, page + 32 + entry_index * 48 + 8, 8);
        if (!bytes || (offset & 4095) || seg + offset + bytes > (blocks << 12)) {rc = EFTYPE; continue;}
        struct ShengFwUfs *p = (struct ShengFwUfs *)IOMalloc(sizeof *p);
        if (!p) {rc = ENOMEM; break;}
        bzero(p, sizeof *p);
        p->block = (uint8_t *)IOMalloc(4096);
        if (!p->block) {IOFree(p, sizeof *p); rc = ENOMEM; break;}
        p->lun = lun;
        p->first = first;
        p->win = seg + offset;
        p->size = bytes;
        p->cached = ~(uint64_t)0;
        *handle = p;
        *out_size = bytes;
        rc = 0;
    }
    IOFree(page, 4096);
    return rc;
}

int sheng_fw_ufs_read(void *handle, uint64_t offset, void *to, size_t length)
{
    struct ShengFwUfs *p = (struct ShengFwUfs *)handle;
    if (!p || !p->block || offset > p->size || length > p->size - offset) return EIO;
    uint8_t *out = (uint8_t *)to;
    while (length) {
        const uint64_t abs = p->win + offset;
        const uint32_t in = (uint32_t)(abs & 4095);
        if (!in && length >= 4096) {  // whole blocks straight into the caller's buffer
            const uint32_t blocks = (uint32_t)(length >> 12);
            if (!native_ufs_part_read(p->lun, p->first + (abs >> 12), blocks, out)) return EIO;
            const size_t done = (size_t)blocks << 12;
            out += done; offset += done; length -= done;
            continue;
        }
        const uint64_t lba = p->first + (abs >> 12);
        if (p->cached != lba) {
            if (!native_ufs_part_read(p->lun, lba, 1, p->block)) return EIO;
            p->cached = lba;
        }
        const size_t piece = 4096 - in < length ? 4096 - in : length;
        memcpy(out, p->block + in, piece);
        out += piece; offset += piece; length -= piece;
    }
    return 0;
}

void sheng_fw_ufs_close(void *handle)
{
    struct ShengFwUfs *p = (struct ShengFwUfs *)handle;
    if (!p) return;
    if (p->block) IOFree(p->block, 4096);
    IOFree(p, sizeof *p);
}
