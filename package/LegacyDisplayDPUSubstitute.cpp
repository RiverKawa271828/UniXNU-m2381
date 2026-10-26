// SPDX-License-Identifier: BSD-2-Clause-Patent
// Zero substitutes for the display driver's direct-scanout diagnostic hooks.
// NativeLegacyDisplay.cpp declares native_ufs_dpu_map/native_ufs_dpu_state as
// weak imports (Apple's linker binds unresolved weak symbols to zero; the
// driver guards every use with !&symbol and the state's bit 31). This board's
// cctools ld64 errors on unresolved weak references instead (the r35 wall),
// and sheng — whose author builds with Apple's ld — never needed a
// definition. This board runs no sheng-dpu lane, so the substitutes stay
// zero and the guards keep the diagnostic permanently off.
#include <stdint.h>

extern "C" uint32_t native_ufs_dpu_map(unsigned slot, const uint64_t *pages, unsigned count) {
    (void)slot; (void)pages; (void)count; return 0;
}
extern "C" volatile uint32_t native_ufs_dpu_state = 0;
