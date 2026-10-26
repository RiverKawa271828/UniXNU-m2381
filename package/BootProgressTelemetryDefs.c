// SPDX-License-Identifier: MIT
// Zero-value stand-ins for the boot-progress telemetry providers this board
// deliberately leaves off (NATIVE_LEGACY_DISPLAY=n — no legacy display
// qualification, no touch, no Adreno, no cpufreq, no Wi-Fi): the boot_progress
// page renders zeros for them, which is exactly what Apple's linker binds for
// the same weak references. This ld64 (956) instead errors on unresolved weak
// references, so the zeros must be linked in as data.
// The set is the resolved dangling list of the real libBootProgress.a against
// the m2381 kernel and component archives (2026-10-26, kernel ee3255a8 era).
// If kits/sheng/BootProgress.c grows a telemetry reference that still links,
// the kernel link will name it; add it here with the declaration's type.
#include <stdint.h>

// Functions the sheng monitor surfaces normally provide (BootLog.c and the
// cpufreq poller); no-ops keep the weak callers on their NULL-guard paths.
void boot_log_tick(unsigned unused) { (void)unused; }
void boot_process_capture(void) {}
void boot_process_snapshot(void) {}
void boot_ui_trace_snapshot(unsigned phase) { (void)phase; }
unsigned boot_ui_trace_role_rows(unsigned role, char rows[][120], unsigned cap, unsigned depth) {
    (void)role; (void)rows; (void)cap; (void)depth; return 0;
}
void sheng_cpufreq_poll(void) {}

// Boot process and UI trace state
volatile unsigned boot_process_attempts = 0;
volatile unsigned boot_process_busy = 0;
volatile unsigned boot_process_passes = 0;
volatile unsigned boot_process_seen = 0;
char boot_process_rows[10][120] = {{0}};
volatile unsigned boot_ui_trace_index = 0;
char boot_ui_trace_label[120] = {0};
volatile unsigned boot_ui_trace_phase = 0;
unsigned boot_ui_trace_ready = 0;
char boot_ui_trace_rows[14][120] = {{0}};

// Adreno (NATIVE_ADRENO=n)
volatile uint32_t native_adreno_audit_attr = 0;
volatile uint64_t native_adreno_audit_ticks = 0;
volatile uint64_t native_adreno_cache_stats[5] = {0};
volatile uint32_t native_adreno_coherence[8] = {0};
volatile uint64_t native_adreno_reassert_ticks = 0;
volatile uint32_t native_adreno_wc_audit[6] = {0};
volatile uint32_t native_adreno_wc_distrusted = 0;

// cpufreq (sheng-cpufreq off)
char native_cpufreq_row[120] = {0};
volatile uint32_t native_cpufreq_stage = 0;

// GOP GPU hand-off counters (sheng-fb-gpu off)
volatile uint64_t native_gop_gpu_offers = 0;
volatile uint64_t native_gop_gpu_completions = 0;
volatile uint64_t native_gop_gpu_failures = 0;
volatile uint64_t native_gop_gpu_abandoned = 0;
volatile uint64_t native_gop_virtual = 0;

// HID input (offline-hid off)
volatile uint32_t native_hid_input_events[8] = {0};
volatile int native_hid_input_results[8] = {0};

// Legacy display client (NATIVE_LEGACY_DISPLAY=n)
volatile uint32_t native_legacy_client_calls = 0;
char native_legacy_client_class[64] = {0};
volatile int native_legacy_client_pid = 0;
volatile int native_legacy_client_status = 0;
volatile uint32_t native_legacy_client_type = 0;
volatile uint64_t native_legacy_copy_bytes_last = 0;
volatile uint64_t native_legacy_copy_bytes_sum = 0;
volatile uint64_t native_legacy_copy_last = 0;
volatile uint64_t native_legacy_copy_max = 0;
volatile uint64_t native_legacy_copy_n = 0;
volatile uint64_t native_legacy_copy_sum = 0;
volatile uint64_t native_legacy_early_retires = 0;
volatile uint64_t native_legacy_early_failures = 0;
volatile uint64_t native_legacy_frame_color_counts[8][4] = {{0}};
volatile uint64_t native_legacy_frame_color_other[8] = {0};
volatile uint32_t native_legacy_frame_colors[8][4] = {{0}};
volatile uint32_t native_legacy_frame_count = 0;
volatile uint32_t native_legacy_frame_kind[32] = {0};
volatile uint64_t native_legacy_frame_stats[32][5] = {{0}};
volatile uint32_t native_legacy_frame_time[32] = {0};
volatile uint64_t native_legacy_gop_bytes = 0;
volatile uint64_t native_legacy_gop_physical = 0;
volatile uint64_t native_legacy_gop_virtual = 0;
volatile uint32_t native_legacy_gpu_fallbacks = 0;
volatile uint32_t native_legacy_gpu_last_status = 0;
volatile uint32_t native_legacy_guard_slot = 0;
volatile uint32_t native_legacy_pm_callbacks = 0;
volatile uint32_t native_legacy_pm_calls = 0;
volatile uint32_t native_legacy_pm_stage = 0;
volatile uint32_t native_legacy_prepare_attempts = 0;
volatile uint32_t native_legacy_prepare_calls = 0;
volatile uint32_t native_legacy_prepare_reason = 0;
char native_legacy_rej_class[32] = {0};
volatile uint32_t native_legacy_rej_reason = 0;
volatile uint32_t native_legacy_rej_size[2] = {0};
volatile uint32_t native_legacy_rej_state[3] = {0};
volatile uint64_t native_legacy_rej_surface[7] = {0};
volatile uint64_t native_legacy_rej_surfaces[4] = {0};
volatile uint32_t native_legacy_retirement_calls = 0;
volatile uint32_t native_legacy_stage = 0;
volatile uint32_t native_legacy_swap_accepted_count = 0;
volatile uint32_t native_legacy_swap_rejected_count = 0;
volatile uint32_t native_legacy_swap_validation_calls = 0;
volatile uint32_t native_legacy_swap_validation_reason = 0;
volatile uint32_t native_legacy_swap_validation_result = 0;
volatile uint64_t native_legacy_transfer_bytes = 0;
volatile uint32_t native_legacy_transfer_calls = 0;
volatile int native_legacy_transfer_status = 0;

// Touch (sheng-touch off; the touch lane provides these when it lands)
volatile uint32_t native_touch_seq = 0;
volatile uint32_t native_touch_count = 0;
char native_touch_rows[4][120] = {{0}};
volatile unsigned native_touch_stage_req = 0;
volatile int native_touch_xs[12] = {0};
volatile int native_touch_ys[12] = {0};
