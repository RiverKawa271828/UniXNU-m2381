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

// Functions the sheng monitor surfaces normally provide; no-ops keep the weak
// callers on their NULL-guard paths. boot_log_tick is NOT stubbed here: the
// real BootLog.o (the sheng-log=1 writer, compiled into libBootProgress.a
// since 2026-10-26) provides it — a stub here would collide with it.
void boot_process_capture(void) {}
void boot_process_snapshot(void) {}
void boot_ui_trace_snapshot(unsigned phase) { (void)phase; }
unsigned boot_ui_trace_role_rows(unsigned role, char rows[][120], unsigned cap, unsigned depth) {
    (void)role; (void)rows; (void)cap; (void)depth; return 0;
}
void sheng_cpufreq_poll(void) {}

// The same for BootLog.c's optional surfaces (no legacy display, no touch/
// Adreno/Wi-Fi probes, no BootReset lane on this board): NULL-guarded text
// exporters that only the log's [sections] would call.
unsigned boot_ui_trace_hot_rows(char rows[][120], unsigned cap) {
    (void)rows; (void)cap; return 0;
}
int native_ufs_extra_fault(uint32_t *fault) { (void)fault; return 0; }
unsigned native_legacy_properties_now(char *out, unsigned cap) { (void)out; (void)cap; return 0; }
unsigned native_legacy_clients_dump(char *out, unsigned cap) { (void)out; (void)cap; return 0; }
unsigned native_legacy_swap_timeline(char *out, unsigned cap) { (void)out; (void)cap; return 0; }
unsigned native_legacy_prepare_report(char *out, unsigned cap) { (void)out; (void)cap; return 0; }
unsigned native_legacy_state_words(char *out, unsigned cap) { (void)out; (void)cap; return 0; }
// The fastboot reset kit (BootReset.c) is not compiled on this board; a
// refused probe keeps every sheng-autoreset path on its "skipped" branch.
int boot_reset_probe(char *out, unsigned cap) { (void)out; (void)cap; return -1; }
int boot_reset_bootloader(char *out, unsigned cap) { (void)out; (void)cap; return -1; }
int boot_reset_mark_bootloader(char *out, unsigned cap) { (void)out; (void)cap; return -1; }
int boot_reset_watchdog(uint32_t seconds, char *out, unsigned cap) {
    (void)seconds; (void)out; (void)cap; return -1;
}

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

// --- BootLog.c's families (the sheng-log=1 writer joined libBootProgress.a on
// 2026-10-26; everything below is the rest of its dangling weak set against
// this lane's providers, same rule as above: the qualified probe replaces
// these when its topic lands). Types match BootLog.c's extern declarations
// byte for byte — the consumers index these arrays.

// kern_exec-side counters this lane's patches never added (guarded sections
// of the log's compose(); zeros mean the section never ran).
volatile int native_cryptex_os_stage = 0;
volatile int native_cryptex_os_status = 0;
volatile int native_gestalt_cache_status = 0;
volatile int native_ls_store_status = 0;

// Buttons and backlight (no ButtonProbe/AppleARMBacklight bring-up lane)
volatile int32_t native_buttons_stats[10] = {0};
volatile int32_t native_backlight_stats[16] = {0};
volatile int32_t native_backlight_request[6] = {0};

// Wi-Fi (no WifiProbe lane)
volatile uint32_t native_wifi_stats[29] = {0};
volatile uint32_t native_wifi_dump[108] = {0};
volatile uint32_t native_wifi_pmic[472] = {0};
volatile uint32_t native_wifi_ep[16] = {0};
volatile uint32_t native_wifi_pon[12] = {0};
volatile uint32_t native_wifi_cfg[32] = {0};
volatile uint32_t native_wifi_chip[16] = {0};
volatile uint32_t native_wifi_ev[48] = {0};
volatile uint32_t native_wifi_ldo[24] = {0};
volatile uint32_t native_wifi_mhi[16] = {0};
volatile uint32_t native_wifi_mhi_ms[8] = {0};
char native_wifi_text[512][112] = {{0}};
volatile uint32_t native_wifi_text_n = 0;
char native_wifi_note[128][112] = {{0}};
volatile uint32_t native_wifi_note_n = 0;
struct nw_wifi_stats_shape { uint32_t stage, scans, frames, beacons, bss_seen; int last_err; };
struct nw_wifi_stats_shape nw_wifi_stats = {0};
volatile uint64_t nw_wifi_where[4] = {0};

// Display controller and panel (no DisplayTimingProbe lane)
volatile uint32_t native_dpu_stats[20] = {0};
volatile uint32_t native_dpu_pipes[54] = {0};

// Safari/lsd failed-lookup log: the kernel's native-lookup-trace patch
// defines these itself (vfs_lookup.c); nothing to stub here.

// Audio DSP / audio framework / battery (no AdspProbe/ShengBattery lanes)
volatile int32_t native_adsp_stats[16] = {0};
char native_adsp_text[96] = {0};
volatile int32_t native_audio_stats[16] = {0};
volatile int32_t native_battery_stats[16] = {0};

// UI swipe timing (no boot-ui-focus trace lane); 17: the [swipe2] row reads
// slot 16 (the "heavy" gesture second) — the fork's extern under-declared it.
volatile uint32_t native_swipe_stats[17] = {0};

// Touch (the rest of BootLog.c's touch sections)
volatile int32_t native_touch_strokes[16][7] = {{0}};
volatile uint32_t native_touch_stroke_count = 0;
volatile int32_t native_touch_extent[4] = {0};
volatile uint32_t native_touch_jitter[3] = {0};
volatile uint32_t native_touch_hold[14] = {0};
volatile uint32_t native_touch_edge_stats[4] = {0};
volatile uint32_t native_touch_hid_multi[3] = {0};

// Adreno GPU diagnostics (NATIVE_ADRENO=n; the GPU chain's topic returns these)
volatile uint32_t native_adreno_fence_wait[8] = {0};
volatile uint32_t native_adreno_stall[24] = {0};
volatile uint32_t native_adreno_stall_mem[59] = {0};
volatile uint32_t native_adreno_unstick[15] = {0};
volatile uint64_t native_adreno_wait_outer[4] = {0};
volatile uint32_t native_adreno_export_stats[4] = {0};
volatile uint32_t native_adreno_method_stats[20][4] = {{0}};
volatile uint64_t native_adreno_vm_phase_us[2][8] = {{0}};
volatile uint32_t native_adreno_map_fail[7][2] = {{0}};
volatile uint32_t native_adreno_pool_stats[8] = {0};
volatile uint32_t native_adreno_submit_ibs[4] = {0};
struct native_adreno_client_record_shape { char name[20]; uint32_t opens, refused, closes, slot, peak_mib, last_refusal; };
struct native_adreno_client_record_shape native_adreno_client_log[8] = {{0}};
struct native_adreno_client_text_shape { char name[20]; char text[64]; };
struct native_adreno_client_text_shape native_adreno_client_text[4] = {{0}};
struct native_adreno_asker_record_shape { char name[20]; uint32_t reads; };
struct native_adreno_asker_record_shape native_adreno_metal_askers[12] = {{0}};
volatile uint32_t native_adreno_mount_fail[4] = {0};
volatile uint32_t native_adreno_window_overflow[4][3] = {{0}};
volatile uint32_t native_adreno_client_stats[5][6] = {{0}};
char native_gpu_coherence_row[120] = {0};
volatile uint64_t native_gpu_idle_sleeps = 0;
volatile uint64_t native_gpu_idle_spins = 0;
volatile uint32_t native_adreno_coherent_skips[4] = {0};
volatile uint32_t native_adreno_io_coherent = 0;
uint32_t native_gpu_perf_vote[2] = {0};
volatile uint32_t native_adreno_pool_status = 0;
volatile uint32_t native_adreno_pool_wc = 0;
volatile uint64_t native_adreno_fence_phys = 0;
volatile uint32_t native_adreno_ring_log[4][4 + 112] = {{0}};
volatile uint32_t native_adreno_ring_log_count = 0;
volatile uint32_t native_adreno_ib_log[4][4 + 28] = {{0}};
volatile uint32_t native_adreno_ib_log_count = 0;
char native_adreno_metal_rows[48][96] = {{0}};
volatile uint32_t native_adreno_view_diag[6] = {0};
volatile uint64_t native_adreno_import_diag[10] = {0};
volatile uint32_t native_adreno_import_stage = 0;
volatile uint64_t native_adreno_import_live[3 + 8 * 4] = {0};
volatile uint32_t native_adreno_import_persistent[2] = {0};
volatile uint64_t native_adreno_import_fail_pa = 0;
volatile uint64_t native_adreno_import_fail_offset = 0;
int (*native_adreno_dram_read32)(uint64_t, uint32_t *) = 0;
int (*native_adreno_cached_read32)(uint64_t, uint32_t *) = 0;

// Scanout-copy wait statistics (no GOP presenter lane)
volatile uint64_t native_gop_wait_stats[7] = {0};
