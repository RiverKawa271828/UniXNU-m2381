// SPDX-License-Identifier: BSD-2-Clause-Patent
// r64 cache-global audit, dynamic leg: the 0xf00/0xf1 garbage family lives in
// UIKitCore's lazily-cached singleton globals, and every candidate found so far
// sits in UIKitCore's __DATA_DIRTY (bgTC slot 0x1F48CE5E0, mainScreen singleton
// 0x1F48D5550, their locks). The file image is all-zero there — the poison is
// written at runtime. This probe watches the whole __DATA_DIRTY window in the
// target process's shared region every 2 s and publishes, into the diagnostic
// page's ext rows 4-7, when each slot turns nonzero and to what value: the
// log-slot t-series answers "when did 0xf1 appear and in which slot first".
// Gate: uikit-cache-probe=1 (default off; the scan is diagnostic work the
// stock boot path must not pay for). Compiled against the kernel's own
// startup.o command record (the BootFaultProbe precedent: the private task /
// vm_map ABI of this exact source revision, not a portable guess).
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <pexpert/pexpert.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/sched.h>
#include <kern/task.h>
#include <kern/misc_protos.h>
#include <vm/vm_map.h>

// Exact private process ABI from this source revision's proc.h/proc_internal.h
// (the BootProcessProbe precedent — do not mix header type universes).
struct proc;typedef struct proc *proc_t;
char *proc_best_name(proc_t);
int proc_pid(proc_t);
task_t proc_task(proc_t);
void proc_iterate(unsigned,int (*)(proc_t,void *),void *,int (*)(proc_t,void *),void *);
#define PROC_RETURNED 0
#define PROC_ALLPROCLIST (1U<<0)
#define PROC_NOWAITTRANS (1U<<2)

extern char boot_progress_ext[8][48];

// Unslid UIKitCore (iPad7,1 21H461) __DATA_DIRTY and the disease slots inside
// it, from the image's LC_SEGMENT_64 (verified by temp/audit64-slots.py).
#define UK_DIRTY_BASE 0x1f489fef0ULL
#define UK_DIRTY_SIZE 0x39958ULL
#define SLOT_MAINSCREEN 0x1f48d5550ULL  // __MergedGlobals+0x20, [UIScreen mainScreen] fast path
#define SLOT_BGTC       0x1f48ce5e0ULL  // __backgroundThreadFallbackTraitCollection
#define SLOT_MSTC_LOCK  0x1f48cf938ULL  // __UIMainScreenTraitCollectionLock

// Pointers in this cache are >= 0x1_80000000 unslid; anything small is garbage.
#define GARBAGE_LIMIT 0x1000000ULL

static char probe_target[32] = "SpringBoard";
static uint64_t window_cur[UK_DIRTY_SIZE / 8], window_prev[UK_DIRTY_SIZE / 8];
static volatile unsigned probe_ticks, probe_hits, probe_status = 1;
static unsigned first_garbage_tick, garbage_total;
static uint64_t first_garbage_off, first_garbage_val;
static unsigned last_change_tick;
static uint64_t last_change_off, last_change_val;
static unsigned prev_valid;

static void put(unsigned row, char *buf, size_t cap)
{
    for (unsigned i = 0; i < 47; ++i) boot_progress_ext[row][i] = buf[i] ? buf[i] : ' ';
    boot_progress_ext[row][47] = 0;
}

static int capture(proc_t p, void *arg)
{
    (void)arg;
    if (strcmp(proc_best_name(p), probe_target) != 0) return PROC_RETURNED;
    task_t task = proc_task(p);
    if (!task || !task_lock_try(task)) { probe_status = 2; return PROC_RETURNED; }
    uint64_t slide = (uint64_t)task->task_shared_region_slide;
    vm_map_t map = get_task_map(task);
    task_unlock(task);
    if (!map) { probe_status = 3; return PROC_RETURNED; }

    kern_return_t kr = vm_map_read_user(map, (vm_map_offset_t)(UK_DIRTY_BASE + slide),
                                        window_cur, UK_DIRTY_SIZE);
    ++probe_ticks;
    if (kr != KERN_SUCCESS) { probe_status = 4; return PROC_RETURNED; }
    probe_status = 0;
    ++probe_hits;

    const unsigned n = (unsigned)(UK_DIRTY_SIZE / 8);
    unsigned nonzero = 0, garbage = 0;
    for (unsigned i = 0; i < n; ++i) {
        uint64_t v = window_cur[i];
        if (v) ++nonzero;
        if (v && v < GARBAGE_LIMIT) {
            ++garbage;
            if (!garbage_total) {
                first_garbage_tick = probe_ticks;
                first_garbage_off = (uint64_t)i * 8;
                first_garbage_val = v;
            }
        }
        if (prev_valid && v != window_prev[i]) {
            last_change_tick = probe_ticks;
            last_change_off = (uint64_t)i * 8;
            last_change_val = v;
        }
    }
    memcpy(window_prev, window_cur, sizeof window_prev);
    prev_valid = 1;
    garbage_total += garbage;

    char buf[64];
    snprintf(buf, sizeof buf, "UKC k%u st%u +%llx n%u g%u",
             probe_ticks, probe_status, slide, nonzero, garbage);
    put(4, buf, sizeof buf);
    snprintf(buf, sizeof buf, "M%llx B%llx",
             window_cur[(SLOT_MAINSCREEN + slide - UK_DIRTY_BASE) / 8],
             window_cur[(SLOT_BGTC + slide - UK_DIRTY_BASE) / 8]);
    put(5, buf, sizeof buf);
    snprintf(buf, sizeof buf, "G k%u +%llx v%llx",
             first_garbage_tick, first_garbage_off, first_garbage_val);
    put(6, buf, sizeof buf);
    snprintf(buf, sizeof buf, "C k%u +%llx v%llx",
             last_change_tick, last_change_off, last_change_val);
    put(7, buf, sizeof buf);
    return PROC_RETURNED;
}

static void monitor(void *arg, wait_result_t result)
{
    (void)arg;(void)result;
    thread_set_thread_name(current_thread(), "uikit_cache_probe");
    for (;;) {
        proc_iterate(PROC_ALLPROCLIST | PROC_NOWAITTRANS, capture, NULL, NULL, NULL);
        assert_wait_timeout((event_t)&probe_ticks, THREAD_UNINT, 2000, NSEC_PER_MSEC);
        thread_block(THREAD_CONTINUE_NULL);
    }
}

void native_uikit_cache_probe_start(void);
void native_uikit_cache_probe_start(void)
{
    unsigned enable = 0;
    if (!PE_parse_boot_argn("uikit-cache-probe", &enable, sizeof(enable)) || enable != 1) return;
    PE_parse_boot_argn("uikit-cache-proc", probe_target, sizeof probe_target);
    probe_target[sizeof probe_target - 1] = 0;
    thread_t thread;
    if (kernel_thread_start_priority(monitor, 0, BASEPRI_KERNEL, &thread) == KERN_SUCCESS)
        thread_deallocate(thread);
}
