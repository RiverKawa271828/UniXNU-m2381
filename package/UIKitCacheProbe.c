// SPDX-License-Identifier: BSD-2-Clause-Patent
// r65 cache-global audit, dynamic leg v2. r64 established two facts and one
// bug: the 0xf1/0xf00 garbage sits in UIKitCore's lazily-cached singleton
// globals (bgTC slot 0x1F48CE5E0, mainScreen singleton 0x1F48D5550), the
// poison is ALREADY in place when SpringBoard is first scanned (t ~= 20 s,
// 21003 nonzero + 44 small-value slots), and the r64 probe thread died on
// its own first capture because row 5's index added the slide a second time
// (the read already starts at UK_DIRTY_BASE + slide) — a ~45M-slot OOB load
// that killed the thread between put(4) and put(5) and lost the t-series.
// v2 therefore sweeps EVERY task that has the dyld shared cache mapped
// (slide != 0): UIKitCore's __DATA_DIRTY is file-backed-clean (all-zero in
// the image) until a process runs its fixups/COW, so the first process whose
// disease slots read nonzero-small names the writer's host. Maps are taken
// with get_task_map_reference (safe against crash-loop teardown, which the
// raw get_task_map + immediate read of r64 got away with only by luck).
// Rows (published once per 2 s round by the monitor, not per capture):
// X4 "UKC k<round> p<procs w/ dirty data> n<nonzero> g<small-value>" aggregate;
// X5 first disease-slot event (who poisoned bgTC/mainScreen first);
// X6 latest disease-slot event; X7 first any-slot small-value event.
// Gate: uikit-cache-probe=1; uikit-cache-proc=<name> pins the r64
// single-process mode (aggregate rows then describe that one process).
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

// Pointers in this cache are >= 0x1_80000000 unslid; anything small is garbage.
#define GARBAGE_LIMIT 0x1000000ULL

static char probe_target[32];
static uint64_t window_cur[UK_DIRTY_SIZE / 8];
static volatile unsigned probe_round, probe_status = 1;
static unsigned probe_readfails;
static unsigned first_disease_round, last_disease_round;
static char first_disease_proc[16], last_disease_proc[16];
static uint64_t first_disease_b, first_disease_m, last_disease_b, last_disease_m;
static unsigned first_garbage_round;
static char first_garbage_proc[16];
static uint64_t first_garbage_off, first_garbage_val;
static unsigned agg_procs, agg_nonzero, agg_garbage;

static void put(unsigned row, char *buf, size_t cap)
{
    for (unsigned i = 0; i < 47; ++i) boot_progress_ext[row][i] = buf[i] ? buf[i] : ' ';
    boot_progress_ext[row][47] = 0;
}

static void note_disease(const char *name, uint64_t b, uint64_t m)
{
    if (!first_disease_round) {
        first_disease_round = probe_round;
        strlcpy(first_disease_proc, name, sizeof first_disease_proc);
        first_disease_b = b; first_disease_m = m;
    }
    last_disease_round = probe_round;
    strlcpy(last_disease_proc, name, sizeof last_disease_proc);
    last_disease_b = b; last_disease_m = m;
}

static void note_garbage(const char *name, uint64_t off, uint64_t val)
{
    if (!first_garbage_round) {
        first_garbage_round = probe_round;
        strlcpy(first_garbage_proc, name, sizeof first_garbage_proc);
        first_garbage_off = off; first_garbage_val = val;
    }
}

static int capture(proc_t p, void *arg)
{
    (void)arg;
    const char *name = proc_best_name(p);
    if (probe_target[0] && strcmp(name, probe_target) != 0) return PROC_RETURNED;
    task_t task = proc_task(p);
    if (!task) return PROC_RETURNED;
    task_lock(task);
    uint64_t slide = (uint64_t)task->task_shared_region_slide;
    vm_map_t map = get_task_map_reference(task);
    task_unlock(task);
    if (!map || !slide) return PROC_RETURNED;  // no shared cache = no UIKit window

    kern_return_t kr = vm_map_read_user(map, (vm_map_offset_t)(UK_DIRTY_BASE + slide),
                                        window_cur, UK_DIRTY_SIZE);
    vm_map_deallocate(map);
    if (kr != KERN_SUCCESS) { probe_status = 4; ++probe_readfails; return PROC_RETURNED; }
    probe_status = 0;

    const unsigned n = (unsigned)(UK_DIRTY_SIZE / 8);
    unsigned nonzero = 0, garbage = 0;
    uint64_t b = 0, m = 0;
    for (unsigned i = 0; i < n; ++i) {
        uint64_t v = window_cur[i];
        if (!v) continue;
        ++nonzero;
        if (v < GARBAGE_LIMIT) note_garbage(name, (uint64_t)i * 8, v), ++garbage;
    }
    // Disease slots live at fixed offsets FROM UK_DIRTY_BASE (no slide — the
    // r64 OOB: the read above already starts at UK_DIRTY_BASE + slide).
    if (SLOT_BGTC >= UK_DIRTY_BASE && SLOT_MAINSCREEN >= UK_DIRTY_BASE &&
        SLOT_BGTC < UK_DIRTY_BASE + UK_DIRTY_SIZE &&
        SLOT_MAINSCREEN < UK_DIRTY_BASE + UK_DIRTY_SIZE) {
        b = window_cur[(SLOT_BGTC - UK_DIRTY_BASE) / 8];
        m = window_cur[(SLOT_MAINSCREEN - UK_DIRTY_BASE) / 8];
        if ((b && b < GARBAGE_LIMIT) || (m && m < GARBAGE_LIMIT))
            note_disease(name, b, m);
    }

    agg_procs += (nonzero != 0);
    agg_nonzero += nonzero;
    agg_garbage += garbage;
    return PROC_RETURNED;
}

static void monitor(void *arg, wait_result_t result)
{
    (void)arg;(void)result;
    thread_set_thread_name(current_thread(), "uikit_cache_probe");
    for (;;) {
        agg_procs = agg_nonzero = agg_garbage = probe_readfails = 0;
        proc_iterate(PROC_ALLPROCLIST | PROC_NOWAITTRANS, capture, NULL, NULL, NULL);
        ++probe_round;
        char buf[64];
        snprintf(buf, sizeof buf, "UKC k%u p%u n%u g%u f%u",
                 probe_round, agg_procs, agg_nonzero, agg_garbage, probe_readfails);
        put(4, buf, sizeof buf);
        if (first_disease_round)
            snprintf(buf, sizeof buf, "D %.12s k%u B%llx M%llx",
                     first_disease_proc, first_disease_round,
                     first_disease_b, first_disease_m);
        else
            snprintf(buf, sizeof buf, "D -");
        put(5, buf, sizeof buf);
        if (last_disease_round)
            snprintf(buf, sizeof buf, "L %.12s k%u B%llx M%llx",
                     last_disease_proc, last_disease_round,
                     last_disease_b, last_disease_m);
        else
            snprintf(buf, sizeof buf, "L -");
        put(6, buf, sizeof buf);
        if (first_garbage_round)
            snprintf(buf, sizeof buf, "G %.12s k%u +%llx v%llx",
                     first_garbage_proc, first_garbage_round,
                     first_garbage_off, first_garbage_val);
        else
            snprintf(buf, sizeof buf, "G -");
        put(7, buf, sizeof buf);
        assert_wait_timeout((event_t)&probe_round, THREAD_UNINT, 2000, NSEC_PER_MSEC);
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
