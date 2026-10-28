// SPDX-License-Identifier: BSD-2-Clause-Patent
// r69 cache-global audit, dynamic leg v4: three-window pinned scan.
//
// History that got us here: r66 wedged CPU1's AP bring-up (a failing
// cross-task vm_map_read_user inside the vm_map_switch window + a map
// refcount double-deallocate); r67's A/B proved the probe thread was the
// trigger; r68's fixed probe survived and produced the decisive negative —
// 165 rounds scanning 196 processes' UIKitCore __DATA_DIRTY while
// SpringBoard crashed 465 times on the same objc_retain(0xf1) at unslid
// 0x1800F5FAC, and the watched disease slots NEVER held a small value.
// The r63 "bgTC slot is poisoned" inference is therefore dead: the garbage
// never lives in __DATA_DIRTY.
//
// r68 postmortem disassembly pinned the real chain instruction-exact:
// __UIGetCurrentFallbackTraitCollection loads its receiver from
// 0x1f049f1c8, calls _objc_msgSend$mainScreen (SEL slot 0x1f046e1d8, IMP
// slot 0x1f00eb808), and the dispatch dies with FAR=0xf1 inside objc's
// initialize wrapper. ALL THREE slots sit in UIKitCore __DATA_CONST
// (0x1f00e6440..0x1f04b9920, LC-parsed) — a segment the r64-r68 probes
// never watched. The file image there is clean chain encodings, so the
// poison, if real, is in the RUNTIME BOUND values (dyld binds / COW).
//
// v4 therefore pins the default target to SpringBoard (the crashing
// process) and reads THREE windows of its address space every 2 s:
// __DATA_DIRTY, __DATA, __DATA_CONST. Rows: X4 carries the three exact
// suspect slots' current values (IMP, receiver, SEL); X5/X6/X7 carry the
// first small-value (<0x1000000) event seen in DATA_CONST / DATA / DIRTY
// (round, offset, value). Gate: uikit-cache-probe=1; uikit-cache-proc=
// retargets, and uikit-cache-proc=* restores the r68 all-process sweep
// (DIRTY window only — three windows across every process is too much
// copyin). Warmup 6 rounds; a failed read goes silent for only 3 rounds
// (r68's 100-round breaker blinded the probe for 200 s after one
// transient failure at k7).
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
extern char boot_progress_ext_wide[2][112]; // W0/W1 rows in BootLog; free (ADRENO=n)

// UIKitCore (iPad7,1 21H461) segments, LC-parsed from the image macho.
#define UK_DIRTY_BASE 0x1f489fef0ULL
#define UK_DIRTY_SIZE 0x39958ULL
#define UK_DATA_BASE  0x1ed7c26e0ULL
#define UK_DATA_SIZE  0x7b438ULL
#define UK_CONST_BASE 0x1f00e6440ULL
#define UK_CONST_SIZE 0x3d34e0ULL
#define SLOT_RECV 0x1f049f1c8ULL   // receiver loaded by __UIGetCurrentFallbackTraitCollection
#define SLOT_IMPF 0x1f00eb808ULL   // _objc_msgSend$mainScreen IMP slot (br target)
#define SLOT_SELP 0x1f046e1d8ULL   // _objc_msgSend$mainScreen SEL slot
#define SLOT_BGTC 0x1f48ce5e0ULL   // __backgroundThreadFallbackTraitCollection lazy slot (DIRTY)
#define SLOT_MAINSCREEN 0x1f48d5550ULL // [UIScreen mainScreen] fast path (DIRTY)
#define SLOT_SCREENCACHE 0x1f48d59f8ULL // __UIGet screen cache 2, page-cache branch premise (DIRTY)
#define SLOT_GATECHK1 0x1f48ce5f0ULL   // __UIGet cmn #-1 gate slot (DIRTY)
#define SLOT_GATECHK2 0x1f48ce5f8ULL   // __UIGet w19 gate slot == scene-branch X19 (DIRTY)

// Pointers in this cache are >= 0x1_80000000 unslid; anything small is garbage.
#define GARBAGE_LIMIT 0x1000000ULL

static char probe_target[32] = "SpringBoard";
static uint64_t win_dirty[UK_DIRTY_SIZE / 8];
static uint64_t win_data[UK_DATA_SIZE / 8];
static uint64_t win_const[UK_CONST_SIZE / 8];
static volatile unsigned probe_round, probe_status = 1;
static unsigned probe_readfails;
static unsigned probe_silence_until;
static unsigned first_small_round[3];
static uint64_t first_small_off[3], first_small_val[3];
static unsigned win_fresh;
static unsigned agg_procs, agg_nonzero, agg_garbage;

static void put(unsigned row, char *buf, size_t cap)
{
    for (unsigned i = 0; i < 47; ++i) boot_progress_ext[row][i] = buf[i] ? buf[i] : ' ';
    boot_progress_ext[row][47] = 0;
}

static void note_small(unsigned w, unsigned round, uint64_t off, uint64_t val)
{
    if (!first_small_round[w]) {
        first_small_round[w] = round;
        first_small_off[w] = off;
        first_small_val[w] = val;
    }
}

// Read one window under the protection pre-gate. Returns 0 on success,
// 1 if the gate skipped it (region not mapped readable yet), 2 on read fail.
static int read_window(vm_map_t map, uint64_t base, uint64_t size, uint64_t slide, uint64_t *buf)
{
    if (!vm_map_check_protection(map, (vm_map_offset_t)(base + slide),
                                 (vm_map_offset_t)(base + slide + size),
                                 VM_PROT_READ))
        return 1;
    if (vm_map_read_user(map, (vm_map_offset_t)(base + slide), buf, size) != KERN_SUCCESS)
        return 2;
    return 0;
}

static void scan_window(unsigned w, uint64_t *buf, unsigned nslots)
{
    for (unsigned i = 0; i < nslots; ++i) {
        uint64_t v = buf[i];
        if (v && v < GARBAGE_LIMIT) note_small(w, probe_round, (uint64_t)i * 8, v);
    }
}

static int capture(proc_t p, void *arg)
{
    (void)arg;
    const char *name = proc_best_name(p);
    if (strcmp(name, probe_target) != 0) return PROC_RETURNED;
    task_t task = proc_task(p);
    if (!task) return PROC_RETURNED;
    // get_task_map_reference takes the task lock ITSELF (bsd_kern.c:386) —
    // never hold it (r65a recursive-acquired into panic). The reference
    // handles !active; task_shared_region_slide is write-once, unlocked
    // aligned read is fine.
    vm_map_t map = get_task_map_reference(task);
    if (!map) return PROC_RETURNED;
    uint64_t slide = (uint64_t)task->task_shared_region_slide;
    if (!slide) { vm_map_deallocate(map); return PROC_RETURNED; }

    int rc[3];
    rc[0] = read_window(map, UK_DIRTY_BASE, UK_DIRTY_SIZE, slide, win_dirty);
    rc[1] = read_window(map, UK_DATA_BASE, UK_DATA_SIZE, slide, win_data);
    rc[2] = read_window(map, UK_CONST_BASE, UK_CONST_SIZE, slide, win_const);
    vm_map_deallocate(map);

    if (rc[0] == 2 || rc[1] == 2 || rc[2] == 2) {
        probe_status = 4;
        ++probe_readfails;
        probe_silence_until = probe_round + 3;
        return PROC_RETURNED;
    }
    // Per-window freshness: a gate-skipped window leaves its buffer stale,
    // so rows may only publish windows that were actually read this round.
    win_fresh = (unsigned)((rc[0] == 0) | ((rc[1] == 0) << 1) | ((rc[2] == 0) << 2));
    probe_status = 0;
    if (win_fresh & 1) scan_window(0, win_dirty, (unsigned)(UK_DIRTY_SIZE / 8));
    if (win_fresh & 2) scan_window(1, win_data, (unsigned)(UK_DATA_SIZE / 8));
    if (win_fresh & 4) scan_window(2, win_const, (unsigned)(UK_CONST_SIZE / 8));
    return PROC_RETURNED;
}

// r68 all-process sweep (uikit-cache-proc=*): DIRTY window only.
static int capture_sweep(proc_t p, void *arg)
{
    (void)arg;
    task_t task = proc_task(p);
    if (!task) return PROC_RETURNED;
    vm_map_t map = get_task_map_reference(task);
    if (!map) return PROC_RETURNED;
    uint64_t slide = (uint64_t)task->task_shared_region_slide;
    if (!slide) { vm_map_deallocate(map); return PROC_RETURNED; }
    int rc = read_window(map, UK_DIRTY_BASE, UK_DIRTY_SIZE, slide, win_dirty);
    vm_map_deallocate(map);
    if (rc) { if (rc == 2) { ++probe_readfails; probe_silence_until = probe_round + 3; } return PROC_RETURNED; }

    const unsigned n = (unsigned)(UK_DIRTY_SIZE / 8);
    unsigned nonzero = 0;
    for (unsigned i = 0; i < n; ++i) {
        uint64_t v = win_dirty[i];
        if (!v) continue;
        ++nonzero;
        if (v < GARBAGE_LIMIT) note_small(0, probe_round, (uint64_t)i * 8, v);
    }
    agg_procs += (nonzero != 0);
    agg_nonzero += nonzero;
    return PROC_RETURNED;
}

static void monitor(void *arg, wait_result_t result)
{
    (void)arg;(void)result;
    thread_set_thread_name(current_thread(), "uikit_cache_probe");
    char buf[64];
    for (;;) {
        agg_procs = agg_nonzero = probe_readfails = 0;
        if (probe_round >= 6 && probe_round >= probe_silence_until)
            proc_iterate(PROC_ALLPROCLIST | PROC_NOWAITTRANS,
                         probe_target[0] == '*' ? capture_sweep : capture, NULL, NULL, NULL);
        ++probe_round;
        if (probe_target[0] == '*') {
            snprintf(buf, sizeof buf, "UKC k%u p%u n%u g%u f%u",
                     probe_round, agg_procs, agg_nonzero,
                     0, probe_readfails);
            put(4, buf, sizeof buf);
            if (first_small_round[0])
                snprintf(buf, sizeof buf, "G k%u +%llx v%llx",
                         first_small_round[0], first_small_off[0], first_small_val[0]);
            else
                snprintf(buf, sizeof buf, "G k%u -", probe_round);
            put(7, buf, sizeof buf);
        } else {
            // The three exact __DATA_CONST suspect slots, current values
            // (only when __DATA_CONST was actually read this round).
            uint64_t imp = 0, recv = 0, sel = 0;
            if (win_fresh & 4) {
                imp  = win_const[(SLOT_IMPF - UK_CONST_BASE) / 8];
                recv = win_const[(SLOT_RECV - UK_CONST_BASE) / 8];
                sel  = win_const[(SLOT_SELP - UK_CONST_BASE) / 8];
            }
            snprintf(buf, sizeof buf, "UKC k%u I%llx R%llx S%llx",
                     probe_round, imp, recv, sel);
            put(4, buf, sizeof buf);
            if (win_fresh & 1) {
                unsigned bg = (unsigned)((SLOT_BGTC - UK_DIRTY_BASE) / 8);
                unsigned ms = (unsigned)((SLOT_MAINSCREEN - UK_DIRTY_BASE) / 8);
                snprintf(buf, sizeof buf, "B%llx M%llx",
                         win_dirty[bg], win_dirty[ms]);
            } else {
                snprintf(buf, sizeof buf, "B- M-");
            }
            put(5, buf, sizeof buf);
            // r70: the three feeder slots of the (fixed) bl bgTC at
            // __UIGet+0xa8 — page-cache premise and the two gate slots.
            // Published on wide row W0 (111 chars; BootLog emits "W0 ...").
            if (win_fresh & 1) {
                unsigned sc = (unsigned)((SLOT_SCREENCACHE - UK_DIRTY_BASE) / 8);
                unsigned g1 = (unsigned)((SLOT_GATECHK1 - UK_DIRTY_BASE) / 8);
                unsigned g2 = (unsigned)((SLOT_GATECHK2 - UK_DIRTY_BASE) / 8);
                snprintf(buf, sizeof buf, "S%llx G1%llx G2%llx x19ref%llx",
                         win_dirty[sc], win_dirty[g1], win_dirty[g2],
                         win_dirty[g2]);
            } else {
                snprintf(buf, sizeof buf, "S- G1- G2-");
            }
            for (unsigned i = 0; i < 111; ++i)
                boot_progress_ext_wide[0][i] = buf[i] ? buf[i] : ' ';
            boot_progress_ext_wide[0][111] = 0;
            if (first_small_round[2])
                snprintf(buf, sizeof buf, "C k%u +%llx v%llx",
                         first_small_round[2], first_small_off[2], first_small_val[2]);
            else
                snprintf(buf, sizeof buf, "C k%u -", probe_round);
            put(6, buf, sizeof buf);
            if (first_small_round[1])
                snprintf(buf, sizeof buf, "A k%u +%llx v%llx",
                         first_small_round[1], first_small_off[1], first_small_val[1]);
            else
                snprintf(buf, sizeof buf, "A k%u -", probe_round);
            put(7, buf, sizeof buf);
        }
        assert_wait_timeout((event_t)&probe_round, THREAD_UNINT, 2000, NSEC_PER_MSEC);
        thread_block(THREAD_CONTINUE_NULL);
    }
}

void native_uikit_cache_probe_start(void);
void native_uikit_cache_probe_start(void)
{
    unsigned enable = 0;
    if (!PE_parse_boot_argn("uikit-cache-probe", &enable, sizeof(enable)) || enable != 1) return;
    char t[32];
    if (PE_parse_boot_argn("uikit-cache-proc", t, sizeof t)) {
        t[sizeof t - 1] = 0;
        strlcpy(probe_target, t, sizeof probe_target);
    }
    thread_t thread;
    if (kernel_thread_start_priority(monitor, 0, BASEPRI_KERNEL, &thread) == KERN_SUCCESS)
        thread_deallocate(thread);
}
