// SPDX-License-Identifier: MIT
// m2381 stand-in definitions for the sheng board hook surface. The kernel
// side of the upstream lane defines these through patches (zzzzzzzzz-sheng-
// unnest-trace.patch), and our ld64 errors on unresolved weak references
// where Apple's binds them to zero (the BootProgressTelemetryDefs.c
// precedent). BootLatencyTrace.c registers its own capture functions into
// these pointers at boot, so defining them zero-initialized here keeps the
// sheng latency capture fully live; native_gpu_role_thread is the weakly
// imported GPU role query the sheng GPU integration answers, and this board
// runs no GPU integration, so it reports no mapping.
#include <stdint.h>

void (*sheng_user_fault_hook)(int, const int64_t *, unsigned);
void (*sheng_unnest_hook)(uint64_t, uint64_t);
void (*sheng_user_exit_hook)(int, int, uint32_t, uint64_t, const char *, const char *);

uint64_t
native_gpu_role_thread(uint32_t pid __unused, uint32_t role __unused)
{
	return 0;
}
