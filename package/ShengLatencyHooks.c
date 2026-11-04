// SPDX-License-Identifier: MIT
// m2381 stand-in for the one weak import our ld64 refuses to bind zero. The
// sheng kernel-side hook pointers (sheng_unnest_hook family) are defined by
// their kernel patches, which this lane carries since the 24A446 switch, so
// those live in the kernel now; native_gpu_role_thread however has no
// definition anywhere on the sheng lane either — Apple's linker binds the
// weak import to zero (the consumer guards on &symbol) while our ld64 errors
// on it. This board runs no GPU role integration, so reporting no mapping is
// also the semantics sheng's lane gets from the zero binding.
#include <stdint.h>

uint64_t
native_gpu_role_thread(uint32_t pid __unused, uint32_t role __unused)
{
	return 0;
}
