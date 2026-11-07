// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
// Shared production window reader. Ops owns synchronization, block I/O,
// integrity verification and copying to the caller. No callback runs under
// this guard: the IOKit wrapper completes the request after this returns.
//
// Integrity is signed over whole kVerifyUnit units (the verifier's block
// size), so every batch is aligned to the window's unit grid and reads whole
// units: a request that begins mid-unit also reads the head of its first
// unit, and one that ends mid-unit reads the tail of its last unit. Each
// ops.verify call therefore receives exactly one whole verifier block
// (unitIndex, unit bytes, expected length) and maps straight onto it.
constexpr uint64_t kVerifyUnit = 16384;   // VR_BLOCK_BYTES: one signed hash-table entry
static bool ufsWindowGeometry (uint64_t absolute, uint64_t bytes)
{
  constexpr uint64_t limit = (uint64_t (UINT32_MAX) + 1) * 4096;
  return bytes && !(bytes & 511) && !(absolute & 4095) && absolute < limit && bytes <= limit - absolute;
}
struct UfsWindowResult { IOReturn status; uint64_t done; };
template <class Ops> struct UfsWindowGuard {
  Ops &ops;
  explicit UfsWindowGuard (Ops &value) : ops(value) { ops.lock (); }
  ~UfsWindowGuard () { ops.unlock (); }
  UfsWindowGuard (const UfsWindowGuard &) = delete;
  UfsWindowGuard &operator= (const UfsWindowGuard &) = delete;
};
template <class Ops>
static UfsWindowResult ufsReadWindow (Ops &ops, uint64_t absolute, uint64_t bytes,
                                     uint64_t block, uint64_t count, uint8_t *bounce)
{
  static_assert (kDataMax % kVerifyUnit == 0);
  if (!bounce || !ufsWindowGeometry (absolute, bytes) || !count || block >= bytes / 512 || count > bytes / 512 - block)
    return { kIOReturnBadArgument, 0 };
  UfsWindowGuard<Ops> guard (ops);
  uint64_t start = absolute + block * 512, remaining = count * 512;
  uint64_t head = (block * 512) % kVerifyUnit;
  UfsWindowResult result = { kIOReturnSuccess, 0 };
  while (remaining) {
    uint64_t span = (head + remaining + kVerifyUnit - 1) / kVerifyUnit * kVerifyUnit;
    if (span > kDataMax) span = kDataMax;
    uint64_t first = start + result.done - head;
    result.status = ops.read (first / 4096, static_cast<uint32_t> (span / 4096), bounce);
    if (result.status != kIOReturnSuccess) break;
    // The window lock protects this same snapshot through verify AND copy.
    // The transport lock alone protects only the DMA-to-bounce copy.
    for (uint64_t index = 0; index < span / kVerifyUnit; ++index) {
      uint64_t unitIndex = (first - absolute) / kVerifyUnit + index;
      uint64_t offset = unitIndex * kVerifyUnit;
      if (offset >= bytes) { result.status = kIOReturnBadArgument; break; }
      uint64_t length = bytes - offset < kVerifyUnit ? bytes - offset : kVerifyUnit;
      result.status = ops.verify (unitIndex, bounce + index * kVerifyUnit, static_cast<size_t> (length));
      if (result.status != kIOReturnSuccess) break;
    }
    if (result.status != kIOReturnSuccess) break;
    uint64_t usable = span - head;
    if (usable > remaining) usable = remaining;
    uint64_t copied = ops.copy (result.done, bounce + head, usable);
    if (copied > usable) { result.status = kIOReturnIOError; break; }
    result.done += copied;
    if (copied != usable) { result.status = kIOReturnIOError; break; }
    remaining -= usable;
    head = 0;
  }
  return result;
}
