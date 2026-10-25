// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
// Shared production window reader. Ops owns synchronization, block I/O,
// integrity verification and copying to the caller. No callback runs under
// this guard: the IOKit wrapper completes the request after this returns.
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
                                     uint64_t block, uint64_t count, uint8_t *bounce,
                                     uint64_t stride)
{
  if (!bounce || !stride || stride & 4095 || stride > kDataMax || !ufsWindowGeometry (absolute, bytes)
      || !count || block >= bytes / 512 || count > bytes / 512 - block)
    return { kIOReturnBadArgument, 0 };
  UfsWindowGuard<Ops> guard (ops);
  uint64_t start = absolute + block * 512, remaining = count * 512;
  UfsWindowResult result = { kIOReturnSuccess, 0 };
  while (remaining) {
    // One round trip batches whole verification blocks up to the bounce
    // capacity, DMA's them, verifies each block against its hash, and serves
    // the request's slice from the same bounce snapshot (the window lock
    // covers verify AND copy; the transport lock alone protects only the
    // DMA-to-bounce copy).
    uint64_t windowOffset = start + result.done - absolute;
    uint64_t firstBlock = windowOffset / stride;
    uint64_t inBlock = windowOffset - firstBlock * stride;
    uint64_t batched = (inBlock + remaining + stride - 1) / stride * stride;
    if (batched > kDataMax) batched = kDataMax / stride * stride;
    uint64_t available = bytes - firstBlock * stride;
    if (batched > available) batched = available;
    result.status = ops.read ((absolute + firstBlock * stride) / 4096,
                              static_cast<uint32_t> ((batched + 4095) / 4096), bounce);
    if (result.status != kIOReturnSuccess) break;
    uint64_t blocks = batched / stride, tail = batched - blocks * stride;
    for (uint64_t i = 0; i < blocks; ++i) {
      result.status = ops.verify (firstBlock + i, bounce + i * stride,
                                  static_cast<size_t> (stride));
      if (result.status != kIOReturnSuccess) break;
    }
    if (result.status == kIOReturnSuccess && tail)
      result.status = ops.verify (firstBlock + blocks, bounce + blocks * stride,
                                  static_cast<size_t> (tail));
    if (result.status != kIOReturnSuccess) break;
    uint64_t usable = batched - inBlock;
    if (usable > remaining) usable = remaining;
    uint64_t copied = ops.copy (result.done, bounce + inBlock, usable);
    if (copied > usable) { result.status = kIOReturnIOError; break; }
    result.done += copied;
    if (copied != usable) { result.status = kIOReturnIOError; break; }
    remaining -= usable;
  }
  return result;
}
