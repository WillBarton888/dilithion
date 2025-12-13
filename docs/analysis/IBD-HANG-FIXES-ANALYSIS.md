# IBD Hang Fixes - Logic Analysis

**Date**: 2025-01-XX  
**Status**: Research Analysis Complete

## Overview

This document analyzes the logic and code flow of 5 IBD hang fixes identified by Claude. Each fix addresses a specific root cause of IBD stalls and hanging.

---

## Fix #15: Update Window Target as New Headers Arrive

### Problem Identified

**Root Cause**: During IBD, the download window is initialized with `target_height = header_height` at initialization time. However, headers continue to arrive during IBD, causing `header_height` to grow. When `window_start > target_height`, the window becomes "complete" (`IsComplete()` returns `true`), preventing new heights from being requested.

**Code Flow**:
1. `InitializeWindow(chain_height, header_height)` sets `m_target_height = header_height`
2. Headers continue arriving → `header_height` increases
3. Window advances → `window_start` increases
4. Eventually `window_start > target_height` → `IsComplete()` returns `true`
5. `GetWindowPendingHeights()` returns empty → no chunks assigned → IBD stalls

### Fix Implementation

**Location**: `src/net/block_fetcher.h:288-310`, `src/node/ibd_coordinator.cpp:204-208`

**Logic**:
```cpp
bool UpdateTargetHeight(int new_target_height) {
    if (new_target_height <= m_target_height) {
        return false;  // Target unchanged or decreased
    }
    
    int old_target = m_target_height;
    m_target_height = new_target_height;
    
    // If window was "complete" (window_start > old_target), repopulate pending
    if (m_window_start > old_target) {
        int window_end = std::min(m_window_start + WINDOW_SIZE - 1, m_target_height);
        for (int h = m_window_start; h <= window_end; h++) {
            if (m_pending.count(h) == 0 && m_in_flight.count(h) == 0 && m_received.count(h) == 0) {
                m_pending.insert(h);
            }
        }
    }
    
    return true;
}
```

**Called From**: `CIbdCoordinator::DownloadBlocks()` checks if window is initialized, then calls `UpdateWindowTarget(header_height)` every tick.

### Analysis

**✅ Correctness**: The fix is logically sound:
- Only updates if `new_target_height > m_target_height` (prevents regression)
- Repopulates pending only if window was complete (`window_start > old_target`)
- Checks all tracking sets before adding to pending (prevents duplicates)

**⚠️ Potential Issues**:
1. **Race Condition**: If headers arrive very quickly, `UpdateWindowTarget()` might be called multiple times before window advances. This is safe (idempotent), but could cause redundant work.
2. **Window Range**: The repopulation logic adds heights from `window_start` to `window_end`, but doesn't check if these heights are actually needed (e.g., already connected). This is handled by the tracking set checks, but could add unnecessary heights if blocks are already connected.
3. **Timing**: The fix relies on `DownloadBlocks()` being called regularly. If IBD coordinator stalls, target won't be updated.

**Recommendation**: ✅ **APPROVE** - The fix is correct and necessary. Consider adding a check to skip heights that are already connected to the chain.

---

## Fix #18: Remove from Pending When Block Received

### Problem Identified

**Root Cause**: Blocks can arrive before being marked as in-flight (e.g., fast network, unsolicited blocks, or race conditions). Without removing from `m_pending`, heights get stuck in pending state, causing `GetWindowPendingHeights()` to return stale heights.

**Code Flow**:
1. Height added to `m_pending` via `AddToPending()` or `Initialize()`
2. Block arrives quickly → `OnBlockReceived()` called
3. `OnBlockReceived()` removes from `m_in_flight` and adds to `m_received`
4. **BUT**: Height still in `m_pending` → `GetWindowPendingHeights()` returns it → duplicate request

### Fix Implementation

**Location**: `src/net/block_fetcher.h:140-145`

**Logic**:
```cpp
void OnBlockReceived(int height) {
    // IBD HANG FIX #18: Also remove from pending (block may arrive before marked in-flight)
    m_pending.erase(height);  // ✅ NEW: Remove from pending
    m_in_flight.erase(height);
    m_received.insert(height);
}
```

### Analysis

**✅ Correctness**: The fix is correct:
- Ensures clean state transitions: `pending → in_flight → received`
- Handles race condition where block arrives before `MarkAsInFlight()` is called
- Prevents duplicate requests for blocks already received

**⚠️ Potential Issues**:
1. **Double Removal**: If `MarkAsInFlight()` was already called, `m_pending.erase()` is a no-op (safe).
2. **State Consistency**: This ensures `m_pending` accurately reflects what needs to be requested.

**Recommendation**: ✅ **APPROVE** - The fix is correct and necessary. No issues identified.

---

## Fix #13: Always Notify CPeerManager Even If Block Not Tracked

### Problem Identified

**Root Cause**: When a block arrives but wasn't tracked in `mapBlocksInFlight` (e.g., chunk cancelled, timeout, or tracking desync), `MarkBlockReceived()` previously returned early without notifying `CPeerManager`. This caused `nBlocksInFlight` to stay high, making peers appear at capacity forever.

**Code Flow**:
1. Chunk assigned → blocks added to `mapBlocksInFlight` and `CPeerManager`
2. Chunk cancelled → blocks removed from `mapBlocksInFlight` but NOT from `CPeerManager`
3. Block arrives late → `MarkBlockReceived()` finds block not in `mapBlocksInFlight`
4. **OLD**: Return early without notifying `CPeerManager` → `nBlocksInFlight` stays high
5. **NEW**: Always notify `CPeerManager` → `nBlocksInFlight` decremented

### Fix Implementation

**Location**: `src/net/block_fetcher.cpp:109-118`

**Logic**:
```cpp
auto it = mapBlocksInFlight.find(hash);
if (it == mapBlocksInFlight.end()) {
    // Not tracked locally (chunk may have been cancelled/timed out)
    // IBD HANG FIX #13: ALWAYS notify CPeerManager to decrement nBlocksInFlight
    if (g_peer_manager) {
        g_peer_manager->MarkBlockAsReceived(peer, hash);  // ✅ NEW: Always notify
    }
    return false;  // Still return false so caller knows it wasn't in local tracking
}
```

**CPeerManager Handling**: `CPeerManager::MarkBlockAsReceived(peer_id, hash)` handles untracked blocks gracefully:
- If block is tracked: Removes from tracked peer's list and decrements counter
- If block is NOT tracked: Decrements the receiving peer's counter (prevents "all peers at capacity" stall)

### Analysis

**✅ Correctness**: The fix is correct:
- Ensures `CPeerManager` always knows when blocks are received, even if tracking is desynchronized
- Prevents `nBlocksInFlight` from staying artificially high
- `CPeerManager::MarkBlockAsReceived()` handles untracked blocks gracefully (decrements receiving peer)

**⚠️ Potential Issues**:
1. **Peer Mismatch**: If block was requested from peer A but arrives from peer B, `CPeerManager` decrements peer B's counter. This is correct behavior (peer B sent the block), but could cause slight inaccuracy if peer A's counter isn't decremented. However, this is handled by `CPeerManager::MarkBlockAsReceived()` which checks tracked peer first.
2. **Double Decrement**: If block was tracked and arrives normally, `CPeerManager` is notified twice (once in the `if` block, once after). However, `CPeerManager::MarkBlockAsReceived()` checks `mapBlocksInFlight` first, so double decrement is prevented.

**Recommendation**: ✅ **APPROVE** - The fix is correct and necessary. The `CPeerManager` implementation handles edge cases gracefully.

---

## Fix #11: Match Per-Peer Chunk Limit to MAX_BLOCKS_IN_FLIGHT_PER_PEER

### Problem Identified

**Root Cause**: The per-peer chunk limit was hardcoded to `4 * 16 = 64` blocks, but `CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER = 128`. This mismatch caused "no suitable peers" when chunks hit 64 blocks, even though peers had capacity for 128 blocks.

**Code Flow**:
1. Chunk assigned → `blocks_pending = 64`
2. Chunk extended → `blocks_pending` approaches 64
3. New chunk assignment attempted → `current_pending + new_blocks > 64` → rejected
4. Peer appears at capacity → "no suitable peers" → IBD stalls
5. **REALITY**: Peer has capacity for 128 blocks, but chunk limit blocks at 64

### Fix Implementation

**Location**: `src/net/block_fetcher.cpp:610-617`

**Logic**:
```cpp
// IBD HANG FIX #11: Match per-peer chunk limit to MAX_BLOCKS_IN_FLIGHT_PER_PEER
int max_per_peer = CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER;  // 128
if (current_pending + new_blocks > max_per_peer) {
    // Peer already has maximum blocks in-flight
    return false;
}
```

### Analysis

**✅ Correctness**: The fix is correct:
- Aligns chunk limit with actual peer capacity (128 blocks)
- Prevents premature "no suitable peers" stalls
- Uses the same constant as `CPeerManager`, ensuring consistency

**⚠️ Potential Issues**:
1. **Chunk Size**: The fix allows chunks up to 128 blocks, but chunks are typically 16 blocks. This is fine (chunks can extend), but ensures consistency with peer capacity.
2. **Multiple Chunks**: If a peer has multiple chunks, the total `blocks_pending` across all chunks is checked against 128. This is correct.

**Recommendation**: ✅ **APPROVE** - The fix is correct and necessary. Ensures consistency between chunk limits and peer capacity.

---

## Fix #16: Remove Blocks from CPeerManager When Chunk Cancelled

### Problem Identified

**Root Cause**: When a chunk is cancelled (stalled/timeout), blocks are removed from `mapBlocksInFlight` and moved to `mapCancelledChunks`, but NOT removed from `CPeerManager` tracking. This causes `nBlocksInFlight` to stay high, making peers appear at capacity forever.

**Code Flow**:
1. Chunk assigned → blocks added to `mapBlocksInFlight` and `CPeerManager`
2. Chunk stalls → `CancelStalledChunk()` called
3. **OLD**: Blocks removed from `mapBlocksInFlight`, moved to `mapCancelledChunks`, but NOT removed from `CPeerManager`
4. `nBlocksInFlight` stays high → peer appears at capacity → no new chunks assigned → IBD stalls

### Fix Implementation

**Location**: `src/net/block_fetcher.cpp:933-951`

**Logic**:
```cpp
// IBD HANG FIX #16: Remove all blocks for this peer from CPeerManager tracking
if (g_peer_manager) {
    int blocks_removed = 0;
    for (auto block_it = mapBlocksInFlight.begin(); block_it != mapBlocksInFlight.end(); ) {
        if (block_it->second.peer == peer_id) {
            g_peer_manager->RemoveBlockFromFlight(block_it->first);  // ✅ NEW: Remove from CPeerManager
            block_it = mapBlocksInFlight.erase(block_it);
            blocks_removed++;
        } else {
            ++block_it;
        }
    }
    // Also clean up mapPeerBlocks
    mapPeerBlocks.erase(peer_id);
}
```

### Analysis

**✅ Correctness**: The fix is correct:
- Ensures `CPeerManager` tracking is cleaned up when chunks are cancelled
- Prevents `nBlocksInFlight` from staying artificially high
- Decrements peer's counter so peer can accept new chunks

**⚠️ Potential Issues**:
1. **Late Arrivals**: Blocks removed from `CPeerManager` might still arrive later (during grace period). However, `Fix #13` handles this by always notifying `CPeerManager` when blocks arrive, even if not tracked.
2. **Double Removal**: If a block arrives during grace period and `Fix #13` decrements `nBlocksInFlight`, then `Fix #16` tries to remove it again, `RemoveBlockFromFlight()` will return -1 (not found). This is safe (no-op).
3. **Order of Operations**: The fix removes blocks from `CPeerManager` BEFORE removing from `mapBlocksInFlight`. This is correct (ensures `CPeerManager` is updated first).

**Recommendation**: ✅ **APPROVE** - The fix is correct and necessary. Works in conjunction with `Fix #13` to handle late arrivals gracefully.

---

## Summary of Analysis

| Fix | Issue | Correctness | Recommendation |
|-----|-------|-------------|---------------|
| #15 | Window target not updated | ✅ Correct | ✅ APPROVE |
| #18 | Pending not cleared on receive | ✅ Correct | ✅ APPROVE |
| #13 | CPeerManager not notified | ✅ Correct | ✅ APPROVE |
| #11 | Chunk limit mismatch | ✅ Correct | ✅ APPROVE |
| #16 | CPeerManager not cleaned up | ✅ Correct | ✅ APPROVE |

### Overall Assessment

**All 5 fixes are logically sound and necessary**. They address root causes of IBD stalls:

1. **Window Target**: Prevents window from becoming "complete" prematurely
2. **Pending State**: Ensures clean state transitions
3. **CPeerManager Sync**: Prevents tracking desynchronization
4. **Chunk Limits**: Aligns limits with actual capacity
5. **Cleanup**: Ensures proper cleanup when chunks are cancelled

### Potential Improvements

1. **Fix #15**: Consider skipping heights that are already connected to the chain when repopulating pending.
2. **Fix #13**: The `CPeerManager` implementation already handles edge cases, but consider adding logging for untracked blocks to help diagnose tracking issues.
3. **Fix #16**: Consider logging when blocks are removed from `CPeerManager` to help diagnose cleanup issues.

### Testing Recommendations

1. **Fix #15**: Test with headers arriving continuously during IBD to ensure window target is updated regularly.
2. **Fix #18**: Test with fast network to ensure blocks arriving before in-flight marking don't cause duplicate requests.
3. **Fix #13**: Test with chunk cancellation and late-arriving blocks to ensure `nBlocksInFlight` is decremented correctly.
4. **Fix #11**: Test with chunks extending beyond 64 blocks to ensure peers aren't marked as at capacity prematurely.
5. **Fix #16**: Test with chunk cancellation to ensure `nBlocksInFlight` is decremented and peers can accept new chunks.

---

## Conclusion

All fixes are **APPROVED** for implementation. They address critical root causes of IBD stalls and hanging, ensuring:
- Window stays synchronized with header growth
- State transitions are clean and consistent
- Peer capacity tracking is accurate
- Cleanup is performed correctly

The fixes work together to prevent the "all peers at capacity" and "window complete" stalls that were causing IBD to hang.

