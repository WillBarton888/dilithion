# IBD Hang Fixes - Implementation Summary

**Date**: 2025-01-XX  
**Status**: ✅ Implemented

## Overview

Fixed the IBD hang/restart cycle caused by a race condition between chunk cancellation and block arrival. The root cause was premature chunk cancellation when blocks were still in-flight due to network delay.

---

## Root Cause

1. **CheckStalledChunks()** didn't check if blocks were still in-flight before marking chunks as stalled
2. **CancelStalledChunk()** erased height mappings immediately, preventing late-arriving blocks from being tracked
3. Blocks arriving after cancellation couldn't be attributed to chunks, causing tracking failures

---

## Fixes Implemented

### Fix #1: Check In-Flight Blocks Before Marking Chunks as Stalled

**File**: `src/net/block_fetcher.cpp:730-754`

**Change**: Modified `CheckStalledChunks()` to check `mapBlocksInFlight` before marking chunks as stalled.

**Before**:
```cpp
if (elapsed.count() >= CHUNK_STALL_TIMEOUT_SECONDS) {
    stalled.emplace_back(peer_id, chunk);
}
```

**After**:
```cpp
// Check if blocks are still in-flight before marking as stalled
bool has_in_flight = false;
for (const auto& [hash, in_flight] : mapBlocksInFlight) {
    if (in_flight.peer == peer_id &&
        in_flight.nHeight >= chunk.height_start &&
        in_flight.nHeight <= chunk.height_end) {
        has_in_flight = true;
        break;
    }
}

if (has_in_flight) {
    continue;  // Don't mark as stalled - blocks are still arriving
}

// Only check timeout if no blocks are in-flight
if (elapsed.count() >= CHUNK_STALL_TIMEOUT_SECONDS) {
    stalled.emplace_back(peer_id, chunk);
}
```

**Impact**: Prevents premature chunk cancellation when blocks are still in transit (network delay).

---

### Fix #2: Grace Period for Cancelled Chunks

**Files**: 
- `src/net/block_fetcher.h:736-742` (data structures)
- `src/net/block_fetcher.cpp:864-912` (CancelStalledChunk)
- `src/net/block_fetcher.cpp:915-947` (CleanupCancelledChunks)

**Change**: Implemented grace period mechanism for cancelled chunks.

**Added Data Structures**:
```cpp
struct CancelledChunk {
    PeerChunk chunk;
    std::chrono::steady_clock::time_point cancelled_time;
    CancelledChunk(const PeerChunk& c) : chunk(c), cancelled_time(std::chrono::steady_clock::now()) {}
};
std::map<NodeId, CancelledChunk> mapCancelledChunks;
static constexpr int CANCELLED_CHUNK_GRACE_PERIOD_SECONDS = 30;
```

**CancelStalledChunk() Changes**:
- Moves chunk to `mapCancelledChunks` instead of erasing immediately
- Keeps heights in `mapHeightToPeer` during grace period
- Doesn't remove blocks from `mapBlocksInFlight` (let block-level timeout handle them)

**CleanupCancelledChunks()**:
- Called periodically from `RetryTimeoutsAndStalls()`
- Removes cancelled chunks after grace period expires
- Erases height mappings for chunks where blocks never arrived

**Impact**: Allows blocks that arrive after cancellation (network delay) to be properly tracked and credited to chunks.

---

### Fix #3: Handle Cancelled Chunks in OnChunkBlockReceived()

**File**: `src/net/block_fetcher.cpp:684-768`

**Change**: Modified `OnChunkBlockReceived()` to check both active and cancelled chunks.

**Before**:
```cpp
auto chunk_it = mapActiveChunks.find(peer_id);
if (chunk_it != mapActiveChunks.end()) {
    // Update chunk tracking
}
return peer_id;
```

**After**:
```cpp
// First, try active chunk
auto chunk_it = mapActiveChunks.find(peer_id);
if (chunk_it != mapActiveChunks.end()) {
    // Update active chunk tracking
    return peer_id;
}

// Check cancelled chunks (grace period)
auto cancelled_it = mapCancelledChunks.find(peer_id);
if (cancelled_it != mapCancelledChunks.end()) {
    // Update cancelled chunk stats
    // Remove height from mapHeightToPeer
    // If chunk complete, remove from cancelled map
    return peer_id;
}
```

**Impact**: Blocks arriving after chunk cancellation are properly credited to the cancelled chunk, preventing tracking failures.

---

### Fix #4: Periodic Cleanup of Cancelled Chunks

**File**: `src/node/ibd_coordinator.cpp:430-435`

**Change**: Added call to `CleanupCancelledChunks()` in `RetryTimeoutsAndStalls()`.

**Before**:
```cpp
void CIbdCoordinator::RetryTimeoutsAndStalls() {
    // Check for block-level timeouts
    // Check for stalled chunks
}
```

**After**:
```cpp
void CIbdCoordinator::RetryTimeoutsAndStalls() {
    // IBD HANG FIX #4: Clean up cancelled chunks after grace period expires
    m_node_context.block_fetcher->CleanupCancelledChunks();
    
    // Check for block-level timeouts
    // Check for stalled chunks
}
```

**Impact**: Ensures cancelled chunks are cleaned up after grace period, preventing memory leaks and stale height mappings.

---

### Fix #5: UpdateChunkActivity() Already Implemented

**File**: `src/node/ibd_coordinator.cpp:413`

**Status**: ✅ Already implemented - `UpdateChunkActivity()` is called after GETDATA is sent.

**Impact**: Prevents false stall detection when network is slow by updating activity timer when GETDATA is sent, not just when blocks arrive.

---

## Expected Behavior After Fixes

### Before Fixes
1. Chunk assigned (heights 33-96)
2. GETDATA sent
3. Network delay (16-20s)
4. After 15s, chunk marked as stalled (no check for in-flight blocks)
5. Chunk cancelled, heights erased immediately
6. Blocks arrive 1-5s later
7. `OnChunkBlockReceived()` can't find height → tracking fails
8. Chunk shows "0/64 blocks received"
9. Cycle repeats

### After Fixes
1. Chunk assigned (heights 33-96)
2. GETDATA sent, activity timer updated
3. Network delay (16-20s)
4. After 15s, `CheckStalledChunks()` checks `mapBlocksInFlight`
5. Blocks still in-flight → chunk NOT marked as stalled
6. Blocks arrive → properly tracked and credited to chunk
7. Chunk completes successfully
8. OR: If no blocks in-flight and timeout exceeded → chunk cancelled
9. Chunk moved to cancelled map (grace period)
10. Heights remain in `mapHeightToPeer` for 30s
11. If blocks arrive during grace period → credited to cancelled chunk
12. After grace period → cancelled chunk cleaned up

---

## Testing Recommendations

1. **Monitor Chunk Cancellations**: Verify chunks are only cancelled when no blocks are in-flight
2. **Track Block Arrival Times**: Log time between GETDATA send and block arrival
3. **Monitor Cancelled Chunks**: Verify cancelled chunks are properly tracked during grace period
4. **Verify Cleanup**: Ensure cancelled chunks are cleaned up after grace period expires
5. **Test Network Delay**: Simulate network delay (16-20s) and verify chunks aren't prematurely cancelled

---

## Files Modified

1. `src/net/block_fetcher.h` - Added cancelled chunk data structures and `CleanupCancelledChunks()` declaration
2. `src/net/block_fetcher.cpp` - Implemented all fixes:
   - `CheckStalledChunks()` - Check in-flight blocks
   - `CancelStalledChunk()` - Grace period implementation
   - `OnChunkBlockReceived()` - Handle cancelled chunks
   - `CleanupCancelledChunks()` - Cleanup expired cancelled chunks
3. `src/node/ibd_coordinator.cpp` - Added cleanup call in `RetryTimeoutsAndStalls()`

---

## Conclusion

The IBD hang/restart cycle has been fixed by:
1. Preventing premature chunk cancellation when blocks are still in-flight
2. Implementing a grace period for cancelled chunks to handle late-arriving blocks
3. Properly tracking and crediting blocks that arrive after chunk cancellation

These fixes ensure that blocks are properly tracked even when network delay causes them to arrive after the chunk timeout, eliminating the race condition that caused the hang/restart cycle.

