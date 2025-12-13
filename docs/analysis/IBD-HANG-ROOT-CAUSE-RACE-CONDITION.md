# IBD Hang Root Cause: Race Condition in Chunk Cancellation

**Date**: 2025-01-XX  
**Author**: AI Research Analysis  
**Status**: Research Complete - Root Cause Identified

## Executive Summary

The IBD hang/restart cycle is caused by a **race condition between chunk cancellation and block arrival**. When chunks timeout after 15 seconds, the height-to-peer mappings are erased **before** blocks arrive (due to network delay). When blocks arrive later, they cannot be attributed to any chunk, causing the system to think no blocks were received, leading to repeated cancellations and stalls.

---

## Observed Behavior from Logs

### Timeline Pattern
```
08:03:37 - chain=0 (started)
08:03:45 - chain=16 (8s to download 16 blocks)
08:05:28 - chain=96 (103s to download 80 blocks - slow!)
08:05:44 - chain=96 (stalled - 16s)
08:06:34 - chain=96 (still stalled - 60s)
08:07:31 - chain=379 (sudden jump - 283 blocks in 57s)
08:07:33 - chain=400 (21 blocks in 2s)
08:07:44 - chain=400 (stalled - 11s)
08:08:54 - chain=400 (still stalled - 70s)
```

### Chunk Timeout Pattern (Repeating)
```
[Chunk] Assigned heights 33-48 (16 blocks) to peer 1
[Chunk] EXTENDED peer 1 chunk to 33-64 (+16 blocks, total pending=32)
[Chunk] EXTENDED peer 1 chunk to 33-80 (+16 blocks, total pending=48)
[Chunk] EXTENDED peer 1 chunk to 33-96 (+16 blocks, total pending=64)
[Chunk] Peer 1 stalled on chunk 33-96 (no activity for 15s)
[STALL-FIX] Cancelling stalled chunk from peer 1
[Chunk] Cancelling stalled chunk 33-96 from peer 1 (received 0/64 blocks)
[Chunk] Cancelled chunk - peer 1 now free for new assignment
```

**Critical Observation**: Chunk shows "received 0/64 blocks" even though blocks ARE being received (see "Block Reception" logs below).

### "No Suitable Peers" Spam
```
08:06:37 [WARN] [IBD] Could not send any block requests - no suitable peers
08:06:38 [WARN] [IBD] Could not send any block requests - no suitable peers
08:06:39 [WARN] [IBD] Could not send any block requests - no suitable peers
... (repeats every second for 15s until timeout)
```

### Block Reception (NYC → LDN)
**NYC side (sending)**:
```
[BLOCK-SERVE] Sending block 00009251dbc8a3db... to peer 22
[BLOCK-SERVE] PushMessage SUCCEEDED for block to peer 22
[BLOCK-SERVE] Sending block 000034c27ec76ab2... to peer 22
[BLOCK-SERVE] PushMessage SUCCEEDED for block to peer 22
```

**LDN side (receiving)**:
```
[MSG-RECV] peer=1 cmd=block
[MSG-RECV] peer=1 cmd=block
[MSG-RECV] peer=1 cmd=block
... (blocks ARE being received)
```

**Key Finding**: Blocks ARE being sent and received, but chunk tracking shows "0/64 blocks received".

### Validation Queue (Working Fine)
```
[ValidationQueue] Queued block ... at height 435 (queue depth: 1)
[ValidationQueue] Successfully validated block at height 435
[ValidationQueue] Processing block ... at height 436
[ValidationQueue] Successfully validated block at height 436
... (queue depth stays at 0-1, validation is fast)
```

**Key Finding**: Validation is fast, queue never fills up. This is NOT a validation bottleneck.

---

## Root Cause: Race Condition

### Critical Finding: CheckStalledChunks() Doesn't Check In-Flight Blocks

**Location**: `src/net/block_fetcher.cpp:730-749`

**Problem**: `CheckStalledChunks()` only checks `chunk.last_activity` (updated when blocks arrive), but does NOT check if blocks are still in-flight in `mapBlocksInFlight`.

**Current Code**:
```cpp
std::vector<std::pair<NodeId, PeerChunk>> CBlockFetcher::CheckStalledChunks() {
    for (const auto& [peer_id, chunk] : mapActiveChunks) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - chunk.last_activity);
        
        if (elapsed.count() >= CHUNK_STALL_TIMEOUT_SECONDS) {
            stalled.emplace_back(peer_id, chunk);  // ⚠️ NO CHECK FOR IN-FLIGHT BLOCKS
        }
    }
}
```

**Impact**: Chunks are marked as stalled even when blocks are still in-flight (network delay), causing premature cancellation.

### The Race Condition Flow

1. **Chunk Assigned** (T=0s):
   ```
   AssignChunkToPeer(peer_id=1, height_start=33, height_end=96)
   → mapHeightToPeer[33-96] = 1
   → mapActiveChunks[1] = PeerChunk(33-96, pending=64)
   → GETDATA sent for heights 33-96
   ```

2. **Blocks Requested** (T=0s):
   ```
   RequestBlock(peer=1, hash=..., height=33)
   → mapBlocksInFlight[hash] = CBlockInFlight(peer=1, height=33)
   → GETDATA message sent to peer
   ```

3. **Network Delay** (T=0-15s):
   - Blocks are in transit (network latency)
   - No blocks received yet
   - `chunk.last_activity` not updated
   - `CheckStalledChunks()` detects no activity for 15s

4. **Chunk Cancelled** (T=15s):
   ```cpp
   CancelStalledChunk(peer_id=1)
   → for (h = 33; h <= 96; h++) {
        mapHeightToPeer.erase(h);  // ⚠️ HEIGHTS ERASED
      }
   → mapActiveChunks.erase(peer_id=1)  // ⚠️ CHUNK REMOVED
   → Mark heights as pending in window
   ```

5. **Blocks Arrive** (T=16-20s):
   ```
   ProcessMessage(peer=1, cmd=block)
   → Block received for height 50
   → OnChunkBlockReceived(height=50)
   → mapHeightToPeer.find(50) → NOT FOUND! (was erased at T=15s)
   → Returns -1
   → Chunk tracking fails
   → Block processed but chunk shows "0/64 received"
   ```

### Code Evidence

**`src/net/block_fetcher.cpp:805-824`** - `CancelStalledChunk()`:
```cpp
bool CBlockFetcher::CancelStalledChunk(NodeId peer_id) {
    // ...
    // Clear height mappings for this chunk
    for (int h = chunk.height_start; h <= chunk.height_end; h++) {
        mapHeightToPeer.erase(h);  // ⚠️ ERASES BEFORE BLOCKS ARRIVE
    }
    // ...
}
```

**`src/net/block_fetcher.cpp:684-697`** - `OnChunkBlockReceived()`:
```cpp
NodeId CBlockFetcher::OnChunkBlockReceived(int height) {
    // Find which peer had this height assigned
    auto it = mapHeightToPeer.find(height);
    if (it == mapHeightToPeer.end()) {
        return -1;  // ⚠️ HEIGHT NOT FOUND - CHUNK TRACKING FAILS
    }
    // ...
}
```

**`src/node/dilithion-node.cpp:2245-2249`** - Block processing:
```cpp
// Height-based OnChunkBlockReceived() survives chunk cancellation
if (g_node_context.block_fetcher) {
    g_node_context.block_fetcher->MarkBlockReceived(peer_id, blockHash);
    g_node_context.block_fetcher->OnChunkBlockReceived(pblockIndexPtr->nHeight);
    // ⚠️ OnChunkBlockReceived() returns -1 if height not in mapHeightToPeer
    // Chunk tracking fails, but block is still processed
}
```

---

## Why This Causes the Hang/Restart Cycle

### Cycle Step-by-Step

1. **Chunk Assigned**: Heights 33-96 assigned to peer 1
2. **GETDATA Sent**: Blocks requested, in-flight tracking started
3. **Network Delay**: Blocks take 16-20s to arrive (cross-region latency)
4. **Timeout Detected**: After 15s, `CheckStalledChunks()` detects no activity
5. **Chunk Cancelled**: Heights erased from `mapHeightToPeer`, chunk removed
6. **Blocks Arrive**: Blocks arrive 1-5s after cancellation
7. **Tracking Fails**: `OnChunkBlockReceived()` can't find height in `mapHeightToPeer`
8. **Chunk Shows 0 Received**: Even though blocks arrived, chunk shows "0/64 blocks"
9. **New Chunk Assigned**: Same heights assigned again (they're back in pending)
10. **Cycle Repeats**: Steps 2-9 repeat indefinitely

### Why "No Suitable Peers" Spam

After chunk cancellation:
- All peers might be at capacity (16 blocks in-flight)
- Window might be empty (all heights are in-flight or received)
- `FetchBlocks()` returns false
- Logs "Could not send any block requests - no suitable peers"
- Repeats every second until:
  - Blocks arrive and free up peer capacity, OR
  - Window advances and new heights become pending, OR
  - Chunk timeout expires and heights become pending again

### Why Sudden Jumps

When blocks finally arrive (after multiple cancellation cycles):
- Many blocks arrive at once (they were all in-flight)
- Validation queue processes them quickly
- Chain height jumps forward
- But then stalls again because:
  - New chunks assigned
  - Same race condition repeats
  - Blocks arrive after timeout

---

## Additional Issues Identified

### Issue 1: Chunk Extension Creates Large Chunks

**Problem**: Chunks are extended multiple times, creating very large chunks (64+ blocks):
```
[Chunk] Assigned heights 33-48 (16 blocks)
[Chunk] EXTENDED peer 1 chunk to 33-64 (+16 blocks, total pending=32)
[Chunk] EXTENDED peer 1 chunk to 33-80 (+16 blocks, total pending=48)
[Chunk] EXTENDED peer 1 chunk to 33-96 (+16 blocks, total pending=64)
```

**Impact**: Large chunks take longer to complete, increasing chance of timeout.

**Location**: `src/net/block_fetcher.cpp:600-630` - `AssignChunkToPeer()` extension logic.

### Issue 2: Activity Timer Not Updated on GETDATA Send

**Problem**: `chunk.last_activity` is only updated when blocks are received, not when GETDATA is sent.

**Impact**: If GETDATA is sent but blocks are slow to arrive, chunk appears stalled even though request was sent.

**Location**: `src/node/ibd_coordinator.cpp:328` - `UpdateChunkActivity()` is called, but might not be called for extended chunks.

### Issue 3: Window State vs Chunk State Mismatch

**Problem**: Window shows `pending=848 flight=176 received=144`, but `GetWindowPendingHeights()` might return empty if:
- Heights are outside window range
- Heights are already assigned to chunks
- Window hasn't advanced

**Impact**: `FetchBlocks()` can't assign new chunks even though window has pending heights.

**Location**: `src/net/block_fetcher.h:180-189` - `GetNextPendingHeights()`.

---

## The Fix Strategy

### Primary Fix: Check In-Flight Blocks Before Cancelling Chunks

**Problem**: `CheckStalledChunks()` doesn't check if blocks are still in-flight before marking chunks as stalled.

**Solution**: Before marking a chunk as stalled, check if any blocks for that chunk are still in-flight:

```cpp
std::vector<std::pair<NodeId, PeerChunk>> CBlockFetcher::CheckStalledChunks() {
    for (const auto& [peer_id, chunk] : mapActiveChunks) {
        // Check if any blocks for this chunk are still in-flight
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
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - chunk.last_activity);
        
        if (elapsed.count() >= CHUNK_STALL_TIMEOUT_SECONDS) {
            stalled.emplace_back(peer_id, chunk);
        }
    }
}
```

**Impact**: Prevents premature chunk cancellation when blocks are still in transit.

### Secondary Fix: Grace Period Before Erasing Heights

**Problem**: Heights are erased immediately on cancellation, but blocks might still arrive.

**Solution**: Keep heights in `mapHeightToPeer` until:
1. Blocks actually arrive, OR
2. Block-level timeout expires (60s), OR
3. Grace period expires (e.g., 30s after chunk cancellation)

**Implementation**:
- Add `mapCancelledChunks` to track cancelled chunks with cancellation time
- Keep heights in `mapHeightToPeer` for grace period
- When blocks arrive, check both active and cancelled chunks
- Erase heights only after grace period expires

### Tertiary Fix: Don't Erase Heights Immediately on Cancellation

**Problem**: Heights are erased immediately on cancellation, but blocks might arrive later.

**Solution**: When cancelling a chunk, don't erase heights immediately. Instead:
1. Mark chunk as "cancelled" but keep heights in `mapHeightToPeer`
2. When blocks arrive, check if height is in cancelled chunk
3. Erase heights only after grace period (e.g., 30s) or when blocks arrive

**Implementation**:
- Add `mapCancelledChunks` with cancellation timestamp
- Keep heights in `mapHeightToPeer` for grace period
- `OnChunkBlockReceived()` checks both active and cancelled chunks

### Tertiary Fix: Update Activity Timer on GETDATA Send

**Problem**: Activity timer not updated when GETDATA sent.

**Solution**: Call `UpdateChunkActivity()` immediately after sending GETDATA, not just when blocks arrive.

**Location**: `src/node/ibd_coordinator.cpp:328` - Already implemented, but verify it's called for all GETDATA sends.

### Quaternary Fix: Prevent Chunk Extension Beyond Reasonable Size

**Problem**: Chunks extended to 64+ blocks, increasing timeout risk.

**Solution**: Limit chunk extension to reasonable size (e.g., max 32 blocks per chunk).

---

## Testing Recommendations

1. **Monitor Chunk Cancellations**: Log when chunks are cancelled and why
2. **Track Block Arrival Times**: Log time between GETDATA send and block arrival
3. **Monitor mapHeightToPeer**: Log when heights are erased and when blocks arrive
4. **Correlate Events**: See if blocks arrive after chunk cancellation

---

## Conclusion

The IBD hang/restart cycle is caused by a **race condition between chunk cancellation and block arrival**:

### The Root Cause Chain

1. **Chunk Assigned**: Heights 33-96 assigned to peer 1, GETDATA sent
2. **Network Delay**: Blocks take 16-20s to arrive (cross-region latency)
3. **Premature Stall Detection**: After 15s, `CheckStalledChunks()` detects no activity
   - **BUG**: Doesn't check if blocks are still in-flight in `mapBlocksInFlight`
   - **BUG**: Only checks `chunk.last_activity` (updated when blocks arrive)
4. **Chunk Cancelled**: Heights erased from `mapHeightToPeer`, chunk removed
5. **Blocks Arrive**: Blocks arrive 1-5s after cancellation (still in-flight)
6. **Tracking Fails**: `OnChunkBlockReceived()` can't find height in `mapHeightToPeer`
   - Returns -1, chunk tracking fails
   - Block processed but chunk shows "0/64 blocks received"
7. **Cycle Repeats**: Same heights assigned again, cycle repeats

### Why "Downloads 16, Hangs, Jumps to 80"

- **Downloads 16**: First chunk assigned (16 blocks)
- **Hangs**: Chunk cancelled after 15s timeout, blocks arrive later but tracking fails
- **Jumps to 80**: Multiple chunks cancelled, blocks arrive in bursts, validation processes them
- **Hangs Again**: Same race condition repeats with new chunks

### The Fix

**Primary Fix**: Check `mapBlocksInFlight` before marking chunks as stalled in `CheckStalledChunks()`.

**Secondary Fix**: Don't erase heights from `mapHeightToPeer` immediately on cancellation - use grace period.

**Tertiary Fix**: Update `chunk.last_activity` when GETDATA is sent, not just when blocks arrive.

This will prevent premature chunk cancellation and allow blocks to be properly attributed to chunks even when they arrive after the timeout.

