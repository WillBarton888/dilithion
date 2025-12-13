# IBD Hang/Restart Cycle Analysis

**Date**: 2025-01-XX  
**Author**: AI Research Analysis  
**Status**: Research Complete - No Code Changes

## Executive Summary

IBD exhibits a cyclic pattern: **working → hanging → working → hanging**. This analysis identifies the root causes of this behavior and explains why the process stalls and then resumes.

**Key Finding**: Multiple interdependent bottlenecks create a feedback loop where IBD stops when certain conditions are met, then resumes when those conditions change.

---

## Observed Behavior Pattern

```
[IBD Working] → Blocks downloading, validation queue processing
     ↓
[IBD Hangs] → No new blocks requested, no progress
     ↓
[IBD Resumes] → Blocks start downloading again
     ↓
[IBD Hangs] → Cycle repeats
```

---

## Root Causes Identified

### 1. Validation Queue Backpressure Cycle ⚠️ CRITICAL

**Location**: `src/node/ibd_coordinator.cpp:114-128`

**Problem**: When validation queue depth exceeds 80 blocks, `ShouldAttemptDownload()` returns `false`, completely stopping IBD. This creates a cycle:

1. **Download Phase**: Blocks download faster than validation can process
2. **Queue Fills**: Validation queue reaches 80+ blocks
3. **IBD Stops**: `ShouldAttemptDownload()` returns false → no new blocks requested
4. **Validation Catches Up**: Worker thread processes queued blocks
5. **Queue Drops**: Queue depth falls below 80
6. **IBD Resumes**: `ShouldAttemptDownload()` returns true → downloads resume
7. **Cycle Repeats**: Queue fills again → IBD stops again

**Current Code**:
```cpp
if (m_node_context.validation_queue && m_node_context.validation_queue->IsRunning()) {
    size_t queue_depth = m_node_context.validation_queue->GetQueueDepth();
    if (queue_depth > 80) {  // 80% of MAX_QUEUE_DEPTH (100)
        return false;  // Skip this attempt - COMPLETE STOP
    }
}
```

**Impact**:
- IBD completely stops when queue > 80 blocks
- Creates visible "hang" periods where no progress is made
- Resumes when queue processes enough blocks
- Creates the cyclic behavior observed

**Evidence**: This is a binary on/off switch - when queue > 80, IBD stops entirely. When queue < 80, IBD resumes.

---

### 2. Window Empty State ⚠️ HIGH PRIORITY

**Location**: `src/node/ibd_coordinator.cpp:259`, `src/net/block_fetcher.h:177-186`

**Problem**: `GetWindowPendingHeights()` can return empty when:
- All heights in window are `in_flight` (requested but not received)
- All heights in window are `received` (downloaded but not connected)
- Window hasn't advanced because blocks aren't fully connected

When `chunk_heights.empty()`, `FetchBlocks()` breaks early, stopping block requests.

**Current Code**:
```cpp
chunk_heights = m_node_context.block_fetcher->GetWindowPendingHeights(MAX_BLOCKS_PER_CHUNK);
if (chunk_heights.empty()) {
    break;  // No more heights to assign - IBD STOPS
}
```

**Impact**:
- IBD stops when window has no pending heights
- Can happen when:
  - All blocks are in-flight (waiting for network)
  - All blocks are received (waiting for validation)
  - Window can't advance (blocks stuck in received state)

**Window Advancement Logic**:
```cpp
void AdvanceWindow() {
    while (m_window_start <= m_target_height) {
        // Only advance if height is NOT pending, NOT in-flight, NOT received
        if (m_pending.count(m_window_start) == 0 &&
            m_in_flight.count(m_window_start) == 0 &&
            m_received.count(m_window_start) == 0) {
            m_window_start++;  // Advance past connected blocks
        } else {
            break;  // Can't advance - height still being processed
        }
    }
}
```

**Problem**: If blocks are stuck in `received` state (downloaded but not yet connected), window can't advance, and no new heights become pending.

---

### 3. Blocks Stuck in "Received" State ⚠️ HIGH PRIORITY

**Location**: `src/net/block_fetcher.h:139-142`, `src/node/block_validation_queue.cpp:323-327`

**Problem**: Blocks are marked as "received" when they arrive, but only marked as "connected" after async validation completes. During validation lag:

1. Block arrives → `OnBlockReceived()` → moved to `m_received` set
2. Block queued for async validation → validation takes time
3. Window can't advance → blocks in `m_received` prevent advancement
4. No new heights become pending → `GetWindowPendingHeights()` returns empty
5. IBD stops until validation completes

**Current Flow**:
```
Block Arrives → OnBlockReceived() → m_received.insert(height)
     ↓
Queued for Async Validation (takes 50-500ms per block)
     ↓
Validation Completes → OnWindowBlockConnected() → m_received.erase(height)
     ↓
Window Can Advance
```

**Impact**:
- If validation is slow, many blocks accumulate in `m_received`
- Window can't advance past received blocks
- No new heights become pending
- IBD stops until validation catches up

**Timing Issue**: With async validation, there's a delay between "received" and "connected". During this delay, window is blocked.

---

### 4. Chunk Stall/Cancel Cycle ⚠️ MEDIUM PRIORITY

**Location**: `src/node/ibd_coordinator.cpp:357-400`

**Problem**: Chunks can stall (no activity for 10 seconds), get cancelled, then immediately re-requested, creating a cycle:

1. **Chunk Assigned**: Heights assigned to peer, marked as `in_flight`
2. **Chunk Stalls**: No blocks received for 10 seconds
3. **Chunk Cancelled**: Heights moved back to `pending`
4. **Chunk Re-assigned**: Same heights assigned to same or different peer
5. **Chunk Stalls Again**: Cycle repeats

**Current Code**:
```cpp
auto stalled_chunks = m_node_context.block_fetcher->CheckStalledChunks();
for (const auto& [peer_id, chunk] : stalled_chunks) {
    // Try to reassign...
    if (!reassigned) {
        m_node_context.block_fetcher->CancelStalledChunk(peer_id);
        // Heights become pending again
    }
}
```

**Impact**:
- Creates oscillation: assign → stall → cancel → assign → stall
- Wastes bandwidth re-requesting same blocks
- Can cause IBD to appear "stuck" when chunks keep stalling

**Root Cause**: 10-second timeout might be too aggressive for slow networks, or peers genuinely aren't responding.

---

### 5. Peer Availability Fluctuation ⚠️ MEDIUM PRIORITY

**Location**: `src/node/ibd_coordinator.cpp:229-234`, `src/net/peers.cpp:1041-1092`

**Problem**: `GetValidPeersForDownload()` can return empty when:
- Peers haven't completed handshake
- Peers are stalling (too many stalls)
- Peers are at capacity (16 blocks in-flight)
- CNode state is invalid (disconnected, invalid socket)

When no peers are available, `FetchBlocks()` returns false, stopping IBD.

**Current Code**:
```cpp
std::vector<int> available_peers = m_node_context.peer_manager->GetValidPeersForDownload();
if (available_peers.empty()) {
    m_ibd_no_peer_cycles++;
    LogPrintIBD(WARN, "No peers available for block download");
    return false;  // IBD STOPS
}
```

**Impact**:
- IBD stops when no peers available
- Can happen temporarily during:
  - Peer handshake completion
  - Peer capacity exhaustion
  - Peer stall detection
- Resumes when peers become available again

**Potential Issue**: Peers might be temporarily unavailable due to:
- Handshake in progress
- All peers at capacity (16/16 blocks)
- Stalling peers being avoided

---

### 6. Window Advancement Too Conservative ⚠️ MEDIUM PRIORITY

**Location**: `src/net/block_fetcher.h:217-241`

**Problem**: Window only advances when heights are **completely removed** from all tracking (not pending, not in-flight, not received). This is very conservative and can cause stalls:

**Current Logic**:
```cpp
// Only advance if height is NOT in any set
if (m_pending.count(m_window_start) == 0 &&
    m_in_flight.count(m_window_start) == 0 &&
    m_received.count(m_window_start) == 0) {
    m_window_start++;  // Advance
}
```

**Problem**: If blocks are:
- In-flight (waiting for network) → can't advance
- Received (waiting for validation) → can't advance
- Pending (not yet requested) → can't advance

Window can't advance until blocks are **fully connected**, which requires async validation to complete.

**Impact**:
- Window stalls when blocks are in-flight or received
- No new heights become pending
- IBD stops until blocks are connected

---

## Interaction Between Issues

### The Perfect Storm Scenario

1. **Initial State**: IBD working, blocks downloading
2. **Queue Fills**: Validation queue reaches 80+ blocks
3. **IBD Stops**: `ShouldAttemptDownload()` returns false
4. **Blocks Received**: Blocks continue arriving (were already in-flight)
5. **Window Fills**: All heights in window are `received` (waiting for validation)
6. **Window Can't Advance**: Blocks in `received` prevent advancement
7. **No Pending Heights**: `GetWindowPendingHeights()` returns empty
8. **Validation Processes**: Queue processes blocks, depth drops below 80
9. **IBD Resumes**: `ShouldAttemptDownload()` returns true
10. **But Window Still Empty**: No pending heights → `FetchBlocks()` returns false
11. **Wait for Validation**: Blocks in `received` need to be validated
12. **Validation Completes**: Blocks connected, window advances
13. **New Heights Pending**: Window advances, new heights become pending
14. **IBD Resumes**: `FetchBlocks()` can now assign chunks
15. **Cycle Repeats**: Queue fills again → back to step 2

---

## Detailed Flow Analysis

### Phase 1: IBD Working

```
Tick() called
  ↓
ShouldAttemptDownload() → true (queue < 80)
  ↓
DownloadBlocks()
  ↓
QueueMissingBlocks() → queues blocks
  ↓
FetchBlocks()
  ↓
GetWindowPendingHeights() → returns heights
  ↓
AssignChunkToPeer() → assigns chunks
  ↓
Send GETDATA → blocks requested
  ↓
Blocks arrive → OnBlockReceived() → m_received.insert()
  ↓
Queue for async validation → queue depth increases
```

### Phase 2: Queue Fills Up

```
Validation queue depth: 75 → 76 → 77 → 78 → 79 → 80 → 81
  ↓
ShouldAttemptDownload() → false (queue > 80)
  ↓
Tick() returns early → IBD STOPS
  ↓
No new blocks requested
  ↓
But blocks already in-flight continue arriving
  ↓
Blocks marked as received → m_received fills up
  ↓
Window can't advance (blocks in received state)
```

### Phase 3: IBD Hanging

```
Tick() called every second
  ↓
ShouldAttemptDownload() → false (queue still > 80)
  ↓
Tick() returns immediately → no work done
  ↓
Validation worker processing blocks (in background)
  ↓
Queue depth: 81 → 80 → 79 → 78...
  ↓
But window still can't advance (blocks in received)
  ↓
GetWindowPendingHeights() → returns empty
```

### Phase 4: Validation Catches Up

```
Validation worker processes blocks
  ↓
OnWindowBlockConnected() called → m_received.erase()
  ↓
Window can advance → m_window_start++
  ↓
New heights added to pending
  ↓
Queue depth drops below 80
  ↓
ShouldAttemptDownload() → true
  ↓
But GetWindowPendingHeights() might still be empty
  ↓
(If window hasn't advanced enough)
```

### Phase 5: IBD Resumes

```
Window advances enough → new heights pending
  ↓
GetWindowPendingHeights() → returns heights
  ↓
FetchBlocks() → assigns chunks
  ↓
Send GETDATA → blocks requested
  ↓
Cycle repeats
```

---

## Specific Bottlenecks

### Bottleneck 1: Binary Backpressure Switch

**Issue**: `ShouldAttemptDownload()` is a binary switch - when queue > 80, IBD stops completely.

**Better Approach**: Gradual backpressure instead of binary stop:
- Queue 80-90: Reduce request rate (request fewer blocks)
- Queue 90-95: Further reduce rate
- Queue 95-100: Stop completely

**Current**: All-or-nothing approach causes visible hangs.

---

### Bottleneck 2: Window Advancement Blocked by Received Blocks

**Issue**: Window can't advance when blocks are in `received` state, even though they're just waiting for validation.

**Problem**: `AdvanceWindow()` requires heights to be completely removed from all tracking before advancing. But blocks in `received` are valid - they're just waiting for async validation.

**Better Approach**: Allow window to advance past received blocks if they're queued for validation:
- Check if block is in validation queue
- If queued, allow window to advance (validation will complete eventually)
- Only block advancement if block is truly stuck (not queued, not connected)

---

### Bottleneck 3: No Distinction Between "Stuck" and "Processing"

**Issue**: Window treats all `received` blocks the same - whether they're:
- Queued for validation (normal, will complete)
- Stuck due to validation failure (problem, needs attention)

**Problem**: Can't distinguish between normal processing delay and actual stuck state.

**Better Approach**: Track validation queue status per height:
- If height is in validation queue → allow window advancement
- If height is received but NOT in queue → might be stuck, investigate

---

### Bottleneck 4: Chunk Stall Timeout Too Aggressive

**Issue**: 10-second timeout might be too aggressive for:
- Cross-region peers (high latency)
- Slow networks
- Large blocks

**Current**: Chunks cancelled after 10 seconds of no activity.

**Impact**: Creates oscillation - chunks cancelled, re-assigned, cancelled again.

---

## Recommendations

### High Priority Fixes

1. **Gradual Backpressure Instead of Binary Stop**
   - Reduce request rate gradually as queue fills
   - Only stop completely at 95+ blocks
   - Prevents visible "hangs"

2. **Allow Window Advancement Past Queued Blocks**
   - Check if blocks in `received` are queued for validation
   - If queued, allow window to advance
   - Prevents window from stalling during validation lag

3. **Track Validation Queue Status Per Height**
   - Know which heights are queued vs stuck
   - Allow advancement for queued heights
   - Investigate stuck heights separately

### Medium Priority Fixes

4. **Increase Chunk Stall Timeout**
   - Consider 15-20 seconds for cross-region peers
   - Or make timeout adaptive based on peer latency

5. **Better Window State Tracking**
   - Distinguish between "processing" and "stuck"
   - Allow window to advance more aggressively

6. **Monitor and Log Hang Causes**
   - Log why IBD stopped (queue full, no peers, window empty)
   - Helps diagnose specific issues

---

## Testing Recommendations

1. **Monitor Queue Depth**: Track validation queue depth over time to see fill/drain cycles
2. **Monitor Window State**: Track pending/in-flight/received counts to see when window stalls
3. **Monitor Peer Availability**: Track when `GetValidPeersForDownload()` returns empty
4. **Monitor Chunk Stalls**: Track chunk stall/cancel cycles
5. **Correlate Events**: See if hangs correlate with specific events (queue full, window empty, no peers)

---

### 7. Chunk Cancellation Doesn't Reset nNextChunkHeight ⚠️ LOW PRIORITY

**Location**: `src/net/block_fetcher.cpp:800-859`

**Problem**: When chunks are cancelled, heights are marked as pending in the window, but `nNextChunkHeight` is not reset. This could cause issues if the fallback `GetNextChunkHeights()` is used instead of `GetWindowPendingHeights()`.

**Current Code**:
```cpp
bool CBlockFetcher::CancelStalledChunk(NodeId peer_id) {
    // Clear height mappings
    for (int h = chunk.height_start; h <= chunk.height_end; h++) {
        mapHeightToPeer.erase(h);
    }
    
    // Mark heights as pending in window
    if (m_window_initialized) {
        for (int h = chunk.height_start; h <= chunk.height_end; h++) {
            if (!m_download_window.IsReceived(h)) {
                m_download_window.MarkAsPending(h);
            }
        }
    }
    
    // NOTE: nNextChunkHeight is NOT reset
}
```

**Impact**:
- If window system fails and fallback `GetNextChunkHeights()` is used, cancelled heights might be skipped
- `nNextChunkHeight` might have advanced past cancelled heights
- Heights become "lost" - marked as pending in window but not returned by `GetNextChunkHeights()`

**Note**: This is low priority because the window system is primary, but could cause issues if window system fails.

---

### 8. Race Condition: Window State vs Chunk State ⚠️ LOW PRIORITY

**Location**: `src/net/block_fetcher.cpp:679-758`

**Problem**: Window state (`m_download_window`) and chunk state (`mapHeightToPeer`, `mapActiveChunks`) are updated separately, which can cause inconsistencies:

- Block received → `OnChunkBlockReceived()` → updates window
- Chunk cancelled → `CancelStalledChunk()` → updates window
- But these updates happen at different times and might not be synchronized

**Impact**:
- Window might think heights are pending when chunks are active
- Chunks might think heights are assigned when window has moved on
- Can cause duplicate requests or missed requests

**Note**: Low priority because both systems use the same mutex (`cs_fetcher`), so race conditions are prevented, but logic inconsistencies could still occur.

---

## Conclusion

The IBD hang/restart cycle is caused by **multiple interdependent bottlenecks**:

1. **Primary Cause**: Validation queue backpressure creates binary stop/resume cycle
2. **Secondary Cause**: Window advancement blocked by blocks in "received" state
3. **Tertiary Cause**: Chunk stall/cancel cycles waste bandwidth
4. **Contributing Factor**: Peer availability fluctuations

The cycle is:
- **Working**: Blocks download, queue fills
- **Hanging**: Queue > 80 → IBD stops, window can't advance
- **Resuming**: Validation processes → queue drops → window advances → IBD resumes
- **Repeat**: Cycle continues

**Key Insight**: The binary backpressure switch (queue > 80 = stop) combined with window advancement being blocked by received blocks creates a feedback loop that causes visible hangs.

---

## Summary: The Hang/Restart Cycle Explained

### The Cycle in Simple Terms

1. **IBD Working**: Blocks download, validation queue processes them
2. **Queue Fills**: Downloads faster than validation → queue reaches 80+ blocks
3. **IBD Stops**: Binary backpressure switch → `ShouldAttemptDownload()` returns false
4. **Blocks Still Arriving**: Blocks already in-flight continue arriving
5. **Window Fills**: All heights in window become `received` (waiting for validation)
6. **Window Stalls**: Can't advance because blocks are in `received` state
7. **No Pending Heights**: `GetWindowPendingHeights()` returns empty
8. **Validation Processes**: Worker thread processes queued blocks
9. **Queue Drops**: Queue depth falls below 80
10. **IBD Resumes**: `ShouldAttemptDownload()` returns true
11. **But Window Still Empty**: No pending heights → `FetchBlocks()` returns false
12. **Wait for Validation**: Blocks in `received` need to be validated
13. **Validation Completes**: Blocks connected → `OnWindowBlockConnected()` called
14. **Window Advances**: Heights removed from `received` → window can advance
15. **New Heights Pending**: Window advances → new heights become pending
16. **IBD Fully Resumes**: `FetchBlocks()` can now assign chunks
17. **Cycle Repeats**: Queue fills again → back to step 2

### Why It's Visible

The hang is visible because:
- **Binary Stop**: When queue > 80, IBD stops completely (no gradual slowdown)
- **Window Blocked**: Window can't advance until validation completes
- **No Progress**: During hang, no new blocks requested, no progress made
- **Resume Delay**: Even after queue drops, window might still be empty

### The Root Cause

**Primary**: Binary backpressure switch creates all-or-nothing behavior  
**Secondary**: Window advancement blocked by blocks in "received" state  
**Tertiary**: No distinction between "processing" (queued) and "stuck" blocks

### The Fix Strategy

1. **Gradual Backpressure**: Reduce rate gradually instead of binary stop
2. **Smart Window Advancement**: Allow advancement past queued blocks
3. **Better State Tracking**: Distinguish processing vs stuck states

This will eliminate the visible hangs and create smoother IBD progress.

