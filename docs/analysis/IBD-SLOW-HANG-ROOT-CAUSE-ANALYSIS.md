# IBD Slow/Hang Root Cause Analysis

**Date**: 2025-01-XX  
**Status**: Research Complete - Critical Issues Identified

## Executive Summary

After thorough analysis, **three critical issues** have been identified that explain why IBD is slow and hanging:

1. **Window/Queue Disconnect**: Blocks are queued to old priority queue but NOT to window's `m_pending` set, causing `GetWindowPendingHeights()` to return empty
2. **Window Not Populated**: Window initialization doesn't populate `m_pending` with initial heights
3. **Chunk Extension Logic**: Chunks extend but window doesn't provide new heights, causing gaps

---

## Observed Behavior

- **Initial download**: Always 16 blocks (first chunk)
- **Spurts**: 40-50 blocks (chunks extended)
- **Gaps**: Minutes between downloads
- **Hanging**: IBD stalls repeatedly

---

## Critical Issue #1: Window/Queue Disconnect

### The Problem

**Location**: `src/node/ibd_coordinator.cpp:258-278` (`QueueMissingBlocks()`)

**Issue**: Blocks are queued to the **old priority queue** (`queueBlocksToFetch`) but **NOT** to the window's `m_pending` set.

**Code Flow**:
```cpp
void CIbdCoordinator::QueueMissingBlocks(int chain_height, int blocks_to_queue) {
    for (int h = chain_height + 1; h <= chain_height + blocks_to_queue; h++) {
        // ...
        m_node_context.block_fetcher->QueueBlockForDownload(hash, h, false);
        // ⚠️ This adds to OLD priority queue, NOT to window's m_pending!
    }
}
```

**Then in `FetchBlocks()`**:
```cpp
std::vector<int> chunk_heights;
if (m_node_context.block_fetcher->IsWindowInitialized()) {
    chunk_heights = m_node_context.block_fetcher->GetWindowPendingHeights(MAX_BLOCKS_PER_CHUNK);
    // ⚠️ This reads from window's m_pending, which is EMPTY!
}
```

**Result**: `GetWindowPendingHeights()` returns empty → no chunks assigned → IBD stalls

### Why This Causes Gaps

1. Initial 16 blocks: Window might have some initial heights (if initialized correctly)
2. After first chunk: Blocks queued to old queue, but window's `m_pending` is empty
3. `FetchBlocks()` calls `GetWindowPendingHeights()` → returns empty
4. No new chunks assigned → IBD stalls
5. Eventually old queue is processed → blocks arrive → window advances → cycle repeats

---

## Critical Issue #2: Window Not Properly Initialized

### The Problem

**Location**: `src/net/block_fetcher.h:100-120` (`CBlockDownloadWindow::Initialize()`)

**Issue**: Window initialization might not populate `m_pending` with all heights from `chain_height+1` to `target_height`.

**Expected Behavior**: When window is initialized, it should populate `m_pending` with all heights in the window range.

**Actual Behavior**: Need to verify if `Initialize()` actually populates `m_pending`.

**Impact**: If `m_pending` is not populated during initialization, `GetWindowPendingHeights()` will return empty even after initialization.

---

## Critical Issue #3: Chunk Extension Without Window Updates

### The Problem

**Location**: `src/net/block_fetcher.cpp:600-640` (`AssignChunkToPeer()` extension logic)

**Issue**: When chunks are extended, new heights are added to `mapHeightToPeer` but **NOT** to window's `m_pending` set.

**Code Flow**:
```cpp
// EXTEND existing chunk
for (int h = height_start; h <= height_end; h++) {
    if (mapHeightToPeer.count(h) == 0) {
        mapHeightToPeer[h] = peer_id;  // ✅ Added to height mapping
        // ⚠️ BUT NOT added to window's m_pending!
    }
}
```

**Result**: 
- Heights are assigned to chunks
- But window's `m_pending` doesn't know about them
- When chunk completes, window can't provide new heights
- IBD stalls until window advances or is re-populated

---

## Critical Issue #4: Window Advancement Stalls

### The Problem

**Location**: `src/net/block_fetcher.h:220-250` (`AdvanceWindow()`)

**Issue**: Window only advances when blocks are **connected**, but blocks might be stuck in "received" state waiting for validation.

**Code Flow**:
```cpp
void OnBlockConnected(int height, ...) {
    // Remove from tracking
    m_received.erase(height);
    m_pending.erase(height);
    m_in_flight.erase(height);
    
    // Advance window
    AdvanceWindow(is_height_queued_callback);
}
```

**Problem**: If blocks are queued for async validation:
1. Block received → moved to `m_received`
2. Block queued → callback says "queued"
3. Window advances past queued blocks ✅
4. **BUT**: If callback fails or isn't called, window doesn't advance
5. Window stalls → `GetWindowPendingHeights()` returns empty → IBD stalls

---

## Critical Issue #5: QueueMissingBlocks Doesn't Update Window

### The Problem

**Location**: `src/node/ibd_coordinator.cpp:258-278`

**Issue**: `QueueMissingBlocks()` adds blocks to old priority queue but doesn't ensure they're in window's `m_pending`.

**Fix Needed**: After queuing blocks, also add them to window's `m_pending` set (if window is initialized).

**Code Change Needed**:
```cpp
void CIbdCoordinator::QueueMissingBlocks(int chain_height, int blocks_to_queue) {
    for (int h = chain_height + 1; h <= chain_height + blocks_to_queue; h++) {
        // ... existing code ...
        m_node_context.block_fetcher->QueueBlockForDownload(hash, h, false);
        
        // ✅ ADD: Also add to window's pending set
        if (m_node_context.block_fetcher->IsWindowInitialized()) {
            // Need a method to add height to window's pending set
            m_node_context.block_fetcher->AddHeightToWindowPending(h);
        }
    }
}
```

---

## Why Initial Download is Always 16 Blocks

**Root Cause**: `MAX_BLOCKS_PER_CHUNK = 16`

**Flow**:
1. First `FetchBlocks()` call
2. `GetWindowPendingHeights(16)` returns first 16 heights (if window initialized correctly)
3. Chunk assigned: heights 1-16
4. GETDATA sent for 16 blocks
5. Blocks arrive → validation → window advances
6. **BUT**: Next `FetchBlocks()` call → `GetWindowPendingHeights()` returns empty (Issue #1)
7. No new chunks assigned → IBD stalls

---

## Why Spurts of 40-50 Blocks

**Root Cause**: Chunk extension logic

**Flow**:
1. First chunk: 16 blocks assigned
2. Chunk extended: +16 blocks (total 32)
3. Chunk extended again: +16 blocks (total 48)
4. Chunk extended again: +16 blocks (total 64, but max is 64)
5. **BUT**: Window's `m_pending` is empty, so extensions happen but no new heights available
6. Eventually window advances or gets re-populated → blocks arrive in spurts

---

## Why Gaps Between Downloads

**Root Cause**: Window becomes empty

**Flow**:
1. Blocks queued to old priority queue (not window)
2. `GetWindowPendingHeights()` returns empty
3. No new chunks assigned
4. IBD stalls
5. Eventually:
   - Window advances (blocks connected)
   - Or old queue processed
   - Or window re-initialized
6. New heights become available → chunks assigned → blocks arrive
7. Cycle repeats

---

## Recommended Fixes

### Fix #1: Synchronize QueueMissingBlocks with Window

**Problem**: Blocks queued to old queue but not window's `m_pending`

**Solution**: After queuing blocks, also add them to window's `m_pending` set.

**Implementation**:
- Add method `CBlockFetcher::AddHeightToWindowPending(int height)`
- Call it from `QueueMissingBlocks()` after queuing blocks

### Fix #2: Verify Window Initialization

**Problem**: Window might not populate `m_pending` during initialization

**Solution**: Ensure `CBlockDownloadWindow::Initialize()` populates `m_pending` with all heights in window range.

**Implementation**:
- Verify `Initialize()` adds heights `chain_height+1` to `min(chain_height+WINDOW_SIZE, target_height)` to `m_pending`

### Fix #3: Update Window When Chunks Extended

**Problem**: Chunk extension doesn't update window's `m_pending`

**Solution**: When chunks are extended, ensure new heights are also added to window's `m_pending` (if not already there).

**Implementation**:
- In `AssignChunkToPeer()` extension logic, add heights to window's `m_pending`

### Fix #4: Remove Old Priority Queue Dependency

**Problem**: Two systems (old queue + window) causing confusion

**Solution**: Use window system exclusively, remove old priority queue dependency.

**Implementation**:
- Make `FetchBlocks()` use window exclusively
- Remove `QueueMissingBlocks()` dependency on old queue
- Or ensure both systems stay synchronized

### Fix #5: Ensure Window Advancement Works

**Problem**: Window might not advance properly when blocks are queued

**Solution**: Verify `AdvanceWindow()` callback works correctly and window advances past queued blocks.

**Implementation**:
- Add logging to track window advancement
- Verify callback is called correctly
- Ensure window advances even when blocks are queued

---

## Testing Recommendations

1. **Log Window State**: Add logging to show `m_pending`, `m_in_flight`, `m_received` sizes
2. **Log QueueMissingBlocks**: Log how many blocks are queued and whether they're added to window
3. **Log GetWindowPendingHeights**: Log when it's called and what it returns
4. **Track Window Advancement**: Log when window advances and why
5. **Monitor Chunk Assignment**: Log when chunks are assigned and from where heights come

---

## Conclusion

The root cause of IBD slowness and hanging is a **disconnect between the old priority queue system and the new window system**:

1. Blocks are queued to old queue but NOT to window
2. `FetchBlocks()` reads from window (which is empty)
3. No chunks assigned → IBD stalls
4. Eventually window advances or gets re-populated → cycle repeats

**The Fix**: Synchronize `QueueMissingBlocks()` with window's `m_pending` set, or use window exclusively and remove old queue dependency.

