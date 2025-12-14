# IBD Stuck at Height 256 - Root Cause Analysis

**Date**: 2025-12-14  
**Status**: Research Complete - Multiple Root Causes Identified

## Problem Summary

After implementing IBD HANG FIX #23 (orphan block resolution fixes), LDN node's chain is stuck at height 256 despite:
- Blocks arriving from peers
- Orphan resolution partially working (heights 194-240)
- Header height at 2015 (far ahead of chain)
- Valid peers connected (2-4 peers)

**Key Symptom**: "Could not send any block requests - all peers at capacity" despite `nBlocksInFlight = 0`

---

## Root Cause #1: Orphan Resolution Only Checks Direct Children

### Problem

**Location**: `src/node/block_validation_queue.cpp:333-399` and `src/node/dilithion-node.cpp:2275`

**Issue**: When block 256 connects, orphan resolution only checks for **direct children** of block 256. However, during chunk-based IBD, blocks arrive out-of-order in chunks. Block 257 might arrive, but block 300 might arrive first (with parent=299). When block 256 connects, it only finds block 257 as a child, not block 300 (which has parent=299, not 256).

**Code Flow**:
```cpp
// After block 256 validates successfully
std::vector<uint256> orphanChildren = g_node_context.orphan_manager->GetOrphanChildren(block256Hash);
// This ONLY finds blocks whose hashPrevBlock == block256Hash
// It does NOT find block 300 (parent=299) even though block 299's parent might be 256
```

**Impact**: 
- Blocks 257+ stored as orphans with parent hashes that don't match block 256
- Orphan resolution only processes direct children, leaving grandchildren/great-grandchildren stuck
- Blocks arrive out-of-order: block 300 arrives before block 257, so block 300's parent (299) isn't in chain yet

**Evidence from Logs**:
```
[P2P] Parent block not found: 000095f491927011...  (block 300's parent 299)
[P2P] Storing block as orphan and requesting parent
[P2P] Parent block not found: 000037c16d344c05...  (block 299's parent 298)
```

### Solution

**Fix #1**: Recursive orphan resolution - when an orphan is processed, check for ITS children too (already implemented in `dilithion-node.cpp:2351-2354`, but needs to be in validation queue completion)

**Fix #2**: Periodic orphan scan - periodically check ALL orphans to see if their parents are now in chain (not just when a block connects)

**Fix #3**: Process orphans in height order - when multiple orphans can be processed, process them in height order to ensure parents are connected before children

---

## Root Cause #2: Tracking System Desynchronization

### Problem

**Location**: Multiple files - `src/net/peers.cpp`, `src/net/block_fetcher.cpp`, `src/node/ibd_coordinator.cpp`

**Issue**: Three separate tracking systems are out of sync:

1. **CPeerManager::mapBlocksInFlight** - Tracks blocks by hash → (peer_id, iterator)
2. **CBlockFetcher::mapBlocksInFlight** - Tracks blocks by hash → CBlockInFlight
3. **CPeer::nBlocksInFlight** - Counter of blocks in-flight per peer

**Evidence from Logs**:
```
[DEBUG] Untracked block from peer 1 - nBlocksInFlight: 0 -> 0
[WARN] nBlocksInFlight already 0 in RemoveBlockFromFlight - skipping decrement
[Chunk] IBD HANG FIX #16: Removed 0 blocks from peer 1 tracking
```

**What's Happening**:
1. Chunks assigned → blocks added to `CBlockFetcher::mapBlocksInFlight` and `CPeerManager::mapBlocksInFlight`
2. Chunks cancelled → blocks removed from `CBlockFetcher::mapBlocksInFlight` but NOT from `CPeerManager::mapBlocksInFlight`
3. Blocks arrive → `MarkBlockReceived()` finds block NOT in `CBlockFetcher::mapBlocksInFlight` → marks as "untracked"
4. `CPeerManager::MarkBlockAsReceived()` decrements `nBlocksInFlight` even though it was already 0
5. Capacity check uses `CPeer::nBlocksInFlight` which is 0, but `CPeerManager::mapBlocksInFlight` still has entries

### Solution

**Fix #1**: Ensure `CancelStalledChunk()` removes blocks from BOTH tracking systems:
- `CBlockFetcher::mapBlocksInFlight` ✅ (already done)
- `CPeerManager::mapBlocksInFlight` ❌ (missing)

**Fix #2**: When blocks arrive as "untracked", check `CPeerManager::mapBlocksInFlight` to see if they're tracked there

**Fix #3**: Use single source of truth - either `CPeerManager` OR `CBlockFetcher`, not both

---

## Root Cause #3: Window Tracking State Corruption

### Problem

**Location**: `src/net/block_fetcher.h:130-200` (CBlockDownloadWindow)

**Issue**: The window tracking system (`m_pending`, `m_received`) may have heights stuck in an invalid state:

**Window States**:
- `m_pending` - Heights not yet requested
- `m_received` - Heights received but not yet connected
- `m_in_flight` - **REMOVED** in IBD HANG FIX #20

**What Happens**:
1. Heights 257-272 added to `m_pending` when chunk assigned
2. Chunk cancelled → heights should be moved back to `m_pending` (via `MarkAsPending()`)
3. But if blocks already arrived and were marked as `m_received`, they're stuck in `m_received`
4. `GetWindowPendingHeights()` returns empty (all heights in `m_received`, not `m_pending`)
5. No new chunks assigned → IBD stalls

**Evidence**: Log shows chunks were assigned but then cancelled, and window shows `pending=1008` but no new chunks assigned.

### Solution

**Fix #1**: When chunk cancelled, ensure heights are moved from `m_received` back to `m_pending` (not just `m_in_flight`)

**Fix #2**: Add periodic cleanup to move stale `m_received` heights back to `m_pending` if their blocks never connected

**Fix #3**: Check window state when capacity check fails - if window has pending heights but no chunks assigned, force chunk assignment

---

## Root Cause #4: Capacity Check Logic Flaw

### Problem

**Location**: `src/node/ibd_coordinator.cpp:324-337`

**Issue**: Capacity check uses `peer->nBlocksInFlight` which shows 0, but peers are still marked as "at capacity". This suggests the check is using stale data or checking the wrong counter.

**Code**:
```cpp
bool all_peers_at_capacity = true;
for (int peer_id : available_peers) {
    auto peer = m_node_context.peer_manager->GetPeer(peer_id);
    if (peer && peer->nBlocksInFlight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        all_peers_at_capacity = false;
        break;
    }
}
```

**What's Wrong**:
- `peer->nBlocksInFlight` is 0 (according to logs)
- But `CPeerManager::mapBlocksInFlight` might still have entries for this peer
- The check should also verify `CPeerManager::GetBlocksInFlight(peer_id) == 0`

### Solution

**Fix #1**: Use `CPeerManager::GetBlocksInFlight(peer_id)` instead of `peer->nBlocksInFlight` for capacity check

**Fix #2**: Add logging to show both counters when capacity check fails

**Fix #3**: Ensure `nBlocksInFlight` counter is kept in sync with `mapBlocksInFlight`

---

## Root Cause #5: Orphan Resolution Not Triggered After Async Validation

### Problem

**Location**: `src/node/block_validation_queue.cpp:333-399`

**Issue**: Orphan resolution in validation queue completion only checks for children of the **just-validated block**. However, if block 256 was validated async, and block 257 was already an orphan, the resolution might not find it if:
- Block 256's validation completed before block 257 was stored as orphan
- Orphan resolution runs before block 257 is stored
- Timing issue: block 257 arrives after block 256 validation completes

**Code Flow**:
```cpp
// In ValidateBlock() after successful validation
CBlockIndex* pindex = m_chainstate.GetBlockIndex(blockHash);
if (pindex) {
    // Check for orphan children
    std::vector<uint256> orphanChildren = g_node_context.orphan_manager->GetOrphanChildren(blockHash);
    // This only finds direct children of THIS block
    // If block 257 was stored as orphan AFTER block 256 validated, it won't be found
}
```

### Solution

**Fix #1**: Periodic orphan scan - every N seconds, check ALL orphans to see if their parents are now in chain

**Fix #2**: Trigger orphan resolution when new orphans are added - if orphan's parent is already in chain, process immediately

**Fix #3**: Store "pending orphan resolution" list - when block validates, check if any orphans are waiting for ancestors of this block

---

## Root Cause #6: Blocks Arriving Out of Order in Chunks

### Problem

**Location**: `src/node/dilithion-node.cpp:2019-2104` (orphan storage)

**Issue**: During chunk-based IBD, blocks arrive out-of-order:
- Chunk 257-272 assigned to peer 1
- Block 300 arrives first (parent=299)
- Block 257 arrives later (parent=256)
- Block 300 stored as orphan (parent 299 not in chain)
- Block 257 stored as orphan (parent 256 not in chain yet)
- Block 256 connects → finds block 257 as child ✅
- Block 257 connects → but block 299 still not in chain, so block 300 remains orphan ❌

**Impact**: Orphan chains form: block 300 → block 299 → block 298 → ... → block 257 → block 256. Only the direct child (257) is processed when 256 connects.

### Solution

**Fix #1**: Recursive orphan processing - when an orphan connects, process ITS children recursively (already implemented but needs verification)

**Fix #2**: Process orphans in height order - when multiple orphans can be processed, process lowest height first

**Fix #3**: Request missing parents proactively - when orphan chain detected, request all missing parents in order

---

## Recommended Fixes (Priority Order)

### Priority 1: Fix Tracking Desync (Root Cause #2)

**Fix**: Ensure `CancelStalledChunk()` removes blocks from `CPeerManager::mapBlocksInFlight`

**Location**: `src/net/block_fetcher.cpp:933-951`

**Change**:
```cpp
// IBD HANG FIX #16: Remove all blocks for this peer from CPeerManager tracking
if (g_peer_manager) {
    // ... existing code removes from CBlockFetcher::mapBlocksInFlight ...
    
    // ALSO remove from CPeerManager::mapBlocksInFlight
    for (auto it = g_peer_manager->mapBlocksInFlight.begin(); 
         it != g_peer_manager->mapBlocksInFlight.end(); ) {
        if (it->second.first == peer_id) {
            // Remove from peer's list
            auto peer_it = g_peer_manager->peers.find(peer_id);
            if (peer_it != g_peer_manager->peers.end()) {
                CPeer* peer = peer_it->second.get();
                peer->vBlocksInFlight.erase(it->second.second);
                peer->nBlocksInFlight--;
            }
            it = g_peer_manager->mapBlocksInFlight.erase(it);
        } else {
            ++it;
        }
    }
}
```

### Priority 2: Fix Capacity Check (Root Cause #4)

**Fix**: Use `CPeerManager::GetBlocksInFlight()` instead of `peer->nBlocksInFlight`

**Location**: `src/node/ibd_coordinator.cpp:324-337`

**Change**:
```cpp
bool all_peers_at_capacity = true;
for (int peer_id : available_peers) {
    auto peer = m_node_context.peer_manager->GetPeer(peer_id);
    if (peer) {
        // Use CPeerManager's tracking, not peer's counter
        int blocks_in_flight = m_node_context.peer_manager->GetBlocksInFlight(peer_id);
        if (blocks_in_flight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
            all_peers_at_capacity = false;
            break;
        }
    }
}
```

### Priority 3: Periodic Orphan Scan (Root Cause #1, #5)

**Fix**: Add periodic check to process ALL orphans whose parents are now in chain

**Location**: `src/node/ibd_coordinator.cpp` (in `DownloadBlocks()` or new method)

**Add**:
```cpp
// Periodic orphan resolution (every 10 seconds)
static auto last_orphan_scan = std::chrono::steady_clock::now();
auto now = std::chrono::steady_clock::now();
if (std::chrono::duration_cast<std::chrono::seconds>(now - last_orphan_scan).count() >= 10) {
    last_orphan_scan = now;
    
    // Get all orphans
    std::vector<uint256> all_orphans = g_node_context.orphan_manager->GetAllOrphans();
    for (const uint256& orphanHash : all_orphans) {
        CBlock orphanBlock;
        if (g_node_context.orphan_manager->GetOrphanBlock(orphanHash, orphanBlock)) {
            // Check if parent is in chain
            CBlockIndex* parent = g_chainstate.GetBlockIndex(orphanBlock.hashPrevBlock);
            if (parent && (parent->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
                // Parent is connected - trigger orphan processing
                // (reuse existing orphan resolution code)
            }
        }
    }
}
```

### Priority 4: Fix Window State (Root Cause #3)

**Fix**: When chunk cancelled, ensure heights are moved from `m_received` back to `m_pending`

**Location**: `src/net/block_fetcher.cpp:920-926`

**Change**:
```cpp
// Mark heights as pending again in the window
if (m_window_initialized) {
    for (int h = chunk.height_start; h <= chunk.height_end; h++) {
        // Remove from ALL states and add to pending
        m_download_window.MarkAsPending(h);  // This should remove from m_received too
    }
}
```

**Verify**: `MarkAsPending()` in `CBlockDownloadWindow` removes from `m_received` (IBD SLOW FIX #4 should have done this)

---

## Testing Recommendations

1. **Add Logging**:
   - Log `CPeerManager::GetBlocksInFlight(peer_id)` vs `peer->nBlocksInFlight` when capacity check fails
   - Log window state (`m_pending.size()`, `m_received.size()`) when no chunks assigned
   - Log orphan pool state when block connects

2. **Monitor**:
   - Track `nBlocksInFlight` counter changes
   - Track `mapBlocksInFlight` size changes
   - Track window state transitions

3. **Verify**:
   - When chunk cancelled, verify blocks removed from BOTH tracking systems
   - When block arrives, verify it's found in tracking system
   - When orphan stored, verify parent hash matches expected parent

---

## Conclusion

**Primary Issue**: Multiple tracking systems are desynchronized, causing capacity checks to fail even when peers have capacity.

**Secondary Issue**: Orphan resolution only processes direct children, leaving orphan chains stuck.

**Tertiary Issue**: Window state corruption prevents new chunks from being assigned.

**Recommended Action**: Implement Priority 1 and Priority 2 fixes first (tracking desync and capacity check), then Priority 3 (periodic orphan scan) to handle orphan chains.

