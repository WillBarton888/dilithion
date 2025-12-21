# Dilithion vs Bitcoin Core IBD: Comparison and Recommendations

## Executive Summary

After analyzing Bitcoin Core's IBD implementation and comparing it to Dilithion's current approach, several critical differences emerge. This document outlines what Dilithion is doing right, what needs to be fixed, and specific recommendations for improvement.

---

## Current State Analysis

### What Dilithion Has (Good)

1. **Similar tracking structures**:
   - `mapBlocksInFlight` (hash -> in-flight info)
   - `mapPeerBlocks` (peer -> blocks)
   - Chunk-based assignment system
   - Stall detection logic

2. **Constants match Bitcoin Core**:
   - `MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16` ✓
   - `BLOCK_DOWNLOAD_WINDOW_SIZE = 1024` ✓
   - `BLOCK_STALL_TIMEOUT_SECONDS = 2` ✓

3. **Advanced features**:
   - Moving window system (`CBlockDownloadWindow`)
   - Parallel download support
   - Per-peer capacity tracking
   - Grace period for cancelled chunks

### What Dilithion is Missing (Critical)

1. **NO Headers-First Implementation**
   - Bitcoin Core: Downloads ALL headers first, THEN blocks
   - Dilithion: Appears to be downloading blocks without header phase

2. **Hash Computed on Arrival (Wrong Pattern)**
   - Bitcoin Core: Hash computed during headers phase, known before block download
   - Dilithion: Hash likely computed when block arrives (see `MarkBlockReceived` hash lookup failures)

3. **No `CBlockIndex` Early Creation**
   - Bitcoin Core: Creates `CBlockIndex` when header arrives
   - Dilithion: No evidence of block index created before block download

4. **Complex Chunk System (Bitcoin Core doesn't use this)**
   - Dilithion: `PeerChunk`, `mapActiveChunks`, `mapHeightToPeer` - extensive chunk tracking
   - Bitcoin Core: Simple per-block assignment (up to 16 blocks per peer, NO chunks)

---

## Critical Problem: Hash Mismatch Issues

### Evidence from Code

From `block_fetcher.cpp:136-150`:
```cpp
auto it = mapBlocksInFlight.find(hash);
if (it == mapBlocksInFlight.end()) {
    // BUG #161 DEBUG: Log hash lookup for debugging hash mismatch
    std::cout << "[MarkBlockReceived] NOT FOUND - dumping first 3 in-flight hashes:" << std::endl;
    int count = 0;
    for (const auto& entry : mapBlocksInFlight) {
        if (count++ < 3) {
            std::cout << "  [" << entry.second.nHeight << "] "
                      << entry.first.GetHex().substr(0, 16) << "..." << std::endl;
        }
    }
```

**This is a SMOKING GUN!** The code is debugging hash mismatches - blocks arrive but can't be found in `mapBlocksInFlight` because the hash doesn't match. This is EXACTLY what happens when you don't use headers-first.

### Why This Happens

**Without Headers-First**:
1. Request block by height (or some identifier)
2. Block arrives with its actual hash
3. Try to look up in `mapBlocksInFlight[actual_hash]`
4. Lookup FAILS because you stored it under a different hash (or didn't know the hash)
5. Block appears "unexpected" even though you requested it

**With Headers-First (Bitcoin Core)**:
1. Download header first
2. Compute hash from header
3. Store in `mapBlocksInFlight[computed_hash]`
4. Request block using that known hash
5. Block arrives, you compute hash again
6. Lookup in `mapBlocksInFlight[computed_hash]`
7. Lookup SUCCEEDS - hash matches perfectly

---

## Detailed Comparison Table

| Feature | Bitcoin Core | Dilithion | Status | Priority |
|---------|--------------|-----------|--------|----------|
| **Headers-First** | Yes | No | Missing | CRITICAL |
| **Hash Known Before Download** | Yes (from headers) | No (computed on arrival?) | Wrong | CRITICAL |
| **CBlockIndex Early Creation** | On header arrival | On block arrival? | Wrong | CRITICAL |
| **Block Assignment** | Per-block (16/peer) | Chunk-based (16-block chunks) | Different | HIGH |
| **mapBlocksInFlight** | `multimap<hash, pair<NodeId, iterator>>` | `map<hash, CBlockInFlight>` | Close | MEDIUM |
| **Stall Timeout** | 2 seconds (IBD) | 2-20 seconds (variable) | Close | MEDIUM |
| **Window Size** | 1024 blocks | 1024 blocks | Match | OK |
| **Max Per Peer** | 16 blocks | 16 blocks (64 in some paths?) | Inconsistent | MEDIUM |
| **Parallel Download** | Yes (multimap) | Yes (set of peers) | Match | OK |
| **FindNextBlocksToDownload** | Yes | Simulated via chunks | Different | HIGH |
| **MarkBlockAsInFlight** | Yes | Yes (but no headers-first) | Incomplete | HIGH |
| **MarkBlockAsReceived** | Yes | Yes (but hash lookup fails) | Buggy | HIGH |

---

## Root Cause Analysis

### The Core Problem

Dilithion's IBD is experiencing hash mismatch issues because it's NOT using headers-first download. This causes:

1. **Hash Lookup Failures**: Blocks arrive but can't be found in `mapBlocksInFlight`
2. **Stale Tracking Entries**: mapBlocksInFlight fills up with entries that never get cleared
3. **128-Block Stalls**: When mapBlocksInFlight reaches capacity, system stalls (see BUG #163 fix)
4. **Complex Workarounds**: Massive code to clean up by height, handle mismatches, etc.

### Evidence of Workarounds

From `block_fetcher.cpp:1437-1461` (BUG #163 FIX):
```cpp
// BUG #163 FIX: Clean up mapBlocksInFlight by HEIGHT when block is connected
// This fixes the 128-block stall where blocks arrive with different hashes than requested
// (due to FastHash vs RandomX hash mismatch). The blocks connect to the chain but
// mapBlocksInFlight entries are never removed because MarkBlockReceived() can't find them.
// By cleaning up by height, we prevent mapBlocksInFlight from filling up with stale entries.
```

**This workaround would NOT be needed with headers-first!** The hash would match perfectly because it was computed from the header before requesting the block.

---

## Recommendations

### Phase 1: Implement Headers-First (CRITICAL)

**Goal**: Port Bitcoin Core's headers-first download pattern

**Steps**:

1. **Create Header Download Phase**:
   ```cpp
   // BEFORE downloading any blocks:
   1. Request headers from peer (GETHEADERS)
   2. Receive 2000 headers (HEADERS message)
   3. For each header:
      - Validate header (PoW, prev hash, timestamp)
      - Compute hash = RandomX(header) or FastHash(header)
      - Create CBlockIndex with hash
      - Store in mapBlockIndex[hash] = pindex
      - Mark as VALID_TREE
   4. Update pindexBestKnownBlock
   5. Repeat until all headers downloaded
   ```

2. **Modify Block Request Logic**:
   ```cpp
   // FindNextBlocksToDownload equivalent:
   std::vector<CBlockIndex*> FindNextBlocksToDownload(NodeId peer, int count) {
       std::vector<CBlockIndex*> result;

       // Start from chain height + 1
       int chain_height = GetChainHeight();
       CBlockIndex* pindex = mapBlockIndex[chain_height];

       // Walk forward through headers we already have
       while (pindex && result.size() < count) {
           CBlockIndex* pnext = pindex->pnext;  // Next header
           if (!pnext) break;

           // Only request if not in-flight and not on disk
           if (!IsBlockInFlight(pnext->GetBlockHash()) &&
               !HaveBlockData(pnext->GetBlockHash())) {
               result.push_back(pnext);
           }
           pindex = pnext;
       }

       return result;
   }
   ```

3. **Request Blocks Using Known Hash**:
   ```cpp
   for (CBlockIndex* pindex : blocks_to_download) {
       uint256 hash = pindex->GetBlockHash();  // Hash ALREADY KNOWN from header
       int height = pindex->nHeight;

       // Track request
       mapBlocksInFlight[hash] = CBlockInFlight(hash, peer, height);

       // Send GETDATA with known hash
       SendGetData(peer, hash);
   }
   ```

4. **Match Arriving Blocks**:
   ```cpp
   void OnBlockArrived(const CBlock& block, NodeId peer) {
       // Compute hash from block header
       uint256 hash = block.GetHash();

       // Look up in mapBlocksInFlight
       auto it = mapBlocksInFlight.find(hash);
       if (it == mapBlocksInFlight.end()) {
           // Unrequested block - ignore or log as DOS
           return;
       }

       // Hash matches! Process block
       ProcessBlock(block);

       // Remove from tracking
       mapBlocksInFlight.erase(it);
   }
   ```

**Expected Outcome**:
- NO MORE hash mismatch errors
- NO MORE cleanup by height workarounds
- NO MORE 128-block stalls due to mapBlocksInFlight filling up
- Clean, simple request/response matching

### Phase 2: Simplify Block Assignment (HIGH)

**Goal**: Replace chunk system with Bitcoin Core's per-block model

**Current State (Dilithion)**:
- `PeerChunk` struct (88 lines)
- `mapActiveChunks` tracking
- `mapHeightToPeer` tracking
- `mapCancelledChunks` tracking (grace period)
- `AssignChunkToPeer`, `ReassignChunk`, `CancelStalledChunk` methods
- Complex chunk completion logic

**Bitcoin Core State**:
- `QueuedBlock` struct (just `CBlockIndex* pindex`)
- `vBlocksInFlight` list per peer (max 16 entries)
- `mapBlocksInFlight` multimap (hash -> peer)
- Simple: request up to 16 blocks, track by hash

**Migration Plan**:

1. **Keep Height Tracking for Transition**:
   ```cpp
   struct BlockRequest {
       CBlockIndex* pindex;      // Block index (has hash, height, prev, etc.)
       NodeId peer;              // Peer downloading from
       std::chrono::time_point request_time;  // For stall detection
   };

   // Per-peer tracking
   std::map<NodeId, std::vector<BlockRequest>> mapPeerRequests;

   // Global tracking (for hash-based lookup)
   std::multimap<uint256, NodeId> mapBlocksInFlight;
   ```

2. **Assign Blocks Individually**:
   ```cpp
   void AssignBlocksToPeer(NodeId peer, const std::vector<CBlockIndex*>& blocks) {
       auto& requests = mapPeerRequests[peer];

       for (CBlockIndex* pindex : blocks) {
           if (requests.size() >= 16) break;  // Max per peer

           uint256 hash = pindex->GetBlockHash();
           requests.push_back({pindex, peer, now()});
           mapBlocksInFlight.insert({hash, peer});
       }
   }
   ```

3. **Remove Chunk Complexity**:
   - Delete `PeerChunk` struct
   - Delete `mapActiveChunks`
   - Delete `mapHeightToPeer` (or keep for height-based queries)
   - Delete `mapCancelledChunks` and grace period logic
   - Delete `AssignChunkToPeer`, `ReassignChunk`, `CancelStalledChunk`

**Expected Outcome**:
- Simpler codebase (hundreds of lines removed)
- Fewer edge cases
- Fewer bugs
- Easier to reason about

### Phase 3: Port FindNextBlocksToDownload (HIGH)

**Goal**: Implement Bitcoin Core's block selection algorithm

**Key Features**:

1. **Block Locator for Fork Point Finding**:
   ```cpp
   // Find last common block between us and peer
   CBlockIndex* FindForkPoint(NodeId peer) {
       // Get peer's best known block
       CBlockIndex* peerBest = GetPeerBestKnownBlock(peer);

       // Walk back from our tip to find common ancestor
       CBlockIndex* ours = GetChainTip();
       while (ours && !IsAncestor(ours, peerBest)) {
           ours = ours->pprev;
       }
       return ours;
   }
   ```

2. **Walk Forward from Fork Point**:
   ```cpp
   std::vector<CBlockIndex*> FindNextBlocksToDownload(NodeId peer, int max_count) {
       std::vector<CBlockIndex*> result;

       // Start from fork point
       CBlockIndex* pindex = FindForkPoint(peer);
       if (!pindex) return result;

       // Walk forward through headers
       while (result.size() < max_count && pindex->pnext) {
           pindex = pindex->pnext;

           // Skip if already have block data
           if (HaveBlockData(pindex->GetBlockHash())) continue;

           // Skip if already in flight
           if (IsBlockInFlight(pindex->GetBlockHash())) continue;

           result.push_back(pindex);
       }

       return result;
   }
   ```

3. **Request from Multiple Peers in Parallel**:
   ```cpp
   void RequestBlocksFromAllPeers() {
       std::vector<NodeId> peers = GetValidPeers();

       for (NodeId peer : peers) {
           // Get next blocks this peer should download
           auto blocks = FindNextBlocksToDownload(peer, 16);

           // Assign and request
           AssignBlocksToPeer(peer, blocks);
           SendGetDataMessages(peer, blocks);
       }
   }
   ```

**Expected Outcome**:
- Efficient block selection
- Natural handling of forks
- Simple parallel download from multiple peers

### Phase 4: Implement Proper Stall Detection (MEDIUM)

**Goal**: Port Bitcoin Core's stall detection logic

**Bitcoin Core Pattern**:

1. **2-Second Timeout During IBD**:
   ```cpp
   const auto BLOCK_STALL_TIMEOUT = std::chrono::seconds(2);

   bool IsBlockStalled(const BlockRequest& req) {
       auto elapsed = now() - req.request_time;
       return elapsed >= BLOCK_STALL_TIMEOUT;
   }
   ```

2. **Parallel Download on Stall** (NOT cancel):
   ```cpp
   void HandleStalledBlocks() {
       for (auto& [peer, requests] : mapPeerRequests) {
           for (auto& req : requests) {
               if (IsBlockStalled(req)) {
                   // Don't cancel - request from SECOND peer in parallel
                   NodeId second_peer = SelectBestPeer();
                   RequestBlockFromPeer(second_peer, req.pindex);

                   // Now TWO peers are racing to deliver this block
               }
           }
       }
   }
   ```

3. **First Responder Wins**:
   ```cpp
   void OnBlockReceived(uint256 hash, NodeId peer) {
       // Remove from ALL peers that were downloading it
       auto range = mapBlocksInFlight.equal_range(hash);
       for (auto it = range.first; it != range.second; ++it) {
           NodeId racing_peer = it->second;
           RemoveBlockFromPeer(racing_peer, hash);
       }

       // Clear all tracking for this block
       mapBlocksInFlight.erase(hash);
   }
   ```

**Expected Outcome**:
- Faster IBD (no waiting for slow peers)
- Redundancy (if one peer fails, another delivers)
- Natural peer quality selection (fast peers win)

---

## Migration Path

### Step-by-Step Migration

**Week 1: Headers-First Foundation**
1. Implement header download loop
2. Create CBlockIndex on header arrival
3. Store in mapBlockIndex
4. Compute and cache block hash

**Week 2: Refactor Block Requests**
1. Change RequestBlock to use known hash from CBlockIndex
2. Update mapBlocksInFlight to use hash from headers
3. Fix MarkBlockReceived to match by hash (should work now)
4. Remove height-based cleanup workarounds

**Week 3: Simplify Chunk System**
1. Keep chunk code but add per-block path alongside
2. Test per-block path with headers-first
3. Verify no hash mismatches
4. Verify 128-block stalls are gone

**Week 4: Port FindNextBlocksToDownload**
1. Implement block locator
2. Implement fork point finding
3. Implement forward walk
4. Integrate with existing peer manager

**Week 5: Complete Migration**
1. Remove chunk system entirely
2. Remove all workarounds (BUG #163, etc.)
3. Simplify state tracking
4. Comprehensive testing

### Testing Checklist

After each phase:
- [ ] No hash mismatch errors in logs
- [ ] mapBlocksInFlight never exceeds 128 entries
- [ ] Blocks match on arrival (MarkBlockReceived succeeds)
- [ ] IBD completes without stalls
- [ ] Multi-peer download works
- [ ] Peer disconnection handled gracefully
- [ ] Fork recovery works
- [ ] No memory leaks

---

## Expected Benefits

### After Headers-First Implementation

**Before**:
- Hash mismatches (BUG #161)
- mapBlocksInFlight fills up (BUG #163)
- 128-block stalls
- Complex height-based cleanup
- Unreliable block matching

**After**:
- NO hash mismatches
- mapBlocksInFlight never fills (entries cleared when blocks arrive)
- NO stalls due to hash problems
- Simple hash-based matching
- Reliable request/response tracking

### After Chunk Removal

**Before**:
- ~1000 lines of chunk management code
- Complex state machine
- Grace periods
- Chunk cancellation/reassignment
- Height tracking in multiple places

**After**:
- ~200 lines of simple per-block tracking
- Clear state: pending, in-flight, received
- No grace periods needed
- Simple reassignment (just request again)
- Height tracking in one place (CBlockIndex)

### After FindNextBlocksToDownload Port

**Before**:
- Manual chunk assignment
- No fork detection
- Manual peer selection
- Complex window management

**After**:
- Automatic block selection
- Natural fork handling
- Efficient peer utilization
- Simple window (just track in-flight limit)

---

## Code Size Comparison

### Bitcoin Core (net_processing.cpp)

**Headers-First Core Functions**:
- `FindNextBlocksToDownload`: ~100 lines
- `MarkBlockAsInFlight`: ~20 lines
- `MarkBlockAsReceived`: ~30 lines
- Stall detection: ~50 lines
- **Total**: ~200 lines

**Data Structures**:
- `QueuedBlock`: 1 field (CBlockIndex*)
- `mapBlocksInFlight`: std::multimap
- `vBlocksInFlight`: std::list per peer
- **Total**: ~50 lines

**Grand Total**: ~250 lines for complete IBD block download logic

### Dilithion (block_fetcher.cpp)

**Chunk System**:
- `PeerChunk` struct: 88 lines
- `AssignChunkToPeer`: 97 lines
- `OnChunkBlockReceived`: 183 lines
- `CheckStalledChunks`: 57 lines
- `ReassignChunk`: 52 lines
- `CancelStalledChunk`: 98 lines
- `CleanupCancelledChunks`: 28 lines
- `mapActiveChunks`, `mapHeightToPeer`, `mapCancelledChunks`: ~50 lines
- **Chunk Total**: ~650 lines

**Workarounds**:
- BUG #163 fix (height-based cleanup): 20 lines
- BUG #161 debug (hash mismatch): 15 lines
- BUG #162 fix (connected check): 30 lines
- BUG #165 fix (unsuitable peers): 65 lines
- Various IBD HANG fixes: ~100 lines
- **Workaround Total**: ~230 lines

**Window System**:
- `CBlockDownloadWindow`: 424 lines
- Window integration: ~100 lines
- **Window Total**: ~524 lines

**Grand Total**: ~1400 lines

**Savings from Migration**: ~1400 - 250 = **1150 lines removed**

---

## Risk Analysis

### Risks of NOT Implementing Headers-First

1. **Hash Mismatches Continue**: BUG #161 will persist, causing unreliable block matching
2. **Stalls Continue**: BUG #163 and similar will continue appearing as mapBlocksInFlight fills up
3. **Technical Debt Grows**: More workarounds added, code becomes unmaintainable
4. **Performance Degradation**: Workarounds are slower than proper implementation
5. **Security Risks**: Unreliable block matching could be exploited

### Risks of Implementing Headers-First

1. **Migration Complexity**: Need to refactor existing IBD code
   - Mitigation: Incremental migration, keep old code until new code proven

2. **Testing Burden**: Need comprehensive testing across all scenarios
   - Mitigation: Detailed test plan, multi-phase rollout

3. **Temporary Instability**: Bugs during transition period
   - Mitigation: Feature flag, rollback plan

### Risk Mitigation Strategy

1. **Feature Flag**:
   ```cpp
   static bool USE_HEADERS_FIRST = false;  // Default off

   if (USE_HEADERS_FIRST) {
       // New headers-first path
   } else {
       // Old chunk-based path
   }
   ```

2. **Parallel Implementation**:
   - Implement headers-first alongside chunk system
   - Test extensively with headers-first enabled
   - Only remove chunk system when headers-first proven stable

3. **Gradual Rollout**:
   - Week 1-2: Headers-first on testnet only
   - Week 3-4: Headers-first on developer nodes
   - Week 5+: Headers-first enabled by default
   - Keep rollback option for 2+ weeks

---

## Conclusion

Dilithion's IBD implementation has the right intentions but is missing the **critical foundation**: **headers-first download**. This missing foundation causes cascading problems that have been "fixed" with increasingly complex workarounds.

**The solution is clear**: Port Bitcoin Core's headers-first approach. This will:

1. Eliminate hash mismatch bugs
2. Eliminate mapBlocksInFlight stalls
3. Allow removal of ~1150 lines of workaround code
4. Provide a stable foundation for future improvements
5. Align with battle-tested Bitcoin Core patterns

**Recommendation**: Prioritize headers-first implementation as the **highest priority** for IBD stability and performance.

---

## Appendix: Bitcoin Core Source References

### Key Files to Study

1. **net_processing.cpp**:
   - `FindNextBlocksToDownload()` (line ~1038)
   - `MarkBlockAsInFlight()` (now `BlockRequested`)
   - `MarkBlockAsReceived()` (now `RemoveBlockRequest`)
   - Stall detection logic

2. **validation.cpp**:
   - `ProcessNewBlock()`
   - `AcceptBlock()`
   - `CheckBlock()`
   - `ActivateBestChain()`

3. **Data Structures**:
   - `CBlockIndex` (chain.h)
   - `QueuedBlock` (net_processing.cpp)
   - `mapBlockIndex` (validation.cpp)
   - `mapBlocksInFlight` (net_processing.cpp)

### Recommended Reading Order

1. Start with Bitcoin Wiki: [Bitcoin Core 0.11 Initial Block Download](https://en.bitcoin.it/wiki/Bitcoin_Core_0.11_(ch_5):_Initial_Block_Download)
2. Read PR #8872: [Remove block-request logic from INV message processing](https://github.com/bitcoin/bitcoin/pull/8872)
3. Read PR #22141: [Remove hash and fValidatedHeaders from QueuedBlock](https://github.com/bitcoin/bitcoin/pull/22141)
4. Study net_processing.cpp directly (latest master)

---

*Analysis completed: 2025-12-21*
*Dilithion version analyzed: Current codebase*
*Bitcoin Core version analyzed: master branch (latest)*
