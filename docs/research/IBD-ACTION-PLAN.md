# Dilithion IBD: Action Plan (Priority-Ordered)

## Critical Insight

**Dilithion is missing headers-first download.** This causes hash mismatches, stalls, and requires complex workarounds. Bitcoin Core solved this 10+ years ago.

---

## Priority 1: Implement Headers-First (CRITICAL - 2 weeks)

### What It Is

Download ALL block headers BEFORE downloading any full blocks.

### Why It Matters

- Hash is computed from header (80 bytes)
- Hash is KNOWN before requesting full block (1MB)
- Block arrival can be matched by hash lookup
- NO MORE hash mismatches

### Implementation

```cpp
// PHASE 1: Download headers
void SyncHeaders(NodeId peer) {
    while (true) {
        // Request 2000 headers at a time
        SendGetHeaders(peer, locator);

        // Receive HEADERS message
        std::vector<CBlockHeader> headers = ReceiveHeaders(peer);
        if (headers.empty()) break;  // No more headers

        // Process each header
        for (const CBlockHeader& header : headers) {
            // Validate header
            if (!CheckBlockHeader(header)) continue;
            if (!ContextualCheckBlockHeader(header)) continue;

            // Compute hash
            uint256 hash = header.GetHash();  // SHA256(SHA256(header))

            // Create block index
            CBlockIndex* pindex = new CBlockIndex(header);
            pindex->nHeight = GetNextHeight();
            pindex->phashBlock = new uint256(hash);

            // Store in map
            mapBlockIndex[hash] = pindex;
            pindex->pprev->pnext = pindex;

            // Mark as validated
            pindex->nStatus |= BLOCK_VALID_TREE;
        }

        // Update best known
        UpdateBestHeaderChain();
    }
}

// PHASE 2: Download blocks using known hashes
void SyncBlocks() {
    // Now we have ALL headers with KNOWN hashes
    int chain_height = GetChainHeight();
    CBlockIndex* pindex = mapBlockIndex[chain_height];

    // Walk forward through headers we downloaded
    std::vector<uint256> to_download;
    while (pindex->pnext && to_download.size() < 16) {
        pindex = pindex->pnext;

        // Hash is ALREADY KNOWN from header
        uint256 hash = pindex->GetBlockHash();

        // Request block by KNOWN hash
        to_download.push_back(hash);
    }

    // Send GETDATA with known hashes
    for (uint256 hash : to_download) {
        mapBlocksInFlight[hash] = CBlockInFlight(hash, peer, height);
        SendGetData(peer, hash);
    }
}

// PHASE 3: Match arriving blocks
void OnBlockReceived(const CBlock& block, NodeId peer) {
    // Compute hash from block header
    uint256 hash = block.GetHash();

    // Look up in mapBlocksInFlight
    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        // NOT FOUND - unrequested block
        LogPrint("Unrequested block from peer %d\n", peer);
        return;
    }

    // FOUND - hash matches perfectly!
    ProcessBlock(block);
    mapBlocksInFlight.erase(it);
}
```

### Success Criteria

- [ ] NO hash mismatch errors in logs
- [ ] MarkBlockReceived succeeds for all arriving blocks
- [ ] mapBlocksInFlight entries cleared when blocks arrive
- [ ] Can remove BUG #161, #163 workarounds

### Files to Modify

1. Create `src/net/headers_sync.cpp` - new file
2. Modify `src/net/block_fetcher.cpp` - add headers phase
3. Modify `src/node/ibd_coordinator.cpp` - call headers sync first
4. Create `src/chain/block_index.h` - CBlockIndex structure

### Estimated Effort

- Implementation: 3 days
- Testing: 4 days
- Integration: 3 days
- **Total**: 10 days

---

## Priority 2: Port FindNextBlocksToDownload (HIGH - 1 week)

### What It Is

Bitcoin Core's algorithm for selecting which blocks to download next.

### Why It Matters

- Efficient block selection
- Natural fork handling
- Optimal peer utilization

### Implementation

```cpp
std::vector<CBlockIndex*> FindNextBlocksToDownload(NodeId peer, int max_count) {
    std::vector<CBlockIndex*> result;

    // Get peer's best known block (from headers sync)
    CBlockIndex* peerBest = GetPeerBestKnownBlock(peer);
    if (!peerBest) return result;

    // Find fork point (last common ancestor)
    CBlockIndex* pindex = GetChainTip();
    while (pindex && !IsAncestor(pindex, peerBest)) {
        pindex = pindex->pprev;
    }

    // Walk forward from fork point
    while (result.size() < max_count && pindex->pnext) {
        pindex = pindex->pnext;

        // Skip if already have block
        if (HaveBlockData(pindex->GetBlockHash())) {
            continue;
        }

        // Skip if already in flight
        if (IsBlockInFlight(pindex->GetBlockHash())) {
            continue;
        }

        result.push_back(pindex);
    }

    return result;
}
```

### Success Criteria

- [ ] Blocks selected in optimal order
- [ ] Forks detected and handled
- [ ] No gaps in block requests
- [ ] Multiple peers download in parallel

### Files to Modify

1. Modify `src/net/block_fetcher.cpp` - add FindNextBlocksToDownload
2. Modify `src/net/peers.cpp` - track peer best known block
3. Modify `src/chain/chain.h` - add ancestor checking

### Estimated Effort

- Implementation: 2 days
- Testing: 2 days
- Integration: 1 day
- **Total**: 5 days

---

## Priority 3: Simplify to Per-Block Model (HIGH - 1 week)

### What It Is

Replace chunk system with Bitcoin Core's per-block assignment.

### Why It Matters

- Simpler code (~1150 lines removed)
- Fewer bugs
- Easier to maintain

### Implementation

```cpp
// OLD (chunk-based):
struct PeerChunk {
    NodeId peer_id;
    int height_start;
    int height_end;
    int blocks_pending;
    int blocks_received;
    // + 80 more lines
};
std::map<NodeId, PeerChunk> mapActiveChunks;
std::map<int, NodeId> mapHeightToPeer;
std::map<NodeId, CancelledChunk> mapCancelledChunks;
// + 600 lines of chunk management

// NEW (per-block):
struct QueuedBlock {
    CBlockIndex* pindex;  // That's it!
};
std::list<QueuedBlock> vBlocksInFlight;  // Per peer (max 16)
std::multimap<uint256, NodeId> mapBlocksInFlight;  // Global lookup
// + ~50 lines of simple tracking
```

### Migration Steps

1. **Week 1**: Keep chunk system, add per-block path alongside
2. **Week 2**: Test per-block path extensively
3. **Week 3**: Switch default to per-block
4. **Week 4**: Remove chunk system entirely

### Success Criteria

- [ ] Per-block path works correctly
- [ ] Chunk code removed
- [ ] Codebase ~1150 lines smaller
- [ ] All tests pass

### Files to Modify

1. Modify `src/net/block_fetcher.h` - remove PeerChunk, add QueuedBlock
2. Modify `src/net/block_fetcher.cpp` - replace chunk logic
3. Delete chunk-related methods (AssignChunk, ReassignChunk, etc.)

### Estimated Effort

- Implementation: 3 days
- Testing: 2 days
- Cleanup: 2 days
- **Total**: 7 days

---

## Priority 4: Implement Parallel Download on Stall (MEDIUM - 3 days)

### What It Is

When a block stalls (no response in 2 seconds), request from SECOND peer in parallel.

### Why It Matters

- Faster IBD (no waiting for slow peers)
- Redundancy (if one fails, another delivers)
- Natural peer quality selection

### Implementation

```cpp
void CheckForStalledBlocks() {
    auto now = std::chrono::steady_clock::now();

    for (auto& [hash, info] : mapBlocksInFlight) {
        auto elapsed = now - info.request_time;

        if (elapsed >= std::chrono::seconds(2)) {
            // Block stalled - add parallel peer
            if (info.peers.size() < 2) {  // Max 2 peers per block
                NodeId second_peer = SelectBestPeer();
                if (second_peer >= 0) {
                    // Request from second peer
                    SendGetData(second_peer, hash);
                    info.peers.insert(second_peer);

                    LogPrint("Block %s stalled, requesting from peer %d\n",
                             hash.GetHex(), second_peer);
                }
            }
        }
    }
}

void OnBlockReceived(uint256 hash, NodeId peer) {
    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) return;

    // Remove from ALL peers (they were racing)
    for (NodeId racing_peer : it->second.peers) {
        RemoveBlockFromPeer(racing_peer, hash);
    }

    mapBlocksInFlight.erase(it);
}
```

### Success Criteria

- [ ] Stalled blocks automatically get second peer
- [ ] First responder wins
- [ ] Slow peers gradually phased out
- [ ] IBD completes faster

### Files to Modify

1. Modify `src/net/block_fetcher.cpp` - add parallel download logic
2. Modify `mapBlocksInFlight` to track multiple peers per block

### Estimated Effort

- Implementation: 1 day
- Testing: 1 day
- Integration: 1 day
- **Total**: 3 days

---

## Timeline

### Month 1: Foundation
- **Week 1-2**: Implement headers-first (Priority 1)
- **Week 3**: Port FindNextBlocksToDownload (Priority 2)
- **Week 4**: Testing and integration

### Month 2: Simplification
- **Week 1-2**: Implement per-block model (Priority 3)
- **Week 3**: Remove chunk system
- **Week 4**: Parallel download on stall (Priority 4)

### Month 3: Testing & Optimization
- Comprehensive testing
- Performance optimization
- Documentation

**Total**: ~3 months to complete migration

---

## Testing Checklist

### After Each Priority

**Headers-First** (Priority 1):
- [ ] All headers downloaded before blocks
- [ ] Hash computed from header
- [ ] Hash matches when block arrives
- [ ] No hash mismatch errors

**FindNextBlocksToDownload** (Priority 2):
- [ ] Blocks selected in order
- [ ] Forks detected
- [ ] No missing blocks
- [ ] Multiple peers utilized

**Per-Block Model** (Priority 3):
- [ ] 16 blocks max per peer
- [ ] No chunk state machine
- [ ] Simple assignment logic
- [ ] Cleanup complete (code removed)

**Parallel Download** (Priority 4):
- [ ] Stalls trigger parallel download
- [ ] First responder wins
- [ ] Slow peers phased out
- [ ] IBD faster than before

### Integration Testing

- [ ] Full IBD from genesis on testnet
- [ ] Multi-peer IBD (3+ peers)
- [ ] Peer disconnection during IBD
- [ ] Fork recovery
- [ ] Reorg handling
- [ ] Memory leak check
- [ ] Performance benchmark

---

## Success Metrics

### Before Migration

- Hash mismatch errors: ~10 per 1000 blocks
- 128-block stalls: ~5 per IBD
- Code complexity: ~1400 lines
- IBD time (testnet): ~X minutes

### After Migration

- Hash mismatch errors: 0
- 128-block stalls: 0
- Code complexity: ~250 lines
- IBD time (testnet): ~X/2 minutes (target: 50% faster)

---

## Rollback Plan

If any priority fails:

1. **Headers-First Fails**:
   - Keep feature flag off
   - Continue with chunk system
   - Debug headers implementation
   - Re-attempt next sprint

2. **FindNextBlocksToDownload Fails**:
   - Fallback to manual chunk assignment
   - Debug block selection
   - Re-attempt with simpler version

3. **Per-Block Model Fails**:
   - Keep chunk system
   - Use per-block only for new code
   - Gradual migration over longer period

4. **Parallel Download Fails**:
   - Disable parallel download feature
   - Keep sequential download
   - Debug race conditions
   - Re-enable when stable

---

## Key Takeaways

1. **Headers-First is CRITICAL** - everything else depends on it
2. **Port, don't reinvent** - Bitcoin Core has solved these problems
3. **Simplify, don't add complexity** - chunk system is overkill
4. **Test thoroughly** - IBD is critical path, can't afford bugs
5. **Incremental migration** - keep rollback options

---

## Quick Reference: Bitcoin Core vs Dilithion

| Feature | Bitcoin Core | Dilithion Current | Dilithion Target |
|---------|--------------|-------------------|------------------|
| Download Method | Headers-first | Blocks-first? | **Headers-first** |
| Hash Known | Before download | On arrival | **Before download** |
| Assignment | Per-block (16/peer) | Chunk (16-block) | **Per-block** |
| Stall Handling | Parallel download | Cancel chunk | **Parallel download** |
| Code Size | ~250 lines | ~1400 lines | **~250 lines** |
| Complexity | Low | High | **Low** |

---

*Action plan created: 2025-12-21*
*Based on Bitcoin Core master branch analysis*
*Target completion: 3 months*
