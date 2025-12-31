# Block Propagation Improvement - Implementation Handoff Report

**Date**: 2025-12-30
**Status**: Planning Complete - Ready for Implementation
**Plan File**: `C:\Users\will\.claude\plans\swift-churning-dusk.md`

---

## Executive Summary

This document provides all context needed to continue implementing the block propagation improvements in a new conversation. The implementation consists of 3 phases that will dramatically improve Dilithion's block relay efficiency.

### Background Problem Solved This Session

Before starting this plan, we fixed a critical bug where seed nodes stopped syncing after IBD:
- **Root Cause**: `SyncHeadersFromPeer()` had dedup logic that skipped header requests when `peer_height <= m_headers_requested_height`
- **Fix Applied**: Added `force` parameter to bypass dedup, INV-triggered requests use `force=true`
- **Commit**: `42d2542` - "fix: Force header request when receiving INV for unknown blocks"
- **Version**: v1.3.6 deployed to all 3 seed nodes and working

This fix is a band-aid. The proper solution is the 3-phase plan below.

---

## The 3-Phase Implementation Plan

### Phase 1: Clear IBD/SYNCED State Machine (2-3 hours)

**Goal**: Create authoritative `IsSynced()` method that cleanly separates IBD from steady-state behavior.

**Why Needed**: Current code mixes IBD and steady-state logic, requiring hacks like the `force` parameter.

**Files to Modify**:
| File | Changes |
|------|---------|
| `src/node/ibd_coordinator.h` | Add `IsSynced()`, `IsInitialBlockDownload()`, `m_synced` atomic |
| `src/node/ibd_coordinator.cpp` | Implement sync detection with hysteresis in `UpdateState()` |
| `src/net/headers_manager.cpp` | Simplify `SyncHeadersFromPeer()` - no dedup in synced state |
| `src/core/node_context.h` | Add convenience `IsSynced()` wrapper |

**Key Implementation**:
```cpp
// ibd_coordinator.h - Add after IsActive():
bool IsSynced() const;
bool IsInitialBlockDownload() const;

// Private members:
std::atomic<bool> m_synced{false};
static constexpr int SYNC_TOLERANCE_BLOCKS = 2;

// ibd_coordinator.cpp:
bool CIbdCoordinator::IsSynced() const {
    return m_synced.load();
}

// In UpdateState(), set m_synced when:
// - header_height >= best_peer_height - SYNC_TOLERANCE_BLOCKS
// - chain_height >= header_height
// - m_state == IBDState::COMPLETE
```

**Simplify headers_manager.cpp**:
```cpp
bool CHeadersManager::SyncHeadersFromPeer(NodeId peer, int peer_height, bool force) {
    // STEADY-STATE: Simple request, no dedup
    if (g_node_context.ibd_coordinator && g_node_context.ibd_coordinator->IsSynced()) {
        RequestHeaders(peer, GetBestHeaderHash());
        return true;
    }
    // IBD MODE: Use existing dedup logic (unchanged)
    // ...
}
```

---

### Phase 2: sendheaders Protocol - BIP 130 (2-3 hours)

**Goal**: Allow peers to signal preference for HEADERS over INV, reducing 1 round trip.

**Current Flow**: INV → getheaders → headers → getdata → block (4 RTT)
**New Flow**: HEADERS → getdata → block (2 RTT for preferring peers)

**Files to Modify**:
| File | Changes |
|------|---------|
| `src/net/protocol.h` | Add `MSG_SENDHEADERS` to MessageType enum |
| `src/net/node.h` | Add `fPreferHeaders`, `fSentSendHeaders` atomic flags |
| `src/net/net.h` | Add `SendHeadersHandler` type and setter |
| `src/net/net.cpp` | Implement `ProcessSendHeadersMessage()`, add to dispatch |
| `src/node/dilithion-node.cpp` | Send sendheaders after handshake complete |
| `src/net/async_broadcaster.cpp` | Route by preference: HEADERS vs INV |

**Protocol Addition** (protocol.h):
```cpp
enum MessageType {
    // ... existing ...
    MSG_SENDHEADERS,  // BIP 130
    MSG_SENDCMPCT,    // BIP 152
    MSG_CMPCTBLOCK,   // BIP 152
    MSG_GETBLOCKTXN,  // BIP 152
    MSG_BLOCKTXN,     // BIP 152
};
```

**Per-Peer Flags** (node.h, after line 100):
```cpp
std::atomic<bool> fPreferHeaders{false};     // Peer sent sendheaders
std::atomic<bool> fSentSendHeaders{false};   // We sent sendheaders
std::atomic<bool> fPreferCompactBlocks{false};  // BIP 152
std::atomic<bool> fHighBandwidth{false};        // BIP 152 high-bandwidth
```

**Announcement Routing** (async_broadcaster.cpp):
```cpp
// In BroadcastBlock():
for (int peer_id : peer_ids) {
    CNode* pnode = m_connman->GetNode(peer_id);
    if (pnode->fPreferHeaders.load()) {
        headers_peers.push_back(peer_id);
    } else {
        inv_peers.push_back(peer_id);
    }
}
// Send HEADERS to preferring peers, INV to others
```

---

### Phase 3: Compact Blocks - BIP 152 (4-6 hours)

**Goal**: 85-90% bandwidth reduction by sending header + short tx IDs instead of full blocks.

**New Files to Create**:
- `src/net/compact_blocks.h`
- `src/net/compact_blocks.cpp`

**Files to Modify**:
- `src/net/net.h` - Add compact block handlers
- `src/net/net.cpp` - Process CMPCTBLOCK, GETBLOCKTXN, BLOCKTXN
- `src/node/dilithion-node.cpp` - Handle reconstruction
- `src/net/async_broadcaster.cpp` - Send CMPCTBLOCK to HB peers
- `Makefile` - Add new source files

**Key Data Structures** (compact_blocks.h):
```cpp
struct CBlockHeaderAndShortTxIDs {
    CBlockHeader header;
    uint64_t nonce;  // For SipHash
    std::vector<uint64_t> short_txids;  // 6-byte short IDs
    std::vector<PrefilledTransaction> prefilled_txs;  // Coinbase always included

    explicit CBlockHeaderAndShortTxIDs(const CBlock& block);
    uint64_t GetShortID(const uint256& txid) const;
};

struct CBlockTransactionsRequest {
    uint256 blockhash;
    std::vector<uint16_t> indices;  // Missing tx indices
};

struct CBlockTransactions {
    uint256 blockhash;
    std::vector<CTransactionRef> txs;
};

class CCompactBlockState {
    std::map<uint256, PartialBlock> m_partial_blocks;
    int InitializePartialBlock(const CBlockHeaderAndShortTxIDs& cmpct, CTxMemPool* mempool);
    bool AddTransactions(const uint256& blockhash, const std::vector<CTransactionRef>& txs);
};
```

**Short ID Calculation**:
- Key derivation: `SHA256(block_header || nonce)` → k0, k1
- Short ID: `SipHash(k0, k1, txid) & 0xffffffffffff` (6 bytes)

**Reconstruction Flow**:
1. Receive CMPCTBLOCK
2. Try to reconstruct from mempool using short IDs
3. If all txs found → process block immediately
4. If missing txs → send GETBLOCKTXN request
5. Receive BLOCKTXN → complete block → process

---

## Current Codebase State

### Key Files (Read These First)

1. **`src/node/ibd_coordinator.h`** (193 lines)
   - IBDState enum at line 20-26
   - CIbdCoordinator class at line 38
   - Add `IsSynced()` after line 75

2. **`src/node/ibd_coordinator.cpp`**
   - `UpdateState()` - add sync detection here
   - `Tick()` - main IBD loop

3. **`src/net/headers_manager.cpp`**
   - `SyncHeadersFromPeer()` at line 406 - simplify for synced state

4. **`src/net/node.h`** (150+ lines)
   - CNode class at line 69
   - Add preference flags after line 100

5. **`src/net/protocol.h`** (150+ lines)
   - MessageType enum at line 42-58
   - InvType enum at line 61-66 (MSG_CMPCT_BLOCK = 4 already exists)

6. **`src/net/async_broadcaster.cpp`**
   - `BroadcastBlock()` - modify to route by preference

### Already Existing

- `MSG_CMPCT_BLOCK = 4` in InvType enum
- Async broadcaster pattern for block relay
- Handler registration via `SetXxxHandler()` pattern
- Message creation via `CreateXxxMessage()` pattern

---

## Seed Node Information

| Location | IP | Role |
|----------|-----|------|
| NYC | 134.122.4.164 | Seed/Relay |
| SGP | 188.166.255.63 | Seed/Relay |
| LDN | 209.97.177.197 | Seed/Relay |

**Current Version**: v1.3.6 (deployed 2025-12-30)
**Current Chain Height**: ~4992 blocks

**Restart Command** (per SEED NODE OPERATIONS protocol):
```bash
ssh root@IP "pkill dilithion; rm -f /root/.dilithion-testnet/*/LOCK; cd /root/dilithion && git pull && make clean && make dilithion-node -j4 && nohup ./dilithion-node --testnet > /root/node.log 2>&1 &"
```

---

## Testing Strategy

### Phase 1 Tests
1. Fresh node start: `IsSynced()` = false
2. After full sync: `IsSynced()` = true, stable
3. INV for new block: Headers requested without `force` hack
4. Network partition: Correct IBD re-entry

### Phase 2 Tests
1. Handshake: Both peers exchange sendheaders
2. Block mined: HEADERS to preferring, INV to others
3. Mixed network: Old peers work normally

### Phase 3 Tests
1. Full mempool: Reconstruct without GETBLOCKTXN
2. Partial mempool: Request missing via GETBLOCKTXN
3. Empty mempool: Fallback to full block
4. High-bandwidth: Unsolicited CMPCTBLOCK on new tip

---

## Implementation Order

1. **Start with Phase 1** - Foundation for other phases
2. **Phase 2** - Can be done in parallel with Phase 3 prep
3. **Phase 3** - Most complex, requires Phase 1 complete

Each phase should be:
1. Implemented
2. Tested locally
3. Deployed to one seed node
4. Verified working
5. Deployed to remaining seed nodes

---

## Commands for New Session

**Start new conversation with**:
```
Continue implementing the block propagation improvements from BLOCK-PROPAGATION-IMPROVEMENT-HANDOFF.md.
Start with Phase 1: Clear IBD/SYNCED State Machine.
```

**Key files to read first**:
```
src/node/ibd_coordinator.h
src/node/ibd_coordinator.cpp
src/net/headers_manager.cpp
C:\Users\will\.claude\plans\swift-churning-dusk.md
```

---

## Recent Git History

```
42d2542 fix: Force header request when receiving INV for unknown blocks (v1.3.6)
d9c64ac feat: Add detailed wallet impact messaging during fork resync
82385c1 fix: Reset m_headers_requested_height in Clear() for proper resync
e5a06c2 fix: Reset initial_request_done and handle header_height=-1 after resync
6023323 fix: Use Genesis::GetGenesisHash() in resync prompt
3465f98 fix: Reindex stoi crash + add interactive resync prompt
```

---

## Success Criteria

| Phase | Metric |
|-------|--------|
| 1 | Clean state separation, `force` parameter no longer needed |
| 2 | Block announcements via HEADERS reduce 1 RTT |
| 3 | 85-90% bandwidth reduction for block relay |

---

*This report was generated to enable seamless continuation in a new conversation.*
