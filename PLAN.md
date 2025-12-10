# BUG #119: Block Download Stall Fix - Implementation Plan

## Problem Analysis

### Root Cause
There are **two separate tracking systems** for in-flight blocks that are not synchronized:

| System | Timeout | Stall Threshold | Max In-Flight |
|--------|---------|-----------------|---------------|
| NodeStateManager | 10-320s adaptive | 5 stalls → disconnect | 64 total, 16/peer |
| BlockFetcher | 60s fixed | 10 stalls → unsuitable | 16 total, 8/peer |

### The Deadlock Scenario
1. T+10s: NodeState detects stall, logs warning
2. T+10-60s: BlockFetcher still has block consuming slot (hasn't timed out)
3. T+10-60s: `IsPeerSuitable()` may return false (peer stalling)
4. T+10-60s: `SelectPeerForDownload()` skips peers with no free slots
5. Result: Only peer is "unsuitable" AND has no slots → no fallback → deadlock

### Bitcoin Core Approach
- Single stall detection system
- Disconnect stalling peer immediately (frees slots)
- Adaptive timeout that increases after disconnect to prevent cascade
- Can request same block from multiple peers

---

## Implementation Plan

### Phase 1: Fix Fallback Logic (Critical - 30min)

**File:** `src/net/block_fetcher.cpp`

**Change:** Modify `SelectPeerForDownload()` to set fallback even when peer has no available slots.

Current code (line ~310-328):
```cpp
for (const auto& entry : mapPeerStates) {
    int availableSlots = GetAvailableSlotsForPeer(peer);
    if (availableSlots <= 0) {
        continue;  // SKIPS ENTIRELY - doesn't set fallback
    }
    if (!suitable) {
        fallbackPeer = peer;  // Only reached if has slots
    }
}
```

New code:
```cpp
for (const auto& entry : mapPeerStates) {
    int availableSlots = GetAvailableSlotsForPeer(peer);

    // BUG #119 FIX: Track as fallback even if no slots available
    // "A stalled peer with no slots is better than no peer at all"
    // This prevents deadlock when only 1 peer is connected
    if (!IsPeerSuitable(peer)) {
        if (fallbackPeer == -1) {
            fallbackPeer = peer;  // Track even without slots
        }
        continue;
    }

    if (availableSlots <= 0) {
        continue;  // Still skip for best peer selection
    }
    // ... rest of scoring logic
}
```

### Phase 2: Synchronize Timeouts (Important - 15min)

**File:** `src/net/block_fetcher.h`

**Change:** Reduce `BLOCK_DOWNLOAD_TIMEOUT` from 60s to 15s

```cpp
// BUG #119 FIX: Reduced from 60s to 15s to align with NodeState stall detection
// NodeState detects stalls at 10s (base), BlockFetcher should timeout shortly after
static constexpr auto BLOCK_DOWNLOAD_TIMEOUT = std::chrono::seconds(15);
```

**Rationale:**
- NodeState detects at 10s
- BlockFetcher times out at 15s
- Only 5s of "dead time" instead of 50s

### Phase 3: Remove Duplicate Stall Tracking (Recommended - 45min)

**Files:** `src/net/block_fetcher.cpp`, `src/net/block_fetcher.h`

**Changes:**
1. Remove `IsPeerSuitable()` - use NodeStateManager instead
2. Remove `PEER_STALL_THRESHOLD` constant
3. Remove `nStalls` from `PeerDownloadState`
4. Query `CNodeStateManager::Get()` for peer health

```cpp
// Instead of:
bool suitable = IsPeerSuitable(peer);

// Use:
CNodeState* state = CNodeStateManager::Get().GetState(peer);
bool suitable = (state && state->nStallingCount < 3);  // Allow some stalls
```

### Phase 4: Optional - Increase Stall Tolerance (15min)

**File:** `src/net/node_state.cpp`

**Change:** Increase disconnect threshold from 5 to 8 stalls during IBD

```cpp
// Line 266: Consider context when deciding disconnect threshold
// During IBD with few peers, be more tolerant
int disconnect_threshold = (GetHandshakeCompleteCount() <= 2) ? 8 : 5;
if (state.nStallingCount >= disconnect_threshold) {
    stallingPeers.push_back(nodeid);
}
```

---

## Testing Plan

1. **Build and run locally** on Windows
2. **Deploy to Singapore** (fresh sync from 0)
3. **Monitor logs** for:
   - "no suitable peers" warnings (should decrease)
   - "Checkpoint X verified" (should still work)
   - Block progression (should be faster)
4. **Deploy to London** after Singapore verified
5. **Monitor all 3 nodes** until synced

---

## Risk Assessment

| Phase | Risk | Mitigation |
|-------|------|------------|
| Phase 1 | Low - only fallback logic | Peer scoring still prefers better peers |
| Phase 2 | Medium - more frequent timeouts | Adaptive retry prevents cascade |
| Phase 3 | Medium - requires careful coordination | Keep NodeStateManager as source of truth |
| Phase 4 | Low - just changes threshold | Only affects IBD with few peers |

---

## Files Modified

1. `src/net/block_fetcher.cpp` - Fallback logic, remove duplicate tracking
2. `src/net/block_fetcher.h` - Timeout constant, remove stall members
3. `src/net/node_state.cpp` - Optional: IBD-aware disconnect threshold

---

## Estimated Time

- Phase 1: 30 minutes
- Phase 2: 15 minutes
- Phase 3: 45 minutes
- Phase 4: 15 minutes
- Testing: 30 minutes

**Total: ~2.5 hours**

## Recommendation

Implement **Phase 1 + Phase 2** first (45 min) - these are the critical fixes.
Phase 3 can be done as a follow-up cleanup.
Phase 4 is optional optimization.
