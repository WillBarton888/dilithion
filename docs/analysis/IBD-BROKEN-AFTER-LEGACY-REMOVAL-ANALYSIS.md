# IBD Broken After Legacy Code Removal - Analysis

**Date**: 2025-12-14  
**Status**: Research Complete - Issues Identified  
**Type**: Research Only - No Code Changes

## Executive Summary

After removing legacy code (CConnectionManager and global variables), IBD is not working. This analysis identifies potential root causes and issues in the IBD code flow.

---

## Initialization Order Analysis

### NodeContext Initialization Sequence

**File**: `src/core/node_context.cpp`

```cpp
// Line 35-43: Initialization order
headers_manager = std::make_unique<CHeadersManager>();
orphan_manager = std::make_unique<COrphanManager>();
block_fetcher = std::make_unique<CBlockFetcher>(peer_manager.get());
```

**Key Observation**: 
- `block_fetcher` is created **AFTER** `peer_manager` is created
- `peer_manager.get()` is passed to `CBlockFetcher` constructor
- **POTENTIAL ISSUE**: If `peer_manager` is `nullptr` at this point, `CBlockFetcher` will store `nullptr` in `m_peer_manager`

### CBlockFetcher Constructor

**File**: `src/net/block_fetcher.cpp:24-28`

```cpp
CBlockFetcher::CBlockFetcher(CPeerManager* peer_manager)
    : m_peer_manager(peer_manager), nBlocksReceivedTotal(0)
{
    lastBlockReceived = std::chrono::steady_clock::now();
}
```

**Key Observations**:
- Constructor accepts `CPeerManager*` (can be `nullptr`)
- No null check in constructor
- `m_peer_manager` can be `nullptr` if `peer_manager.get()` returns `nullptr`

### Null Checks in CBlockFetcher Methods

**File**: `src/net/block_fetcher.cpp`

All methods check `if (!m_peer_manager)` before use:
- Line 71: `RequestBlock()` - returns `false` if null
- Line 281: `SelectPeerForDownload()` - returns `-1` if null
- Line 386: `GetBlocksInFlightForPeer()` - returns `0` if null
- Line 580: `AssignChunkToPeer()` - returns `false` if null
- Line 900: `ReassignChunkToPeer()` - returns `false` if null

**Analysis**: Methods handle null gracefully, but if `m_peer_manager` is null, IBD will fail silently (methods return early).

---

## IBD Coordinator Analysis

### CIbdCoordinator Constructor

**File**: `src/node/ibd_coordinator.cpp:50-60`

```cpp
CIbdCoordinator::CIbdCoordinator(CChainState& chainstate, NodeContext& node_context)
    : m_chainstate(chainstate), m_node_context(node_context)
{
    // ...
}
```

**Key Observation**: 
- Stores reference to `NodeContext`
- Uses `m_node_context.block_fetcher` and `m_node_context.peer_manager`
- **POTENTIAL ISSUE**: If `block_fetcher` or `peer_manager` are null, methods will fail

### Peer Availability Checks

**File**: `src/node/ibd_coordinator.cpp:315-340`

```cpp
// Get valid peers for download
std::vector<int> available_peers = m_node_context.peer_manager->GetValidPeersForDownload();

// Check if all peers are at capacity
bool all_peers_at_capacity = true;
for (int peer_id : available_peers) {
    auto peer = m_node_context.peer_manager->GetPeer(peer_id);
    if (peer && peer->nBlocksInFlight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        all_peers_at_capacity = false;
        break;
    }
}
```

**CRITICAL ISSUE #1**: 
- Uses `peer->nBlocksInFlight` (stale counter from `CPeer` object)
- Should use `m_node_context.peer_manager->GetBlocksInFlightForPeer(peer_id)` instead
- This is the SSOT fix that was applied to `CBlockFetcher` but NOT to `CIbdCoordinator`

**User's Fix Applied**: The user already fixed this in `CBlockFetcher` (using `GetBlocksInFlightForPeer()`), but `CIbdCoordinator` still uses the stale counter.

### Block Fetching Flow

**File**: `src/node/ibd_coordinator.cpp:380-450`

```cpp
void CIbdCoordinator::FetchBlocks(const std::vector<int>& chunk_heights) {
    // ...
    for (int height : chunk_heights) {
        uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(height);
        if (hash.IsNull()) {
            continue;  // Skip if hash not available
        }
        
        // Request block from best peer
        NodeId peer = m_node_context.block_fetcher->SelectPeerForDownload(hash, -1);
        if (peer == -1) {
            // No suitable peer
            continue;
        }
        
        // Request block
        if (!m_node_context.block_fetcher->RequestBlock(peer, hash, height)) {
            // Request failed
            continue;
        }
    }
}
```

**POTENTIAL ISSUE #2**:
- If `m_node_context.block_fetcher` is null, this will crash
- No null check before calling `SelectPeerForDownload()` or `RequestBlock()`

---

## Dependency Injection Issues

### CBlockFetcher Dependency on CPeerManager

**File**: `src/net/block_fetcher.h:432`

```cpp
explicit CBlockFetcher(CPeerManager* peer_manager);
```

**File**: `src/net/block_fetcher.h:853`

```cpp
private:
    CPeerManager* m_peer_manager;  // Single source of truth - no global dependency
```

**Analysis**:
- `CBlockFetcher` requires `CPeerManager*` to function
- If `m_peer_manager` is `nullptr`, all methods return early/fail
- No way to recover if `peer_manager` is null

### Forward Declaration Issue

**File**: `src/net/block_fetcher.h:17`

```cpp
// Forward declaration for dependency injection
class CPeerManager;
```

**File**: `src/net/block_fetcher.cpp:6`

```cpp
#include <net/peers.h>  // Phase A: Unified CPeerManager block tracking
```

**Analysis**: 
- Forward declaration in header is correct
- Include in `.cpp` is correct
- **NO ISSUE HERE**

---

## Potential Root Causes

### Issue #1: Null m_peer_manager in CBlockFetcher

**Scenario**: 
- `NodeContext::Init()` creates `block_fetcher` with `peer_manager.get()`
- If `peer_manager` is `nullptr` at that point, `m_peer_manager` will be `nullptr`
- All `CBlockFetcher` methods will return early/fail silently

**Evidence**:
- All methods check `if (!m_peer_manager)` and return early
- No error logging when null
- IBD would appear to "work" but no blocks would be requested

**Verification Needed**:
- Check if `peer_manager` is initialized before `block_fetcher` in `NodeContext::Init()`
- Check if `peer_manager.get()` can return `nullptr`

### Issue #2: CIbdCoordinator Uses Stale Counter

**Scenario**:
- `CIbdCoordinator::FetchBlocks()` checks `peer->nBlocksInFlight` (stale counter)
- Counter can become desynchronized during chunk cancellation
- Peers appear "at capacity" even when they're not

**Evidence**:
- User already fixed this in `CBlockFetcher` (using `GetBlocksInFlightForPeer()`)
- `CIbdCoordinator` still uses `peer->nBlocksInFlight` directly
- This matches the "IBD STUCK FIX #9" pattern the user applied

**Impact**:
- All peers marked "at capacity" incorrectly
- No blocks requested
- IBD stalls

### Issue #3: Missing Null Checks in CIbdCoordinator

**Scenario**:
- `CIbdCoordinator` calls `m_node_context.block_fetcher->...` without null checks
- If `block_fetcher` is null, will crash

**Evidence**:
- No null checks before calling `block_fetcher` methods
- No null checks before calling `peer_manager` methods

**Impact**:
- Potential crashes if components not initialized

### Issue #4: Initialization Order Dependency

**Scenario**:
- `CBlockFetcher` requires `CPeerManager*` in constructor
- If `peer_manager` is created after `block_fetcher`, or if it's reset, `m_peer_manager` will be stale/null

**Evidence**:
- `NodeContext::Init()` creates `peer_manager` first, then `block_fetcher`
- But if `NodeContext::Reset()` or `Shutdown()` is called, order matters

**Impact**:
- `m_peer_manager` pointer becomes invalid if `peer_manager` is destroyed/recreated

---

## Code Flow Analysis

### IBD Startup Sequence

1. **NodeContext::Init()** (line 35-43)
   - Creates `peer_manager`
   - Creates `block_fetcher` with `peer_manager.get()`
   - Creates `headers_manager`, `orphan_manager`

2. **CIbdCoordinator Creation** (in `dilithion-node.cpp`)
   - Created with `NodeContext&` reference
   - Stores reference to `m_node_context`

3. **IBD Trigger** (periodic call to `CIbdCoordinator::DownloadBlocks()`)
   - Checks if headers ahead of chain
   - Calls `FetchBlocks()` with chunk heights
   - `FetchBlocks()` calls `block_fetcher->SelectPeerForDownload()`
   - `SelectPeerForDownload()` checks `m_peer_manager` (can be null)
   - If null, returns `-1` (no peer)
   - `FetchBlocks()` skips block request

4. **Peer Capacity Check** (in `CIbdCoordinator::FetchBlocks()`)
   - Checks `peer->nBlocksInFlight` (stale counter)
   - If counter is wrong, peers marked "at capacity"
   - No blocks requested

---

## Specific Issues Found

### Issue #1: CIbdCoordinator Uses Stale Counter

**Location**: `src/node/ibd_coordinator.cpp:324-337`

```cpp
// Current code (WRONG):
for (int peer_id : available_peers) {
    auto peer = m_node_context.peer_manager->GetPeer(peer_id);
    if (peer && peer->nBlocksInFlight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        all_peers_at_capacity = false;
        break;
    }
}
```

**Problem**: 
- Uses `peer->nBlocksInFlight` (stale counter)
- Counter can be desynchronized during chunk cancellation
- Should use `m_node_context.peer_manager->GetBlocksInFlightForPeer(peer_id)` instead

**Impact**: 
- Peers incorrectly marked "at capacity"
- IBD stalls with "all peers at capacity" message

### Issue #2: Missing Null Checks in CIbdCoordinator

**Location**: `src/node/ibd_coordinator.cpp:315+`

```cpp
// Current code (POTENTIALLY UNSAFE):
std::vector<int> available_peers = m_node_context.peer_manager->GetValidPeersForDownload();
```

**Problem**:
- No null check for `m_node_context.peer_manager`
- No null check for `m_node_context.block_fetcher`
- Will crash if components not initialized

**Impact**:
- Potential crashes during startup/shutdown

### Issue #3: CBlockFetcher Silent Failures

**Location**: `src/net/block_fetcher.cpp:71+`

```cpp
// Current code:
if (!m_peer_manager) {
    return false;  // Silent failure
}
```

**Problem**:
- Returns `false` silently if `m_peer_manager` is null
- No error logging
- IBD appears to "work" but no blocks requested

**Impact**:
- IBD stalls without clear error message
- Hard to debug

### Issue #4: Initialization Order Verification

**Location**: `src/core/node_context.cpp:35-43`

```cpp
// Current order:
headers_manager = std::make_unique<CHeadersManager>();
orphan_manager = std::make_unique<COrphanManager>();
block_fetcher = std::make_unique<CBlockFetcher>(peer_manager.get());
```

**Question**: 
- Is `peer_manager` guaranteed to be non-null at this point?
- What if `NodeContext::Init()` is called multiple times?
- What if `Reset()` is called?

**Impact**:
- If `peer_manager.get()` returns `nullptr`, `m_peer_manager` will be null
- All `CBlockFetcher` methods will fail silently

---

## Comparison with User's Fixes

### User's Fixes Applied to CBlockFetcher

The user has already applied fixes to `CBlockFetcher`:

1. **IBD STUCK FIX #9**: Use `GetBlocksInFlightForPeer()` instead of `peer->nBlocksInFlight`
   - Applied in: `RequestBlock()`, `SelectPeerForDownload()`, `AssignChunkToPeer()`, `ReassignChunkToPeer()`
   - **NOT APPLIED** to `CIbdCoordinator`

2. **Forward Declaration**: Added `class CPeerManager;` forward declaration
   - Applied correctly

### Missing Fixes in CIbdCoordinator

**Location**: `src/node/ibd_coordinator.cpp:324-337`

**Current Code**:
```cpp
for (int peer_id : available_peers) {
    auto peer = m_node_context.peer_manager->GetPeer(peer_id);
    if (peer && peer->nBlocksInFlight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        all_peers_at_capacity = false;
        break;
    }
}
```

**Should Be**:
```cpp
for (int peer_id : available_peers) {
    // IBD STUCK FIX #9: Use GetBlocksInFlightForPeer() instead of stale counter
    int blocks_in_flight = m_node_context.peer_manager->GetBlocksInFlightForPeer(peer_id);
    if (blocks_in_flight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        all_peers_at_capacity = false;
        break;
    }
}
```

---

## Additional Potential Issues

### Issue #5: Window Initialization

**Location**: `src/net/block_fetcher.cpp` (window-related methods)

**Question**: 
- Is `m_download_window` properly initialized?
- Does it depend on `m_peer_manager`?

**Analysis Needed**: Check if window methods require `m_peer_manager` to be non-null.

### Issue #6: Chunk Assignment Flow

**Location**: `src/node/ibd_coordinator.cpp:380+` and `src/net/block_fetcher.cpp:575+`

**Question**:
- Does `AssignChunkToPeer()` work correctly with dependency injection?
- Are there any assumptions about global state?

**Analysis Needed**: Verify chunk assignment doesn't rely on removed globals.

### Issue #7: Orphan Block Handling

**Location**: `src/node/dilithion-node.cpp` (orphan processing)

**Question**:
- Does orphan processing use `g_orphan_manager` (removed)?
- Does it use `g_node_context.orphan_manager` correctly?

**Analysis Needed**: Verify orphan handling doesn't rely on removed globals.

---

## Recommended Fixes (For Future Implementation)

### Fix #1: Update CIbdCoordinator Capacity Check

**Priority**: 🔴 **CRITICAL**

**Location**: `src/node/ibd_coordinator.cpp:324-337`

**Change**: Use `GetBlocksInFlightForPeer()` instead of `peer->nBlocksInFlight`

**Impact**: Fixes "all peers at capacity" false positive

### Fix #2: Add Null Checks in CIbdCoordinator

**Priority**: 🟡 **HIGH**

**Location**: `src/node/ibd_coordinator.cpp:315+`

**Change**: Add null checks before using `peer_manager` and `block_fetcher`

**Impact**: Prevents crashes, adds error logging

### Fix #3: Add Error Logging in CBlockFetcher

**Priority**: 🟡 **MEDIUM**

**Location**: `src/net/block_fetcher.cpp:71+`

**Change**: Log error when `m_peer_manager` is null

**Impact**: Makes debugging easier

### Fix #4: Verify Initialization Order

**Priority**: 🟢 **LOW**

**Location**: `src/core/node_context.cpp:35-43`

**Change**: Add assertion or check that `peer_manager` is non-null before creating `block_fetcher`

**Impact**: Catches initialization bugs early

---

## Conclusion

### Most Likely Root Cause

**Issue #1: CIbdCoordinator Uses Stale Counter** is the most likely cause of IBD failure:

1. User already fixed this in `CBlockFetcher` (evidence: user's changes)
2. `CIbdCoordinator` still uses `peer->nBlocksInFlight` directly
3. Counter becomes stale during chunk cancellation
4. All peers marked "at capacity" incorrectly
5. No blocks requested → IBD stalls

### Secondary Issues

- Missing null checks could cause crashes
- Silent failures make debugging difficult
- Initialization order needs verification

### Next Steps

1. **Verify** `CIbdCoordinator` capacity check uses stale counter
2. **Check** if `m_peer_manager` can be null in production
3. **Review** initialization order in `NodeContext::Init()`
4. **Test** IBD with fixes applied

---

## Files to Review

1. `src/node/ibd_coordinator.cpp` - Capacity check logic
2. `src/core/node_context.cpp` - Initialization order
3. `src/net/block_fetcher.cpp` - Null handling
4. `src/node/dilithion-node.cpp` - IBD trigger and orphan handling

---

**Status**: ✅ **Analysis Complete** - Ready for implementation of fixes

