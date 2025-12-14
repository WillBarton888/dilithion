# Single Source of Truth (SSOT) Opportunities

**Date**: 2025-12-14  
**Status**: Analysis Complete

## Executive Summary

After analyzing the Dilithion codebase, I've identified **6 major areas** where Single Source of Truth (SSOT) principles could be applied to prevent synchronization issues similar to the block tracking desync we fixed. These areas have duplicate state tracking that could lead to bugs.

---

## Areas Identified

### 1. ⚠️ **Peer Connection State** (HIGH PRIORITY)

**Problem**: Two separate classes track peer connection state:
- `CPeer::state` (`src/net/peers.h:45`)
- `CNode::state` (`src/net/node.h:93`)

**Current State**:
```cpp
// CPeer tracks state
enum State {
    STATE_DISCONNECTED,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_VERSION_SENT,
    STATE_HANDSHAKE_COMPLETE,
    STATE_BANNED,
};
State state;  // In CPeer

// CNode also tracks state (same enum)
std::atomic<State> state{STATE_DISCONNECTED};  // In CNode
```

**Issues**:
- `CPeer::state` and `CNode::state` can become out of sync
- `GetValidPeersForDownload()` checks `CNode::state` but `CPeer::state` is also used
- Handshake completion tracked in both places
- Bug #148 was partially fixed but both states still exist

**Evidence**: 
- `src/net/peers.cpp:1115-1119` checks `CPeer::IsHandshakeComplete()` (uses `CPeer::state`)
- `src/net/peers.cpp:1097-1101` checks `CNode::state` (uses `CNode::state`)
- Both checks needed for peer validation

**Recommendation**: 
- **SSOT**: `CNode::state` should be the single source of truth
- `CPeer::state` should be removed or made a getter that queries `CNode::state`
- All code should check `CNode::state` only

**Impact**: HIGH - Prevents peer validation bugs, handshake state desync

---

### 2. ⚠️ **Chain Height Tracking** (MEDIUM PRIORITY)

**Problem**: Chain height tracked in multiple places:
- `CChainState::pindexTip->nHeight` (primary)
- `CChainState::m_cachedHeight` (atomic cache)
- `CHeadersManager::GetBestHeight()` (header height)

**Current State**:
```cpp
// CChainState
CBlockIndex* pindexTip;  // Primary source
std::atomic<int> m_cachedHeight{-1};  // Cache for lock-free reads

// CHeadersManager
int GetBestHeight() const;  // Header height (may differ from chain height)
```

**Issues**:
- `m_cachedHeight` can become stale if not updated atomically
- `GetBestHeight()` returns header height, not chain height
- Multiple callers use different sources:
  - `GetHeight()` uses `m_cachedHeight` (lock-free)
  - `pindexTip->nHeight` used directly (requires lock)
  - `GetBestHeight()` uses header manager (different value)

**Evidence**:
- `src/consensus/chain.cpp:599` updates `m_cachedHeight` when tip changes
- `src/consensus/chain.h:61` documents atomic cache for lock-free reads
- `src/net/headers_manager.cpp` tracks header height separately

**Recommendation**:
- **SSOT**: `CChainState::pindexTip->nHeight` is primary source ✅
- `m_cachedHeight` is cache (acceptable) ✅
- `GetBestHeight()` should be renamed to `GetBestHeaderHeight()` for clarity
- All chain height queries should use `CChainState::GetHeight()`

**Impact**: MEDIUM - Prevents height desync bugs, improves clarity

---

### 3. ⚠️ **Block Index Storage** (LOW PRIORITY)

**Problem**: Block/header data stored in multiple places:
- `CChainState::mapBlockIndex` (block indices by hash)
- `CHeadersManager::mapHeaders` (headers by FastHash)
- `CHeadersManager::mapHeightIndex` (height -> hash mapping)

**Current State**:
```cpp
// CChainState
std::map<uint256, std::unique_ptr<CBlockIndex>> mapBlockIndex;

// CHeadersManager
std::map<uint256, HeaderWithChainWork> mapHeaders;  // By FastHash
std::map<int, uint256> mapHeightIndex;  // Height -> hash
```

**Issues**:
- `mapBlockIndex` stores block indices (includes full block data)
- `mapHeaders` stores headers (lighter weight, FastHash indexed)
- Different hash types: RandomX hash vs FastHash
- Both needed for different purposes (headers sync vs block validation)

**Analysis**: 
- These serve different purposes:
  - `mapBlockIndex`: Block validation, chain state
  - `mapHeaders`: Header sync, IBD coordination
- **NOT a SSOT violation** - legitimate separation of concerns

**Recommendation**: 
- **No change needed** - Different data structures for different purposes
- Consider documenting the distinction clearly

**Impact**: LOW - Not a bug, but could be confusing

---

### 4. ⚠️ **Validation Queue Depth** (MEDIUM PRIORITY)

**Problem**: Queue depth checked in multiple places:
- `CBlockValidationQueue::GetQueueDepth()` (actual queue size)
- `m_queue.size()` accessed directly in some places
- Queue depth used for backpressure calculations

**Current State**:
```cpp
// CBlockValidationQueue
size_t GetQueueDepth() const {
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    return m_queue.size();
}

// Used in IBD coordinator
size_t queue_depth = m_node_context.validation_queue->GetQueueDepth();
```

**Issues**:
- `GetQueueDepth()` is the correct way to check ✅
- But `m_queue.size()` could be accessed directly (race condition)
- Need to verify all accesses use `GetQueueDepth()`

**Evidence**:
- `src/node/ibd_coordinator.cpp:131` uses `GetQueueDepth()` ✅
- `src/node/block_validation_queue.cpp` - need to check for direct `m_queue.size()` access

**Recommendation**:
- **SSOT**: `GetQueueDepth()` should be the only way to check queue depth
- Make `m_queue` private and ensure all access goes through `GetQueueDepth()`
- Add assertions to prevent direct access

**Impact**: MEDIUM - Prevents race conditions, ensures accurate backpressure

---

### 5. ⚠️ **Peer Handshake Completion** (HIGH PRIORITY)

**Problem**: Handshake completion checked in multiple ways:
- `CPeer::IsHandshakeComplete()` (checks `CPeer::state`)
- `CNode::state == STATE_HANDSHAKE_COMPLETE` (checks `CNode::state`)
- `CNode::fSuccessfullyConnected` (atomic flag)

**Current State**:
```cpp
// CPeer
bool IsHandshakeComplete() const {
    return state == STATE_HANDSHAKE_COMPLETE;
}

// CNode
std::atomic<State> state{STATE_DISCONNECTED};
std::atomic<bool> fSuccessfullyConnected{false};
```

**Issues**:
- Three different ways to check handshake completion
- `CPeer::state` and `CNode::state` can desync
- `fSuccessfullyConnected` is redundant with `state`
- Bug #148 partially addressed this but both still exist

**Evidence**:
- `src/net/peers.cpp:1116` checks `CPeer::IsHandshakeComplete()`
- `src/net/peers.cpp:1097` checks `CNode::state`
- `src/net/node.h:95` has `fSuccessfullyConnected` flag

**Recommendation**:
- **SSOT**: `CNode::state` should be single source of truth
- Remove `CPeer::state` or make it a getter
- Remove `fSuccessfullyConnected` (redundant with `state`)
- All code should check `CNode::state` only

**Impact**: HIGH - Prevents handshake state bugs, simplifies code

---

### 6. ⚠️ **Peer Socket State** (MEDIUM PRIORITY)

**Problem**: Socket state tracked in multiple places:
- `CPeer::HasValidSocket()` (checks `CPeer::m_sock`)
- `CNode::HasValidSocket()` (checks `CNode::m_sock`)
- Socket stored in both `CPeer` and `CNode`

**Current State**:
```cpp
// CPeer
std::shared_ptr<CSocket> m_sock;
bool HasValidSocket() const {
    return m_sock && m_sock->IsValid();
}

// CNode (need to verify)
// Socket likely stored here too
```

**Issues**:
- Socket stored in both `CPeer` and `CNode`
- Both classes have `HasValidSocket()` methods
- Could lead to socket state desync

**Evidence**:
- `src/net/peers.h:66-69` has `CPeer::HasValidSocket()`
- `src/net/peers.cpp:1106` checks `CNode::HasValidSocket()`
- Socket ownership unclear

**Recommendation**:
- **SSOT**: Socket should be stored in `CNode` only (event-driven I/O)
- `CPeer` should query `CNode` for socket state
- Remove `CPeer::m_sock` or make it a getter

**Impact**: MEDIUM - Prevents socket state bugs, clarifies ownership

---

## Summary Table

| Area | Priority | Current Issue | SSOT Solution | Impact |
|------|----------|---------------|---------------|--------|
| **Peer Connection State** | HIGH | `CPeer::state` vs `CNode::state` | Use `CNode::state` only | Prevents validation bugs |
| **Peer Handshake** | HIGH | 3 ways to check completion | Use `CNode::state` only | Prevents handshake bugs |
| **Chain Height** | MEDIUM | Multiple height sources | Use `CChainState::GetHeight()` | Prevents height desync |
| **Validation Queue** | MEDIUM | Direct `m_queue.size()` access | Use `GetQueueDepth()` only | Prevents race conditions |
| **Peer Socket** | MEDIUM | Socket in both classes | Store in `CNode` only | Prevents socket bugs |
| **Block Index** | LOW | Different structures (OK) | No change needed | Not a bug |

---

## Recommended Implementation Order

### Phase 1: High Priority (Prevent Bugs)
1. **Peer Connection State** - Consolidate to `CNode::state`
2. **Peer Handshake** - Remove redundant checks

### Phase 2: Medium Priority (Improve Reliability)
3. **Validation Queue** - Enforce `GetQueueDepth()` usage
4. **Peer Socket** - Consolidate socket ownership
5. **Chain Height** - Document and standardize usage

### Phase 3: Low Priority (Clarify)
6. **Block Index** - Document separation of concerns

---

## Implementation Guidelines

### For Each SSOT Fix:

1. **Identify Primary Source**: Determine which is the "true" source
2. **Make Others Getters**: Convert duplicates to getters/queries
3. **Update All Callers**: Change all code to use primary source
4. **Add Assertions**: Prevent direct access to duplicates
5. **Test Thoroughly**: Ensure no regressions

### Example Pattern:

```cpp
// BEFORE (SSOT Violation)
class CPeer {
    State state;  // Duplicate
};

class CNode {
    State state;  // Primary
};

// AFTER (SSOT Compliant)
class CPeer {
    CNode* m_node;  // Reference to node
    State GetState() const { return m_node->state.load(); }  // Getter
};

class CNode {
    std::atomic<State> state;  // Single source of truth
};
```

---

## Related Issues Fixed

- **IBD STUCK FIX #1**: Block tracking desync (`CBlockFetcher::mapBlocksInFlight` vs `CPeerManager::mapBlocksInFlight`)
- **IBD STUCK FIX #2**: Capacity check using stale counter (`peer->nBlocksInFlight` vs `GetBlocksInFlightForPeer()`)
- **Bug #148**: Handshake state desync (partially fixed, but both states still exist)

---

## Conclusion

The most critical SSOT violations are:
1. **Peer connection state** (HIGH) - Two separate state machines
2. **Peer handshake** (HIGH) - Three ways to check completion

These should be addressed first to prevent bugs similar to the block tracking desync we fixed.

The other areas are lower priority but would benefit from SSOT principles for code clarity and maintainability.

