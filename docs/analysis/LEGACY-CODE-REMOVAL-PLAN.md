# Legacy Code Removal Plan

**Date**: 2025-12-14  
**Status**: Planning Complete - Ready for Implementation  
**Type**: Refactoring Plan Only - No Code Changes

## Executive Summary

This document outlines a comprehensive plan to remove all remaining legacy code:
1. **CConnectionManager** class (used in tests)
2. **Legacy global variables** (`g_peer_manager`, `g_block_fetcher`, `g_headers_manager`, `g_orphan_manager`)

The plan is designed to minimize risk, maintain functionality, and ensure a smooth migration path.

---

## Current State Analysis

### 1. CConnectionManager Class

**Location**:
- `src/net/net.h` (lines 119-187) - Class definition
- `src/net/net.cpp` (lines 1468-2196) - Implementation (13 methods, ~730 lines)

**Current Usage**:
- ✅ **Production Code**: NOT used - All production code uses `CConnman`
- ⚠️ **Tests**: Used in 2 test files:
  - `src/test/integration_tests.cpp` (line 390) - Creates instance
  - `src/test/net_tests.cpp` (line 245) - Creates instance and tests methods

**Dependencies**:
- Requires `CPeerManager&` and `CNetMessageProcessor&` in constructor
- Methods: `ConnectToPeer()`, `AcceptConnection()`, `PerformHandshake()`, `DisconnectPeer()`, `SendMessage()`, `ReceiveMessages()`, etc.

**Replacement**: `CConnman` class (already implemented and used in production)

---

### 2. Legacy Global Variables

#### 2.1. `g_peer_manager`

**Location**:
- `src/net/peers.cpp` (line 13) - Declaration: `CPeerManager* g_peer_manager = nullptr;`
- `src/net/peers.h` (line 389) - Extern: `extern CPeerManager* g_peer_manager;`
- `src/node/dilithion-node.cpp` (line 1486) - Assignment: `g_peer_manager = g_node_context.peer_manager.get();`

**Current Usage**:
- ⚠️ **ACTIVELY USED** in `src/net/block_fetcher.cpp` (11 references):
  - Line 71: `if (!g_peer_manager)` - Null check
  - Line 75: `g_peer_manager->GetPeer(peer)` - Get peer object
  - Line 93: `g_peer_manager->MarkBlockAsInFlight(peer, hash, nullptr)` - Mark block in flight
  - Line 114-115: `g_peer_manager->MarkBlockAsReceived(peer, hash)` - Mark block received (2 places)
  - Line 121-122: `g_peer_manager->MarkBlockAsReceived(peer, hash)` - Mark block received
  - Line 134-135: `g_peer_manager->UpdatePeerStats(peer, true, responseTime)` - Update stats
  - Line 244-245: `g_peer_manager->UpdatePeerStats(stalledPeer, false, ...)` - Update stats
  - Line 260-261: `g_peer_manager->RemoveBlockFromFlight(hash)` - Remove from flight

**Replacement**: `NodeContext::peer_manager` or pass `CPeerManager*` to `CBlockFetcher`

---

#### 2.2. `g_block_fetcher`

**Location**:
- `src/net/net.cpp` (line 184) - Extern: `extern CBlockFetcher* g_block_fetcher;`
- `src/node/dilithion-node.cpp` (line 144) - Declaration: `CBlockFetcher* g_block_fetcher = nullptr;`
- `src/node/dilithion-node.cpp` (line 1489) - Assignment: `g_block_fetcher = g_node_context.block_fetcher.get();`

**Current Usage**:
- ❓ **Need to verify** - Extern declared but usage unclear

**Replacement**: `NodeContext::block_fetcher`

---

#### 2.3. `g_headers_manager`

**Location**:
- `src/node/dilithion-node.cpp` (line 142) - Declaration: `CHeadersManager* g_headers_manager = nullptr;`
- `src/node/dilithion-node.cpp` (line 1487) - Assignment: `g_headers_manager = g_node_context.headers_manager.get();`

**Current Usage**:
- ❓ **Need to verify** - Assigned but usage unclear

**Replacement**: `NodeContext::headers_manager`

---

#### 2.4. `g_orphan_manager`

**Location**:
- `src/node/dilithion-node.cpp` (line 143) - Declaration: `COrphanManager* g_orphan_manager = nullptr;`
- `src/node/dilithion-node.cpp` (line 1488) - Assignment: `g_orphan_manager = g_node_context.orphan_manager.get();`

**Current Usage**:
- ❓ **Need to verify** - Assigned but usage unclear

**Replacement**: `NodeContext::orphan_manager`

---

## Removal Plan

### Phase 1: Remove CConnectionManager from Tests (LOW RISK)

**Goal**: Update tests to use `CConnman` instead of `CConnectionManager`, then remove the deprecated class.

**Steps**:

1. **Update `src/test/integration_tests.cpp`**:
   - Replace `CConnectionManager connection_manager(peer_manager, message_processor);` 
   - With `CConnman` initialization (create `CConnman` instance, call `Start()`)
   - Update any method calls to use `CConnman` API instead of `CConnectionManager` API
   - Verify test still passes

2. **Update `src/test/net_tests.cpp`**:
   - Replace `CConnectionManager conn_mgr(*g_peer_manager, processor);`
   - With `CConnman` initialization
   - Update `test_connection_manager()` function to test `CConnman` methods:
     - `ConnectNode()` instead of `ConnectToPeer()`
     - `PushMessage()` instead of `SendMessage()`
     - `DisconnectNode()` instead of `DisconnectPeer()`
   - Rename function to `test_connman()` for clarity
   - Verify test still passes

3. **Remove CConnectionManager Class**:
   - Remove class definition from `src/net/net.h` (lines 119-187)
   - Remove all method implementations from `src/net/net.cpp` (lines 1468-2196, ~730 lines)
   - Remove any includes if no longer needed
   - Verify compilation succeeds

**Dependencies**: None - Tests are isolated

**Risk**: ✅ **LOW** - Tests can be updated independently

**Estimated Effort**: 2-4 hours

---

### Phase 2: Refactor CBlockFetcher to Remove g_peer_manager Dependency (MEDIUM RISK)

**Goal**: Remove `g_peer_manager` global by passing `CPeerManager*` to `CBlockFetcher` methods or storing it as a member.

**Current Architecture**:
- `CBlockFetcher` is a singleton-like class (accessed via `g_block_fetcher`)
- Methods use `g_peer_manager` global directly
- No constructor parameters - uses globals

**Refactoring Options**:

#### Option A: Store CPeerManager* as Member (RECOMMENDED)

**Steps**:

1. **Modify `CBlockFetcher` Constructor**:
   - Add `CPeerManager* peer_manager` parameter
   - Store as member: `CPeerManager* m_peer_manager;`
   - Remove dependency on `g_peer_manager` global

2. **Update All Methods**:
   - Replace `g_peer_manager` with `m_peer_manager` in all 11 locations
   - Add null checks: `if (!m_peer_manager) return false;`

3. **Update CBlockFetcher Creation**:
   - In `src/node/dilithion-node.cpp`, pass `g_node_context.peer_manager.get()` to constructor
   - Update: `g_node_context.block_fetcher = std::make_unique<CBlockFetcher>(g_node_context.peer_manager.get());`

4. **Remove Global Declaration**:
   - Remove `CPeerManager* g_peer_manager = nullptr;` from `src/net/peers.cpp`
   - Remove `extern CPeerManager* g_peer_manager;` from `src/net/peers.h`
   - Remove assignment `g_peer_manager = ...` from `src/node/dilithion-node.cpp`

**Dependencies**: 
- `CBlockFetcher` creation point
- Any code that calls `CBlockFetcher` methods (need to verify)

**Risk**: ⚠️ **MEDIUM** - Requires updating constructor and all call sites

**Estimated Effort**: 4-6 hours

#### Option B: Pass CPeerManager* to Each Method (NOT RECOMMENDED)

**Why Not**: Would require changing method signatures, affecting all callers. More invasive.

---

### Phase 3: Verify and Remove Remaining Legacy Globals (LOW-MEDIUM RISK)

**Goal**: Remove `g_block_fetcher`, `g_headers_manager`, `g_orphan_manager` if they're not used.

**Steps**:

1. **Verify Usage**:
   - Search for all references to `g_block_fetcher`, `g_headers_manager`, `g_orphan_manager`
   - Check if they're actually used (not just declared/assigned)
   - Document findings

2. **Remove Unused Globals**:
   - If `g_block_fetcher` is unused:
     - Remove extern from `src/net/net.cpp`
     - Remove declaration from `src/node/dilithion-node.cpp`
     - Remove assignment from `src/node/dilithion-node.cpp`
   
   - If `g_headers_manager` is unused:
     - Remove declaration from `src/node/dilithion-node.cpp`
     - Remove assignment from `src/node/dilithion-node.cpp`
   
   - If `g_orphan_manager` is unused:
     - Remove declaration from `src/node/dilithion-node.cpp`
     - Remove assignment from `src/node/dilithion-node.cpp`

3. **Update Any Remaining Usage**:
   - If any globals are still used, refactor to use `NodeContext` instead
   - Follow same pattern as `g_peer_manager` refactoring

**Dependencies**: Verification step must be thorough

**Risk**: ⚠️ **LOW-MEDIUM** - Depends on actual usage

**Estimated Effort**: 2-4 hours

---

## Detailed Implementation Steps

### Step 1: Update Integration Tests

**File**: `src/test/integration_tests.cpp`

**Current Code** (line 390):
```cpp
CConnectionManager connection_manager(peer_manager, message_processor);
```

**New Code**:
```cpp
CConnman connman;
CConnmanOptions options;
options.nMaxOutbound = 8;
options.nMaxInbound = 117;
options.nMaxTotal = 125;
if (!connman.Start(peer_manager, message_processor, options)) {
    // Handle error
}
```

**Changes Required**:
- Include `#include <net/connman.h>`
- Create `CConnman` instance
- Call `Start()` with appropriate options
- Update any method calls (if any) to use `CConnman` API

---

### Step 2: Update Net Tests

**File**: `src/test/net_tests.cpp`

**Current Code** (line 245):
```cpp
CConnectionManager conn_mgr(*g_peer_manager, processor);
```

**New Code**:
```cpp
CConnman connman;
CConnmanOptions options;
// ... set options ...
if (!connman.Start(*g_peer_manager, processor, options)) {
    // Handle error
}
```

**Function Updates**:
- `test_connection_manager()` → `test_connman()`
- Update test cases:
  - `ConnectToPeer()` → `ConnectNode()`
  - `SendMessage()` → `PushMessage()`
  - `DisconnectPeer()` → `DisconnectNode()`
  - `ReceiveMessages()` → Use `CConnman::ThreadMessageHandler()` pattern

**Changes Required**:
- Include `#include <net/connman.h>`
- Update all test assertions to use `CConnman` API
- Verify tests still pass

---

### Step 3: Remove CConnectionManager Class

**Files**: `src/net/net.h`, `src/net/net.cpp`

**Actions**:
1. Remove class definition from `src/net/net.h` (lines 119-187)
2. Remove all method implementations from `src/net/net.cpp`:
   - `CConnectionManager::CConnectionManager()` (line 1468)
   - `CConnectionManager::ConnectToPeer()` (line 1474)
   - `CConnectionManager::AcceptConnection()` (line 1610)
   - `CConnectionManager::PerformHandshake()` (line 1692)
   - `CConnectionManager::DisconnectPeer()` (line 1709)
   - `CConnectionManager::PeriodicMaintenance()` (line 1746)
   - `CConnectionManager::GenerateNonce()` (line 1773)
   - `CConnectionManager::SendMessage()` (line 1784)
   - `CConnectionManager::ReceiveMessages()` (line 1895)
   - `CConnectionManager::SendVersionMessage()` (line 2143)
   - `CConnectionManager::SendVerackMessage()` (line 2170)
   - `CConnectionManager::SendPingMessage()` (line 2182)
   - `CConnectionManager::SendPongMessage()` (line 2191)
   - `CConnectionManager::Cleanup()` (line 2196)

3. Remove any includes if `CConnectionManager` was the only reason for them

**Verification**:
- Compile successfully
- All tests pass
- No references to `CConnectionManager` remain (except in comments)

---

### Step 4: Refactor CBlockFetcher to Use CPeerManager Member

**File**: `src/net/block_fetcher.h`

**Current Constructor**:
```cpp
CBlockFetcher();
```

**New Constructor**:
```cpp
explicit CBlockFetcher(CPeerManager* peer_manager);
```

**New Member**:
```cpp
private:
    CPeerManager* m_peer_manager;  // Single source of truth - no global dependency
```

---

**File**: `src/net/block_fetcher.cpp`

**Current Implementation** (line 71):
```cpp
if (!g_peer_manager) {
    return false;
}
auto peer_obj = g_peer_manager->GetPeer(peer);
```

**New Implementation**:
```cpp
if (!m_peer_manager) {
    return false;
}
auto peer_obj = m_peer_manager->GetPeer(peer);
```

**Changes Required** (11 locations):
1. Line 71: `g_peer_manager` → `m_peer_manager`
2. Line 75: `g_peer_manager->GetPeer()` → `m_peer_manager->GetPeer()`
3. Line 93: `g_peer_manager->MarkBlockAsInFlight()` → `m_peer_manager->MarkBlockAsInFlight()`
4. Line 114-115: `g_peer_manager->MarkBlockAsReceived()` → `m_peer_manager->MarkBlockAsReceived()` (2 places)
5. Line 121-122: `g_peer_manager->MarkBlockAsReceived()` → `m_peer_manager->MarkBlockAsReceived()`
6. Line 134-135: `g_peer_manager->UpdatePeerStats()` → `m_peer_manager->UpdatePeerStats()`
7. Line 244-245: `g_peer_manager->UpdatePeerStats()` → `m_peer_manager->UpdatePeerStats()`
8. Line 260-261: `g_peer_manager->RemoveBlockFromFlight()` → `m_peer_manager->RemoveBlockFromFlight()`

**Constructor Implementation**:
```cpp
CBlockFetcher::CBlockFetcher(CPeerManager* peer_manager)
    : m_peer_manager(peer_manager)
{
    // Initialize other members...
}
```

---

**File**: `src/node/dilithion-node.cpp`

**Current Code** (around line 1489):
```cpp
g_node_context.block_fetcher = std::make_unique<CBlockFetcher>();
```

**New Code**:
```cpp
g_node_context.block_fetcher = std::make_unique<CBlockFetcher>(g_node_context.peer_manager.get());
```

---

### Step 5: Remove g_peer_manager Global

**File**: `src/net/peers.cpp`

**Remove** (line 13):
```cpp
CPeerManager* g_peer_manager = nullptr;
```

**File**: `src/net/peers.h`

**Remove** (line 389):
```cpp
extern CPeerManager* g_peer_manager;
```

**File**: `src/node/dilithion-node.cpp`

**Remove** (line 1486):
```cpp
g_peer_manager = g_node_context.peer_manager.get();
```

**Verification**:
- Compile successfully
- No references to `g_peer_manager` remain (except in test files if they use it)

---

### Step 6: Verify and Remove Remaining Globals

**For each global** (`g_block_fetcher`, `g_headers_manager`, `g_orphan_manager`):

1. **Search for Usage**:
   ```bash
   grep -rn "g_block_fetcher" src --include="*.cpp" --include="*.h"
   grep -rn "g_headers_manager" src --include="*.cpp" --include="*.h"
   grep -rn "g_orphan_manager" src --include="*.cpp" --include="*.h"
   ```

2. **Categorize Usage**:
   - **Declaration**: `CBlockFetcher* g_block_fetcher = nullptr;`
   - **Assignment**: `g_block_fetcher = ...;`
   - **Actual Usage**: `g_block_fetcher->SomeMethod()`

3. **If Unused** (only declarations/assignments):
   - Remove declaration
   - Remove extern (if exists)
   - Remove assignment

4. **If Used**:
   - Refactor to use `NodeContext` instead
   - Follow same pattern as `g_peer_manager` removal

---

## Risk Assessment

### Phase 1: CConnectionManager Removal
- **Risk Level**: ✅ **LOW**
- **Impact**: Tests only - no production code affected
- **Mitigation**: Update tests incrementally, verify each test passes

### Phase 2: g_peer_manager Removal
- **Risk Level**: ⚠️ **MEDIUM**
- **Impact**: `CBlockFetcher` refactoring - core IBD component
- **Mitigation**: 
  - Thorough testing after refactoring
  - Verify all 11 locations updated correctly
  - Test IBD functionality end-to-end

### Phase 3: Remaining Globals
- **Risk Level**: ⚠️ **LOW-MEDIUM** (depends on usage)
- **Impact**: Unknown until verification
- **Mitigation**: Thorough verification before removal

---

## Testing Strategy

### After Each Phase:

1. **Compilation**:
   - Verify code compiles without errors
   - Fix any compilation issues immediately

2. **Unit Tests**:
   - Run all tests: `make test` or equivalent
   - Verify updated tests pass
   - Verify no regressions

3. **Integration Tests**:
   - Test IBD functionality
   - Test peer connections
   - Test block downloads

4. **Manual Testing**:
   - Start node and verify it connects to peers
   - Verify IBD progresses normally
   - Verify no crashes or errors

---

## Rollback Plan

If issues arise:

1. **Phase 1 (Tests)**: Revert test changes, keep `CConnectionManager` class
2. **Phase 2 (g_peer_manager)**: Revert `CBlockFetcher` changes, restore global
3. **Phase 3 (Other globals)**: Revert individual global removals

**Git Strategy**: Create a branch for each phase, merge only after verification

---

## Dependencies and Prerequisites

### Before Starting:

1. ✅ **NodeContext Migration Complete**: Already done - `NodeContext` is used throughout
2. ✅ **CConnman Implementation Complete**: Already done - `CConnman` is used in production
3. ⚠️ **Test Infrastructure**: Need to verify test framework supports `CConnman` initialization

### External Dependencies:

- None - All changes are internal refactoring

---

## Estimated Timeline

- **Phase 1**: 2-4 hours (test updates + CConnectionManager removal)
- **Phase 2**: 4-6 hours (CBlockFetcher refactoring + g_peer_manager removal)
- **Phase 3**: 2-4 hours (verification + remaining globals removal)
- **Testing**: 2-4 hours (comprehensive testing after each phase)
- **Total**: 10-18 hours

---

## Success Criteria

### Phase 1 Complete When:
- ✅ All tests pass using `CConnman`
- ✅ `CConnectionManager` class removed
- ✅ No compilation errors
- ✅ No references to `CConnectionManager` (except in comments)

### Phase 2 Complete When:
- ✅ `CBlockFetcher` uses `CPeerManager*` member instead of global
- ✅ `g_peer_manager` global removed
- ✅ IBD functionality works correctly
- ✅ No compilation errors

### Phase 3 Complete When:
- ✅ All unused globals removed
- ✅ Any used globals refactored to use `NodeContext`
- ✅ No compilation errors
- ✅ All functionality verified

---

## Implementation Order

**Recommended Sequence**:

1. **Phase 1** (Lowest Risk) → Remove `CConnectionManager`
2. **Phase 2** (Medium Risk) → Remove `g_peer_manager`
3. **Phase 3** (Variable Risk) → Remove remaining globals

**Rationale**: Start with lowest risk, build confidence, then tackle more complex refactoring.

---

## Notes and Considerations

### CBlockFetcher Architecture

**Current**: Singleton-like pattern using global
**Future**: Dependency injection via constructor

**Benefits**:
- Explicit dependencies
- Easier testing (can inject mock `CPeerManager`)
- No global state
- Follows Single Source of Truth principle

### Test Updates

**Challenge**: `CConnman` requires more setup than `CConnectionManager`
- Need to create `CConnmanOptions`
- Need to call `Start()` method
- Need to handle thread lifecycle

**Solution**: Create test helper function to initialize `CConnman` for tests

### Backward Compatibility

**Not Required**: These are internal refactorings, no external API changes

---

## Conclusion

This plan provides a clear, step-by-step approach to removing all legacy code. The phased approach minimizes risk and allows for incremental verification. Each phase can be implemented independently, with thorough testing after each step.

**Status**: ✅ **Plan Complete** - Ready for implementation

**Next Step**: Begin with Phase 1 (CConnectionManager removal from tests)

