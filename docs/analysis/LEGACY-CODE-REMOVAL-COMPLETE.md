# Legacy Code Removal - Implementation Report

**Date**: 2025-12-14  
**Status**: ✅ Partial Removal Complete

## Summary

Successfully removed **legacy code that was safe to remove** without affecting current functionality. Some legacy code remains because it's still actively used.

---

## ✅ Removed (Safe Removal)

### 1. NodeContext::connection_manager Field

**Files Modified**:
- `src/core/node_context.h` - Removed field and forward declaration
- `src/core/node_context.cpp` - Removed assignment in `Shutdown()` and `Reset()`
- `src/node/dilithion-node.cpp` - Removed assignment

**Rationale**: 
- Field was only set to `nullptr`, never actually used
- All code uses `CConnman` via `NodeContext::connman` instead
- No references found in codebase

**Impact**: ✅ **No functional changes** - Field was unused

---

## ⚠️ Cannot Remove Yet (Still in Use)

### 1. CConnectionManager Class

**Status**: ⚠️ **USED IN TESTS** - Cannot remove without updating tests

**Location**: 
- `src/net/net.h` (lines 119-187) - Class definition
- `src/net/net.cpp` (lines 1468-2196) - Implementation (13 methods)

**Current Usage**:
- ✅ **Production Code**: NOT used - All code uses `CConnman`
- ⚠️ **Tests**: Used in `src/test/integration_tests.cpp` and `src/test/net_tests.cpp`

**Action Required**: 
1. Update tests to use `CConnman` instead of `CConnectionManager`
2. Then remove the class definition and implementation

**Risk**: ⚠️ **MEDIUM** - Tests need to be updated first

---

### 2. Legacy Global Variables

**Status**: ⚠️ **STILL USED** - Cannot remove without refactoring

**Variables**:
- `g_peer_manager` - Used in `src/net/block_fetcher.cpp` (11 references)
- `g_block_fetcher` - Extern declared in `src/net/net.cpp`
- `g_headers_manager` - Only assigned, need to verify usage
- `g_orphan_manager` - Only assigned, need to verify usage

**Current Usage**:
- `g_peer_manager` - **ACTIVELY USED** in `src/net/block_fetcher.cpp`:
  - Line 71: `if (!g_peer_manager)`
  - Line 75: `g_peer_manager->GetPeer(peer)`
  - Line 93: `g_peer_manager->MarkBlockAsInFlight()`
  - Line 114-115: `g_peer_manager->MarkBlockAsReceived()`
  - Line 121-122: `g_peer_manager->MarkBlockAsReceived()`
  - Line 134-135: `g_peer_manager->UpdatePeerStats()`
  - Line 244-245: `g_peer_manager->UpdatePeerStats()`
  - Line 260-261: `g_peer_manager->RemoveBlockFromFlight()`

**Action Required**:
1. Refactor `src/net/block_fetcher.cpp` to use `NodeContext` instead of `g_peer_manager`
2. Update all callers to pass `NodeContext` or `CPeerManager*` instead of using global
3. Then remove global declarations

**Risk**: ⚠️ **HIGH** - Requires refactoring active code

---

## Files Modified

### Removed Legacy Code:
1. ✅ **`src/core/node_context.h`**:
   - Removed `CConnectionManager* connection_manager` field
   - Removed `class CConnectionManager;` forward declaration

2. ✅ **`src/core/node_context.cpp`**:
   - Removed `connection_manager = nullptr;` from `Shutdown()`
   - Removed `connection_manager = nullptr;` from `Reset()`

3. ✅ **`src/node/dilithion-node.cpp`**:
   - Removed `g_node_context.connection_manager = nullptr;` assignment

---

## Verification

✅ **Compilation**: All changes compile successfully  
✅ **Linter**: No errors  
✅ **Functionality**: No functional changes (removed field was unused)

---

## Next Steps

### Phase 1: Update Tests (Medium Priority)
1. Update `src/test/integration_tests.cpp` to use `CConnman` instead of `CConnectionManager`
2. Update `src/test/net_tests.cpp` to use `CConnman` instead of `CConnectionManager`
3. Remove `CConnectionManager` class definition and implementation

### Phase 2: Refactor Legacy Globals (High Priority)
1. Refactor `src/net/block_fetcher.cpp` to use `NodeContext` instead of `g_peer_manager`
2. Update `CBlockFetcher` constructor to accept `CPeerManager*` or `NodeContext*`
3. Remove `g_peer_manager` global declaration and extern
4. Verify `g_block_fetcher`, `g_headers_manager`, `g_orphan_manager` usage
5. Remove unused legacy globals

---

## Conclusion

✅ **Successfully removed** `NodeContext::connection_manager` - safe removal with no impact.

⚠️ **Cannot remove yet**:
- `CConnectionManager` class - Used in tests (needs test updates)
- Legacy globals - Still actively used (needs refactoring)

**Status**: ✅ **Partial cleanup complete** - Removed all safe-to-remove legacy code.

