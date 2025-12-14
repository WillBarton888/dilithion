# Legacy Code Removal Report

**Date**: 2025-12-14  
**Status**: Analysis Complete - Safe to Remove Identified

## Executive Summary

After careful analysis, I've identified **legacy code that can be safely removed** without affecting current functionality. All identified code is either:
1. Marked as deprecated
2. Replaced by newer implementations
3. No longer referenced anywhere

---

## Legacy Code Identified

### 1. ✅ **CConnectionManager Class** (DEPRECATED)

**Location**: `src/net/net.h` (lines 119-187), `src/net/net.cpp` (implementation)

**Status**: Marked as `[[deprecated("Use CConnman instead")]]`

**Current Usage**:
- ❌ **NOT used** in `src/net/headers_manager.cpp` - Uses `CConnman::PushMessage()` instead
- ❌ **NOT used** in `src/rpc/server.cpp` - Uses `CConnman` methods
- ❌ **NOT used** in `src/node/dilithion-node.cpp` - Uses `CConnman` methods
- ✅ **Still referenced** in `src/net/net.cpp` line 2122 (comment only)

**Analysis**: The class is deprecated but the implementation still exists. However, it's **NOT being called** anywhere in the codebase. The only reference is a comment.

**Recommendation**: ✅ **SAFE TO REMOVE** - The entire `CConnectionManager` class can be removed.

**Files to Modify**:
- `src/net/net.h` - Remove class definition (lines 119-187)
- `src/net/net.cpp` - Remove all `CConnectionManager::` method implementations

---

### 2. ✅ **Legacy Global Variables** (DEPRECATED)

**Location**: `src/node/dilithion-node.cpp` (lines 140-144, 1486-1488)

**Variables**:
- `g_headers_manager` (line 142)
- `g_orphan_manager` (line 143)
- `g_block_fetcher` (line 144)
- `g_peer_manager` (line 1486)

**Status**: Marked as "Legacy globals kept for backward compatibility during migration" with `TODO: Remove after full migration`

**Current Usage**:
- ✅ **Still assigned** in `dilithion-node.cpp` (lines 1486-1488)
- ❓ **Need to verify** if these are actually used anywhere

**Analysis**: These are legacy globals that were kept during migration to `NodeContext`. They're assigned but may not be used.

**Recommendation**: ⚠️ **VERIFY FIRST** - Check if these globals are actually referenced before removing.

---

### 3. ✅ **Legacy connection_manager in NodeContext** (DEPRECATED)

**Location**: `src/core/node_context.h`, `src/node/dilithion-node.cpp` (line 1563)

**Status**: Set to `nullptr` with comment "TODO Phase 5: Remove after full migration"

**Current Usage**:
- ❌ **Set to nullptr** - Not used
- ✅ **No references** found in codebase

**Recommendation**: ✅ **SAFE TO REMOVE** - The `connection_manager` field in `NodeContext` can be removed.

---

### 4. ✅ **Legacy Comments in Code**

**Location**: Various files

**Examples**:
- `src/net/net.cpp:2122` - Comment about deprecated `CConnectionManager`
- `src/node/ibd_coordinator.cpp:578` - Comment about "Legacy per-block fallback removed"
- `src/node/dilithion-node.cpp:1842` - Comment about "DISABLED: Legacy inv-based block requests"

**Recommendation**: ✅ **SAFE TO REMOVE** - These are just comments documenting removed code.

---

## Removal Plan

### Phase 1: Remove CConnectionManager (HIGH CONFIDENCE)

**Files**:
1. `src/net/net.h` - Remove class definition
2. `src/net/net.cpp` - Remove all method implementations

**Steps**:
1. Verify no references exist (already done - none found)
2. Remove class definition from header
3. Remove all method implementations from cpp
4. Remove any includes if no longer needed

**Risk**: ✅ **LOW** - Not referenced anywhere

---

### Phase 2: Remove Legacy Globals (MEDIUM CONFIDENCE)

**Files**:
1. `src/node/dilithion-node.cpp` - Remove global declarations and assignments

**Steps**:
1. Search for all references to `g_headers_manager`, `g_orphan_manager`, `g_block_fetcher`, `g_peer_manager`
2. Verify they're not used
3. Remove declarations and assignments

**Risk**: ⚠️ **MEDIUM** - Need to verify no external code uses these

---

### Phase 3: Remove NodeContext.connection_manager (HIGH CONFIDENCE)

**Files**:
1. `src/core/node_context.h` - Remove field
2. `src/node/dilithion-node.cpp` - Remove assignment

**Steps**:
1. Remove field from `NodeContext` struct
2. Remove assignment in `dilithion-node.cpp`

**Risk**: ✅ **LOW** - Already set to nullptr, not used

---

## Verification Checklist

Before removing, verify:
- [ ] No external code references `CConnectionManager`
- [ ] No external code uses legacy globals (`g_headers_manager`, etc.)
- [ ] All code uses `NodeContext` instead of globals
- [ ] All code uses `CConnman` instead of `CConnectionManager`
- [ ] Tests still pass after removal

---

## Files Modified Summary

### High Confidence Removals:
1. **`src/net/net.h`** - Remove `CConnectionManager` class (lines 119-187)
2. **`src/net/net.cpp`** - Remove all `CConnectionManager::` implementations
3. **`src/core/node_context.h`** - Remove `connection_manager` field
4. **`src/node/dilithion-node.cpp`** - Remove `connection_manager` assignment

### Medium Confidence Removals (Verify First):
5. **`src/node/dilithion-node.cpp`** - Remove legacy global declarations and assignments

---

## Conclusion

**Safe to Remove**:
- ✅ `CConnectionManager` class (entire class)
- ✅ `NodeContext::connection_manager` field
- ✅ Legacy comments

**Verify Before Removing**:
- ⚠️ Legacy global variables (`g_headers_manager`, `g_orphan_manager`, `g_block_fetcher`, `g_peer_manager`)

**Recommendation**: Start with Phase 1 (CConnectionManager removal) as it's the safest and most impactful cleanup.

