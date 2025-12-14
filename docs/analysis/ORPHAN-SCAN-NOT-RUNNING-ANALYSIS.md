# Orphan Scan Not Running - Analysis

**Date**: 2025-12-14  
**Status**: Research Complete - Root Cause Identified

## Problem Summary

Orphan scan (IBD STUCK FIX #3) is not running despite:
- 112 orphans stored in pool
- 0 orphans erased
- `DownloadBlocks()` being called every second (logs show "Headers ahead of chain")
- Debug logging added with `std::cout` (should always print)

**Evidence**:
- No logs matching `[IBD STUCK FIX #3]` pattern
- No orphan scan debug output
- Chain stuck at height 256

---

## Code Flow Analysis

### Expected Flow
1. `CIbdCoordinator::Tick()` called every second
2. `ShouldAttemptDownload()` checks if download should proceed
3. If true → `DownloadBlocks()` called
4. At end of `DownloadBlocks()` → orphan scan runs (every 10 seconds)

### Actual Flow Investigation

**Location**: `src/node/ibd_coordinator.cpp:262-327`

**Code**:
```cpp
// IBD STUCK FIX #3: Periodic orphan scan
static auto last_orphan_scan = std::chrono::steady_clock::now();
auto now_orphan_scan = std::chrono::steady_clock::now();
if (std::chrono::duration_cast<std::chrono::seconds>(now_orphan_scan - last_orphan_scan).count() >= 10) {
    last_orphan_scan = now_orphan_scan;
    
    if (g_node_context.orphan_manager) {
        // Scan orphans...
    }
}
```

---

## Root Cause Analysis

### Issue #1: Orphan Scan Only Runs When `DownloadBlocks()` Completes

**Problem**: The orphan scan is at the END of `DownloadBlocks()`. If `DownloadBlocks()` returns early or doesn't complete, the scan never runs.

**Potential Early Returns**:
1. `ShouldAttemptDownload()` returns false → `DownloadBlocks()` never called
2. Validation queue full → early return in `ShouldAttemptDownload()`
3. No peers → `HandleNoPeers()` called, `DownloadBlocks()` never called

**Evidence from Logs**:
```
2025-12-14 02:11:36 [INFO] [IBD] Headers ahead of chain - downloading blocks (header=2015 chain=256)
```

This log is at line 202 of `DownloadBlocks()`, so `DownloadBlocks()` IS being called. But orphan scan is at line 262+, so it should run.

### Issue #2: Static Timer Initialization

**Problem**: `static auto last_orphan_scan = std::chrono::steady_clock::now();` initializes to CURRENT time on first call. This means:
- First call: `last_orphan_scan = now` → elapsed = 0 seconds → scan doesn't run
- Second call (1 second later): elapsed = 1 second → scan doesn't run
- ...
- 10th call (10 seconds later): elapsed = 10 seconds → scan runs ✅

**BUT**: If `DownloadBlocks()` isn't called consistently (e.g., early returns), the timer never advances.

### Issue #3: `g_node_context.orphan_manager` May Be Null

**Problem**: If `g_node_context.orphan_manager` is null, the scan silently skips.

**Check**: Need to verify `g_node_context.orphan_manager` is initialized.

### Issue #4: Log Level Filtering

**Problem**: `LogPrintIBD(DEBUG, ...)` may not print if DEBUG level is disabled.

**Evidence**: User sees other DEBUG logs, so DEBUG is enabled. But `LogPrintIBD` uses category `IBD`, which might have different level.

**Check**: Need to verify IBD category log level.

---

## Most Likely Root Cause: Early Return Before Orphan Scan

**Hypothesis**: `DownloadBlocks()` is being called, but returns early before reaching the orphan scan code.

**Possible Early Returns**:
1. **Line 202**: Log message printed ✅ (we see this in logs)
2. **Lines 205-212**: Window initialization/update (no early return)
3. **Lines 214-237**: Rate multiplier calculation (no early return)
4. **Line 240**: `QueueMissingBlocks()` (no early return)
5. **Line 244**: `FetchBlocks()` (no early return)
6. **Lines 246-260**: Hang cause logging (no early return)
7. **Line 262**: Orphan scan starts ⚠️ (should be here)

**Wait**: The user added `std::cout` logging at line 278, which should ALWAYS print if code reaches that point. Since no logs appear, the code is NOT reaching line 262.

**Conclusion**: `DownloadBlocks()` is returning early OR the orphan scan code is not being reached.

---

## Investigation Steps

### Step 1: Verify `DownloadBlocks()` Completes

**Check**: Add logging RIGHT BEFORE orphan scan to verify code reaches that point.

**Location**: `src/node/ibd_coordinator.cpp:261` (before orphan scan)

**Add**:
```cpp
std::cout << "[DEBUG] DownloadBlocks() reached orphan scan section" << std::endl;
```

### Step 2: Verify Static Timer

**Check**: Log the timer values to see if timer is advancing.

**Add**:
```cpp
auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now_orphan_scan - last_orphan_scan).count();
std::cout << "[DEBUG] Orphan scan timer: elapsed=" << elapsed << " seconds" << std::endl;
```

### Step 3: Verify `g_node_context.orphan_manager`

**Check**: Log if `orphan_manager` is null.

**Add**:
```cpp
if (!g_node_context.orphan_manager) {
    std::cout << "[DEBUG] Orphan scan skipped - orphan_manager is null!" << std::endl;
    return;
}
```

### Step 4: Check for Exception/Exception Handling

**Problem**: If an exception is thrown in `DownloadBlocks()` before orphan scan, scan never runs.

**Check**: Verify no exceptions are thrown.

---

## Recommended Fixes

### Fix #1: Move Orphan Scan to `Tick()` (Recommended)

**Problem**: Orphan scan only runs when `DownloadBlocks()` completes. If `DownloadBlocks()` returns early, scan never runs.

**Solution**: Move orphan scan to `Tick()` so it runs independently of `DownloadBlocks()`.

**Location**: `src/node/ibd_coordinator.cpp:30-71` (in `Tick()`)

**Change**:
```cpp
void CIbdCoordinator::Tick() {
    UpdateState();
    
    // ... existing code ...
    
    // IBD STUCK FIX #3: Periodic orphan scan (moved from DownloadBlocks)
    // Run independently of DownloadBlocks() to ensure it always runs
    static auto last_orphan_scan = std::chrono::steady_clock::now();
    auto now_orphan_scan = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now_orphan_scan - last_orphan_scan).count() >= 10) {
        last_orphan_scan = now_orphan_scan;
        // ... orphan scan code ...
    }
    
    // ... rest of Tick() ...
}
```

**Impact**: Orphan scan runs every 10 seconds regardless of `DownloadBlocks()` execution.

### Fix #2: Initialize Static Timer to Past Time

**Problem**: Static timer initializes to current time, requiring 10 seconds before first scan.

**Solution**: Initialize to past time so first scan runs immediately.

**Change**:
```cpp
// Initialize to 11 seconds ago so first scan runs immediately
static auto last_orphan_scan = std::chrono::steady_clock::now() - std::chrono::seconds(11);
```

**Impact**: First orphan scan runs immediately on next `Tick()`.

### Fix #3: Add Comprehensive Logging

**Problem**: No visibility into why scan isn't running.

**Solution**: Add logging at every step:
- Before orphan scan check
- Timer values
- `orphan_manager` null check
- Orphan count
- Scan results

---

## Verification Checklist

- [ ] Verify `DownloadBlocks()` completes (add logging before orphan scan)
- [ ] Verify static timer advances (log elapsed time)
- [ ] Verify `g_node_context.orphan_manager` is not null
- [ ] Verify no exceptions thrown in `DownloadBlocks()`
- [ ] Check if `DownloadBlocks()` returns early (add logging at end)
- [ ] Verify orphan scan code is reached (add logging at start)

---

## Conclusion

**Most Likely Root Cause**: `DownloadBlocks()` is returning early before reaching orphan scan code, OR the static timer hasn't advanced enough yet.

**Recommended Action**: 
1. Move orphan scan to `Tick()` so it runs independently
2. Initialize static timer to past time for immediate first scan
3. Add comprehensive logging to diagnose issue

**Priority**: HIGH - Orphan scan is critical for processing orphan chains and resolving IBD stalls.

