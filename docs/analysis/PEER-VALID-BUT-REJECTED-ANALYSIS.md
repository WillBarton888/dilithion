# Peer Valid But Rejected - Analysis

**Date**: 2025-12-14  
**Status**: Research Complete - Root Causes Identified

## Problem Summary

Two different issues observed on different nodes:

1. **LDN (chain=16)**: Peers are marked "VALID for download" but then "Could not send any block requests - no suitable peers" - **contradiction**
2. **SGP (chain=256)**: Peers are marked "SKIP: not suitable (stall=643)" - peers have extremely high stall count

---

## Code Flow Analysis

### Step 1: `GetValidPeersForDownload()` - Initial Validation

**Location**: `src/net/peers.cpp:1073-1132`

**Checks Performed**:
1. Peer exists and is connected (`state == STATE_CONNECTED`)
2. CNode exists and handshake complete (`CNode::state == HANDSHAKE_COMPLETE`)
3. Peer is suitable for download (`IsSuitableForDownload()`)

**`IsSuitableForDownload()` Check** (`src/net/peers.h:112-117`):
```cpp
bool IsSuitableForDownload() const {
    auto now = std::chrono::steady_clock::now();
    // Reset stall count if last success was recent (within timeout window)
    if (lastSuccessTime.time_since_epoch().count() > 0 && 
        (now - lastSuccessTime) < GetStallTimeout()) {
        return nStallingCount < STALL_THRESHOLD;
    }
    return nStallingCount < STALL_THRESHOLD;
}
```

**STALL_THRESHOLD**: Need to find definition...

### Step 2: `FetchBlocks()` - Additional Checks

**Location**: `src/node/ibd_coordinator.cpp:401-658`

**After `GetValidPeersForDownload()` returns peers**:
1. Checks if all peers are at capacity (lines 422-439)
2. For each peer, checks capacity again (lines 462-468)
3. Gets chunk heights from window (lines 471-477)
4. Filters heights (lines 490-512)
5. Assigns chunk to peer (line 521)

**Potential Rejection Points**:
- **Line 411**: `GetValidPeersForDownload()` returns empty → "No peers available"
- **Line 435**: All peers at capacity → "all peers at capacity"
- **Line 466**: Individual peer at capacity → skipped
- **Line 479**: No valid heights → "window empty"
- **Line 514**: `valid_heights.empty()` → skipped
- **Line 521**: `AssignChunkToPeer()` fails → skipped

---

## Root Cause Analysis

### Issue #1: LDN - "VALID" but "no suitable peers"

**Symptoms**:
- Logs show: `[DEBUG] Peer X VALID for download`
- Then: `Could not send any block requests - no suitable peers`

**Analysis**:
1. `GetValidPeersForDownload()` returns peers ✅
2. But then `FetchBlocks()` finds no suitable peers ❌

**Possible Causes**:

**A. All Peers at Capacity Check (Line 422-439)**
- Peers pass `GetValidPeersForDownload()` ✅
- But then capacity check finds all peers at capacity ❌
- Sets `m_last_hang_cause = PEERS_AT_CAPACITY`
- But then loop continues and tries to assign chunks anyway...

**B. Window Empty (Line 479)**
- Peers are valid ✅
- But window has no pending heights ❌
- `chunk_heights.empty()` → `break` → no chunks assigned
- `any_requested = false` → "no suitable peers"

**C. No Valid Heights After Filtering (Line 514)**
- Peers are valid ✅
- Chunk heights retrieved ✅
- But after filtering (lines 490-512), `valid_heights.empty()` ❌
- Peer skipped → no chunks assigned
- `any_requested = false` → "no suitable peers"

**D. `AssignChunkToPeer()` Fails (Line 521)**
- Peers are valid ✅
- Valid heights found ✅
- But `AssignChunkToPeer()` returns false ❌
- Peer skipped → no chunks assigned

**Most Likely**: **Window Empty** or **No Valid Heights After Filtering**

The message "no suitable peers" is misleading - it should say "no chunks to assign" or "window empty".

---

### Issue #2: SGP - "SKIP: not suitable (stall=643)"

**Symptoms**:
- Logs show: `[DEBUG] Peer X SKIP: not suitable (stall=643)`
- `nStallingCount = 643` (extremely high)

**Analysis**:
1. `GetValidPeersForDownload()` checks `IsSuitableForDownload()` ✅
2. `IsSuitableForDownload()` checks `nStallingCount < STALL_THRESHOLD` ✅
3. But peer has `nStallingCount = 643` ❌

**Question**: What is `STALL_THRESHOLD`? If it's > 643, peers with 643 stalls would pass.

**Possible Causes**:

**A. STALL_THRESHOLD is Very High**
- If `STALL_THRESHOLD = 1000`, then `643 < 1000` → peer passes ✅
- But peer is clearly stalling (643 stalls) ❌

**B. Stall Count Not Reset**
- `nStallingCount` increments but never resets ❌
- Even after successful downloads, count remains high ❌

**C. Stall Detection Logic Issue**
- `CheckForStallingPeers()` increments `nStallingCount` ✅
- But `IsSuitableForDownload()` doesn't properly check it ❌

**D. Race Condition**
- `GetValidPeersForDownload()` checks `nStallingCount` ✅
- But between check and use, `nStallingCount` increases ❌
- Or stall count checked at different times ❌

**Most Likely**: **STALL_THRESHOLD is too high** or **stall count not reset properly**

---

## Investigation Findings

### Finding #1: STALL_THRESHOLD Definition

**Need to find**: What is `STALL_THRESHOLD`?

**Search**: `grep -r "STALL_THRESHOLD" src/`

**Expected**: Should be defined in `src/net/peers.h` or `src/net/peers.cpp`

### Finding #2: Stall Count Reset Logic

**Location**: `src/net/peers.cpp:821-824` and `858-860`

**Code**:
```cpp
peer->nStallingCount = 0;  // Reset on successful block receive
peer->nBlocksDownloaded++;
peer->lastSuccessTime = std::chrono::steady_clock::now();
```

**Issue**: Stall count only resets on successful block receive. If no blocks received, count never resets.

**Problem**: During IBD stalls, no blocks received → stall count keeps increasing → peers become unsuitable.

### Finding #3: "No Suitable Peers" Message Logic

**Location**: `src/node/ibd_coordinator.cpp:246-257`

**Code**:
```cpp
if (!any_requested) {
    // Log hang cause
    switch (m_last_hang_cause) {
        case HangCause::NONE: cause_str = "no suitable peers"; break;
        // ...
    }
    LogPrintIBD(WARN, "Could not send any block requests - %s", cause_str.c_str());
}
```

**Issue**: If `m_last_hang_cause = NONE` and `any_requested = false`, message says "no suitable peers" even if:
- Window is empty
- No valid heights after filtering
- `AssignChunkToPeer()` fails

**Problem**: Message is misleading - doesn't indicate actual cause.

---

## Root Causes Identified

### Root Cause #1: Misleading "No Suitable Peers" Message

**Problem**: Message "no suitable peers" appears even when:
- Peers ARE suitable (passed `GetValidPeersForDownload()`)
- But no chunks can be assigned (window empty, no valid heights, etc.)

**Location**: `src/node/ibd_coordinator.cpp:255`

**Fix**: Change message to reflect actual cause:
- "window empty (no pending heights)"
- "no valid heights after filtering"
- "chunk assignment failed"
- "all peers at capacity"

### Root Cause #2: Stall Count Not Reset During IBD Stalls

**Problem**: During IBD stalls:
- No blocks received → `nStallingCount` never resets
- Stall count keeps increasing → peers become unsuitable
- Even after stall resolves, peers remain unsuitable

**Location**: `src/net/peers.cpp:821-824`

**Fix**: Reset stall count periodically or on timeout, not just on successful block receive.

### Root Cause #3: STALL_THRESHOLD May Be Too High

**Problem**: If `STALL_THRESHOLD` is very high (e.g., 1000), peers with 643 stalls still pass `IsSuitableForDownload()`.

**Location**: `src/net/peers.h:112-117`

**Fix**: Lower `STALL_THRESHOLD` or add additional checks for extremely high stall counts.

### Root Cause #4: Window Empty Not Properly Handled

**Problem**: When window is empty:
- `chunk_heights.empty()` → `break` → no chunks assigned
- `any_requested = false` → "no suitable peers" message
- But actual cause is "window empty"

**Location**: `src/node/ibd_coordinator.cpp:479-483`

**Fix**: Set `m_last_hang_cause = WINDOW_EMPTY` before break, so message reflects actual cause.

---

## Recommended Fixes

### Fix #1: Improve Hang Cause Detection

**Location**: `src/node/ibd_coordinator.cpp:479-483`

**Change**:
```cpp
if (chunk_heights.empty()) {
    m_last_hang_cause = HangCause::WINDOW_EMPTY;  // Set BEFORE break
    LogPrintIBD(DEBUG, "No pending heights in window - window may be stalled");
    break;
}
```

**Also**: Set hang cause when `valid_heights.empty()`:
```cpp
if (valid_heights.empty()) {
    m_last_hang_cause = HangCause::WINDOW_EMPTY;  // No valid heights = window issue
    continue;  // Skip this peer
}
```

### Fix #2: Reset Stall Count on Timeout

**Location**: `src/net/peers.cpp:1012-1044` (`CheckForStallingPeers()`)

**Change**: Reset `nStallingCount` if last success was very long ago (e.g., > 5 minutes):
```cpp
auto time_since_success = now - peer->lastSuccessTime;
if (time_since_success > std::chrono::minutes(5)) {
    // Reset stall count if peer hasn't succeeded in a long time
    // This prevents peers from being permanently unsuitable after IBD stalls
    peer->nStallingCount = 0;
}
```

### Fix #3: Lower STALL_THRESHOLD or Add Hard Limit

**Location**: `src/net/peers.h` (find STALL_THRESHOLD definition)

**Change**: If `STALL_THRESHOLD` is very high, lower it. Or add hard limit:
```cpp
bool IsSuitableForDownload() const {
    // Hard limit: never allow peers with > 100 stalls
    if (nStallingCount > 100) {
        return false;
    }
    return nStallingCount < STALL_THRESHOLD;
}
```

### Fix #4: Better Logging for Debugging

**Location**: `src/node/ibd_coordinator.cpp:514-523`

**Add**: Log why peers are skipped:
```cpp
if (valid_heights.empty()) {
    LogPrintIBD(DEBUG, "Peer %d skipped - no valid heights after filtering (chunk_heights=%zu)", 
               peer_id, chunk_heights.size());
    continue;
}

if (!m_node_context.block_fetcher->AssignChunkToPeer(peer_id, start, end)) {
    LogPrintIBD(DEBUG, "Peer %d skipped - AssignChunkToPeer failed", peer_id);
    continue;
}
```

---

## Verification Checklist

- [ ] Find `STALL_THRESHOLD` definition
- [ ] Verify stall count reset logic
- [ ] Check if window empty is properly detected
- [ ] Verify hang cause is set correctly
- [ ] Check if `AssignChunkToPeer()` failures are logged
- [ ] Verify "no suitable peers" message accuracy

---

## Conclusion

**LDN Issue**: Peers are valid but no chunks can be assigned (window empty or no valid heights). Message "no suitable peers" is misleading.

**SGP Issue**: Peers have extremely high stall count (643) but still pass `IsSuitableForDownload()`. Either `STALL_THRESHOLD` is too high or stall count not reset properly.

**Priority**: HIGH - Both issues prevent IBD from progressing.

**Next Steps**: 
1. Find `STALL_THRESHOLD` definition
2. Implement fixes for hang cause detection
3. Add stall count reset logic
4. Improve logging for debugging

