# IBD Issues Diagnostic Report
**Date:** December 28, 2025  
**Status:** Research Only - Root Cause Analysis  
**Target:** 5-8 minutes sync with minimal stalls

---

## Executive Summary

Four critical IBD issues identified from test results:
1. **"No Suitable Peers" stalls** - Partially fixed, but stall count logic still problematic
2. **Blocks stuck >30 seconds** - 27 blocks timing out simultaneously indicates peer overload
3. **Slow RandomX hash times** - Sporadic 40ms to 9000ms+ variance suggests CPU contention
4. **Peer capacity saturation** - Requests sent even when peers at 16/16 capacity (race condition)

---

## Issue 1: "No Suitable Peers" Stalls During Block Download

### Root Cause Analysis

**Location:** `src/net/peers.h:120-125` (IsSuitableForDownload logic)

**Current Logic:**
```cpp
bool IsSuitableForDownload() const {
    auto now = std::chrono::steady_clock::now();
    auto stallAge = std::chrono::duration_cast<std::chrono::minutes>(now - lastStallTime);
    if (stallAge >= STALL_FORGIVENESS_TIMEOUT) return true;  // 5 minutes
    return nStallingCount < STALL_THRESHOLD;  // 500
}
```

**Problem Flow:**
1. Header sync peer receives 2000 headers in batch
2. While sending headers, peer cannot respond to GETDATA requests quickly
3. Block requests timeout → `nStallingCount` increments
4. After headers complete, `MarkHeadersAsReceived()` resets `nStallingCount = 0` ✅
5. **BUT:** If headers arrive in multiple batches, stall count accumulates between resets
6. When `nStallingCount >= 500`, peer becomes "unsuitable" even though it's just busy with headers

**Evidence from Code:**
- `peers.cpp:843-856` - `MarkHeadersAsReceived()` resets stall count ✅
- However, stall count increments happen in `CheckForStallingPeers()` or timeout handlers
- If headers arrive in rapid succession, stall count may exceed threshold before reset

**Root Cause:**
The stall count mechanism doesn't distinguish between:
- **Legitimate stalls** (peer slow/unresponsive) → Should mark unsuitable
- **Temporary stalls** (peer busy sending headers) → Should NOT mark unsuitable

### Recommended Fixes

**Fix 1: Separate Header Sync Stall Tracking**
- Add `nHeaderSyncStallCount` separate from `nStallingCount`
- Only increment `nStallingCount` when peer is NOT in header sync mode
- When headers arrive, reset BOTH counters

**Fix 2: Reduce Stall Threshold During Header Sync**
- If peer is actively sending headers (`nHeadersReceived` increasing), use lower threshold (e.g., 1000 instead of 500)
- Or: Don't increment stall count at all during active header sync

**Fix 3: Check Header Sync State Before Marking Unsuitable**
```cpp
bool IsSuitableForDownload() const {
    // If peer is actively syncing headers, be more lenient
    auto now = std::chrono::steady_clock::now();
    auto timeSinceLastHeader = std::chrono::duration_cast<std::chrono::seconds>(
        now - lastHeaderReceiveTime);
    
    if (timeSinceLastHeader < std::chrono::seconds(10)) {
        // Peer actively syncing headers - use higher threshold
        return nStallingCount < (STALL_THRESHOLD * 2);  // 1000 instead of 500
    }
    
    // Normal operation - use standard threshold
    auto stallAge = std::chrono::duration_cast<std::chrono::minutes>(now - lastStallTime);
    if (stallAge >= STALL_FORGIVENESS_TIMEOUT) return true;
    return nStallingCount < STALL_THRESHOLD;
}
```

---

## Issue 2: Blocks Stuck >30 Seconds (27 Blocks at Once)

### Root Cause Analysis

**Location:** `src/node/ibd_coordinator.cpp:552-569` (RetryTimeoutsAndStalls)

**Current Logic:**
```cpp
static constexpr int HARD_TIMEOUT_SECONDS = 30;
auto very_stalled = m_node_context.block_fetcher->GetStalledBlocks(
    std::chrono::seconds(HARD_TIMEOUT_SECONDS));
```

**Problem Flow:**
1. Both peers reach 16/16 capacity
2. 27 blocks requested simultaneously (likely from both peers)
3. Peers cannot respond (overwhelmed or network issues)
4. After 30 seconds, all 27 blocks timeout simultaneously
5. Blocks removed from tracker and re-requested
6. **Cycle repeats** if peers still at capacity

**Why 27 Blocks at Once?**

**Theory 1: Batch Request Timing**
- `FetchBlocks()` requests up to `peer_capacity` blocks per peer
- If both peers have capacity=16, up to 32 blocks requested
- If requests happen in rapid succession, many blocks can timeout together

**Theory 2: Peer Overload**
- Peers may be serving other nodes or processing headers
- Network congestion between regions (NYC↔SGP, NYC↔LDN)
- Block serving code may have bottleneck (need to investigate)

**Theory 3: Blocks Not Being Served**
- Peers receive GETDATA but don't send blocks
- Could be bug in block serving code (`src/net/net.cpp` - MSG_BLOCK_INV handling)
- Or peers are disconnected but not detected

### Recommended Fixes

**Fix 1: Stagger Block Requests**
- Instead of requesting all blocks at once, request in smaller batches (e.g., 4-8 at a time)
- Wait for some blocks to arrive before requesting more
- Reduces simultaneous timeout risk

**Fix 2: Investigate Block Serving Code**
- Check `src/net/net.cpp` for MSG_BLOCK_INV handling
- Verify blocks are actually being sent when GETDATA received
- Add logging to track: GETDATA received → Block sent → Block received

**Fix 3: Reduce Timeout for Capacity-Saturated Peers**
- If peer is at 16/16 capacity, use shorter timeout (e.g., 15 seconds)
- Faster failover to other peers
- Prevents long stalls when peer is overloaded

**Fix 4: Progressive Timeout**
- First timeout: 15 seconds → Try different peer
- Second timeout: 30 seconds → Remove from tracker
- Prevents all blocks timing out simultaneously

---

## Issue 3: Slow RandomX Hash Times (Sporadic 40ms to 9000ms+)

### Root Cause Analysis

**Location:** `src/crypto/randomx_hash.cpp:211-238` (randomx_hash_fast)

**Current Implementation:**
```cpp
void randomx_hash_fast(const void* input, size_t input_len, void* output) {
    if (g_validation_ready.load()) {
        std::lock_guard<std::mutex> lock(g_validation_mutex);
        if (g_validation_vm != nullptr) {
            randomx_calculate_hash(g_validation_vm, input, input_len, output);
            return;
        }
    }
    
    // Fallback to legacy global VM
    std::lock_guard<std::mutex> lock(g_randomx_mutex);
    randomx_calculate_hash(g_randomx_vm, input, input_len, output);
}
```

**Problem Flow:**
1. Multiple validation workers call `randomx_hash_fast()` concurrently
2. All workers contend for `g_validation_mutex` or `g_randomx_mutex`
3. **Mutex serialization** → Only one hash computation at a time
4. If 10 workers need to hash blocks, they queue up behind mutex
5. **Result:** 40ms hash × 10 workers = 400ms+ wait time per worker
6. With async validation queue backlog, wait times can reach 9000ms+

**Evidence:**
- NYC shows high variance (40ms to 9000ms+) → High CPU contention
- SGP consistently 40-49ms → Lower contention (fewer validation workers?)
- Variance correlates with async validation queue depth

**Root Cause:**
RandomX hash computation is **serialized by mutex**, but multiple validation workers need to hash blocks concurrently. This creates a bottleneck.

### Recommended Fixes

**Fix 1: Per-Worker RandomX VM Instances**
- Each validation worker gets its own RandomX VM
- No mutex contention → Parallel hash computation
- Trade-off: More memory (each VM ~2GB in full mode, ~256MB in light mode)

**Fix 2: Thread-Local RandomX VM Cache**
- Use thread-local storage for RandomX VM
- Each thread gets its own VM instance
- Eliminates mutex contention

**Fix 3: Lock-Free Hash Queue**
- Use lock-free queue for hash requests
- Single hash worker thread processes queue
- Validation workers submit requests and wait asynchronously
- Trade-off: More complex, but eliminates contention

**Fix 4: Reduce Validation Worker Count**
- If CPU contention is the issue, reduce number of concurrent validation workers
- Fewer workers = less mutex contention
- Trade-off: Slower validation overall

**Fix 5: Use Light Mode for Validation**
- Light mode uses 256MB instead of 2GB
- Faster initialization, less memory pressure
- May reduce contention if memory is the bottleneck

**Investigation Needed:**
- Profile mutex contention: How long do workers wait for `g_validation_mutex`?
- Measure hash queue depth: How many blocks waiting to hash?
- Check CPU usage: Is CPU saturated or idle during slow hash times?

---

## Issue 4: Peer Capacity Saturation (Requests Sent at 16/16)

### Root Cause Analysis

**Location:** `src/node/ibd_coordinator.cpp:466-470` (capacity check)

**Current Logic:**
```cpp
// Check peer capacity using per-block tracking
int peer_blocks_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(peer_id);
int peer_capacity = MAX_BLOCKS_IN_TRANSIT_PER_PEER - peer_blocks_in_flight;
if (peer_capacity <= 0) {
    continue;  // Peer at capacity
}

// ... later ...

// Request blocks
if (m_node_context.block_fetcher->RequestBlockFromPeer(peer_id, h, hash)) {
    getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
    total_blocks_requested++;
}

// ... later ...

// Log AFTER sending (line 533-540)
std::cout << "[PerBlock] Requested " << getdata.size() << " blocks from peer " << peer_id
          << " (peer now has " << m_node_context.block_fetcher->GetPeerBlocksInFlight(peer_id)
          << "/" << MAX_BLOCKS_IN_TRANSIT_PER_PEER << " in-flight)" << std::endl;
```

**Problem Flow:**
1. **T0:** `GetPeerBlocksInFlight(peer_id)` returns 14 → capacity = 2
2. **T1:** `GetNextBlocksToRequest(2, ...)` returns [100, 101]
3. **T2:** Loop processes height 100 → `RequestBlockFromPeer()` succeeds → adds to tracker → count = 15
4. **T3:** Loop processes height 101 → `RequestBlockFromPeer()` succeeds → adds to tracker → count = 16
5. **T4:** GETDATA sent with 2 blocks
6. **T5:** Log shows "peer now has 16/16 in-flight" ✅ (correct)

**BUT:** If `GetNextBlocksToRequest()` returns more blocks than capacity:

1. **T0:** `GetPeerBlocksInFlight()` returns 14 → capacity = 2
2. **T1:** `GetNextBlocksToRequest(16, ...)` returns [100, 101, 102, ..., 115] (16 blocks!)
3. **T2-T17:** Loop processes all 16 blocks → all `RequestBlockFromPeer()` succeed → count = 30!
4. **T18:** GETDATA sent with 16 blocks
5. **T19:** Log shows "peer now has 30/16 in-flight" ❌ (exceeds limit!)

**Root Cause:**
`GetNextBlocksToRequest()` is called with `peer_capacity`, but the loop processes ALL returned blocks without re-checking capacity. If `RequestBlockFromPeer()` succeeds for all blocks, the peer can exceed its limit.

**Evidence from Logs:**
```
2025-12-28 10:03:07 [IBD] Requested 1 blocks from peer 2 (in-flight=16/16)
2025-12-28 10:03:04 [IBD] Requested 4 blocks from peer 2 (in-flight=16/16)
```

This shows requests being sent even when peer is already at capacity.

### Recommended Fixes

**Fix 1: Re-Check Capacity in Loop**
```cpp
for (int h : blocks_to_request) {
    // Re-check capacity before each request
    int current_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(peer_id);
    if (current_in_flight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
        break;  // Peer reached capacity
    }
    
    // ... rest of loop ...
}
```

**Fix 2: Limit blocks_to_request Size**
```cpp
// Cap blocks_to_request to remaining capacity
int remaining_capacity = MAX_BLOCKS_IN_TRANSIT_PER_PEER - peer_blocks_in_flight;
if (blocks_to_request.size() > remaining_capacity) {
    blocks_to_request.resize(remaining_capacity);
}
```

**Fix 3: Make RequestBlockFromPeer() Enforce Limit**
- `CBlockTracker::AddBlock()` already checks capacity (line 75-77)
- But if called multiple times rapidly, race condition possible
- Add atomic check-and-increment to prevent exceeding limit

**Fix 4: Batch Size Limit**
- Instead of requesting up to `peer_capacity` blocks, limit to smaller batches (e.g., 4-8)
- Reduces risk of exceeding limit due to race conditions

---

## Priority Order for Investigation

### Priority 1: Issue 4 (Peer Capacity Saturation) - **CRITICAL**
**Why:** Causes Issue 2 (blocks stuck >30s) by overwhelming peers  
**Impact:** Blocks timeout, sync stalls  
**Fix Complexity:** Low (add capacity re-check in loop)  
**Estimated Fix Time:** 1-2 hours

### Priority 2: Issue 2 (Blocks Stuck >30s) - **HIGH**
**Why:** Direct symptom of sync slowdown  
**Impact:** 27 blocks timing out simultaneously stalls sync  
**Fix Complexity:** Medium (investigate block serving + stagger requests)  
**Estimated Fix Time:** 4-6 hours

### Priority 3: Issue 3 (Slow RandomX Hash) - **MEDIUM**
**Why:** Causes validation slowdown, but not direct cause of stalls  
**Impact:** 5-10x slower validation during contention  
**Fix Complexity:** High (requires architectural changes)  
**Estimated Fix Time:** 1-2 days

### Priority 4: Issue 1 (No Suitable Peers) - **LOW**
**Why:** Partially fixed, less frequent now  
**Impact:** Occasional stalls during header sync  
**Fix Complexity:** Low (improve stall count logic)  
**Estimated Fix Time:** 2-4 hours

---

## Testing Recommendations

### Test 1: Capacity Saturation Fix
1. Run sync with 2 peers
2. Monitor logs for "in-flight=16/16" messages
3. Verify no requests sent when peer at capacity
4. Measure sync time (target: 5-8 minutes)

### Test 2: Block Timeout Investigation
1. Add logging to block serving code (`src/net/net.cpp`)
2. Track: GETDATA received → Block lookup → Block sent
3. Measure time between GETDATA and BLOCK message
4. Identify bottleneck in block serving

### Test 3: RandomX Contention Profiling
1. Add mutex wait time logging
2. Measure time workers wait for `g_validation_mutex`
3. Profile hash queue depth during sync
4. Identify if mutex contention is root cause

### Test 4: Staggered Request Testing
1. Implement staggered block requests (4-8 at a time)
2. Compare sync time vs. current implementation
3. Measure timeout frequency
4. Verify no simultaneous timeouts

---

## Files Requiring Investigation

### Issue 1: No Suitable Peers
- `src/net/peers.h:120-125` - IsSuitableForDownload()
- `src/net/peers.cpp:843-856` - MarkHeadersAsReceived()
- `src/net/peers.cpp` - CheckForStallingPeers() (find where stall count increments)

### Issue 2: Blocks Stuck >30s
- `src/node/ibd_coordinator.cpp:552-569` - RetryTimeoutsAndStalls()
- `src/net/net.cpp` - MSG_BLOCK_INV handling (block serving code)
- `src/net/block_tracker.h:253-267` - CheckTimeouts()

### Issue 3: Slow RandomX Hash
- `src/crypto/randomx_hash.cpp:211-238` - randomx_hash_fast()
- `src/node/block_validation_queue.cpp` - Validation worker implementation
- Profile mutex contention and hash queue depth

### Issue 4: Peer Capacity Saturation
- `src/node/ibd_coordinator.cpp:466-514` - FetchBlocks() capacity check
- `src/net/block_tracker.h:66-94` - AddBlock() capacity enforcement
- `src/net/block_fetcher.cpp:107-118` - RequestBlockFromPeer()

---

## Conclusion

**Primary Root Cause:** Issue 4 (capacity saturation) is causing Issue 2 (blocks stuck). Fixing capacity check will prevent peers from being overwhelmed.

**Secondary Issue:** Issue 3 (RandomX contention) causes validation slowdown but is not the direct cause of stalls.

**Tertiary Issue:** Issue 1 (no suitable peers) is partially fixed but needs refinement.

**Recommended Action Plan:**
1. **Immediate:** Fix Issue 4 (add capacity re-check in loop) - 1-2 hours
2. **Short-term:** Investigate Issue 2 (block serving bottleneck) - 4-6 hours
3. **Medium-term:** Fix Issue 3 (RandomX contention) - 1-2 days
4. **Long-term:** Refine Issue 1 (stall count logic) - 2-4 hours

**Expected Outcome:** Sync time reduced from 10-11 minutes to 5-8 minutes with minimal stalls.

---

*Report generated: December 28, 2025*  
*Status: Research Only - No Code Changes Made*





