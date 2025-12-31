# IBD Fixes - Quick Reference Checklist
**Date:** December 28, 2025  
**Use this as a quick reference while implementing fixes**

---

## Fix 1: Peer Capacity Saturation (CRITICAL - Do First)

### File: `src/node/ibd_coordinator.cpp`
### Lines: 494-514

**Change:** Add capacity re-check inside loop before each `RequestBlockFromPeer()` call

**Code to Add (after line 494):**
```cpp
// CRITICAL FIX: Re-check capacity before each request
int current_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(peer_id);
if (current_in_flight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
    break;  // Peer reached capacity
}
```

**Also Add (after line 485):**
```cpp
// SAFETY FIX: Cap blocks_to_request size
int remaining_capacity = MAX_BLOCKS_IN_TRANSIT_PER_PEER - peer_blocks_in_flight;
if (static_cast<int>(blocks_to_request.size()) > remaining_capacity) {
    blocks_to_request.resize(remaining_capacity);
}
```

**Test:** Verify no requests sent when peer at 16/16 capacity

---

## Fix 2: Blocks Stuck >30s (HIGH Priority)

### File: `src/node/ibd_coordinator.cpp`
### Line: 485

**Change:** Reduce batch size from `peer_capacity` to `min(peer_capacity, 8)`

**Code Change:**
```cpp
// Before:
std::vector<int> blocks_to_request = m_node_context.block_fetcher->GetNextBlocksToRequest(peer_capacity, ...);

// After:
int batch_size = std::min(peer_capacity, 8);
std::vector<int> blocks_to_request = m_node_context.block_fetcher->GetNextBlocksToRequest(batch_size, ...);
```

### File: `src/net/net.cpp`
### Action: Add logging to block serving code

**Add logging when:**
- GETDATA received
- Block fetched from database
- Block sent to peer

**Test:** Verify <5 blocks timeout simultaneously (vs. 27 before)

---

## Fix 3: Slow RandomX Hash (MEDIUM Priority)

### Option A: Thread-Local VM (Complex)
**File:** `src/crypto/randomx_hash.cpp`  
**Lines:** 211-238

**Action:** Implement thread-local RandomX VM to eliminate mutex contention

**See:** Full instructions in `IBD-FIXES-ACTION-PLAN.md` (Option A)

### Option B: Reduce Worker Count (Simple)
**File:** `src/node/block_validation_queue.cpp`

**Change:** Reduce `VALIDATION_WORKER_COUNT` from current value to 2-4

**Test:** Measure hash time variance (should be <200ms)

---

## Fix 4: No Suitable Peers (LOW Priority)

### File: `src/net/peers.h`
### Lines: 120-125

**Change:** Improve `IsSuitableForDownload()` to be lenient during header sync

**Code Change:**
```cpp
// Add at start of function:
auto timeSinceLastHeader = std::chrono::duration_cast<std::chrono::seconds>(
    now - lastSuccessTime);

if (timeSinceLastHeader < std::chrono::seconds(10)) {
    // Peer actively syncing headers - use 2x threshold
    return nStallingCount < (STALL_THRESHOLD * 2);  // 1000 instead of 500
}
```

**Test:** Verify no "unsuitable peers" during header sync

---

## Testing After Each Fix

1. **Build:** `mingw32-make clean && mingw32-make` (Windows) or `make clean && make` (Linux)
2. **Run Sync:** Start fresh node, sync from genesis
3. **Monitor Logs:** Check for:
   - "in-flight=16/16" messages (should not see requests sent)
   - Block timeout messages (should be <5 at once)
   - Hash time logs (should be consistent)
   - "no suitable peers" messages (should be rare)
4. **Measure Time:** Record sync duration
5. **Compare:** Before vs. after each fix

---

## Expected Results

| Fix | Before | After | Test Metric |
|-----|--------|-------|-------------|
| Issue 4 | Requests at 16/16 | No requests at capacity | Peer count never >16 |
| Issue 2 | 27 blocks timeout | <5 blocks timeout | Simultaneous timeouts |
| Issue 3 | 40ms-9000ms hash | 40ms-200ms hash | Hash time variance |
| Issue 1 | Frequent unsuitable | Rare unsuitable | "No suitable peers" count |

**Overall Target:** 5-8 minutes sync time (down from 10-11 minutes)

---

## Quick Commands

### Build
```bash
# Windows
mingw32-make clean
mingw32-make

# Linux/Mac
make clean
make
```

### Run Node
```bash
./dilithion-node --datadir=./test-data --rpcport=18332
```

### Monitor Logs
```bash
# Look for key patterns:
grep "in-flight=16/16" node.log
grep "blocks stuck" node.log
grep "Hash computed" node.log
grep "no suitable peers" node.log
```

---

## Rollback Instructions

If a fix causes issues:

1. **Git:** `git checkout src/node/ibd_coordinator.cpp` (or affected file)
2. **Rebuild:** `make clean && make`
3. **Test:** Verify node works without fix
4. **Investigate:** Check logs for what went wrong
5. **Fix:** Adjust code and retry

---

*Quick Reference Created: December 28, 2025*





