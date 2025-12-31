# IBD Issues Fixes - Action Plan for Claude
**Date:** December 28, 2025  
**Priority Order:** Issue 4 → Issue 2 → Issue 3 → Issue 1  
**Target:** 5-8 minutes sync with minimal stalls

---

## Fix Priority 1: Issue 4 - Peer Capacity Saturation (CRITICAL)

### Problem
Requests are sent to peers even when they're at 16/16 capacity, causing them to exceed limits and become overwhelmed.

### Root Cause
`FetchBlocks()` checks capacity once, then processes all returned blocks without re-checking. If `RequestBlockFromPeer()` succeeds for multiple blocks, peer can exceed limit.

### Files to Modify
- `src/node/ibd_coordinator.cpp` (lines 466-514)

### Specific Fix Instructions

**Step 1:** Modify the capacity check loop in `FetchBlocks()`

**Location:** `src/node/ibd_coordinator.cpp:494-514`

**Current Code:**
```cpp
for (int h : blocks_to_request) {
    // Filter: within header range, not already have, peer has it
    if (h > header_height) continue;
    if (h <= chain_height) continue;
    if (h > peer_height) continue;

    uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
    if (hash.IsNull()) continue;

    // Check if already connected
    CBlockIndex* pindex = m_chainstate.GetBlockIndex(hash);
    if (pindex && (pindex->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
        continue;
    }

    // Request this block from peer using per-block API
    if (m_node_context.block_fetcher->RequestBlockFromPeer(peer_id, h, hash)) {
        getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
        total_blocks_requested++;
    }
}
```

**Replace With:**
```cpp
for (int h : blocks_to_request) {
    // CRITICAL FIX: Re-check capacity before each request to prevent exceeding limit
    int current_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(peer_id);
    if (current_in_flight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
        // Peer reached capacity - stop requesting more blocks
        break;
    }

    // Filter: within header range, not already have, peer has it
    if (h > header_height) continue;
    if (h <= chain_height) continue;
    if (h > peer_height) continue;

    uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
    if (hash.IsNull()) continue;

    // Check if already connected
    CBlockIndex* pindex = m_chainstate.GetBlockIndex(hash);
    if (pindex && (pindex->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
        continue;
    }

    // Request this block from peer using per-block API
    if (m_node_context.block_fetcher->RequestBlockFromPeer(peer_id, h, hash)) {
        getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
        total_blocks_requested++;
    }
}
```

**Step 2:** Add safety check to cap `blocks_to_request` size

**Location:** `src/node/ibd_coordinator.cpp:485-488` (after GetNextBlocksToRequest call)

**Add After Line 485:**
```cpp
std::vector<int> blocks_to_request = m_node_context.block_fetcher->GetNextBlocksToRequest(peer_capacity, chain_height, header_height);
if (blocks_to_request.empty()) {
    break;  // All blocks either connected or in-flight
}

// SAFETY FIX: Cap blocks_to_request to remaining capacity to prevent race conditions
int remaining_capacity = MAX_BLOCKS_IN_TRANSIT_PER_PEER - peer_blocks_in_flight;
if (static_cast<int>(blocks_to_request.size()) > remaining_capacity) {
    blocks_to_request.resize(remaining_capacity);
}
```

### Testing Instructions
1. Run sync with 2-3 peers
2. Monitor logs for "in-flight=16/16" messages
3. Verify NO requests sent when peer already at capacity
4. Check that peer in-flight count never exceeds 16
5. Measure sync time (should improve from 10-11 min to 7-9 min)

### Expected Outcome
- Peers no longer exceed 16/16 capacity
- Reduced simultaneous block timeouts
- Faster sync due to better peer utilization

---

## Fix Priority 2: Issue 2 - Blocks Stuck >30 Seconds (HIGH)

### Problem
27 blocks timing out simultaneously, causing sync stalls.

### Root Cause
Multiple potential causes:
1. Issue 4 (capacity saturation) overwhelming peers
2. Block serving code bottleneck
3. Network congestion between regions

### Files to Investigate
- `src/net/net.cpp` - MSG_BLOCK_INV handling (block serving)
- `src/node/ibd_coordinator.cpp:552-569` - RetryTimeoutsAndStalls()

### Specific Fix Instructions

**Step 1:** Add logging to block serving code

**Location:** `src/net/net.cpp` - Find MSG_BLOCK_INV handling

**Action:** Search for where GETDATA messages are processed and blocks are sent.

**Add Logging:**
```cpp
// When GETDATA received for block
std::cout << "[BLOCK-SERVE] GETDATA received for block " << hash.GetHex().substr(0, 16) 
          << " from peer " << peer_id << std::endl;

// When block fetched from database
auto fetch_start = std::chrono::steady_clock::now();
// ... block fetch code ...
auto fetch_end = std::chrono::steady_clock::now();
auto fetch_time = std::chrono::duration_cast<std::chrono::milliseconds>(fetch_end - fetch_start).count();
std::cout << "[BLOCK-SERVE] Block fetched in " << fetch_time << "ms" << std::endl;

// When block sent
std::cout << "[BLOCK-SERVE] Block sent to peer " << peer_id << std::endl;
```

**Step 2:** Implement staggered block requests

**Location:** `src/node/ibd_coordinator.cpp:485` (modify GetNextBlocksToRequest call)

**Current Code:**
```cpp
std::vector<int> blocks_to_request = m_node_context.block_fetcher->GetNextBlocksToRequest(peer_capacity, chain_height, header_height);
```

**Replace With:**
```cpp
// STAGGER FIX: Request smaller batches to prevent overwhelming peers
// Request up to 8 blocks at a time instead of full capacity
int batch_size = std::min(peer_capacity, 8);
std::vector<int> blocks_to_request = m_node_context.block_fetcher->GetNextBlocksToRequest(batch_size, chain_height, header_height);
```

**Step 3:** Reduce timeout for capacity-saturated peers

**Location:** `src/node/ibd_coordinator.cpp:552-569` (RetryTimeoutsAndStalls)

**Current Code:**
```cpp
static constexpr int HARD_TIMEOUT_SECONDS = 30;
auto very_stalled = m_node_context.block_fetcher->GetStalledBlocks(
    std::chrono::seconds(HARD_TIMEOUT_SECONDS));
```

**Replace With:**
```cpp
// PROGRESSIVE TIMEOUT: Use shorter timeout for blocks from capacity-saturated peers
// Check if blocks are from peers at capacity
auto very_stalled_15s = m_node_context.block_fetcher->GetStalledBlocks(
    std::chrono::seconds(15));
auto very_stalled_30s = m_node_context.block_fetcher->GetStalledBlocks(
    std::chrono::seconds(30));

// Remove blocks stuck >15s from capacity-saturated peers first
for (const auto& [height, peer] : very_stalled_15s) {
    int peer_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(peer);
    if (peer_in_flight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER - 2) {  // At or near capacity
        m_node_context.block_fetcher->RequeueBlock(height);
    }
}

// Remove all blocks stuck >30s
auto very_stalled = very_stalled_30s;
```

### Testing Instructions
1. Run sync and monitor block serving logs
2. Measure time between GETDATA and BLOCK message
3. Identify bottleneck (database lookup, network send, etc.)
4. Verify staggered requests reduce simultaneous timeouts
5. Check that <5 blocks timeout simultaneously (vs. 27 before)

### Expected Outcome
- Reduced simultaneous timeouts (from 27 to <5)
- Faster failover when peers are slow
- Better sync stability

---

## Fix Priority 3: Issue 3 - Slow RandomX Hash Times (MEDIUM)

### Problem
Hash computation times vary wildly from 40ms to 9000ms+ due to mutex contention.

### Root Cause
All validation workers contend for single RandomX VM mutex, serializing hash computation.

### Files to Modify
- `src/crypto/randomx_hash.cpp` - randomx_hash_fast()
- `src/crypto/randomx_hash.h` - Thread-local VM declarations
- `src/node/block_validation_queue.cpp` - Validation worker implementation

### Specific Fix Instructions

**Option A: Thread-Local RandomX VM (Recommended)**

**Step 1:** Add thread-local VM storage

**Location:** `src/crypto/randomx_hash.cpp` (add after global variables)

**Add:**
```cpp
// Thread-local RandomX VM for parallel hash computation
thread_local randomx_vm* g_thread_local_vm = nullptr;
thread_local std::vector<uint8_t> g_thread_local_key;
thread_local bool g_thread_local_light_mode = false;

// Initialize thread-local VM if needed
static void EnsureThreadLocalVM(const void* key, size_t key_len, bool light_mode) {
    std::vector<uint8_t> current_key((const uint8_t*)key, (const uint8_t*)key + key_len);
    
    // Check if thread-local VM needs initialization or re-initialization
    if (g_thread_local_vm == nullptr || 
        g_thread_local_key != current_key || 
        g_thread_local_light_mode != light_mode) {
        
        // Cleanup old VM
        if (g_thread_local_vm != nullptr) {
            randomx_destroy_vm(g_thread_local_vm);
            g_thread_local_vm = nullptr;
        }
        
        // Initialize cache (shared, but VM is per-thread)
        randomx_init_for_hashing(key, key_len, light_mode ? 1 : 0);
        
        // Create thread-local VM
        randomx_flags flags = randomx_get_flags();
        if (!light_mode) {
            flags = flags | RANDOMX_FLAG_FULL_MEM;
        }
        
        // Get shared cache (already initialized by randomx_init_for_hashing)
        std::lock_guard<std::mutex> lock(g_randomx_mutex);
        if (g_randomx_cache == nullptr) {
            // Should not happen, but safety check
            return;
        }
        
        g_thread_local_vm = randomx_create_vm(flags, g_randomx_cache, nullptr);
        g_thread_local_key = current_key;
        g_thread_local_light_mode = light_mode;
    }
}
```

**Step 2:** Modify randomx_hash_fast() to use thread-local VM

**Location:** `src/crypto/randomx_hash.cpp:211-238`

**Replace:**
```cpp
void randomx_hash_fast(const void* input, size_t input_len, void* output) {
    // Validate inputs
    if (input == nullptr && input_len > 0) {
        throw std::invalid_argument("randomx_hash_fast: input is NULL but input_len > 0");
    }
    if (output == nullptr) {
        throw std::invalid_argument("randomx_hash_fast: output buffer is NULL");
    }

    // THREAD-LOCAL FIX: Use per-thread VM to eliminate mutex contention
    // Each validation worker gets its own VM instance
    std::lock_guard<std::mutex> lock(g_randomx_mutex);
    
    // Get key from global cache (needed for thread-local VM initialization)
    if (g_randomx_cache == nullptr) {
        throw std::runtime_error("RandomX cache not initialized");
    }
    
    // Determine if we should use light mode (for validation) or full mode (for mining)
    // Use light mode for block validation to reduce memory usage
    bool use_light_mode = true;  // TODO: Make configurable or detect from context
    
    // Release lock before initializing thread-local VM (may take time)
    {
        // Get key length (assume 32 bytes for Dilithion)
        size_t key_len = 32;
        const void* key = g_current_key.data();
        
        // Ensure thread-local VM is initialized (no lock needed for thread-local access)
        EnsureThreadLocalVM(key, key_len, use_light_mode);
    }
    
    // Use thread-local VM (no mutex needed - thread-local is thread-safe)
    if (g_thread_local_vm != nullptr) {
        randomx_calculate_hash(g_thread_local_vm, input, input_len, output);
        return;
    }
    
    // Fallback to global VM if thread-local initialization failed
    if (g_randomx_vm == nullptr) {
        throw std::runtime_error("RandomX VM not initialized");
    }
    randomx_calculate_hash(g_randomx_vm, input, input_len, output);
}
```

**Note:** This is a complex change. Consider simpler Option B first.

**Option B: Reduce Validation Worker Count (Simpler)**

**Location:** `src/node/block_validation_queue.cpp` - Find where validation workers are created

**Action:** Reduce number of concurrent validation workers from current value to 2-4.

**Find:**
```cpp
// Number of validation worker threads
static constexpr int VALIDATION_WORKER_COUNT = X;  // Current value
```

**Change To:**
```cpp
// REDUCED WORKER COUNT: Fewer workers = less mutex contention
// Trade-off: Slower validation but more consistent hash times
static constexpr int VALIDATION_WORKER_COUNT = 2;  // Reduced from X
```

### Testing Instructions
1. Profile mutex wait times before and after fix
2. Measure hash time variance (should reduce from 40ms-9000ms to 40ms-200ms)
3. Check CPU usage (should be more consistent)
4. Verify validation throughput (may be slightly slower but more consistent)

### Expected Outcome
- Reduced hash time variance (from 9000ms+ to <200ms)
- More consistent validation performance
- Better CPU utilization

---

## Fix Priority 4: Issue 1 - "No Suitable Peers" Refinement (LOW)

### Problem
Peers become "unsuitable" during header sync even though they're just busy sending headers.

### Root Cause
Stall count increments during header sync, but reset happens after headers complete. If headers arrive in batches, stall count can accumulate.

### Files to Modify
- `src/net/peers.h:120-125` - IsSuitableForDownload()
- `src/net/peers.cpp` - CheckForStallingPeers() (find where stall count increments)

### Specific Fix Instructions

**Step 1:** Improve IsSuitableForDownload() logic

**Location:** `src/net/peers.h:120-125`

**Current Code:**
```cpp
bool IsSuitableForDownload() const {
    auto now = std::chrono::steady_clock::now();
    auto stallAge = std::chrono::duration_cast<std::chrono::minutes>(now - lastStallTime);
    if (stallAge >= STALL_FORGIVENESS_TIMEOUT) return true;
    return nStallingCount < STALL_THRESHOLD;
}
```

**Replace With:**
```cpp
bool IsSuitableForDownload() const {
    auto now = std::chrono::steady_clock::now();
    
    // HEADER SYNC FIX: Be more lenient during active header sync
    // If peer recently received headers, it may be busy sending them
    // Use higher threshold to prevent marking as unsuitable
    auto timeSinceLastHeader = std::chrono::duration_cast<std::chrono::seconds>(
        now - lastSuccessTime);  // lastSuccessTime updated when headers received
    
    if (timeSinceLastHeader < std::chrono::seconds(10)) {
        // Peer actively syncing headers - use 2x threshold
        return nStallingCount < (STALL_THRESHOLD * 2);  // 1000 instead of 500
    }
    
    // Normal operation - use standard threshold
    auto stallAge = std::chrono::duration_cast<std::chrono::minutes>(now - lastStallTime);
    if (stallAge >= STALL_FORGIVENESS_TIMEOUT) return true;
    return nStallingCount < STALL_THRESHOLD;
}
```

**Step 2:** Find where stall count increments and add header sync check

**Location:** `src/net/peers.cpp` - Search for `nStallingCount++` or `nStallingCount +=`

**Action:** Before incrementing stall count, check if peer is in header sync mode.

**Add Check:**
```cpp
// Before incrementing nStallingCount:
auto now = std::chrono::steady_clock::now();
auto timeSinceLastHeader = std::chrono::duration_cast<std::chrono::seconds>(
    now - lastSuccessTime);

// Don't increment stall count if peer is actively syncing headers
if (timeSinceLastHeader < std::chrono::seconds(10)) {
    // Peer is busy with headers - don't count as stall
    return;
}

// Normal stall - increment count
nStallingCount++;
```

### Testing Instructions
1. Run sync and monitor "no suitable peers" messages
2. Verify peers don't become unsuitable during header sync
3. Check that stall count resets properly when headers arrive
4. Measure sync time improvement

### Expected Outcome
- Fewer "no suitable peers" stalls during header sync
- Better peer utilization
- Faster sync recovery after header batches

---

## Testing Checklist

After implementing all fixes:

### Test 1: Capacity Saturation Fix
- [ ] Verify no requests sent when peer at 16/16 capacity
- [ ] Check peer in-flight count never exceeds 16
- [ ] Measure sync time improvement

### Test 2: Block Timeout Fix
- [ ] Verify <5 blocks timeout simultaneously (vs. 27 before)
- [ ] Check block serving logs show reasonable fetch times
- [ ] Verify staggered requests reduce peer overload

### Test 3: RandomX Hash Fix
- [ ] Measure hash time variance (should be <200ms)
- [ ] Profile mutex contention (should be minimal)
- [ ] Check validation throughput

### Test 4: Suitable Peers Fix
- [ ] Verify no "unsuitable peers" during header sync
- [ ] Check stall count resets properly
- [ ] Measure sync recovery time

### Overall Sync Test
- [ ] Run full sync from genesis
- [ ] Target: 5-8 minutes sync time
- [ ] Verify <10 total stalls during sync
- [ ] Check no blocks stuck >30s (except network issues)

---

## Implementation Order

1. **Fix Issue 4** (1-2 hours) - Critical, prevents Issue 2
2. **Fix Issue 2** (4-6 hours) - High impact, improves stability
3. **Fix Issue 3** (1-2 days) - Medium impact, improves consistency
4. **Fix Issue 1** (2-4 hours) - Low impact, refinement

**Total Estimated Time:** 2-3 days for all fixes

---

## Notes for Claude

- **Always test each fix independently** before moving to next
- **Add logging** to verify fixes are working
- **Monitor sync times** after each fix
- **Keep backups** of original code before modifying
- **Commit fixes separately** for easier rollback if needed

---

*Action Plan Created: December 28, 2025*  
*Status: Ready for Implementation*





