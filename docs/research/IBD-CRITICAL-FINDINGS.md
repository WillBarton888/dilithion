# Bitcoin Core IBD - Critical Findings Summary

## Quick Reference: How Bitcoin Core Handles Block Download

### The 4 Critical Insights

#### 1. Block Hash is ALWAYS Known Before Download
**In headers-first mode, Bitcoin Core NEVER computes the block hash when the block arrives.**

**Why?**
1. Headers are downloaded FIRST (all 80-byte headers, genesis to tip)
2. Hash is computed from header: `SHA256(SHA256(header))`
3. CBlockIndex is created and stored in `mapBlockIndex[hash]`
4. THEN full blocks are requested using those known hashes
5. When block arrives, hash is only used for LOOKUP, not computation

**Implications for Dilithion**:
- If you're computing hash when block arrives, you're doing it wrong
- Hash should be computed during header validation phase
- Block arrival is just a matter of matching hash to pending request

#### 2. mapBlocksInFlight is the Key Tracking Structure

**Type**: `std::multimap<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator>>`

**What it does**:
- Maps block hash → (peer ID, position in peer's download queue)
- Allows multiple peers to download same block (multimap, not map)
- Used to match arriving blocks to pending requests

**When it's updated**:
```cpp
// On request:
mapBlocksInFlight[hash] = {peer_id, queue_position};

// On arrival:
auto it = mapBlocksInFlight.find(hash);  // Lookup
if (it != end) { /* Block was requested, process it */ }
mapBlocksInFlight.erase(hash);  // Remove from tracking
```

**Implications for Dilithion**:
- You need similar structure to track block requests
- Must be able to identify which peer sent which block
- Must handle case where block arrives but wasn't requested (DOS)

#### 3. Stall Detection is Aggressive (2 seconds during IBD)

**The Problem**:
- Download operates on 1024-block "moving window"
- If block N is missing but blocks N+1 to N+1024 arrived, window is STALLED
- Cannot progress until block N arrives

**The Solution**:
```cpp
if (stalled_for_2_seconds) {
    disconnect_peer();
    request_blocks_from_other_peers();
    connect_to_new_peer();
}
```

**Why 2 seconds?**
- During IBD, there are millions of blocks to download
- Can't afford to wait for slow peers
- Better to aggressively rotate peers for maximum throughput

**Implications for Dilithion**:
- Need stall detection logic
- Need to track when requests were made
- Need to disconnect slow peers quickly during IBD
- Different timeout at chaintip (10-15 minutes is fine)

#### 4. QueuedBlock Tracks Per-Peer Download Queue

**Structure** (simplified after PR #22141):
```cpp
struct QueuedBlock {
    CBlockIndex* pindex;  // Pointer to block index (non-null)
    // hash removed: redundant, use pindex->GetBlockHash()
    // fValidatedHeaders removed: always true in headers-first
};
```

**Per-Peer Tracking**:
```cpp
struct CNodeState {
    std::list<QueuedBlock> vBlocksInFlight;  // Queue of blocks downloading
    int nBlocksInFlight;                     // Count
    // Limited to MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16
};
```

**Implications for Dilithion**:
- Each peer should have its own download queue
- Limit to 16 blocks per peer (DOS protection)
- Store CBlockIndex pointer (already created during headers phase)

---

## The Complete Flow (Simplified)

### PHASE 1: Headers
```
1. Request headers from peer (GETHEADERS)
2. Receive 2000 headers (HEADERS message)
3. For each header:
   - Compute hash = SHA256(SHA256(header))
   - Validate header
   - Create CBlockIndex
   - Store in mapBlockIndex[hash] = pindex
   - Mark as VALID_TREE
```

### PHASE 2: Block Requests
```
1. FindNextBlocksToDownload():
   - Find up to 16 missing blocks from this peer
   - Return list of hashes (already known from headers)

2. For each hash:
   - MarkBlockAsInFlight(hash, peer)
   - Add to mapBlocksInFlight[hash] = {peer, queue_pos}
   - Add QueuedBlock to peer->vBlocksInFlight
   - Send GETDATA with hash
   - Start stall timer
```

### PHASE 3: Block Arrival
```
1. Receive BLOCK message
2. Extract header, compute hash
3. Look up in mapBlocksInFlight:
   - If NOT found → unrequested (possible DOS)
   - If found → get peer ID
4. Look up in mapBlockIndex:
   - Get CBlockIndex* (already exists)
5. Validate block (CheckBlock, AcceptBlock)
6. Write to disk
7. MarkBlockAsReceived(hash):
   - Remove from mapBlocksInFlight
   - Remove from peer->vBlocksInFlight
   - Reset stall timer
```

### PHASE 4: Stall Detection (Parallel)
```
Every iteration:
1. Check if download window is stalled
2. If stalled:
   - Start timer
   - Wait 2 seconds
   - If still stalled → disconnect peer
   - Request blocks from other peers
   - Connect to replacement peer
```

---

## What Dilithion MUST Port

### Critical (Do This First)

1. **Headers-First Approach**
   - Download all headers before blocks
   - Create CBlockIndex on header arrival
   - Compute hash during header validation, NOT on block arrival

2. **mapBlocksInFlight Structure**
   - std::multimap for tracking requests
   - Maps hash → (peer, queue position)
   - Used for matching arrivals to requests

3. **Stall Detection**
   - 2-second timeout during IBD
   - Detect when download window cannot progress
   - Aggressively disconnect stalling peers

4. **Per-Peer Download Queue**
   - QueuedBlock structure
   - vBlocksInFlight list
   - Limit to 16 blocks per peer

5. **MarkBlockAsInFlight / MarkBlockAsReceived**
   - Clean request tracking
   - Clean arrival handling
   - Proper counter management

### Important (Do This Soon)

1. **16-Block Chunks**
   - Request 16 blocks at a time per peer
   - Proven chunk size for efficiency

2. **1024-Block Moving Window**
   - Keeps blocks close together on disk
   - Prevents fragmentation

3. **Block Locator Algorithm**
   - Efficient fork point finding
   - Last 10 blocks + exponential backoff

4. **DOS Protections**
   - Reject unrequested blocks
   - Limit in-flight blocks per peer
   - Rate limiting

### Nice to Have (Later)

1. **Compact Blocks** (BIP 152)
   - Bandwidth optimization
   - Critical for miners

2. **Adaptive Timeouts**
   - Dynamic adjustment
   - Prevent excessive disconnections

---

## Common Mistakes to Avoid

### Mistake 1: Computing Hash on Block Arrival
**Wrong**:
```cpp
// Block arrives
Block block = receive_block();
uint256 hash = compute_hash(block);  // WRONG! Too late!
```

**Right**:
```cpp
// Header arrives first
Header header = receive_header();
uint256 hash = compute_hash(header);  // Compute NOW
CBlockIndex* pindex = new CBlockIndex(hash, ...);
mapBlockIndex[hash] = pindex;

// Later: Block arrives
Block block = receive_block();
uint256 hash = get_hash_from_header(block.header);  // Just extract
auto it = mapBlocksInFlight.find(hash);  // Match to request
```

### Mistake 2: Not Tracking Requests
**Wrong**:
```cpp
// Request block
send_getdata(hash);
// No tracking!

// Block arrives
// How do we know we requested this?
// How do we know which peer sent it?
// How do we detect stalls?
```

**Right**:
```cpp
// Request block
send_getdata(hash);
mapBlocksInFlight[hash] = {peer_id, queue_pos};
start_stall_timer();

// Block arrives
auto it = mapBlocksInFlight.find(hash);
if (it == end) { /* Unrequested - DOS? */ }
else { /* Expected block, process it */ }
```

### Mistake 3: No Stall Detection
**Wrong**:
```cpp
// Request block
send_getdata(hash);

// Wait forever...
// Peer never sends block
// Download hangs indefinitely
```

**Right**:
```cpp
// Request block
send_getdata(hash);
request_time[hash] = now();

// Check periodically
if (now() - request_time[hash] > 2_seconds) {
    disconnect_peer();
    request_from_other_peer();
}
```

### Mistake 4: Single Map Instead of Multimap
**Wrong**:
```cpp
std::map<uint256, NodeId> mapBlocksInFlight;  // Only one peer per block
```

**Right**:
```cpp
std::multimap<uint256, std::pair<NodeId, ...>> mapBlocksInFlight;
// Multiple peers can download same block (redundancy)
```

---

## Performance Benefits of Headers-First

### Before (Blocks-First)
- Download 1 block at a time (serialized)
- Wait for full block before requesting next
- Slow peer blocks entire download
- ~Days to sync full chain

### After (Headers-First)
- Download all headers first (~500 MB, takes minutes)
- Then download blocks in parallel from multiple peers
- 16 blocks in flight per peer × 8 peers = 128 blocks downloading
- Stalling peer quickly replaced
- ~Hours to sync full chain

**Speedup**: 10-100x depending on peer quality

---

## Key Takeaway for Dilithion

**The #1 insight**: Block hash MUST be known before downloading the block.

This is achieved by:
1. Headers-first download (get all headers first)
2. Compute hash from header
3. Create CBlockIndex with hash
4. THEN request full block using that hash
5. When block arrives, just MATCH hash to request (no computation)

If Dilithion is computing the hash when the block arrives, the entire architecture needs to be refactored to headers-first.

---

*Summary created: 2025-12-21*
*Source: Bitcoin Core master branch analysis*
