# Bitcoin Core IBD Block Request Flow Research

## Research Summary
This document analyzes Bitcoin Core's Initial Block Download (IBD) implementation, focusing on block request/arrival flow, stall detection, and key data structures.

---

## 1. Block Request Flow (net_processing.cpp)

### 1.1 FindNextBlocksToDownload()

**Purpose**: Identifies the next blocks to download from a peer during IBD.

**Key Behavior**:
- Uses headers-first approach: downloads all headers first (80 bytes each), then downloads full blocks in parallel
- Operates on a "moving window" of 1024 blocks at a time
- Checks that peer's best known block has enough chain work before proceeding
- Uses block locator algorithm to find fork point efficiently (last 10 blocks, then exponential backoff)
- Requests blocks in chunks of 16 blocks per peer (MAX_BLOCKS_IN_TRANSIT_PER_PEER)
- With AssumeUtxo: aborts if snapshot isn't in peer's best chain (missing undo data)

**Evolution**:
- v0.19.0: Was a static function taking NodeId directly
- Current (master): Member of PeerManagerImpl class, uses helper function FindNextBlocks

**Code Location**: Line ~1038 in net_processing.cpp (master branch)

**How it Works**:
```cpp
// Pseudocode flow:
1. Check peer->pindexBestKnownBlock has sufficient chain work
2. Use block locator to find last common block with peer
3. Walk forward from common block, checking:
   - Block not already in mapBlocksInFlight
   - Block not already on disk
   - Block is next in sequence (maintaining 1024-block window)
4. Add up to 16 blocks to download queue
5. Return list of blocks to request
```

### 1.2 MarkBlockAsInFlight() / BlockRequested()

**Note**: Function was renamed from MarkBlockAsInFlight to BlockRequested in recent versions.

**Purpose**: Tracks blocks that have been requested from peers and are currently "in flight".

**Implementation**:
```cpp
// Location: net_processing.cpp
// Called when sending GETDATA for blocks

Key steps:
1. First calls MarkBlockAsReceived(hash) to ensure no duplicate tracking
2. Creates QueuedBlock entry with:
   - CBlockIndex* pindex (non-null, always)
   - fValidatedHeaders (always true in headers-first)
   - Optional PartiallyDownloadedBlock for compact blocks
3. Inserts QueuedBlock into peer's vBlocksInFlight list
4. Updates mapBlocksInFlight: mapBlocksInFlight[hash] = {nodeid, iterator}
5. Increments nBlocksInFlightValidHeaders counter
```

**DOS Protection**:
- Prevents excessive block requests if peer already has MAX_BLOCKS_IN_TRANSIT_PER_PEER (16) active downloads
- Prevents bogus inv spam from inflating vBlocksInFlight and mapBlocksInFlight

**Bug History**:
- PR #9549: Fixed potential NULL pointer dereference when optional pit parameter was NULL

---

## 2. Block Arrival Flow

### 2.1 Block Hash Already Known Before Arrival

**Critical Insight**: In headers-first mode, Bitcoin Core ALWAYS knows the block hash before requesting the block.

**Why?**
1. Headers are downloaded first (all 80-byte headers from genesis to tip)
2. Each header is validated and creates a CBlockIndex entry
3. CBlockIndex is stored in mapBlockIndex with block hash as key
4. Block hash is computed from header: SHA256(SHA256(80-byte header))
5. Only THEN are full blocks requested using those known hashes

**Header Processing**:
```
1. Receive HEADERS message from peer
2. Stream into vector of CBlockHeaders
3. For each header:
   - Compute hash: SHA256(SHA256(header))
   - CheckBlockHeader (non-contextual validation)
   - ContextualCheckBlockHeader (blockchain-aware validation)
   - Create CBlockIndex with hash, store in mapBlockIndex
   - Mark as VALID_TREE (on valid chain, but no tx data yet)
4. Update pindexBestKnownBlock, pindexBestHeaderSent
```

**Block Request Using Known Hash**:
```
1. FindNextBlocksToDownload() selects hashes from CBlockIndex entries
2. Send GETDATA message with known block hashes (up to 16)
3. Peer responds with BLOCK message
4. Node uses hash to look up CBlockIndex in mapBlockIndex
5. Match incoming block to pending request
```

### 2.2 Block Message Processing

**Entry Point**: ProcessMessage() in net_processing.cpp handles "BLOCK" messages

**Flow**:
```cpp
ProcessMessage("BLOCK") →
  Check block was requested (DOS protection) →
  Compute hash from received block header →
  Look up CBlockIndex using hash →
  Match against mapBlocksInFlight →
  ProcessNewBlock() →
    CheckBlock() (non-contextual validation) →
    AcceptBlock() (contextual validation + write to disk) →
      WriteBlockToDisk() →
      MarkBlockAsReceived() (remove from mapBlocksInFlight) →
    ActivateBestChain() (connect to chain, update UTXO)
```

**Key Points**:
- Hash is computed immediately when block arrives
- Hash matches CBlockIndex already in mapBlockIndex
- Unrequested blocks may indicate DOS attack (but not necessarily)
- Blocks written to disk in AcceptBlock as soon as received
- MarkBlockAsReceived updates tracking structures

### 2.3 MarkBlockAsReceived() / RemoveBlockRequest()

**Note**: Renamed from MarkBlockAsReceived to RemoveBlockRequest in recent versions.

**Purpose**: Remove block from in-flight tracking when received.

**Implementation**:
```cpp
bool MarkBlockAsReceived(uint256 hash) {
    // Look up in mapBlocksInFlight
    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        return false; // Not requested
    }

    NodeId nodeid = it->second.first;
    auto block_it = it->second.second;
    CNodeState* state = State(nodeid);

    // Update counters
    state->nBlocksInFlightValidHeaders--;
    state->nBlocksInFlight--;
    state->nStallingSince = 0; // Reset stall timer

    // Remove from vBlocksInFlight list
    state->vBlocksInFlight.erase(block_it);

    // Remove from mapBlocksInFlight
    mapBlocksInFlight.erase(it);

    return true; // Was in flight
}
```

---

## 3. Stall Detection

### 3.1 BLOCK_STALL_TIMEOUT

**Value**: 2 seconds (during IBD)

**Purpose**: Detect when a peer is stalling block download and preventing the moving window from advancing.

**How Stalling is Detected**:
```
Stalling occurs when:
1. Node cannot connect new blocks past current tip
   Example: tip is height i, blocks [i+2..i+1024] arrived, but block i+1 missing
2. Cannot make more requests (all 1024 window blocks received or in-flight)
3. Peer has not delivered requested block(s) for 2+ seconds
```

**Stall Detection Logic**:
```cpp
if (state.m_stalling_since.count() &&
    state.m_stalling_since < current_time - stalling_timeout) {
    // Peer has stalled for too long - disconnect
    // Node will request blocks from other peers
    // Connect to new peer to replace dropped one
}
```

**Timeout Values**:
- **During IBD**: 2 seconds stall timeout (aggressive)
- **At chaintip**: 10-15 minutes timeout (conservative)

**Why Different Timeouts?**
- IBD: Many blocks to download, need fast progress, can quickly switch peers
- Chaintip: Waiting for newly mined blocks, must be patient

### 3.2 BlockDownloadTimedOut()

**Purpose**: Check if block download from a peer has timed out.

**Related Logic**:
```cpp
// Stalling only triggers when download window cannot move
// During steady state, window is larger than to-be-downloaded set
// So disconnection should only happen during IBD

Behavior:
1. Start stalling_since timer when bottleneck detected
2. Give peer 2 more seconds to fulfill request(s)
3. If timeout expires:
   - Disconnect stalling peer
   - Request blocks from other connected peers
   - Connect to new peer to replace dropped one
```

**Dynamic Timeout Adjustment**:
- Timeout can be doubled during problematic conditions
- Slowly reduced back to default value over time

### 3.3 Known Issues and Mitigations

**CVE-2024-52922** (Medium severity):
- Before v25.1: Attacker could prevent node from downloading latest block
- Mitigation (v26.0, backported to v25.1): Blocks can be requested from up to 3 high-bandwidth compact block peers concurrently, including 1 required outbound connection

**Frequent Timeouts** (Issue #27705):
- 10-minute timeout at chaintip can cause significant stalls
- Problematic for solo mining (high orphan rate risk)
- Adaptive timeout feature being developed (PR #25880)

---

## 4. Key Data Structures

### 4.1 mapBlocksInFlight

**Type**: `std::multimap<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator>>`

**Alias**: `typedef ... BlockDownloadMap`

**Protected By**: `cs_main` mutex

**Purpose**:
- Map block hashes to downloading peer and queue position
- Multimap allows same block to be requested from multiple peers (redundancy)
- Used to match arriving blocks to pending requests

**Structure**:
```cpp
Key: uint256 (block hash)
Value: pair<NodeId, list<QueuedBlock>::iterator>
       - NodeId: Which peer is downloading this block
       - iterator: Position in peer's vBlocksInFlight queue
```

**Evolution**:
- v0.19.0: Was `std::map` (single peer per block)
- Current: `std::multimap` (allows parallel downloads from multiple peers)

**Operations**:
```cpp
// Insert when marking block in flight
mapBlocksInFlight[hash] = {nodeid, queue_iterator};

// Lookup when block arrives
auto it = mapBlocksInFlight.find(hash);
if (it != mapBlocksInFlight.end()) {
    // Block was requested, process it
}

// Remove when block received
mapBlocksInFlight.erase(hash);

// Check range for specific block
auto range = mapBlocksInFlight.equal_range(hash);
for (auto it = range.first; it != range.second; ++it) {
    // Handle multiple peers downloading same block
}
```

**Properties**:
- Only grows and shrinks (never leaked)
- Must be empty when all peer states are erased
- Checked for emptiness in stall detection logic

### 4.2 QueuedBlock Struct

**Original Definition** (before PR #22141):
```cpp
struct QueuedBlock {
    uint256 hash;                    // Block hash
    CBlockIndex* pindex;             // Block index (optional)
    bool fValidatedHeaders;          // Headers validated?
};
```

**Simplified Definition** (after PR #22141):
```cpp
struct QueuedBlock {
    CBlockIndex* pindex;  // Always non-null in headers-first
    // hash removed: redundant, pindex->GetBlockHash() available
    // fValidatedHeaders removed: always true in headers-first
};
```

**Rationale for Simplification**:
- Headers-first syncing means we ALWAYS validate headers before requesting blocks
- Therefore fValidatedHeaders is always true (redundant)
- Block hash is stored in CBlockIndex, so separate hash field is redundant

**Usage**:
- Stored in per-peer vBlocksInFlight list
- Tracks blocks this peer is currently downloading
- Limited to MAX_BLOCKS_IN_TRANSIT_PER_PEER (16) entries

### 4.3 CBlockIndex

**Purpose**: In-memory representation of a block header (may or may not have full block data on disk)

**Storage**: mapBlockIndex (map<uint256, CBlockIndex*>)

**Lifecycle**:
```
1. HEADERS message arrives
2. Validate header (CheckBlockHeader, ContextualCheckBlockHeader)
3. Create CBlockIndex with:
   - Block hash (computed from header)
   - Previous block hash
   - Height
   - Chain work
   - Validation status (initially VALID_TREE)
4. Insert into mapBlockIndex
5. Later: Download full block, validate, mark VALID_TRANSACTIONS
6. Later: Connect to chain, mark VALID_CHAIN
```

**Properties**:
- mapBlockIndex only grows, never shrinks (no erase operations)
- Contains ALL known blocks (superset of active chain)
- Includes orphaned blocks from small reorgs
- Block index exists BEFORE full block is downloaded
- Stores metadata: height, chainwork, file position, validation status

**Validation States**:
- VALID_TREE: Header validated, on valid chain, no tx data yet
- VALID_TRANSACTIONS: Full block downloaded and validated
- VALID_CHAIN: Block connected to active chain
- VALID_SCRIPTS: All scripts verified
- (States cumulative: VALID_CHAIN implies VALID_TRANSACTIONS implies VALID_TREE)

### 4.4 CNodeState

**Purpose**: Per-peer state tracking for block download

**Key Fields**:
```cpp
struct CNodeState {
    // Best known block
    CBlockIndex* pindexBestKnownBlock;
    CBlockIndex* pindexBestHeaderSent;
    uint256 hashLastUnknownBlock;

    // In-flight blocks
    std::list<QueuedBlock> vBlocksInFlight;
    int nBlocksInFlight;
    int nBlocksInFlightValidHeaders;

    // Stall detection
    std::chrono::microseconds m_stalling_since;
    int64_t nStallingSince;  // Legacy field

    // Download tracking
    int64_t nDownloadingSince;
    int nBlocksInFlightValidHeaders;
};
```

**Functions**:
- `ProcessBlockAvailability(NodeId)`: Update what blocks peer has
- `UpdateBlockAvailability(NodeId, hash)`: Mark peer as having block
- `PeerHasHeader(pindex)`: Check if peer has specific header

---

## 5. Critical Path: Request → Arrival → Process

### Complete Flow Diagram

```
STEP 1: HEADERS PHASE
├─ Peer announces headers (HEADERS message)
├─ Node receives 2000 headers at a time
├─ For each header:
│  ├─ Compute hash = SHA256(SHA256(header))
│  ├─ CheckBlockHeader (PoW, timestamp, etc)
│  ├─ ContextualCheckBlockHeader (prev hash, height, etc)
│  ├─ Create CBlockIndex
│  ├─ Insert into mapBlockIndex[hash] = pindex
│  └─ Mark as VALID_TREE
└─ Update pindexBestKnownBlock

STEP 2: BLOCK REQUEST PHASE
├─ FindNextBlocksToDownload(peer)
│  ├─ Check peer has sufficient chain work
│  ├─ Use block locator to find common block
│  ├─ Walk forward, find up to 16 missing blocks
│  └─ Return list of block hashes to request
├─ For each block hash:
│  ├─ MarkBlockAsInFlight(hash, peer)
│  │  ├─ Create QueuedBlock{pindex}
│  │  ├─ Add to peer->vBlocksInFlight
│  │  ├─ Insert into mapBlocksInFlight[hash] = {peer, iterator}
│  │  └─ Increment nBlocksInFlight counter
│  └─ Send GETDATA message with hash
└─ Start stall timer

STEP 3: BLOCK ARRIVAL PHASE
├─ Receive BLOCK message from peer
├─ Extract 80-byte header from message
├─ Compute hash = SHA256(SHA256(header))
├─ Look up in mapBlocksInFlight.find(hash)
│  ├─ If not found: unrequested block (possible DOS)
│  └─ If found: extract NodeId and queue iterator
├─ Look up in mapBlockIndex.find(hash)
│  └─ Get CBlockIndex* pindex (already exists from headers phase)
├─ ProcessNewBlock(pblock)
│  ├─ CheckBlock() - non-contextual validation
│  │  ├─ Check merkle root
│  │  ├─ Check transactions valid
│  │  └─ Check block size limits
│  ├─ AcceptBlock() - contextual validation
│  │  ├─ Check connects to known chain (prev hash)
│  │  ├─ Check timestamp rules
│  │  ├─ Check difficulty target
│  │  ├─ WriteBlockToDisk() - save to blk?????.dat
│  │  └─ Update pindex state to VALID_TRANSACTIONS
│  └─ ActivateBestChain()
│     ├─ Connect block to active chain
│     ├─ Update UTXO set
│     └─ Mark pindex as VALID_CHAIN
├─ MarkBlockAsReceived(hash)
│  ├─ Remove from mapBlocksInFlight
│  ├─ Remove from peer->vBlocksInFlight
│  ├─ Decrement nBlocksInFlight
│  └─ Reset stall timer (nStallingSince = 0)
└─ Continue with next block

STEP 4: STALL DETECTION (parallel monitoring)
├─ Every iteration, check if download window stalled
├─ If stalled:
│  ├─ Start stalling_since timer
│  └─ Wait 2 seconds
├─ If timer expires:
│  ├─ Disconnect stalling peer
│  ├─ Request blocks from other peers
│  └─ Connect to replacement peer
└─ Loop
```

### Key Insights

1. **Hash is Known Before Download**: Headers-first means block hash is ALWAYS computed from header before requesting full block. No need to compute hash when block arrives - just verify it matches.

2. **Two Hash Computations**:
   - First: When header arrives (HEADERS phase)
   - Second: When block arrives (verification that header matches block)

3. **CBlockIndex is Central**: Created during headers phase, used to track everything:
   - Block metadata (height, chainwork)
   - Validation state progression
   - Disk storage location
   - Referenced by mapBlocksInFlight

4. **Matching is Simple**: When block arrives:
   - Compute hash from block header
   - Look up in mapBlocksInFlight (was it requested?)
   - Look up in mapBlockIndex (get metadata)
   - Match!

5. **Stall Detection is Aggressive During IBD**: 2-second timeout ensures fast peer rotation if download stalls. Critical for maintaining download speed.

6. **Parallel Downloads**: multimap allows requesting same block from multiple peers, improving redundancy and speed (especially with compact blocks).

---

## 6. Comparison: Bitcoin Core vs Dilithion

### What Dilithion Should Port

**High Priority**:
1. **Headers-first approach**: Download all headers, then blocks in parallel
2. **mapBlocksInFlight tracking**: Robust request/response matching
3. **QueuedBlock structure**: Clean per-peer download queue
4. **Stall detection with 2-second timeout**: Fast peer rotation during IBD
5. **CBlockIndex early creation**: Create index on header arrival, not block arrival
6. **16-block chunks per peer**: Proven chunk size for efficient downloads
7. **1024-block moving window**: Keeps blocks close together on disk

**Medium Priority**:
1. **Block locator algorithm**: Efficient fork point finding
2. **Adaptive timeout**: Double timeout on issues, slowly reduce
3. **DOS protections**: Limit in-flight blocks, reject unrequested blocks
4. **Parallel peer downloads**: Use multimap to request from multiple peers

**Lower Priority**:
1. **Compact blocks**: Optimization for bandwidth (BIP 152)
2. **AssumeUtxo support**: Advanced feature, not needed initially

### Critical Differences

| Feature | Bitcoin Core | Dilithion Current | Should Port? |
|---------|--------------|-------------------|--------------|
| Headers-first | Yes | Partial? | YES |
| Hash known before download | Yes (from headers) | No (computed on arrival?) | YES |
| mapBlocksInFlight | std::multimap | ? | YES |
| QueuedBlock struct | Yes | ? | YES |
| Stall timeout | 2s during IBD | ? | YES |
| Block chunks | 16 per peer | ? | YES |
| Moving window | 1024 blocks | ? | YES |
| CBlockIndex early creation | On header arrival | On block arrival? | YES |

---

## 7. Sources

### Bitcoin Core Documentation
- [Bitcoin Core net_processing.cpp (master)](https://github.com/bitcoin/bitcoin/blob/master/src/net_processing.cpp)
- [Bitcoin Core 0.11 Initial Block Download](https://en.bitcoin.it/wiki/Bitcoin_Core_0.11_(ch_5):_Initial_Block_Download)
- [Block Relay - Bitcoin Core Onboarding](https://bitcoincore.academy/block-relay.html)

### GitHub Issues and Pull Requests
- [PR #8872: Remove block-request logic from INV message processing](https://github.com/bitcoin/bitcoin/pull/8872)
- [PR #22141: Remove hash and fValidatedHeaders from QueuedBlock](https://github.com/bitcoin/bitcoin/pull/22141)
- [PR #9549: Avoid NULL pointer dereference in MarkBlockAsInFlight](https://github.com/bitcoin/bitcoin/pull/9549)
- [Issue #27705: Frequent "Timeout downloading block" with 24.1](https://github.com/bitcoin/bitcoin/issues/27705)
- [PR #25880: Make stalling timeout adaptive during IBD](https://bitcoincore.reviews/25880)
- [CVE-2024-52922: Hindered block propagation due to stalling peers](https://bitcoincore.org/en/2024/11/05/cb-stall-hindering-propagation/)

### Commits
- [aa81564: Track peers' available blocks](https://github.com/bitcoin/bitcoin/commit/aa81564)
- [304892f: Be stricter in processing unrequested blocks](https://github.com/bitcoin/bitcoin/commit/304892f)
- [b33ca14: Merge #9549](https://github.com/bitcoin/bitcoin/commit/b33ca14)

### Developer Resources
- [P2P Network - Bitcoin Developer Guide](https://developer.bitcoin.org/devguide/p2p_network.html)
- [Block Chain - Bitcoin Developer Reference](https://developer.bitcoin.org/reference/block_chain.html)
- [Protocol Documentation - Bitcoin Wiki](https://en.bitcoin.it/wiki/Protocol_documentation)
- [Bitcoin Core Validation Features](https://bitcoin.org/en/bitcoin-core/features/validation)

### Code Review
- [Bitcoin Core PR Review Club - ProcessNewBlock](https://bitcoincore.reviews/16279)
- [Bitcoin Core PR Review Club - Adaptive IBD timeout](https://bitcoincore.reviews/25880)

### Educational Resources
- [Mastering Bitcoin - Chapter 7: The Blockchain](https://www.oreilly.com/library/view/mastering-bitcoin/9781491902639/ch07.html)
- [Learn Me a Bitcoin - Block Hash](https://learnmeabitcoin.com/technical/block/hash/)
- [Bitcoin Core Data Storage](https://en.bitcoin.it/wiki/Bitcoin_Core_0.11_(ch_2):_Data_Storage)

---

## 8. Recommendations for Dilithion

### Immediate Actions

1. **Implement Headers-First Download**
   - Port FindNextBlocksToDownload logic
   - Ensure CBlockIndex created on header arrival
   - Compute and store block hash during header validation
   - Only request full blocks after headers validated

2. **Port mapBlocksInFlight Structure**
   - Use std::multimap for redundancy
   - Track NodeId and queue position
   - Match arriving blocks by hash lookup

3. **Add QueuedBlock Tracking**
   - Per-peer vBlocksInFlight queue
   - Limit to 16 blocks in flight per peer
   - Store CBlockIndex pointer (already known)

4. **Implement Stall Detection**
   - 2-second timeout during IBD
   - Disconnect stalling peers
   - Request blocks from other peers immediately

5. **Add MarkBlockAsInFlight / MarkBlockAsReceived**
   - Clean request/response tracking
   - Proper counter management
   - Stall timer reset on block arrival

### Testing Priorities

1. **Multi-Peer Scenarios**
   - 3+ peers downloading in parallel
   - Peer disconnection during download
   - Stalling peer detection and replacement

2. **Edge Cases**
   - Unrequested blocks (DOS attempt)
   - Duplicate block requests
   - Out-of-order block arrival

3. **Performance**
   - IBD speed with headers-first vs blocks-first
   - Memory usage with 1024-block window
   - Disk I/O patterns (blocks close together)

### Long-Term Enhancements

1. **Compact Blocks** (BIP 152)
   - Bandwidth optimization
   - Critical for mining efficiency

2. **Adaptive Timeouts**
   - Dynamic adjustment based on network conditions
   - Prevent excessive disconnections

3. **Advanced DOS Protections**
   - Rate limiting
   - Peer scoring
   - Eclipse attack prevention

---

*Research completed: 2025-12-21*
*Bitcoin Core version analyzed: master branch (latest)*
*Researcher: Claude Code (Sonnet 4.5)*
