# Dilithion Development - Next Steps Plan

**Date:** 2025-01-27
**Current Status:** P2P Block Relay Complete
**Branch:** `standalone-implementation`
**Latest Commit:** `6424c1d`

---

## Current Milestone: Phase 3B - P2P Block Relay ✅ COMPLETE

Successfully implemented and tested full P2P block propagation with validation.

**Completed:**
- ✅ Block serialization/deserialization
- ✅ inv/getdata/block message flow
- ✅ RandomX hash consistency
- ✅ PoW validation on receiving nodes
- ✅ Block persistence and chain tip updates
- ✅ Listener-only node support
- ✅ Two-node network testing

---

## Immediate Next Steps (Priority Order)

### 1. Multi-Node Consensus Testing (HIGH PRIORITY)

**Goal:** Verify network behavior with 3+ nodes

**Test Scenarios:**

#### A. Three-Node Network (All Mining)
```bash
# Terminal 1 - Node 1 (Miner)
./dilithion-node --testnet --mine --threads=2

# Terminal 2 - Node 2 (Miner)
./dilithion-node --testnet --datadir=.dilithion-testnet-node2 \
    --port=18445 --rpcport=18333 --mine --threads=2 \
    --connect=127.0.0.1:18444

# Terminal 3 - Node 3 (Miner)
./dilithion-node --testnet --datadir=.dilithion-testnet-node3 \
    --port=18446 --rpcport=18334 --mine --threads=2 \
    --connect=127.0.0.1:18444 --connect=127.0.0.1:18445
```

**Expected Behavior:**
- All nodes should receive blocks from all other nodes
- Occasional competing blocks at same height (normal)
- All nodes should converge to same chain tip
- Longest chain rule should resolve forks

**Acceptance Criteria:**
- [ ] All 3 nodes stay synchronized
- [ ] Blocks propagate to all peers within 1 second
- [ ] Competing blocks handled gracefully
- [ ] No crashes or database corruption
- [ ] Chain height consistent across all nodes after settling

**Deliverable:** `MULTI-NODE-CONSENSUS-TEST-RESULTS.md`

---

#### B. Network Partition and Recovery
```bash
# Start 3 nodes, let them sync
# Disconnect Node 3 from network
# Let Nodes 1 & 2 mine several blocks
# Let Node 3 mine several blocks (different chain)
# Reconnect Node 3
# Verify: Node 3 switches to longest chain
```

**Expected Behavior:**
- Node 3 should detect longer chain when reconnected
- Node 3 should request missing blocks
- Node 3 should reorganize to longer chain
- Orphaned blocks should be abandoned

**Current Limitation:** Chain reorganization NOT implemented yet
**Status:** Will likely FAIL - need to implement reorg logic

**Deliverable:** Identify specific reorg requirements

---

### 2. Chain Reorganization Implementation (CRITICAL)

**Problem:** Currently only implements "first seen" rule, not "longest chain" rule.

**Requirements:**
- Detect when received block extends competing chain
- Calculate chain work/length for all branches
- Switch to heavier chain if found
- Reorganize database to reflect new best chain
- Disconnect orphaned blocks
- Update UTXO set after reorg

**Files to Modify:**
- `src/node/blockchain_storage.h` - Add GetChainWork(), GetBlockLocator()
- `src/node/blockchain_storage.cpp` - Implement chain tracking
- `src/node/dilithion-node.cpp` - Block handler needs reorg logic
- New file: `src/consensus/chain.cpp` - Chain selection logic

**Implementation Steps:**

1. **Track Block Index Chain**
   ```cpp
   struct CBlockIndex {
       CBlockIndex* pprev;          // Pointer to previous block
       CBlockIndex* pnext;          // Pointer to next block (if on main chain)
       int nHeight;                 // Height in chain
       uint256 nChainWork;          // Total work to this block
       bool fMainChain;             // Is this block on main chain?
   };
   ```

2. **Implement Chain Selection**
   ```cpp
   bool ActivateBestChain(const CBlock& block, CBlockIndex* pindex) {
       // Find fork point
       CBlockIndex* fork = FindFork(pindex);

       // Disconnect blocks from fork to current tip
       DisconnectBlocks(fork, current_tip);

       // Connect blocks from fork to new tip
       ConnectBlocks(fork, pindex);

       // Update best block pointer
       WriteBestBlock(pindex->GetBlockHash());
   }
   ```

3. **Add Block Locator Protocol**
   ```cpp
   // Request blocks starting from our best known
   CBlockLocator locator = GetBlockLocator(current_tip);
   SendMessage(peer_id, CreateGetBlocksMessage(locator));
   ```

**Deliverable:** `CHAIN-REORG-IMPLEMENTATION.md`

**Estimated Effort:** 2-3 hours

---

### 3. Full Block Validation (SECURITY)

**Currently Missing:**
- Timestamp validation
- Merkle root verification
- Transaction validation
- Block size limits
- Signature verification

**Implementation Priority:**

#### Phase 1: Basic Validation (1 hour)
```cpp
bool ValidateBlock(const CBlock& block, const CBlockIndex* pprev) {
    // 1. Timestamp validation
    if (!CheckBlockTimestamp(block, pprev)) {
        return false;
    }

    // 2. Merkle root verification
    uint256 merkleRoot = CalculateMerkleRoot(block.vtx);
    if (merkleRoot != block.hashMerkleRoot) {
        return false;
    }

    // 3. Block size limit
    if (GetSerializeSize(block) > MAX_BLOCK_SIZE) {
        return false;
    }

    // 4. First tx must be coinbase
    if (block.vtx.empty() || !block.vtx[0].IsCoinBase()) {
        return false;
    }

    return true;
}
```

#### Phase 2: Transaction Validation (2 hours)
- Input/output validation
- Double-spend prevention
- Signature verification (Dilithium)
- Fee calculation
- Coinbase amount validation

**Files to Create:**
- `src/consensus/validation.h`
- `src/consensus/validation.cpp`

**Deliverable:** `BLOCK-VALIDATION-IMPLEMENTATION.md`

---

### 4. Transaction Relay (FEATURE)

**Goal:** Propagate unconfirmed transactions through network

**Architecture:**

```cpp
// src/node/dilithion-node.cpp

// When wallet creates transaction
void BroadcastTransaction(const CTransaction& tx) {
    uint256 txid = tx.GetHash();

    // Add to mempool
    mempool.AddTx(tx);

    // Broadcast to peers
    vector<CInv> inv;
    inv.push_back(CInv(MSG_TX_INV, txid));
    BroadcastInv(inv);
}

// Register tx message handler
message_processor.SetTxHandler([&](int peer_id, const CTransaction& tx) {
    uint256 txid = tx.GetHash();

    // Validate transaction
    if (!ValidateTransaction(tx)) {
        return;
    }

    // Add to mempool
    if (mempool.AddTx(tx)) {
        // Relay to other peers (except sender)
        RelayTransaction(tx, peer_id);
    }
});
```

**Implementation Steps:**
1. Implement TX serialization/deserialization
2. Add TX validation logic
3. Enhance mempool to track tx origin
4. Implement relay logic (don't relay back to sender)
5. Add orphan tx handling

**Deliverable:** `TX-RELAY-IMPLEMENTATION.md`

**Estimated Effort:** 3-4 hours

---

### 5. DOS Protection and Peer Management (SECURITY)

**Threats:**
- Block spam (invalid blocks)
- Inv spam (announcements for non-existent blocks)
- Connection exhaustion
- Large block attacks

**Mitigation Strategies:**

#### Peer Scoring System
```cpp
struct PeerScore {
    int valid_blocks_sent = 0;
    int invalid_blocks_sent = 0;
    int misbehavior_score = 0;

    bool ShouldBan() {
        return misbehavior_score > 100;
    }
};

// Update on invalid block
peer_scores[peer_id].invalid_blocks_sent++;
peer_scores[peer_id].misbehavior_score += 10;

if (peer_scores[peer_id].ShouldBan()) {
    BanPeer(peer_id, "Invalid blocks");
}
```

#### Rate Limiting
```cpp
struct RateLimiter {
    map<int, deque<time_t>> peer_requests;

    bool AllowRequest(int peer_id) {
        auto& times = peer_requests[peer_id];
        time_t now = time(nullptr);

        // Remove old requests (>1 minute ago)
        while (!times.empty() && times.front() < now - 60) {
            times.pop_front();
        }

        // Max 100 requests per minute
        if (times.size() >= 100) {
            return false;
        }

        times.push_back(now);
        return true;
    }
};
```

#### Connection Limits
```cpp
const int MAX_INBOUND_CONNECTIONS = 125;
const int MAX_OUTBOUND_CONNECTIONS = 8;
```

**Deliverable:** `DOS-PROTECTION-IMPLEMENTATION.md`

---

### 6. Mempool Synchronization (FEATURE)

**Goal:** Share mempool contents on connection

**Protocol:**
```
New Connection Established
    ↓
Node A: SendMessage(peer, "mempool")
    ↓
Node B: Respond with inv messages for all mempool txs
    ↓
Node A: Request missing txs with getdata
    ↓
Node B: Send tx messages
    ↓
Both nodes have synchronized mempools
```

**Implementation:**
```cpp
message_processor.SetMempoolHandler([&](int peer_id) {
    auto mempool_txs = mempool.GetAll();

    vector<CInv> inv;
    for (const auto& tx : mempool_txs) {
        inv.push_back(CInv(MSG_TX_INV, tx.GetHash()));
    }

    // Send in batches of 500
    for (size_t i = 0; i < inv.size(); i += 500) {
        auto end = min(i + 500, inv.size());
        vector<CInv> batch(inv.begin() + i, inv.begin() + end);
        SendMessage(peer_id, CreateInvMessage(batch));
    }
});
```

**Deliverable:** `MEMPOOL-SYNC-IMPLEMENTATION.md`

---

## Medium-Term Goals (1-2 Weeks)

### 7. Performance Optimization

**Targets:**
- Block validation: <5ms (currently <10ms)
- Block propagation: <50ms (currently ~100ms)
- Database writes: <2ms (currently <5ms)

**Optimization Areas:**

1. **Parallel Block Validation**
   - Validate PoW in worker thread
   - Don't block network receive thread

2. **Compact Block Relay (BIP152)**
   - Send block header + tx short IDs
   - Receiver reconstructs from mempool
   - Reduces bandwidth by ~95%

3. **Database Batching**
   - Batch write block + index + best tip
   - Reduces I/O operations

**Deliverable:** `PERFORMANCE-OPTIMIZATION-RESULTS.md`

---

### 8. Network Discovery and DNS Seeds

**Currently:** Manual `--connect` required

**Goal:** Automatic peer discovery

**Implementation:**

1. **DNS Seeds**
   ```cpp
   vector<string> dns_seeds = {
       "seed.dilithion.org",
       "seed.dilithion.network",
       "seed.dilithion.io"
   };

   for (const auto& seed : dns_seeds) {
       vector<CAddress> addrs = DNSLookup(seed);
       for (const auto& addr : addrs) {
           TryConnect(addr);
       }
   }
   ```

2. **Peer Address Exchange**
   - Implement `addr` message support
   - Persist known peers to `peers.dat`
   - Periodically request `getaddr` from peers

**Deliverable:** `PEER-DISCOVERY-IMPLEMENTATION.md`

---

### 9. Checkpoint System

**Goal:** Prevent deep chain reorganizations

**Implementation:**
```cpp
// Hardcoded checkpoints
map<int, uint256> checkpoints = {
    {0, genesis_hash},
    {1000, "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"},
    {10000, "0000000000000539a93d2c096e5a5a5f3a22a0c8b4b5e5a5e6a5e7a5e8a5e9a5"},
};

bool ValidateBlock(const CBlock& block, int height) {
    if (checkpoints.count(height)) {
        if (block.GetHash() != checkpoints[height]) {
            return error("Block rejected: checkpoint mismatch");
        }
    }
    return true;
}
```

**Deliverable:** Checkpoints added to `src/core/chainparams.cpp`

---

## Long-Term Goals (2-4 Weeks)

### 10. Wallet Transaction Creation and Broadcasting

**Current Status:** Wallet exists but cannot create transactions

**Requirements:**
- Coin selection algorithm
- Transaction building
- Fee estimation
- Change address generation
- Transaction signing (Dilithium)
- Network broadcasting

**Deliverable:** `WALLET-TX-CREATION.md`

---

### 11. RPC Interface Enhancement

**Current RPCs:** Basic (getnewaddress, getbalance)

**Needed RPCs:**
- `sendtoaddress <address> <amount>`
- `getblock <hash>`
- `getblockchaininfo`
- `getpeerinfo` (detailed)
- `addnode <node> <add|remove>`
- `getrawmempool`
- `getrawtransaction`
- `sendrawtransaction`

**Deliverable:** Full RPC API documentation

---

### 12. Block Explorer Integration

**Goal:** Web interface to explore blockchain

**Options:**
1. Custom web UI with RPC backend
2. Integrate existing explorer (Insight, BlockCypher)
3. Create REST API endpoint

**Deliverable:** Web-based block explorer

---

### 13. Testnet Public Launch Preparation

**Pre-Launch Checklist:**

- [ ] Multi-node testing complete (3+ nodes, 24+ hours)
- [ ] Chain reorganization tested
- [ ] DOS protection implemented
- [ ] Full block validation active
- [ ] Transaction relay working
- [ ] DNS seeds configured
- [ ] Checkpoint system active
- [ ] RPC interface documented
- [ ] Mining guide published
- [ ] Node setup guide published

**Launch Assets:**
- Website with downloads
- Documentation wiki
- Community Discord/Telegram
- GitHub releases
- Mining pools (optional)

**Deliverable:** `TESTNET-LAUNCH-PLAN.md`

---

## Week 2 Roadmap (Recommended)

### Day 1-2: Multi-Node Testing
- Set up 3-node local network
- Run 24-hour stress test
- Document all issues found
- Fix critical bugs

### Day 3: Chain Reorganization
- Implement block index chain tracking
- Add chain selection logic
- Test network partition scenario
- Verify reorg handles correctly

### Day 4: Block Validation
- Implement timestamp validation
- Add merkle root verification
- Test with invalid blocks
- Add block size limits

### Day 5: Transaction Relay
- Implement TX serialization
- Add TX message handlers
- Test tx propagation
- Verify mempool sync

### Day 6-7: Security Hardening
- Add DOS protection
- Implement peer scoring
- Add rate limiting
- Test attack scenarios

**Expected Output:** Production-ready testnet code

---

## Success Criteria

### Phase 3B Complete (Current)
- ✅ Blocks propagate between nodes
- ✅ PoW validation works
- ✅ Chain tips synchronized

### Phase 4 Complete (Next)
- [ ] 3+ nodes run stably for 24+ hours
- [ ] Chain reorganization handles forks
- [ ] Transactions relay successfully
- [ ] No known security vulnerabilities

### Mainnet Ready
- [ ] 1000+ blocks mined on testnet
- [ ] 10+ nodes running continuously
- [ ] Zero critical bugs in 2 weeks
- [ ] Full validation active
- [ ] DOS protection tested
- [ ] Public documentation complete

---

## Resource Requirements

**Development Time:**
- Multi-node testing: 4-6 hours
- Chain reorganization: 6-8 hours
- Full validation: 4-6 hours
- Transaction relay: 6-8 hours
- Security hardening: 8-10 hours

**Total:** ~30-40 hours for Phase 4

**Infrastructure:**
- 3-5 VPS instances for testnet nodes ($25-50/month)
- Domain for DNS seeds ($12/year)
- Website hosting ($5-10/month)

---

## Risk Assessment

### High Risk
1. **Chain reorganization bugs** - Could cause consensus failure
   - Mitigation: Extensive testing with network partitions

2. **DOS attacks** - Could take down network
   - Mitigation: Implement protection before public testnet

### Medium Risk
3. **Transaction relay bugs** - Could prevent tx propagation
   - Mitigation: Test thoroughly with multiple tx types

4. **Mempool issues** - Could cause memory leaks
   - Mitigation: Add size limits and expiration

### Low Risk
5. **Performance degradation** - Network may slow with more nodes
   - Mitigation: Profile and optimize before scaling

---

## Questions for Decision

1. **Should we implement chain reorg before or after public testnet?**
   - Before: Safer, but delays launch
   - After: Faster launch, but risk of consensus bugs

2. **Should we launch testnet with just block relay, or wait for TX relay?**
   - Just blocks: Simpler, faster
   - With TX: More complete, better testing

3. **Should we implement compact blocks (BIP152) now or later?**
   - Now: Better performance from start
   - Later: Simpler initial implementation

4. **Do we need mining pools for testnet?**
   - Yes: More realistic testing
   - No: Additional complexity

---

## Recommended Next Action

**Start with:** Multi-node consensus testing (3 nodes, 24 hours)

**Rationale:**
- Validates current implementation under realistic conditions
- Will reveal any hidden bugs in P2P relay
- Provides data for prioritizing next features
- Low risk, high value

**Command to run:**
```bash
# See test scenario in section 1.A above
# Monitor for 24 hours
# Document any issues in MULTI-NODE-TEST-RESULTS.md
```

---

**Status:** Ready to proceed with Phase 4
**Next Milestone:** Multi-node consensus verified
**Target:** Week 2 Public Testnet Launch

🤖 Generated with Claude Code
