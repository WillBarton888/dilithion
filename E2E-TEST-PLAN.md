# End-to-End Testing Plan - v1.0.16 Pre-Release
**Date:** 2025-11-20
**Purpose:** Comprehensive network testing before v1.0.16 release

---

## Test Environment

### Network Nodes
- **NYC (134.122.4.164):** 4GB RAM, FULL mode, v1.0.15 + Bug #38 fix + debug cleanup
- **Singapore (188.166.255.63):** 2GB RAM, LIGHT mode, v1.0.15 + Bug #38 fix + debug cleanup
- **London (209.97.177.197):** 2GB RAM, LIGHT mode, v1.0.15 + Bug #38 fix + debug cleanup
- **Local (Windows):** 32GB RAM, FULL mode, latest code

### Current Network State
- All nodes at height ~2-3
- All mining enabled
- Fresh blockchain (wiped after Bug #38 fix)

---

## Test Suite

### 1. Fresh Node IBD Synchronization ⏳
**Objective:** Verify Bug #38 fix allows fresh nodes to sync

**Test Steps:**
1. Start 4th test node with clean blockchain
2. Connect to seed network
3. Verify headers received
4. Verify blocks downloaded via IBD
5. Verify chain advances to current tip
6. Verify mining starts after sync

**Success Criteria:**
- ✅ Headers received with correct heights
- ✅ IBD loop triggers (headerHeight > chainHeight)
- ✅ Blocks download successfully
- ✅ Chain reaches network tip
- ✅ Node begins mining

**Status:** PENDING

---

### 2. Multi-Node Mining & Block Propagation ⏳
**Objective:** Verify blocks propagate correctly across network

**Test Steps:**
1. Monitor all 3 seed nodes
2. Wait for one node to mine a block
3. Verify block propagates to other nodes within 10s
4. Verify all nodes accept and validate block
5. Verify all nodes update chain tip
6. Repeat for 10+ blocks

**Success Criteria:**
- ✅ Blocks propagate to all peers < 10 seconds
- ✅ All nodes accept valid blocks
- ✅ No orphan blocks or chain splits
- ✅ Network maintains consensus

**Status:** PENDING

---

### 3. Transaction Creation & Propagation ⏳
**Objective:** Verify transactions work end-to-end

**Test Steps:**
1. Create new wallet address on Node A
2. Mine block to get coinbase coins
3. Create transaction sending to Node B
4. Broadcast transaction to network
5. Verify transaction in mempool on all nodes
6. Wait for transaction to be mined
7. Verify transaction in block on all nodes
8. Verify Node B receives coins

**Success Criteria:**
- ✅ Transaction broadcasts successfully
- ✅ Transaction appears in all mempools
- ✅ Transaction gets mined into block
- ✅ Recipient receives funds
- ✅ UTXO set updates correctly

**Status:** PENDING

---

### 4. Wallet Operations ⏳
**Objective:** Verify wallet functionality

**Test Steps:**
1. Create new wallet
2. Generate receiving address
3. Check balance (should be 0)
4. Mine block to receive coinbase
5. Check balance updates
6. Send transaction to another address
7. Verify balance decreases
8. Verify transaction history

**Success Criteria:**
- ✅ Wallet creation works
- ✅ Address generation works
- ✅ Balance tracking accurate
- ✅ Transaction sending works
- ✅ Transaction history correct

**Status:** PENDING

---

### 5. Network Resilience ⏳
**Objective:** Verify network handles node failures

**Test Steps:**
1. Stop one seed node (Singapore)
2. Verify other nodes continue mining
3. Let network advance 5+ blocks
4. Restart Singapore node
5. Verify Singapore syncs via IBD
6. Verify Singapore rejoins consensus

**Success Criteria:**
- ✅ Network continues with 2/3 nodes
- ✅ Restarted node syncs successfully
- ✅ Node rejoins network consensus
- ✅ No data corruption

**Status:** PENDING

---

### 6. RPC Endpoints ⏳
**Objective:** Verify all RPC methods work

**Test Methods:**
- `getblockcount` - Get current height
- `getbestblockhash` - Get tip hash
- `getblockchaininfo` - Get chain info
- `getmininginfo` - Get mining stats
- `getpeerinfo` - Get peer list
- `getconnectioncount` - Get peer count
- `getnewaddress` - Generate address
- `getbalance` - Get wallet balance
- `sendtoaddress` - Send transaction
- `listunspent` - List UTXOs
- `startmining` - Start mining
- `stopmining` - Stop mining

**Success Criteria:**
- ✅ All methods return valid responses
- ✅ No errors or crashes
- ✅ Data is accurate

**Status:** PENDING

---

### 7. Edge Cases ⏳
**Objective:** Test unusual scenarios

**Tests:**
- Orphan block handling
- Competing chain tips
- Large mempool (100+ tx)
- Rapid block discovery
- Peer misbehavior detection
- Stale block rejection

**Status:** PENDING

---

## Test Results

### Summary
- **Total Tests:** 7 test categories
- **Passed:** 0
- **Failed:** 0
- **In Progress:** 0
- **Blocked:** 0

### Critical Issues Found
_None yet_

### Non-Critical Issues Found
_None yet_

---

## Sign-Off Criteria

Before v1.0.16 release, ALL tests must:
- ✅ Pass successfully
- ✅ No critical bugs found
- ✅ Network remains stable
- ✅ No data corruption
- ✅ All RPC endpoints functional

**Approved for Release:** ⏳ TESTING IN PROGRESS

---

**Test Engineer:** Claude Code
**Start Time:** 2025-11-20 21:45 UTC
**Status:** IN PROGRESS
