# Phase 5 Implementation Roadmap: Transaction System
**Dilithion Post-Quantum Cryptocurrency**
**Status:** Planning / Not Started
**Timeline:** 1-2 weeks (40-60 development hours)
**Priority:** CRITICAL - Required before any public launch

---

## Executive Summary

Phase 5 completes the Dilithion cryptocurrency by implementing the full transaction system, enabling users to send and receive coins. Without this functionality, Dilithion is mining-only and cannot function as a usable cryptocurrency.

**Current Status:** Phase 4 Complete
- ✅ Mining & PoW Consensus
- ✅ P2P Networking
- ✅ Block Relay
- ✅ Chain Reorganization
- ❌ Transaction System (Phase 5)

---

## 1. Architecture Overview

### 1.1 Transaction Flow
```
Wallet → Create TX → Sign (Dilithium) → Mempool → Relay → Block → Validation → UTXO Update
```

### 1.2 Core Components Required

1. **Transaction Structure** (`src/primitives/transaction.h/cpp`)
   - Input/Output definitions
   - Dilithium signature integration
   - Serialization/deserialization

2. **Transaction Validation** (`src/consensus/validation.h/cpp`)
   - Signature verification (post-quantum)
   - UTXO checking
   - Double-spend prevention
   - Script validation

3. **UTXO Database** (`src/node/utxo_set.h/cpp`)
   - LevelDB-based UTXO storage
   - Efficient lookup/updates
   - Rollback support (for reorgs)

4. **Mempool Enhancement** (`src/node/mempool.h/cpp`)
   - Transaction pool management
   - Fee prioritization
   - Conflict detection
   - Eviction policies

5. **Wallet Send/Receive** (`src/wallet/wallet.h/cpp`)
   - UTXO selection (coin selection)
   - Transaction construction
   - Change address handling
   - Balance calculation from UTXO set

6. **P2P Transaction Relay** (`src/net/net.h/cpp`)
   - MSG_TX_INV handling
   - Transaction flooding prevention
   - Orphan transaction handling

7. **RPC Endpoints** (`src/rpc/server.h/cpp`)
   - `sendtoaddress`
   - `listtransactions`
   - `gettransaction`
   - `getrawmempool`

---

## 2. Detailed Implementation Plan

### Phase 5.1: Transaction Core (Week 1, Days 1-3)
**Estimated Time:** 15-20 hours

#### 5.1.1 Transaction Data Structures
**Files:** `src/primitives/transaction.h`, `src/primitives/transaction.cpp`

**Tasks:**
- [ ] Define `CTxIn` structure (outpoint + Dilithium signature)
- [ ] Define `CTxOut` structure (value + scriptPubKey)
- [ ] Define `CTransaction` structure (inputs + outputs + metadata)
- [ ] Implement serialization/deserialization
- [ ] Add Dilithium signature placeholder integration
- [ ] Create transaction hash calculation (for txid)

**Deliverable:** Complete transaction data structures with tests

#### 5.1.2 UTXO Database
**Files:** `src/node/utxo_set.h`, `src/node/utxo_set.cpp`

**Tasks:**
- [ ] Design UTXO database schema (LevelDB)
- [ ] Implement `CUTXOSet` class
- [ ] Add `GetUTXO(COutPoint)` lookup
- [ ] Add `AddUTXO()` and `SpendUTXO()` operations
- [ ] Implement batch updates (for blocks)
- [ ] Add rollback support (for chain reorgs)
- [ ] Create UTXO consistency checks

**Deliverable:** Functional UTXO database with persistence

#### 5.1.3 Transaction Validation
**Files:** `src/consensus/validation.h`, `src/consensus/validation.cpp`

**Tasks:**
- [ ] Implement `ValidateTransaction()` function
- [ ] Add Dilithium signature verification integration
- [ ] Implement UTXO existence checking
- [ ] Add double-spend detection
- [ ] Implement basic script validation (P2PKH for now)
- [ ] Add transaction fee calculation
- [ ] Create comprehensive validation tests

**Deliverable:** Secure transaction validation system

---

### Phase 5.2: Wallet Integration (Week 1, Days 4-5)
**Estimated Time:** 12-15 hours

#### 5.2.1 Wallet UTXO Management
**Files:** `src/wallet/wallet.h`, `src/wallet/wallet.cpp`

**Tasks:**
- [ ] Track wallet UTXOs (scan blockchain on startup)
- [ ] Implement `GetBalance()` from UTXO set (not placeholder)
- [ ] Add `ListUnspent()` functionality
- [ ] Implement UTXO caching for performance
- [ ] Add transaction history tracking

**Deliverable:** Wallet can track real balance from UTXOs

#### 5.2.2 Transaction Creation
**Files:** `src/wallet/wallet.cpp`

**Tasks:**
- [ ] Implement coin selection algorithm (simple greedy for v1.0)
- [ ] Create `CreateTransaction(recipient, amount)` function
- [ ] Add change address generation and handling
- [ ] Implement transaction signing with Dilithium keys
- [ ] Add fee estimation (fixed fee for v1.0, dynamic later)
- [ ] Handle insufficient balance errors

**Deliverable:** Wallet can create and sign transactions

#### 5.2.3 Transaction Broadcasting
**Files:** `src/wallet/wallet.cpp`

**Tasks:**
- [ ] Implement `SendTransaction()` function
- [ ] Add to local mempool
- [ ] Trigger P2P relay (announce via INV)
- [ ] Add send confirmation/error handling

**Deliverable:** Wallet can broadcast transactions to network

---

### Phase 5.3: Mempool & Relay (Week 2, Days 1-2)
**Estimated Time:** 10-12 hours

#### 5.3.1 Mempool Enhancement
**Files:** `src/node/mempool.h`, `src/node/mempool.cpp`

**Tasks:**
- [ ] Implement `AddTransaction()` with validation
- [ ] Add conflict detection (same input spending)
- [ ] Implement fee-based prioritization
- [ ] Add mempool size limits and eviction
- [ ] Create `RemoveTransaction()` (for blocks)
- [ ] Implement `GetTransactionsForBlock()` for mining

**Deliverable:** Production-ready mempool

#### 5.3.2 P2P Transaction Relay
**Files:** `src/net/net.cpp`, `src/node/dilithion-node.cpp`

**Tasks:**
- [ ] Implement `MSG_TX_INV` message handling
- [ ] Add transaction request/response (GETDATA/TX)
- [ ] Implement transaction flooding prevention (seen cache)
- [ ] Add orphan transaction handling (parent not yet received)
- [ ] Create relay propagation logic

**Deliverable:** Transactions propagate across network

---

### Phase 5.4: Mining Integration (Week 2, Day 3)
**Estimated Time:** 6-8 hours

#### 5.4.1 Block Template with Transactions
**Files:** `src/miner/controller.h`, `src/miner/controller.cpp`

**Tasks:**
- [ ] Modify `CreateBlockTemplate()` to include mempool transactions
- [ ] Implement transaction ordering (fee prioritization)
- [ ] Add block size limit enforcement
- [ ] Calculate and include transaction fees in coinbase
- [ ] Update merkle root calculation for multiple transactions

**Deliverable:** Blocks include real transactions from mempool

#### 5.4.2 Block Validation with Transactions
**Files:** `src/consensus/chain.cpp`

**Tasks:**
- [ ] Add transaction validation to `ConnectTip()`
- [ ] Implement UTXO set updates when connecting blocks
- [ ] Add UTXO rollback when disconnecting blocks (reorg)
- [ ] Update mempool when blocks are connected (remove included TXs)

**Deliverable:** Full block validation with transaction processing

---

### Phase 5.5: RPC Implementation (Week 2, Day 4)
**Estimated Time:** 5-7 hours

#### 5.5.1 Transaction RPC Methods
**Files:** `src/rpc/server.h`, `src/rpc/server.cpp`

**Tasks:**
- [ ] Implement `RPC_SendToAddress()` (send coins)
- [ ] Implement `RPC_ListTransactions()` (transaction history)
- [ ] Implement `RPC_GetTransaction()` (TX details)
- [ ] Implement `RPC_GetRawMempool()` (mempool contents)
- [ ] Implement `RPC_GetRawTransaction()` (raw TX hex)
- [ ] Update `RPC_GetBalance()` to use real UTXO calculation

**Deliverable:** Complete RPC interface for transactions

---

### Phase 5.6: Testing & Security Review (Week 2, Days 5-7)
**Estimated Time:** 12-15 hours

#### 5.6.1 Unit Tests
**Tasks:**
- [ ] Transaction serialization/deserialization tests
- [ ] UTXO database tests
- [ ] Transaction validation tests
- [ ] Coin selection tests
- [ ] Mempool tests

#### 5.6.2 Integration Tests
**Tasks:**
- [ ] Single-node send/receive test
- [ ] Multi-node transaction relay test
- [ ] Mempool propagation test
- [ ] Mining with transactions test
- [ ] Chain reorg with transactions test (UTXO rollback)

#### 5.6.3 Security Review
**Tasks:**
- [ ] Double-spend attack testing
- [ ] Signature verification security audit
- [ ] UTXO database integrity checks
- [ ] Mempool DoS prevention review
- [ ] Transaction flooding attack testing

**Deliverable:** Comprehensive test suite + security audit report

---

## 3. Dependencies & Prerequisites

### 3.1 External Dependencies
- LevelDB (already integrated for block storage)
- Dilithium signature library (already integrated)
- RocksDB or LevelDB for UTXO set (LevelDB recommended for consistency)

### 3.2 Internal Prerequisites
- ✅ Block structure and storage (Phase 4)
- ✅ P2P networking (Phase 4)
- ✅ Wallet key management (Phase 3)
- ✅ Mining controller (Phase 4)

---

## 4. Risk Assessment

### 4.1 High-Risk Areas
1. **UTXO Database Consistency**
   - Risk: Corruption during reorgs
   - Mitigation: Extensive testing, atomic operations

2. **Double-Spend Prevention**
   - Risk: Mempool conflicts not detected
   - Mitigation: Comprehensive conflict detection, security audit

3. **Dilithium Signature Integration**
   - Risk: Signature verification failures
   - Mitigation: Extensive signature testing, test vectors

4. **Performance**
   - Risk: Large Dilithium signatures slow down validation
   - Mitigation: Signature caching, batch verification

### 4.2 Medium-Risk Areas
1. **Mempool DoS**
   - Risk: Attackers flood mempool with invalid TXs
   - Mitigation: Rate limiting, validation before relay

2. **Fee Estimation**
   - Risk: Fixed fees may not scale
   - Mitigation: Start simple, plan for dynamic fees in Phase 6

---

## 5. Testing Strategy

### 5.1 Test Phases
1. **Unit Tests** (throughout development)
2. **Integration Tests** (after each sub-phase)
3. **Network Tests** (3-node minimum)
4. **Security Tests** (dedicated security review)
5. **Stress Tests** (high transaction volume)

### 5.2 Test Scenarios
- Send transaction between two wallets
- Multiple senders to same recipient
- Multiple recipients in one transaction
- Transaction relay across 3+ nodes
- Block creation with 10+ transactions
- Chain reorg with transactions (UTXO rollback verification)
- Mempool full scenarios
- Double-spend attempts (should all fail)

---

## 6. Documentation Requirements

### 6.1 Technical Documentation
- [ ] Transaction format specification
- [ ] UTXO database schema documentation
- [ ] API documentation for wallet functions
- [ ] RPC endpoint documentation

### 6.2 User Documentation
- [ ] How to send coins (RPC examples)
- [ ] How to check balance and transaction history
- [ ] Understanding transaction fees

### 6.3 Security Documentation
- [ ] Security audit report
- [ ] Known limitations and future improvements
- [ ] Best practices for wallet usage

---

## 7. Success Criteria

Phase 5 is complete when:
- [ ] All code implementation tasks completed
- [ ] All unit tests passing
- [ ] All integration tests passing
- [ ] 3-node network test successfully sends/receives transactions
- [ ] Security review completed with no critical issues
- [ ] Documentation complete
- [ ] Full build with zero errors
- [ ] Comprehensive test report generated

---

## 8. Timeline Summary

| Phase | Description | Duration | Status |
|-------|-------------|----------|--------|
| 5.1 | Transaction Core | 3 days | Not Started |
| 5.2 | Wallet Integration | 2 days | Not Started |
| 5.3 | Mempool & Relay | 2 days | Not Started |
| 5.4 | Mining Integration | 1 day | Not Started |
| 5.5 | RPC Implementation | 1 day | Not Started |
| 5.6 | Testing & Security | 3 days | Not Started |
| **TOTAL** | **Complete Phase 5** | **12 days** | **0% Complete** |

**Estimated Hours:** 60-75 hours
**Recommended Approach:** Full-time focus for 1-2 weeks
**Target Completion:** End of Week 2 (from start)

---

## 9. Next Immediate Steps

1. **Set Up Development Environment**
   - Create Phase 5 development branch
   - Set up testing framework

2. **Start with Transaction Core (5.1.1)**
   - Begin with transaction data structures
   - This is the foundation for everything else

3. **Use Specialized Agents**
   - Deploy code-generation agents for boilerplate
   - Use testing agents for test creation
   - Security review agent for final audit

---

## 10. Maintenance & Future Enhancements (Phase 6+)

**Not included in Phase 5, for later:**
- Dynamic fee estimation
- Replace-by-fee (RBF)
- Transaction batching
- Pruning old UTXO data
- Advanced coin selection algorithms
- Multi-signature support
- Atomic swaps
- Lightning-style payment channels

---

**Document Status:** Draft v1.0
**Created:** 2025-10-27
**Last Updated:** 2025-10-27
**Next Review:** Upon Phase 5 completion
