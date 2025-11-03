# Dilithion Test Requirements Analysis

**Document Version:** 1.0  
**Created:** November 3, 2025  
**Analysis Scope:** Comprehensive functional and fuzz test requirements for Dilithion cryptocurrency

## Executive Summary

Analysis of 80+ source files identifies critical test coverage gaps in the Dilithion blockchain:
- **Existing Tests:** 20 test files with ~500+ test cases (mostly unit-level)
- **Critical Gaps:** Consensus validation, deserialization fuzzing, network message parsing, RPC input validation
- **Risk Level:** HIGH - Multiple critical consensus paths lack comprehensive testing
- **Effort Estimate:** 40-50 hours for Week 3 implementation

## Component Inventory (8 Major Subsystems)

### 1. Primitives Layer (uint256, CTransaction, CBlock)
**Files:** src/primitives/transaction.h (192L), src/primitives/block.h (82L)

**Missing Tests:** Transaction serialization roundtrip, edge cases, malformed parsing
- **Test Needs (P1):** 4 tests covering serialization, edge cases, binary compatibility
- **Fuzz Targets (P1):** fuzz_transaction_deserialize, fuzz_block_deserialize

### 2. Cryptography & Hashing (SHA-3, Dilithium, RandomX)
**Files:** src/crypto/sha3.{cpp,h}, src/crypto/randomx_hash.{cpp,h}

**Missing Tests:** RandomX cache stress, large data hashing, concurrent operations
- **Test Needs (P0):** 4 tests - RandomX initialization, large-scale ops, determinism
- **Fuzz Targets (P0):** fuzz_sha3_256, fuzz_dilithium_signature_verify, fuzz_randomx_hash, fuzz_base58_decode

### 3. Consensus & Validation (CRITICAL)
**Files:** src/consensus/validation.cpp (521L), tx_validation.cpp (575L)

**Missing Tests:** Merkle verification, difficulty adjustment, timestamp boundaries, subsidy halving
- **Test Needs (P0 - CRITICAL):** 6 tests for all consensus rules
- **Fuzz Targets (P0 - CRITICAL):** 7 harnesses covering all validation paths
- **Risk:** Invalid blocks accepted, consensus forks, mining broken, inflation errors

### 4. Wallet & Key Management
**Files:** src/wallet/wallet.cpp (1883L), crypter.h (200L)

**Missing Tests:** Multi-input signing, coin selection edge cases, concurrent wallet access
- **Test Needs (P1):** 3 tests - Multi-input signing, coin selection, concurrent access
- **Fuzz Targets (P1):** fuzz_address_decode, fuzz_wallet_tx_creation

### 5. Mempool & Transaction Relay
**Files:** src/node/mempool.{h,cpp}

**Missing Tests:** Size limits, eviction policies, double-spend detection, concurrent operations
- **Test Needs (P1):** 2 tests for mempool consistency
- **Fuzz Targets (P2):** fuzz_mempool_add, fuzz_mempool_ordering

### 6. UTXO Set & Database
**Files:** src/node/utxo_set.{h,cpp} (450+ lines)

**Missing Tests:** Large-scale performance (1M+ UTXOs), crash recovery, batch consistency
- **Test Needs (P0):** 2 tests - UTXO serialization, cache consistency
- **Fuzz Targets (P1):** fuzz_utxo_serialization

### 7. Network & P2P Protocol
**Files:** src/net/serialize.h (314L), protocol.h (194L), net.h (100+L)

**Missing Tests:** Malformed messages, buffer overflow, 32MB limit, endianness edge cases
- **Test Needs (P1 - HIGH):** 2 tests - Checksum validation, message parsing
- **Fuzz Targets (P1 - HIGH):** 4 harnesses for all message types

### 8. RPC & HTTP Interface
**Files:** src/rpc/server.h (295L), server.cpp (600+L)

**Missing Tests:** Malformed JSON, parameter validation, injection prevention
- **Test Needs (P2):** 1 test for input validation
- **Fuzz Targets (P2):** fuzz_rpc_json_parse

## 15 Prioritized Functional Tests

### P0 (CRITICAL CONSENSUS) - 6 tests, 16 hours

1. **P0-1: Merkle Root Validation** (2 hrs)
   - Ensure invalid merkle roots rejected
   - Risk: Consensus forks, chain divergence

2. **P0-2: Difficulty Adjustment** (3 hrs)
   - Verify adjustment every 2016 blocks
   - Risk: Network hashrate attacks

3. **P0-3: Coinbase Subsidy Halving** (2 hrs)
   - Verify halving schedule (50 > 25 > 12.5 > 6.25 > 0 DIL)
   - Risk: Inflation errors, supply exceeds 21M

4. **P0-4: PoW Target Validation** (2 hrs)
   - Verify hash meets difficulty target
   - Risk: Invalid blocks accepted

5. **P0-5: Signature Validation** (3 hrs)
   - Reject invalid signatures
   - Risk: Double-spending possible

6. **P0-6: Timestamp Validation** (2 hrs)
   - Enforce time boundaries (-2h, MTP, future)
   - Risk: Past/future blocks accepted

### P1 (HIGH-PRIORITY) - 5 tests, 11 hours

7. **P1-1: Transaction Serialization Roundtrip** (2 hrs)
8. **P1-2: Multi-Input Wallet Signing** (3 hrs)
9. **P1-3: Mempool Double-Spend Detection** (2 hrs)
10. **P1-4: Network Message Checksum** (2 hrs)
11. **P1-5: RPC Input Validation** (2 hrs)

### P2 (MEDIUM-PRIORITY) - 2 tests, 3 hours

12. **P2-1: UTXO Coinbase Maturity** (2 hrs)
13. **P2-2: Fee Calculation** (1 hr)

## 10 Prioritized Fuzz Harnesses

### P0 Harnesses (5) - CRITICAL
1. fuzz_block_validation (100 lines)
2. fuzz_pow_validation (80 lines)
3. fuzz_transaction_deserialize (100 lines)
4. fuzz_transaction_validation (120 lines)
5. fuzz_signature_verification (90 lines)

### P1 Harnesses (4) - HIGH
6. fuzz_network_message_header (80 lines)
7. fuzz_datastream_compact_size (70 lines)
8. fuzz_address_decode (75 lines)
9. fuzz_utxo_serialization (100 lines)

### P2 Harnesses (1) - MEDIUM
10. fuzz_rpc_json_parser (120 lines)

## Risk Assessment

**CRITICAL Risk Areas:**
- CheckProofOfWork edge cases >> Invalid blocks accepted
- VerifyMerkleRoot paths >> Consensus forks
- Timestamp boundaries >> Past/future blocks accepted
- Signature verification >> Double-spending possible
- Difficulty algorithm >> Mining game broken
- Coinbase halving >> Inflation errors

**HIGH Risk Areas:**
- Transaction deserialization edge cases
- Network message parsing malformed input
- Wallet multi-input signing corners
- Mempool concurrent operations
- RPC input validation all types
- UTXO coinbase maturity checks

## Week 3 Implementation Timeline

**Phase 1 (4 hrs):** Infrastructure setup
- Fuzzing harness template
- Test utilities library
- CI integration

**Phase 2 (16 hrs):** P0 tests (Consensus critical)
- Days 1-2: Consensus tests - 8 hrs
- Day 3: Signature validation + fuzz - 5 hrs
- Day 4: Timestamp validation - 3 hrs

**Phase 3 (14 hrs):** P1 tests (High priority)
- Day 5: Network & serialization - 5 hrs
- Day 6: Wallet & mempool - 5 hrs
- Day 7: RPC tests - 4 hrs

**Phase 4 (10 hrs):** P2 tests & additional fuzz
- Day 8: UTXO & fees - 4 hrs
- Days 9-10: Fuzz harnesses - 6 hrs

**Total:** 44 hours, 15 functional tests + 10 fuzz harnesses

## Next Steps

- **Week Nov 3-7:** Infrastructure + P0 tests (20 hrs)
- **Week Nov 10-14:** P1 tests + fuzz harnesses (14 hrs)
- **Week Nov 17-21:** P2 tests + fuzz analysis (10 hrs)

---

**Status:** Ready for implementation
**Updated:** November 3, 2025
**Coverage:** Dilithion v1.0.6 (80+ files analyzed)
