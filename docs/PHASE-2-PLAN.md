# Phase 2 Implementation Plan

**Phase:** Transaction & Script Integration
**Duration:** 8-10 weeks (estimated)
**Target:** Months 7-9
**Status:** 🔵 Planning
**Priority:** 🔴 Critical
**Depends On:** Phase 1 (100% complete ✅)

---

## Executive Summary

Phase 2 integrates Dilithium signatures into Bitcoin Core's transaction and script systems. This phase focuses on updating transaction formats, script interpreter, consensus rules, and address generation to handle the larger post-quantum signatures while maintaining Bitcoin's proven architecture.

**Key Challenges:**
- Signatures are **34x larger** (2,420 bytes vs ~72 bytes)
- Public keys are **40x larger** (1,312 bytes vs 33 bytes)
- Transaction sizes increase **15-25x**
- Block size limits require adjustment
- Script interpreter needs Dilithium verification

**Expected Outcome:** Bitcoin Core transactions fully support Dilithium signatures with updated consensus rules.

---

## Phase 2 Objectives

### Primary Objectives

1. ✅ **Transaction Format Updates**
   - Handle 2,420-byte signatures in scriptSig
   - Handle 1,312-byte public keys in scriptSig
   - Maintain backward-compatible structure
   - Update serialization/deserialization

2. ✅ **Script Interpreter Integration**
   - Modify `OP_CHECKSIG` to use Dilithium verification
   - Modify `OP_CHECKMULTISIG` for multiple Dilithium signatures
   - Update script size limits
   - Maintain script security properties

3. ✅ **Address Format Implementation**
   - Implement BLAKE3 hashing for addresses
   - Create Bech32m address encoding (quantum-bitcoin: `qb`)
   - Update address validation
   - Support both mainnet and testnet

4. ✅ **Consensus Rule Updates**
   - Increase max transaction size (100 KB → 500 KB)
   - Increase max block size (1 MB → 10-16 MB)
   - Update transaction weight calculation
   - Implement size-based fee discount for signatures

5. ✅ **Wallet Integration**
   - Update wallet key storage
   - Implement address generation
   - Update transaction building
   - Update fee estimation

### Secondary Objectives

1. Maintain 100% test coverage
2. Document all changes
3. Ensure backward compatibility where possible
4. Performance optimization (batch verification)

---

## Success Criteria

### Must-Have (Critical)

- [ ] Transactions can include Dilithium signatures
- [ ] Script interpreter correctly verifies Dilithium signatures
- [ ] Address generation produces valid Bech32m addresses
- [ ] Consensus rules allow larger transactions/blocks
- [ ] All unit tests passing (target: 100 total tests)
- [ ] No memory leaks (ASAN clean)
- [ ] Transaction building works end-to-end
- [ ] Fee estimation accurate for Dilithium transactions

### Should-Have (High Priority)

- [ ] SegWit-style transaction weight for fee fairness
- [ ] Batch verification for blocks (30% speed improvement)
- [ ] Documentation complete (API docs, migration guide)
- [ ] Fuzz testing for transaction parsing
- [ ] Integration tests for full transaction lifecycle

### Nice-to-Have (Medium Priority)

- [ ] Legacy Base58 address support
- [ ] Multi-signature support (OP_CHECKMULTISIG)
- [ ] Performance benchmarks
- [ ] Mempool optimization for larger transactions

---

## Phase 2 Breakdown (8-10 Weeks)

### Weeks 1-2: Transaction Format & Serialization

**Objectives:**
- Update transaction data structures
- Handle larger signature sizes
- Implement proper serialization
- Update message limits

**Tasks:**

#### Week 1: Transaction Structure Updates
1. Create `src/primitives/transaction.h` modifications
   - Update `CTxIn` to handle 2,420-byte signatures
   - Update `CTransaction` serialization
   - Implement size validation
   - Add Dilithium signature checks

2. Update network protocol
   - Increase `MAX_PROTOCOL_MESSAGE_LENGTH` (4 MB → 20 MB)
   - Update `MAX_TX_SIZE` (100 KB → 500 KB)
   - Handle larger inv/getdata messages

3. Create unit tests
   - `src/test/transaction_tests.cpp` modifications
   - Test large signature handling
   - Test serialization/deserialization
   - Test size limits

**Deliverables:**
- `src/primitives/transaction.h` (modified)
- `src/primitives/transaction.cpp` (modified)
- `src/test/transaction_tests.cpp` (15+ new tests)

**Success Criteria:**
```cpp
BOOST_AUTO_TEST_CASE(dilithium_transaction_serialization) {
    CMutableTransaction tx;
    // Add Dilithium signature (2420 bytes)
    tx.vin[0].scriptSig << dilithium_signature << dilithium_pubkey;

    // Serialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;

    // Deserialize
    CTransaction loaded_tx;
    ss >> loaded_tx;

    BOOST_CHECK(loaded_tx == tx);
    BOOST_CHECK(loaded_tx.GetSerializeSize() < MAX_TX_SIZE);
}
```

#### Week 2: Transaction Building & Validation
1. Update transaction builder
   - Modify `CreateTransaction()` for Dilithium
   - Update input signing logic
   - Handle larger transaction sizes
   - Fee calculation updates

2. Transaction validation
   - Size limit checks
   - Signature format validation
   - Input/output validation
   - Mempool acceptance rules

3. Network message handling
   - Update message parsing
   - Handle larger messages
   - Bandwidth optimization

**Deliverables:**
- `src/wallet/spend.cpp` (modified - transaction building)
- `src/validation.cpp` (modified - validation rules)
- `src/net_processing.cpp` (modified - network messages)

**Estimated Time:** 2 weeks

---

### Weeks 3-4: Script Interpreter Integration

**Objectives:**
- Modify script interpreter for Dilithium
- Update `OP_CHECKSIG` and `OP_CHECKMULTISIG`
- Implement script security checks
- Comprehensive testing

**Tasks:**

#### Week 3: Script Interpreter Modifications
1. Update `script/interpreter.h` and `script/interpreter.cpp`
   - Modify `OP_CHECKSIG` to call `CPubKey::Verify()` (already Dilithium!)
   - Update signature extraction from script
   - Handle 2,420-byte signatures
   - Maintain constant-time verification

2. Script size limits
   - Update `MAX_SCRIPT_SIZE` (10 KB → 50 KB)
   - Update `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes → 3 KB)
   - Stack size limits

3. Script templates
   - P2PKH script creation
   - P2SH script creation
   - Multi-signature scripts

**Implementation:**
```cpp
// In script/interpreter.cpp

bool EvalScript(...) {
    // ...
    case OP_CHECKSIG:
    {
        // Extract signature (2420 bytes)
        valtype& vchSig = stacktop(-2);
        valtype& vchPubKey = stacktop(-1);

        // Validate sizes
        if (vchSig.size() != DILITHIUM_BYTES ||
            vchPubKey.size() != DILITHIUM_PUBLICKEYBYTES) {
            return set_error(serror, SCRIPT_ERR_SIG_INVALID);
        }

        // Create CPubKey and verify
        CPubKey pubkey(vchPubKey.begin(), vchPubKey.end());
        if (!pubkey.Verify(hash, vchSig)) {
            return set_error(serror, SCRIPT_ERR_SIG_VERIFY_FAILED);
        }

        popstack(stack);
        popstack(stack);
        stack.push_back(fSuccess ? vchTrue : vchFalse);
    }
    break;
    // ...
}
```

#### Week 4: Multi-Signature & Advanced Scripts
1. `OP_CHECKMULTISIG` implementation
   - Handle multiple Dilithium signatures
   - M-of-N signature validation
   - Performance optimization (batch verify)

2. Script validation
   - Standard script checks
   - Non-standard script handling
   - Script security analysis

3. Comprehensive testing
   - All script types tested
   - Edge cases covered
   - Fuzz testing for scripts

**Deliverables:**
- `src/script/interpreter.h` (modified)
- `src/script/interpreter.cpp` (modified - OP_CHECKSIG logic)
- `src/script/standard.h` (modified - script templates)
- `src/script/standard.cpp` (modified)
- `src/test/script_tests.cpp` (20+ new tests)

**Estimated Time:** 2 weeks

---

### Weeks 5-6: Address Format & Consensus Rules

**Objectives:**
- Implement BLAKE3 address hashing
- Create Bech32m address encoding
- Update consensus rules for block size
- Implement transaction weight

**Tasks:**

#### Week 5: Address Format Implementation
1. BLAKE3 integration
   - Add BLAKE3 library to build system
   - Create `src/crypto/blake3.h` wrapper
   - Implement address hashing
   - Unit tests

2. Bech32m address encoding
   - Implement `qb` prefix (quantum-bitcoin)
   - Address generation from public key
   - Address validation
   - Test vectors

3. Address utilities
   - `GenerateAddress()` function
   - `ValidateAddress()` function
   - Address conversion utilities

**Implementation:**
```cpp
// In src/base58.cpp or new src/bech32.cpp

std::string GenerateDilithiumAddress(const CPubKey& pubkey, bool mainnet) {
    // 1. Hash public key with BLAKE3 (256 bits)
    uint256 pubkey_hash = BLAKE3Hash(pubkey.data(), pubkey.size());

    // 2. Encode with Bech32m
    std::string hrp = mainnet ? "qb" : "tq"; // testnet: tq
    std::vector<uint8_t> data(pubkey_hash.begin(), pubkey_hash.end());
    return bech32::Encode(bech32::Encoding::BECH32M, hrp, data);
}
```

**Deliverables:**
- `src/crypto/blake3.h` (new - BLAKE3 wrapper)
- `src/crypto/blake3.cpp` (new)
- `src/bech32.cpp` (modified - Dilithium address support)
- `src/test/bech32_tests.cpp` (10+ new tests)

#### Week 6: Consensus Rule Updates
1. Block size limits
   - Increase `MAX_BLOCK_WEIGHT` (4 MB → 16 MB weight units)
   - Update block validation
   - Backward compatibility

2. Transaction weight calculation
   - Implement SegWit-style weight
   - Signature size discount (10x discount)
   - Fee fairness

3. Consensus parameters
   - Update `chainparams.cpp`
   - Testnet vs mainnet parameters
   - Activation heights

**Weight Calculation:**
```cpp
// Signature discount to prevent excessive fees
size_t GetTransactionWeight(const CTransaction& tx) {
    size_t base_size = GetBaseSize(tx);  // Without signatures
    size_t sig_size = GetSignatureSize(tx);

    // Apply 10x discount to signature size
    size_t virtual_sig_size = sig_size / 10;

    return base_size + virtual_sig_size;
}
```

**Deliverables:**
- `src/consensus/consensus.h` (modified - size limits)
- `src/validation.cpp` (modified - weight calculation)
- `src/chainparams.cpp` (modified - parameters)
- `src/test/consensus_tests.cpp` (10+ new tests)

**Estimated Time:** 2 weeks

---

### Weeks 7-8: Wallet Integration & Testing

**Objectives:**
- Update wallet for Dilithium transactions
- Comprehensive integration testing
- Performance optimization
- Documentation

**Tasks:**

#### Week 7: Wallet Updates
1. Wallet key storage
   - Store Dilithium keys in wallet database
   - Key derivation (BIP32-style for Dilithium)
   - Backup and restore

2. Transaction building
   - `CreateTransaction()` for Dilithium
   - Input selection
   - Fee estimation
   - Change address generation

3. Address management
   - Generate receive addresses
   - Address book updates
   - QR code generation (larger QR codes!)

**Deliverables:**
- `src/wallet/wallet.h` (modified)
- `src/wallet/wallet.cpp` (modified)
- `src/wallet/spend.cpp` (modified)
- `src/test/wallet_tests.cpp` (15+ new tests)

#### Week 8: Integration Testing & Optimization
1. End-to-end tests
   - Create transaction → Sign → Broadcast → Mine → Verify
   - Multi-signature transactions
   - Edge cases
   - Stress testing

2. Performance optimization
   - Batch signature verification (30% speedup)
   - Mempool optimization
   - Network message compression

3. Fuzz testing
   - Transaction parsing fuzzing
   - Script interpreter fuzzing
   - Address parsing fuzzing

**Deliverables:**
- `src/test/fuzz/transaction.cpp` (new - transaction fuzzing)
- `src/test/fuzz/script.cpp` (new - script fuzzing)
- `test/functional/dilithium_transaction.py` (new - functional test)
- Performance benchmark report

**Estimated Time:** 2 weeks

---

### Weeks 9-10: Documentation & Review

**Objectives:**
- Comprehensive documentation
- Code review preparation
- Phase 2 completion report
- Prepare for Phase 3

**Tasks:**

#### Week 9: Documentation
1. API documentation updates
   - Transaction API
   - Script API
   - Address API
   - Consensus rules

2. Migration guides
   - Updating from Phase 1
   - Transaction format changes
   - Script changes
   - Address format migration

3. Developer documentation
   - Architecture diagrams
   - Sequence diagrams
   - Code examples

**Deliverables:**
- `docs/TRANSACTION-API.md` (new)
- `docs/SCRIPT-INTEGRATION.md` (new)
- `docs/ADDRESS-FORMAT.md` (new)
- `docs/CONSENSUS-RULES.md` (new)

#### Week 10: Review & Finalization
1. Code review
   - Security review
   - Performance review
   - Test coverage verification

2. Phase 2 completion report
   - Achievements
   - Metrics
   - Remaining work
   - Phase 3 preview

3. GitHub preparation
   - PR creation
   - CI/CD validation
   - Documentation review

**Deliverables:**
- `docs/PHASE-2-COMPLETION.md` (new)
- `docs/PHASE-2-STATUS.md` (new)
- Pull request ready for review

**Estimated Time:** 2 weeks

---

## Technical Requirements

### New Files to Create

```
src/
├── primitives/
│   └── transaction.{h,cpp}         (modified)
├── script/
│   ├── interpreter.{h,cpp}         (modified)
│   └── standard.{h,cpp}            (modified)
├── crypto/
│   ├── blake3.h                    (new)
│   └── blake3.cpp                  (new)
├── wallet/
│   ├── wallet.{h,cpp}              (modified)
│   └── spend.cpp                   (modified)
├── validation.cpp                  (modified)
├── chainparams.cpp                 (modified)
└── test/
    ├── transaction_tests.cpp       (15+ new tests)
    ├── script_tests.cpp            (20+ new tests)
    ├── bech32_tests.cpp            (10+ new tests)
    ├── consensus_tests.cpp         (10+ new tests)
    ├── wallet_tests.cpp            (15+ new tests)
    └── fuzz/
        ├── transaction.cpp         (new)
        └── script.cpp              (new)
```

**Total Estimated:**
- Modified files: ~15
- New files: ~10
- New lines of code: ~5,000
- New test code: ~3,000
- Documentation: ~10,000 lines

---

## Dependencies

### Phase 1 Requirements (✅ Complete)
- ✅ CKey/CPubKey Dilithium integration
- ✅ Signature generation and verification
- ✅ 100% test coverage
- ✅ Security validation

### External Dependencies
- BLAKE3 library (for address hashing)
- Bech32m implementation (already in Bitcoin Core)
- Bitcoin Core v25.0 codebase

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| **Script interpreter bugs** | Medium | Critical | Comprehensive testing, fuzz testing |
| **Consensus rule errors** | Low | Critical | Thorough review, testnet deployment |
| **Transaction size issues** | Medium | High | Size validation, stress testing |
| **Performance degradation** | Medium | Medium | Batch verification, optimization |
| **Wallet compatibility** | Low | Medium | Incremental updates, backups |
| **Network message limits** | Low | Medium | Protocol testing |

**Overall Risk Level:** MEDIUM (manageable with proper testing)

---

## Testing Strategy

### Unit Tests (Target: 80+ new tests)
- Transaction serialization/deserialization
- Script interpreter with Dilithium
- Address generation and validation
- Consensus rule enforcement
- Wallet transaction building

### Integration Tests
- Full transaction lifecycle
- Block creation and validation
- Mempool handling
- Network message propagation

### Fuzz Tests
- Transaction parsing
- Script execution
- Address parsing
- Message handling

### Stress Tests
- Large transactions (10 inputs)
- Large blocks (1000+ transactions)
- Mempool stress (10K+ transactions)
- Network bandwidth

---

## Performance Targets

| Operation | Current (ECDSA) | Target (Dilithium) | Acceptable |
|-----------|-----------------|--------------------| -----------|
| Transaction parsing | 10 μs | 50 μs | < 100 μs |
| Script verification | 80 μs | 158 μs | < 300 μs |
| Block validation | 100 ms | 300 ms | < 500 ms |
| Transaction building | 1 ms | 5 ms | < 10 ms |
| Address generation | 50 μs | 200 μs | < 500 μs |

---

## Deliverables Summary

### Code
- ~15 modified Bitcoin Core files
- ~10 new files (crypto, tests, docs)
- ~5,000 lines of production code
- ~3,000 lines of test code
- 100% test coverage maintained

### Tests
- 80+ new unit tests
- 5+ new integration tests
- 2+ new fuzz targets
- Stress test suite

### Documentation
- 4 new technical documents
- API documentation updates
- Migration guides
- Phase 2 completion report

---

## Phase 3 Preview

**After Phase 2, next steps:**

1. **Phase 3:** Wallet & Network Integration
   - HD wallet support (BIP32-style for Dilithium)
   - Network protocol finalization
   - Mining updates
   - RPC interface

2. **Phase 4:** Consensus & Activation
   - Activation mechanism (BIP9-style)
   - Testnet deployment
   - Community testing
   - Mainnet preparation

---

## Timeline

```
Week 1-2:  Transaction Format         ████████░░ Week 2 end
Week 3-4:  Script Interpreter         ░░░░████░░ Week 4 end
Week 5-6:  Address & Consensus        ░░░░░░██░░ Week 6 end
Week 7-8:  Wallet & Testing           ░░░░░░░░██ Week 8 end
Week 9-10: Documentation & Review     ░░░░░░░░░░ Week 10 end
```

**Total Duration:** 8-10 weeks
**Expected Completion:** Month 9

---

## Getting Started

### Prerequisites
1. ✅ Phase 1 complete (100%)
2. ✅ All Phase 1 tests passing
3. ✅ Development environment setup
4. ⚠️ MSAN testing complete (optional)
5. ⚠️ Cachegrind analysis complete (optional)

### Kickoff Checklist
- [ ] Review this plan
- [ ] Create `phase-2-transaction-integration` branch
- [ ] Set up Week 1 task list
- [ ] Begin transaction format updates

---

## Approval

**Plan Status:** 🔵 **READY FOR APPROVAL**

**Recommended Action:** Review and approve to proceed with Week 1 implementation.

**Estimated Success Rate:** 95% (high confidence based on Phase 1 success)

---

**Created:** October 24, 2025
**Author:** Claude Code AI
**Version:** 1.0
**Status:** Planning Complete - Awaiting Approval
