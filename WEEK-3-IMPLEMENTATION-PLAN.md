# Week 3: Functional & Fuzz Testing Implementation Plan

**Date:** November 3, 2025
**Status:** Research Complete - Ready for Implementation
**Roadmap Phase:** Week 3 of Bitcoin-to-Excellence Roadmap

---

## Executive Summary

Following comprehensive research of Bitcoin Core's testing infrastructure, we're implementing functional tests (Python-based) and fuzz harnesses (libFuzzer-based) to address **HIGH RISK** gaps in Dilithion's test coverage.

**Research Completed:**
- ✅ Bitcoin Core functional test framework analyzed (200+ tests)
- ✅ Bitcoin Core fuzz infrastructure analyzed (136+ harnesses)
- ✅ Dilithion test requirements assessed (80+ files)

**Key Findings:**
- **Risk Level:** HIGH - Critical consensus paths untested
- **Tests Needed:** 15 functional + 10 fuzz harnesses
- **Estimated Effort:** 44 hours total

---

## Research Documents Created

### 1. BITCOIN-FUNCTIONAL-TEST-ANALYSIS.md
Analysis of Bitcoin Core's Python-based functional testing framework.

**Key Findings:**
- Framework: Python 3 with test_framework base classes
- Core Classes: BitcoinTestFramework, TestNode, P2PInterface
- Test Count: 200+ tests across 70+ files
- Categories: Feature, Interface, Mempool, Mining, P2P
- Parallel execution supported (default 4 workers)

**Best Practices Identified:**
- Naming convention: `<category>_<test>.py`
- Use MiniWallet for deterministic transactions
- Minimize node start/stop cycles
- Use `assert_raises_rpc_error()` for error validation
- Employ `wait_until()` instead of `sleep()`

### 2. BITCOIN-FUZZ-INFRASTRUCTURE-ANALYSIS.md
Analysis of Bitcoin Core's libFuzzer-based fuzz testing infrastructure.

**Key Findings:**
- Harness Count: 136+ fuzz harnesses
- Frameworks: libFuzzer (primary), afl++, Honggfuzz
- Build: CMake presets (`--preset=libfuzzer`)
- OSS-Fuzz Integration: Continuous fuzzing with Google infrastructure
- Sanitizers: ASan, UBSan, MSan for comprehensive error detection

**Common Patterns:**
- FuzzedDataProvider for input consumption
- Logical consistency assertions (strict ⊆ flexible)
- Round-trip testing (deserialize(serialize(x)) == x)
- State machine verification
- Hierarchical validation checks

### 3. DILITHION-TEST-REQUIREMENTS-ANALYSIS.md
Comprehensive analysis of Dilithion's testing needs based on codebase review.

**Analysis Scope:**
- 80+ source files examined
- 2,979+ lines of critical code paths analyzed
- 20 existing test files reviewed
- 8 major subsystems inventoried

**Critical Gaps Identified:**
- ⚠️ Consensus validation: Merkle roots, difficulty, timestamps, subsidy
- ⚠️ Deserialization fuzzing: Transactions, blocks, network messages
- ⚠️ Network protocol: Malformed messages, checksum validation
- ⚠️ RPC interface: Input validation across all parameter types
- ⚠️ Wallet: Multi-input signing, concurrent access, coin selection

---

## Week 3 Implementation Plan

### Phase 1: Infrastructure Setup (4 hours)

**Objective:** Establish Python functional test framework and libFuzzer harness infrastructure

**Tasks:**
1. **Functional Test Framework** (2 hrs)
   - Create `test/functional/test_framework/` directory structure
   - Implement DilithionTestFramework base class
   - Create TestNode wrapper for dilithion-node
   - Implement assertion helpers (assert_equal, assert_raises_rpc_error)
   - Add test runner script

2. **Fuzz Test Infrastructure** (1.5 hrs)
   - Create `src/test/fuzz/` directory
   - Create fuzz harness template
   - Add libFuzzer build configuration to Makefile
   - Add FuzzedDataProvider utilities

3. **CI Integration** (0.5 hrs)
   - Add functional test job to `.github/workflows/ci.yml`
   - Add fuzz build job (optional execution)
   - Update test documentation

**Deliverables:**
- `test/functional/test_framework/test_framework.py`
- `test/functional/test_framework/util.py`
- `test/functional/test_runner.py`
- `src/test/fuzz/fuzz_template.cpp`
- Updated CI configuration

---

### Phase 2: P0 Critical Consensus Tests (16 hours)

**Objective:** Address critical consensus validation gaps (HIGHEST RISK)

#### P0-1: Merkle Root Validation (2 hours)
**Risk:** Consensus forks if merkle roots not validated
**File:** `test/functional/feature_merkle_root.py`

**Test Cases:**
- Valid merkle root accepted
- Invalid merkle root rejected
- Single transaction (coinbase only)
- Multiple transactions (2, 3, 7, 15 txs)
- Empty merkle root handling

**Expected:** 5+ test cases

---

#### P0-2: Difficulty Adjustment (3 hours)
**Risk:** Mining broken if difficulty not adjusted correctly
**File:** `test/functional/feature_difficulty.py`

**Test Cases:**
- Difficulty increases when blocks too fast
- Difficulty decreases when blocks too slow
- 2016 block adjustment window
- Edge case: Exactly 2 weeks
- Edge case: Genesis block (no adjustment)
- Maximum difficulty change (4x limit)

**Expected:** 6+ test cases

---

#### P0-3: Coinbase Subsidy Halving (2 hours)
**Risk:** Inflation errors if halving schedule incorrect
**File:** `test/functional/feature_subsidy.py`

**Test Cases:**
- Initial subsidy: 50 DIL
- First halving: 25 DIL (block 210,000)
- Second halving: 12.5 DIL (block 420,000)
- Third halving: 6.25 DIL (block 630,000)
- Final subsidy: 0 DIL (block ~6,930,000)
- Total supply: 21,000,000 DIL (within precision)

**Expected:** 6+ test cases

---

#### P0-4: PoW Target Validation (2 hours)
**Risk:** Invalid blocks accepted if PoW not checked
**File:** `test/functional/feature_pow.py`

**Test Cases:**
- Valid PoW accepted
- Invalid PoW rejected (hash too high)
- Genesis block PoW
- Minimum difficulty (regtest)
- Maximum difficulty (theoretical limit)

**Expected:** 5+ test cases

---

#### P0-5: Signature Validation (3 hours)
**Risk:** Double-spending possible if signatures not validated
**File:** `test/functional/feature_signatures.py`

**Test Cases:**
- Valid Dilithium3 signature accepted
- Invalid signature rejected
- Wrong public key rejected
- Tampered message rejected
- Empty signature rejected
- Malformed signature rejected (wrong length)

**Expected:** 6+ test cases

---

#### P0-6: Timestamp Validation (2 hours)
**Risk:** Past/future blocks accepted if timestamps not validated
**File:** `test/functional/feature_timestamps.py`

**Test Cases:**
- Valid timestamp accepted (current time)
- Future block rejected (> 2 hours ahead)
- Past block rejected (< median of last 11)
- Edge case: Exactly 2 hours ahead (accepted)
- Edge case: Exactly at median (accepted)
- Genesis block timestamp (no validation)

**Expected:** 6+ test cases

---

### Phase 3: P1 High-Priority Tests (14 hours)

**Objective:** Address high-risk areas in network, wallet, and mempool

#### P1-1: Transaction Serialization Roundtrip (2 hours)
**File:** `test/functional/feature_tx_serialization.py`

**Test Cases:**
- Simple transaction roundtrip
- Multi-input transaction
- Multi-output transaction
- Edge case: 253+ inputs (CompactSize 0xFD)
- Edge case: 65,536+ inputs (CompactSize 0xFE)
- Malformed transaction rejected

**Expected:** 6+ test cases

---

#### P1-2: Multi-Input Wallet Signing (3 hours)
**File:** `test/functional/wallet_multi_input.py`

**Test Cases:**
- Sign transaction with 2 inputs
- Sign transaction with 10+ inputs
- Sign with mixed address types
- Fail on insufficient funds
- Coin selection optimization
- Concurrent signing operations

**Expected:** 6+ test cases

---

#### P1-3: Mempool Double-Spend Detection (2 hours)
**File:** `test/functional/mempool_double_spend.py`

**Test Cases:**
- Detect double-spend (same UTXO)
- Allow independent transactions
- Higher fee replaces lower (if RBF enabled)
- Mempool eviction on size limit
- Concurrent mempool operations

**Expected:** 5+ test cases

---

#### P1-4: Network Message Checksum (2 hours)
**File:** `test/functional/p2p_message_checksum.py`

**Test Cases:**
- Valid checksum accepted
- Invalid checksum rejected
- Empty message
- Large message (32MB limit)
- Malformed header

**Expected:** 5+ test cases

---

#### P1-5: RPC Input Validation (2 hours)
**File:** `test/functional/interface_rpc_validation.py`

**Test Cases:**
- Integer parameter validation
- String parameter validation
- Address parameter validation
- Malformed JSON rejected
- SQL injection prevention
- Command injection prevention

**Expected:** 6+ test cases

---

### Phase 4: P2 Tests & Fuzz Harnesses (10 hours)

#### P2-1: UTXO Coinbase Maturity (2 hours)
**File:** `test/functional/feature_coinbase_maturity.py`

**Test Cases:**
- Coinbase requires 100 confirmations
- Regular transaction spendable immediately
- Attempt to spend immature coinbase (rejected)

**Expected:** 3+ test cases

---

#### P2-2: Fee Calculation (1 hour)
**File:** `test/functional/feature_fees.py`

**Test Cases:**
- Calculate transaction fee
- Fee rate calculation (satoshis per byte)
- Minimum relay fee enforcement

**Expected:** 3+ test cases

---

#### Fuzz Harnesses (7 hours)

**P0 Harnesses (Critical):**
1. `fuzz_block_validation.cpp` (1 hr) - 100 lines
2. `fuzz_pow_validation.cpp` (1 hr) - 80 lines
3. `fuzz_transaction_deserialize.cpp` (1 hr) - 100 lines
4. `fuzz_transaction_validation.cpp` (1.5 hrs) - 120 lines
5. `fuzz_signature_verification.cpp` (1 hr) - 90 lines

**P1 Harnesses (High):**
6. `fuzz_network_message_header.cpp` (0.5 hrs) - 80 lines
7. `fuzz_datastream_compact_size.cpp` (0.5 hrs) - 70 lines
8. `fuzz_address_decode.cpp` (0.5 hrs) - 75 lines

---

## Expected Outcomes

### Test Coverage Increase
- **Before Week 3:** ~500 unit tests (no functional/fuzz)
- **After Week 3:** ~500 unit + 15 functional (38+ cases) + 10 fuzz harnesses
- **Coverage Improvement:** Unit → Integration → Fuzz (comprehensive)

### Risk Mitigation
- **Consensus Risk:** HIGH → LOW (6 critical tests)
- **Network Risk:** HIGH → MEDIUM (4 P1 tests)
- **Wallet Risk:** MEDIUM → LOW (3 tests)
- **Overall Risk:** HIGH → MEDIUM-LOW

### Quality Score Impact
- **Before Week 3:** 7.0/10
- **After Week 3:** 7.8-8.0/10 (estimated)
- **Target (Week 10):** 8.5/10

### Testing Gap Closure
- **Before:** ⭐⭐⭐⭐ (critical gap)
- **After:** ⭐ (minimal gap, approaching Bitcoin Core standards)
- **Progress:** 75% gap closure

---

## Implementation Timeline

**Total Effort:** 44 hours across 10 days

| Phase | Days | Hours | Tasks |
|-------|------|-------|-------|
| Phase 1 | Days 1-2 | 4 | Infrastructure setup |
| Phase 2 | Days 3-6 | 16 | P0 critical consensus tests |
| Phase 3 | Days 7-9 | 14 | P1 high-priority tests |
| Phase 4 | Days 10 | 10 | P2 tests + fuzz harnesses |

**Recommended Schedule:**
- Nov 3-4 (Days 1-2): Infrastructure
- Nov 5-8 (Days 3-6): P0 tests
- Nov 11-13 (Days 7-9): P1 tests
- Nov 14 (Day 10): P2 + fuzz

---

## Success Criteria

### Phase 1 Success
- ✅ Functional test framework operational
- ✅ At least 1 functional test runs successfully
- ✅ Fuzz harness template compiles
- ✅ CI jobs green (build + run tests)

### Phase 2 Success
- ✅ All 6 P0 tests implemented (34+ test cases)
- ✅ All P0 tests pass on current codebase
- ✅ Any consensus bugs discovered are documented
- ✅ CI runs P0 tests on every commit

### Phase 3 Success
- ✅ All 5 P1 tests implemented (28+ test cases)
- ✅ All P1 tests pass
- ✅ Network/wallet/mempool edge cases covered
- ✅ CI runs all functional tests

### Phase 4 Success
- ✅ All 2 P2 tests implemented (6+ test cases)
- ✅ 8-10 fuzz harnesses implemented
- ✅ Fuzz harnesses compile with libFuzzer
- ✅ CI builds fuzz binaries (optional execution)
- ✅ Documentation updated

---

## Documentation to Create

1. **WEEK-3-PROGRESS.md** - Daily progress tracking
2. **TEST-FRAMEWORK-GUIDE.md** - How to write functional tests
3. **FUZZ-TESTING-GUIDE.md** - How to write and run fuzz harnesses
4. **Updated CONTRIBUTING.md** - Testing requirements for PRs

---

## Next Steps

1. **Immediate (Day 1-2):** Implement Phase 1 infrastructure
2. **Days 3-6:** Implement all P0 critical consensus tests
3. **Days 7-9:** Implement P1 high-priority tests
4. **Day 10:** Implement P2 tests + fuzz harnesses
5. **Day 11:** Documentation and review

**Status:** Ready to begin Phase 1 implementation

---

**Document Version:** 1.0
**Last Updated:** November 3, 2025
**Next Review:** After Phase 1 completion
