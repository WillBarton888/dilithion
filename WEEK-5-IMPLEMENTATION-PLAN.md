# Week 5 Implementation Plan

**Week:** November 11-15, 2025 (Week 5 of 10)
**Phase:** Phase 2 - Extended Validation & Coverage Expansion
**Status:** Planning Complete, Ready to Execute
**Estimated Effort:** 40 hours (5 days × 8 hours)

---

## Executive Summary

Week 5 builds upon Week 4's foundations with three parallel tracks:
1. **Extended Platform Testing** - Validate difficulty determinism across 4+ additional platforms
2. **Coverage Expansion** - Increase coverage from 64% to 70%+
3. **Fuzzing Enhancement** - Create seed corpus and run extended campaigns

**Critical Success Factor:** All platforms must produce IDENTICAL difficulty calculation results

---

## Current Status (Week 4 Complete)

### Achievements ✅
- **C++ Unit Tests:** 142/142 passing (100%)
- **Coverage:** 64.2% lines, 87.7% functions
- **Track B (Primary Platform):** 10/10 difficulty tests passing on Ubuntu GCC 13.3
- **Infrastructure:** LCOV, Codecov, automated scripts ready
- **Decision:** GO - Ready for extended validation

### Blockers Resolved ✅
- Test expected values corrected for difficulty bounds
- Integer-only arithmetic confirmed deterministic
- All CI builds passing

---

## Week 5 Objectives

### Primary Objectives
1. ✅ **Cross-Platform Validation:** Test difficulty on 4+ platforms, all must agree
2. ✅ **Coverage Goal:** Reach 70%+ line coverage
3. ✅ **Fuzzing Foundation:** Create corpus, run initial campaigns
4. ✅ **CI Enhancement:** Automate cross-platform testing

### Success Criteria
- All platforms produce identical difficulty results (EXIT CRITERIA for mainnet)
- Coverage ≥ 70% overall (P0 components ≥ 80%)
- Zero crashes from 1-hour fuzz campaigns
- Automated difficulty validation in CI

---

## Track A: Extended Platform Testing (16 hours)

**Priority:** CRITICAL (P0) - Consensus fork prevention
**Timeline:** Days 1-2

### Day 1: Platform 2-3 Testing (8 hours)

#### A1.1: Windows MinGW Testing (4 hours)

**Environment Setup:**
```bash
# On Windows with MinGW
cd C:\Users\will\dilithion
mingw32-make clean
mingw32-make difficulty_determinism_test
```

**Execution:**
```bash
difficulty_determinism_test.exe > difficulty_results_windows_mingw.json
```

**Validation:**
```bash
python scripts/compare_difficulty_results.py \
    difficulty_results_ubuntu_gcc_wsl2.json \
    difficulty_results_windows_mingw.json
```

**Expected:** Exit 0 (all results identical)

**If FAIL:** CRITICAL - Stop and analyze arithmetic differences

#### A1.2: Ubuntu Clang Testing (4 hours)

**Environment Setup:**
```bash
# In WSL or native Ubuntu
export CC=clang
export CXX=clang++
make clean
make difficulty_determinism_test
```

**Execution:**
```bash
./difficulty_determinism_test > difficulty_results_ubuntu_clang.json
```

**Validation:**
```bash
python scripts/compare_difficulty_results.py \
    difficulty_results_ubuntu_gcc_wsl2.json \
    difficulty_results_ubuntu_clang.json
```

**Expected:** Exit 0 (identical results)

### Day 2: Platform 4-5 Testing (8 hours)

#### A2.1: macOS Testing (4 hours, if available)

**Environment Setup:**
```bash
# On macOS
brew install leveldb
cd dilithion
make clean
make difficulty_determinism_test
```

**Execution:**
```bash
./difficulty_determinism_test > difficulty_results_macos_clang.json
```

**Validation:**
```bash
python3 scripts/compare_difficulty_results.py \
    difficulty_results_ubuntu_gcc_wsl2.json \
    difficulty_results_macos_clang.json
```

#### A2.2: ARM64 Testing (4 hours, if available)

**Alternative if macOS/ARM unavailable:**
- Alpine Linux + musl
- FreeBSD + Clang
- Additional compiler versions (GCC 11, GCC 12, Clang 14, Clang 15)

### Documentation & CI Integration (Time in Day 3)

#### A3.1: Cross-Platform Report

**Create:** `WEEK-5-CROSS-PLATFORM-VALIDATION-RESULTS.md`

**Contents:**
- Results from all platforms (4-6 total)
- Comparison matrix showing identical results
- Platform specifications (OS, compiler, arch)
- GO/NO-GO decision for mainnet
- Any issues discovered and resolved

#### A3.2: CI Automation

**Add to `.github/workflows/ci.yml`:**
```yaml
  difficulty-validation:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        compiler: [gcc, clang]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - name: Build difficulty test
        run: make difficulty_determinism_test
      - name: Run test
        run: ./difficulty_determinism_test
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: difficulty-results-${{ matrix.os }}-${{ matrix.compiler }}
          path: difficulty_results.json

  difficulty-compare:
    needs: difficulty-validation
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - name: Compare all platforms
        run: python scripts/compare_difficulty_results.py difficulty-results-*/*.json
```

---

## Track B: Coverage Expansion (16 hours)

**Goal:** 64.2% → 70%+ coverage
**Priority:** HIGH (P1)
**Timeline:** Days 2-4

### Day 2-3: Identify & Fill Coverage Gaps (8 hours)

#### B1.1: Coverage Gap Analysis (2 hours)

**Generate current report:**
```bash
make coverage
# Opens coverage_html/index.html
```

**Analyze gaps:**
- List all files <50% coverage
- Prioritize by component (P0 > P1 > P2)
- Identify untested functions
- Document in COVERAGE-GAP-ANALYSIS.md

**Target files (based on P0 priority):**
1. `src/consensus/pow.cpp` - Current: Need to check
2. `src/consensus/validation.cpp` - Current: Need to check
3. `src/primitives/transaction.cpp` - Current: 64% (from previous report)
4. `src/primitives/block.cpp` - Current: Need to check
5. `src/wallet/wallet.cpp` - Current: Need to check

#### B1.2: Write Additional Unit Tests (6 hours)

**Focus Areas:**

**1. Consensus Tests (2 hours):**
```cpp
// src/test/consensus_tests.cpp
BOOST_AUTO_TEST_SUITE(consensus_tests)

BOOST_AUTO_TEST_CASE(difficulty_bounds_enforcement) {
    // Test MIN_DIFFICULTY_BITS enforcement
    // Test MAX_DIFFICULTY_BITS enforcement
}

BOOST_AUTO_TEST_CASE(timespan_clamping) {
    // Test 4x faster clamping
    // Test 4x slower clamping
}

BOOST_AUTO_TEST_CASE(compact_target_conversion) {
    // Test CompactToBig edge cases
    // Test BigToCompact edge cases
}

BOOST_AUTO_TEST_SUITE_END()
```

**2. Transaction Tests (2 hours):**
```cpp
// Expand src/test/transaction_tests.cpp
BOOST_AUTO_TEST_CASE(transaction_edge_cases) {
    // Empty inputs
    // Empty outputs
    // Maximum value
    // Overflow protection
}

BOOST_AUTO_TEST_CASE(transaction_serialization_errors) {
    // Malformed data
    // Truncated inputs
    // Invalid signatures
}
```

**3. Block Tests (2 hours):**
```cpp
// Expand src/test/block_tests.cpp
BOOST_AUTO_TEST_CASE(block_validation_errors) {
    // Invalid merkle root
    // Invalid timestamp
    // Invalid difficulty
    // Invalid PoW
}

BOOST_AUTO_TEST_CASE(block_header_edge_cases) {
    // Maximum values
    // Boundary conditions
}
```

### Day 3-4: Verify Coverage Improvement (8 hours)

#### B2.1: Rebuild and Measure (2 hours)

```bash
make clean
make coverage
# Verify new tests pass
# Check coverage increased
```

**Target Metrics:**
- Overall: 70%+ (from 64.2%)
- Consensus (P0): 85%+ (from 87.7% functions)
- Primitives (P0): 80%+
- Wallet (P1): 70%+

#### B2.2: Negative Testing (4 hours)

**Add error path tests:**
- Invalid inputs
- Null pointers
- Overflow conditions
- Out-of-bounds access
- Malformed data

**Example:**
```cpp
BOOST_AUTO_TEST_CASE(handle_null_block_pointer) {
    BOOST_CHECK_THROW(ProcessBlock(nullptr), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(handle_transaction_overflow) {
    CTransaction tx;
    tx.vout.push_back(CTxOut(MAX_MONEY + 1, CScript()));
    BOOST_CHECK(!tx.CheckBasicStructure());
}
```

#### B2.3: Integration Tests (2 hours)

**Add end-to-end test scenarios:**
```cpp
// src/test/integration_tests.cpp
BOOST_AUTO_TEST_CASE(full_block_processing) {
    // Mine block → validate → add to chain → verify state
}

BOOST_AUTO_TEST_CASE(transaction_flow) {
    // Create tx → sign → validate → add to mempool → mine → confirm
}
```

---

## Track C: Fuzzing Enhancement (8 hours)

**Priority:** HIGH (Security)
**Timeline:** Days 4-5

### Day 4: Seed Corpus Creation (4 hours)

#### C1.1: Create Corpus Directory Structure

```bash
mkdir -p test/fuzz/corpus/{transaction,block,compactsize,network_message,address,difficulty,subsidy,merkle}
```

#### C1.2: Generate Seed Files

**Transaction corpus (10 seeds):**
```cpp
// generate_fuzz_seeds.cpp
void generate_transaction_seeds() {
    // 1. Empty transaction
    // 2. Single input, single output
    // 3. Multiple inputs, multiple outputs
    // 4. Maximum inputs (boundary)
    // 5. Maximum outputs (boundary)
    // 6. Coinbase transaction
    // 7. Transaction with all features
    // 8. Large transaction (near limit)
    // 9. Transaction with complex scripts
    // 10. Transaction with dilithium signatures
}
```

**Block corpus (10 seeds):**
- Genesis block
- Empty block (coinbase only)
- Block with 1 tx
- Block with 10 txs
- Block with max txs
- Block at difficulty adjustment
- High difficulty block
- Low difficulty block
- Block with invalid PoW (for negative testing)
- Block with all features

**Other corpora (5 seeds each):**
- CompactSize: boundary values (0, 252, 253, 65535, 65536, MAX_UINT64)
- Network messages: All message types
- Addresses: Valid Dilithium addresses + edge cases
- Difficulty: Various nBits values
- Subsidy: Halving boundaries
- Merkle: Various tree sizes

**Total:** ~80 seed files

#### C1.3: Document Corpus

**Create:** `test/fuzz/CORPUS.md`

**Contents:**
- Purpose of each seed file
- How to regenerate seeds
- How to expand corpus
- Best practices for fuzzing

### Day 5: Initial Fuzzing Campaigns (4 hours)

#### C2.1: Run All Harnesses (3 hours)

**Execute each for 30 minutes:**
```bash
# Run all fuzz targets in parallel
./fuzz_transaction -max_total_time=1800 test/fuzz/corpus/transaction/ &
./fuzz_block -max_total_time=1800 test/fuzz/corpus/block/ &
./fuzz_compactsize -max_total_time=1800 test/fuzz/corpus/compactsize/ &
./fuzz_network_message -max_total_time=1800 test/fuzz/corpus/network_message/ &
./fuzz_address -max_total_time=1800 test/fuzz/corpus/address/ &
./fuzz_difficulty -max_total_time=1800 test/fuzz/corpus/difficulty/ &
./fuzz_subsidy -max_total_time=1800 test/fuzz/corpus/subsidy/ &
./fuzz_merkle -max_total_time=1800 test/fuzz/corpus/merkle/ &

wait
```

**Monitor for:**
- Crashes (saved to crash-*)
- Hangs (timeouts)
- Interesting inputs (saved to corpus)
- Memory leaks (AddressSanitizer)
- UB (UndefinedBehaviorSanitizer)

#### C2.2: Analyze Results (1 hour)

**For each crash:**
1. Reproduce: `./fuzz_X crash-XXXX`
2. Debug with gdb
3. Identify root cause
4. Create fix
5. Add test case
6. Verify fix
7. Re-run fuzzer

**Document findings:**
- `FUZZING-RESULTS-WEEK5.md`
- Number of executions per harness
- Coverage achieved
- Crashes found and fixed
- Interesting edge cases discovered

---

## Timeline

```
Day 1 (Mon):
├─ Track A: Windows MinGW testing (4h)
└─ Track A: Ubuntu Clang testing (4h) → 8h total

Day 2 (Tue):
├─ Track A: macOS/ARM testing (4h)
├─ Track B: Coverage gap analysis (2h)
└─ Track B: Write consensus tests (2h) → 8h total

Day 3 (Wed):
├─ Track B: Write transaction/block tests (4h)
├─ Track B: Rebuild & measure coverage (2h)
└─ Track A: Documentation & CI (2h) → 8h total

Day 4 (Thu):
├─ Track B: Negative testing (4h)
└─ Track C: Seed corpus creation (4h) → 8h total

Day 5 (Fri):
├─ Track B: Integration tests (2h)
├─ Track C: Fuzzing campaigns (3h)
├─ Track C: Analyze results (1h)
└─ Week 5 documentation (2h) → 8h total

Total: 40 hours
```

---

## Success Criteria

### Track A: Cross-Platform Testing ✅
- ✅ Tests run on 4+ platforms
- ✅ All platforms produce IDENTICAL results
- ✅ Automated CI comparison working
- ✅ Comprehensive validation report published

### Track B: Coverage ✅
- ✅ Overall coverage ≥ 70%
- ✅ Consensus (P0) coverage ≥ 85%
- ✅ Primitives (P0) coverage ≥ 80%
- ✅ Negative test coverage added
- ✅ Integration tests passing

### Track C: Fuzzing ✅
- ✅ Seed corpus created (~80 files)
- ✅ All 8 harnesses executed (30 min each)
- ✅ Zero unresolved crashes
- ✅ Corpus documented
- ✅ Results analyzed and documented

---

## Deliverables

### Documentation (5 files):
1. `WEEK-5-CROSS-PLATFORM-VALIDATION-RESULTS.md` - Platform validation report
2. `COVERAGE-GAP-ANALYSIS.md` - Coverage gap identification
3. `test/fuzz/CORPUS.md` - Fuzz corpus documentation
4. `FUZZING-RESULTS-WEEK5.md` - Fuzzing campaign results
5. `WEEK-5-COMPLETE.md` - Week summary

### Code (multiple files):
6. Additional unit tests in `src/test/`
7. Seed corpus files in `test/fuzz/corpus/`
8. Updated `.github/workflows/ci.yml`
9. Platform-specific difficulty results (JSON)

### Data Files:
10. `difficulty_results_windows_mingw.json`
11. `difficulty_results_ubuntu_clang.json`
12. `difficulty_results_macos_clang.json` (if available)
13. `difficulty_results_*` (additional platforms)
14. `test/fuzz/corpus/**/*.dat` (~80 seed files)

---

## Risk Assessment

### High Risk:
1. **Platforms disagree on difficulty**
   - Probability: Low (Week 4 validated algorithm)
   - Impact: CRITICAL (mainnet blocker)
   - Mitigation: Week 4 confirmed integer-only arithmetic
   - Contingency: Implement Bitcoin Core ArithU256 if needed

2. **Fuzzing discovers critical bugs**
   - Probability: Medium (that's the point of fuzzing)
   - Impact: HIGH (security issues)
   - Mitigation: Fix immediately, re-run campaigns
   - Timeline impact: +1-2 days per critical bug

### Medium Risk:
3. **Coverage target not reached**
   - Probability: Low (gap analysis guides effort)
   - Impact: MEDIUM (quality metric)
   - Mitigation: Focus on P0 components, defer P2
   - Acceptable: 68% if P0 components >80%

4. **Platform unavailable (macOS, ARM)**
   - Probability: Medium
   - Impact: LOW (can substitute other platforms)
   - Mitigation: Use Alpine/musl, additional compilers
   - Minimum: 4 platforms required

### Low Risk:
5. **Corpus generation takes longer**
   - Probability: Low
   - Impact: LOW
   - Mitigation: Start with minimal corpus, expand later
   - Minimum: 40 seeds acceptable

6. **CI integration issues**
   - Probability: Low
   - Impact: LOW (can debug quickly)
   - Mitigation: Test locally first
   - Fallback: Manual cross-platform testing documented

---

## Decision Points

### Day 2: Cross-Platform Results
**Question:** Do all tested platforms produce identical results?
- **YES:** Continue to coverage expansion (Track B)
- **NO:** STOP - Fix arithmetic, re-test all platforms

### Day 3: Coverage Progress
**Question:** Is coverage trending toward 70%?
- **YES:** Continue as planned
- **NO:** Prioritize P0 components only, defer P2

### Day 5: Fuzzing Results
**Question:** Any critical crashes discovered?
- **YES:** Fix immediately, document, re-run
- **NO:** Document success, plan Week 6

---

## Week 6 Preview

Based on Week 5 results, Week 6 will focus on:
1. **Performance benchmarking** - Mining, signature verification, block validation
2. **Memory profiling** - Leak detection, optimization
3. **Extended fuzzing** - 24-hour campaigns on all harnesses
4. **Documentation completion** - Architecture, API references
5. **Security audit preparation** - Code review, vulnerability assessment

---

## Conclusion

Week 5 validates Dilithion across multiple platforms, expands test coverage to production-ready levels, and establishes continuous fuzzing infrastructure. The cross-platform validation is EXIT CRITERIA for mainnet - all platforms MUST agree on difficulty calculations.

**Week 5 Status:** Ready to Execute
**Next Action:** Begin Day 1 - Windows MinGW Testing

---

**Document Version:** 1.0
**Created:** November 4, 2025
**Status:** Planning Complete
**Timeline:** November 11-15, 2025 (5 days, 40 hours)
