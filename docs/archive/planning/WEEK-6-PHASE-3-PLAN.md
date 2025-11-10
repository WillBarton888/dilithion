# Week 6 Phase 3 - Fuzzing Infrastructure Plan

**Date:** November 5, 2025
**Phase:** Phase 3 of 4 (Fuzzing Infrastructure)
**Duration:** 12 hours (estimated)
**Prerequisites:** ✅ Phase 2 complete (251/251 tests passing)

---

## Objectives

### Primary Goals:
1. Create fuzzing harnesses for critical components
2. Build initial fuzzing corpus
3. Integrate with AFL++ or libFuzzer
4. Run initial fuzzing campaigns
5. Document and fix any findings

### Success Criteria:
- ✅ 5-8 fuzzing harnesses created
- ✅ Fuzzing infrastructure integrated into build system
- ✅ Initial corpus generated from test cases
- ✅ 24-hour fuzzing campaign completed
- ✅ All critical findings fixed

---

## Target Components for Fuzzing

### Priority 1: Critical (Must Fuzz)
1. **Transaction Deserialization** (CTransaction::Deserialize)
   - Input: Raw bytes
   - Why: Direct network input, complex parsing, history of bugs
   - Risk: Memory corruption, DoS, consensus bugs

2. **Block Deserialization** (DeserializeBlockTransactions)
   - Input: Raw bytes
   - Why: Network-facing, multiple transactions
   - Risk: Memory corruption, consensus bugs

3. **Transaction Validation** (CheckTransactionBasic)
   - Input: Crafted transactions
   - Why: Consensus-critical validation logic
   - Risk: Invalid transactions accepted, DoS

### Priority 2: High (Should Fuzz)
4. **UTXO Operations** (AddUTXO, SpendUTXO, ApplyBlock)
   - Input: Transaction outputs, blocks
   - Why: State management, recently had cache bugs
   - Risk: Double-spend, state corruption

5. **Difficulty Calculation** (GetNextWorkRequired)
   - Input: Block timestamps, heights
   - Why: Consensus-critical, complex logic
   - Risk: Chain split, mining attacks

### Priority 3: Medium (Nice to Fuzz)
6. **Script Validation** (Future - not yet implemented)
7. **P2P Message Parsing** (Future)
8. **Merkle Tree Building** (BuildMerkleRoot)

---

## Fuzzing Architecture

### Approach: Hybrid Fuzzing
- **Structure-Aware Fuzzing:** Use protobuf/custom grammar for valid structures
- **Mutation-Based Fuzzing:** AFL++ for byte-level mutations
- **Coverage-Guided:** libFuzzer for maximizing code coverage

### Tools:
- **Primary:** libFuzzer (built into Clang)
- **Secondary:** AFL++ (for long campaigns)
- **Analysis:** llvm-cov for coverage tracking

---

## Implementation Plan

### Phase 3.1: Setup Fuzzing Infrastructure (2 hours)

**Tasks:**
1. Create `src/fuzz/` directory structure
2. Add fuzzing targets to Makefile
3. Create fuzzing-specific build configuration
4. Set up corpus and crash directories

**Deliverables:**
- `src/fuzz/fuzz_transaction.cpp`
- `src/fuzz/fuzz_block.cpp`
- `Makefile` fuzzing targets
- `fuzz_corpus/` directory structure

### Phase 3.2: Transaction Fuzzing Harness (2 hours)

**Target:** CTransaction::Deserialize

**Harness Design:**
```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Deserialize transaction
    CTransaction tx;
    std::string error;
    tx.Deserialize(data, size, &error);

    // If successful, validate
    if (tx.vin.size() > 0 && tx.vout.size() > 0) {
        tx.CheckBasicStructure();
        tx.GetHash();
        tx.GetSerializedSize();
    }

    return 0;
}
```

**Corpus Generation:**
- Extract serialized transactions from existing tests
- Include edge cases: empty, oversized, malformed

**Success Metrics:**
- Harness compiles and runs
- 1M+ executions per second
- Initial corpus: 50+ samples

### Phase 3.3: Block Fuzzing Harness (2 hours)

**Target:** DeserializeBlockTransactions

**Harness Design:**
```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    CBlock block;
    block.vtx.assign(data, data + size);

    std::vector<CTransactionRef> transactions;
    std::string error;

    CBlockValidator validator;
    validator.DeserializeBlockTransactions(block, transactions, error);

    // If successful, build merkle root
    if (!transactions.empty()) {
        validator.BuildMerkleRoot(transactions);
    }

    return 0;
}
```

**Corpus Generation:**
- Extract block data from tests
- Include: single tx, multiple tx, empty, oversized

**Success Metrics:**
- Harness compiles and runs
- 500K+ executions per second
- Initial corpus: 30+ samples

### Phase 3.4: Transaction Validation Fuzzing (2 hours)

**Target:** CheckTransactionBasic + CheckTransactionInputs

**Harness Design:**
```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Deserialize transaction
    CTransaction tx;
    std::string error;
    if (!tx.Deserialize(data, size, &error)) {
        return 0;
    }

    // Validate
    CTransactionValidator validator;
    validator.CheckTransactionBasic(tx, error);

    // Create minimal UTXO set for input validation
    CUTXOSet utxo;
    // ... populate with fuzzer-controlled UTXOs
    CAmount fee;
    validator.CheckTransactionInputs(tx, utxo, 100, fee, error);

    return 0;
}
```

**Success Metrics:**
- Harness compiles and runs
- 100K+ executions per second
- Initial corpus: 40+ samples

### Phase 3.5: UTXO Operations Fuzzing (2 hours)

**Target:** ApplyBlock, UndoBlock, AddUTXO, SpendUTXO

**Harness Design:**
```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Parse fuzzer input as sequence of operations
    FuzzedDataProvider fdp(data, size);

    CUTXOSet utxo;
    std::string path = CreateTempUTXOSet(utxo);

    while (fdp.remaining_bytes() > 0) {
        uint8_t op = fdp.ConsumeIntegral<uint8_t>() % 4;

        switch(op) {
            case 0: // AddUTXO
                // ... consume bytes to create UTXO
                break;
            case 1: // SpendUTXO
                // ... consume bytes to spend UTXO
                break;
            case 2: // ApplyBlock
                // ... consume bytes to create block
                break;
            case 3: // UndoBlock
                // ... undo last block
                break;
        }
    }

    utxo.Close();
    CleanupTempUTXOSet(path);
    return 0;
}
```

**Success Metrics:**
- Harness compiles and runs
- 50K+ executions per second
- Initial corpus: 20+ samples

### Phase 3.6: Initial Fuzzing Campaign (2 hours)

**Campaign Setup:**
- Run each harness for 2 hours (12 hours total wall time)
- Monitor for crashes, hangs, memory leaks
- Track coverage metrics

**Monitoring:**
```bash
# Transaction fuzzing
./fuzz_transaction -max_total_time=7200 -print_final_stats=1 corpus/transaction/

# Block fuzzing
./fuzz_block -max_total_time=7200 -print_final_stats=1 corpus/block/

# etc.
```

**Success Metrics:**
- No crashes in valid code paths
- Coverage > 60% for fuzzed components
- All findings documented

---

## Expected Findings

### Likely Issues:
1. **Integer overflows** in size calculations
2. **Out-of-bounds reads** in parsing logic
3. **Null pointer dereferences** in edge cases
4. **Memory leaks** in error paths
5. **Assertion failures** on invalid inputs

### Acceptable Findings:
- Crashes on completely invalid input (with proper error handling)
- Timeouts on pathological inputs (with reasonable limits)
- Memory usage within bounds

### Unacceptable Findings:
- Crashes that bypass validation
- Memory corruption
- Undefined behavior in reachable code
- Consensus bugs

---

## Deliverables

### Code:
1. `src/fuzz/fuzz_transaction.cpp`
2. `src/fuzz/fuzz_block.cpp`
3. `src/fuzz/fuzz_validation.cpp`
4. `src/fuzz/fuzz_utxo.cpp`
5. `src/fuzz/fuzz_difficulty.cpp`
6. `Makefile` fuzzing targets

### Corpus:
1. `fuzz_corpus/transaction/` (50+ samples)
2. `fuzz_corpus/block/` (30+ samples)
3. `fuzz_corpus/validation/` (40+ samples)
4. `fuzz_corpus/utxo/` (20+ samples)

### Documentation:
1. `FUZZING.md` - How to run fuzzers
2. `WEEK-6-PHASE-3-RESULTS.md` - Campaign results
3. Crash reports (if any)

---

## Risk Assessment

### High Risk:
- ⚠️ Fuzzing may uncover critical consensus bugs
- ⚠️ Fixes may require extensive testing
- ⚠️ May delay Phase 4 if critical bugs found

### Mitigation:
- ✅ Focus on input validation bugs first
- ✅ Separate "expected" crashes from real bugs
- ✅ Prioritize fixes by severity
- ✅ Run existing test suite after each fix

### Low Risk:
- ✅ All existing tests passing
- ✅ Strong foundation from Phase 2
- ✅ Clear separation of fuzzing code

---

## Timeline

### Hour-by-Hour Breakdown:
- **Hours 0-2:** Setup infrastructure, Makefile integration
- **Hours 2-4:** Transaction fuzzing harness + corpus
- **Hours 4-6:** Block fuzzing harness + corpus
- **Hours 6-8:** Validation fuzzing harness + corpus
- **Hours 8-10:** UTXO fuzzing harness + corpus
- **Hours 10-12:** Initial campaign, analysis, documentation

### Checkpoints:
- ✅ Hour 2: First harness running
- ✅ Hour 6: 3 harnesses running
- ✅ Hour 10: All harnesses complete
- ✅ Hour 12: Results documented

---

## Success Criteria

### Phase 3 Complete When:
1. ✅ 5 fuzzing harnesses created and working
2. ✅ Initial corpus generated (140+ samples total)
3. ✅ 12-hour fuzzing campaign completed
4. ✅ All critical findings fixed
5. ✅ All existing tests still passing
6. ✅ Documentation complete

### Quality Standards:
- A+ code quality
- Professional documentation
- Comprehensive coverage
- No regressions

---

## Next Phase Preview

**Phase 4: Final Verification & Documentation**
- Duration: 6 hours
- Goals:
  - Extended fuzzing campaign (48+ hours)
  - Final coverage analysis
  - Performance benchmarking
  - Complete project documentation
  - Prepare for security audit

---

**Prepared:** November 5, 2025
**Status:** Ready to begin Phase 3
**Prerequisites:** ✅ All complete
**Next Action:** Create fuzzing infrastructure
