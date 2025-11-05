# Fuzzing Guide for Dilithion

**Last Updated:** November 5, 2025
**Version:** Week 6 Phase 3

---

## Overview

Fuzzing is a critical component of Dilithion's security testing strategy. This guide covers how to build, run, and extend the fuzzing infrastructure for discovering bugs in consensus-critical code.

**Current Status:**
- **11 fuzzing harnesses** with 50+ individual fuzz targets
- **~3,074 lines** of fuzzing code
- **libFuzzer** with AddressSanitizer and UndefinedBehaviorSanitizer
- Targets cover: cryptography, serialization, validation, consensus, UTXO operations

---

## Quick Start

### Prerequisites

**Required:**
- Clang 14.0+ with libFuzzer support
- AddressSanitizer and UndefinedBehaviorSanitizer
- LevelDB (for UTXO fuzzing)

**Install on Ubuntu/WSL2:**
```bash
sudo apt-get update
sudo apt-get install clang libfuzzer-14-dev libleveldb-dev
```

**Install on macOS:**
```bash
brew install llvm leveldb
export PATH="/usr/local/opt/llvm/bin:$PATH"
```

### Building Fuzzers

**Build all harnesses:**
```bash
make fuzz
```

**Build individual harness:**
```bash
make fuzz_transaction
make fuzz_utxo
```

**Expected output:**
```
✓ All fuzz tests built successfully (11 harnesses, 50+ targets)
  Run individual: ./fuzz_sha3, ./fuzz_transaction, ./fuzz_block, etc.
  With corpus: ./fuzz_transaction fuzz_corpus/transaction/
  Time limit: ./fuzz_block -max_total_time=60
```

### Running Fuzzers

**Basic run (infinite, Ctrl+C to stop):**
```bash
./fuzz_transaction
```

**With time limit (1 hour):**
```bash
./fuzz_transaction -max_total_time=3600
```

**With corpus directory:**
```bash
./fuzz_transaction fuzz_corpus/transaction/
```

**With multiple options:**
```bash
./fuzz_transaction \
  -max_total_time=3600 \
  -max_len=100000 \
  -timeout=10 \
  fuzz_corpus/transaction/
```

---

## Fuzzing Harnesses

### 1. SHA-3 Hashing (`fuzz_sha3`)
**File:** `src/test/fuzz/fuzz_sha3.cpp`
**Targets:** 1
**Priority:** P2

Tests SHA-3 hashing implementation against malformed inputs.

**Run:**
```bash
./fuzz_sha3 -max_total_time=600
```

### 2. Transaction Serialization (`fuzz_transaction`)
**File:** `src/test/fuzz/fuzz_transaction.cpp`
**Targets:** 3
**Priority:** P1 HIGH

Tests:
- Transaction deserialization from arbitrary bytes
- Round-trip serialization consistency
- Signature data handling

**Run:**
```bash
./fuzz_transaction -max_total_time=3600 fuzz_corpus/transaction/
```

**Expected executions:** 500K-1M+ per second

### 3. Block Validation (`fuzz_block`)
**File:** `src/test/fuzz/fuzz_block.cpp`
**Targets:** 4
**Priority:** P1 HIGH

Tests block header validation, transaction deserialization, merkle root calculation.

**Run:**
```bash
./fuzz_block -max_total_time=3600 fuzz_corpus/block/
```

### 4. CompactSize Encoding (`fuzz_compactsize`)
**File:** `src/test/fuzz/fuzz_compactsize.cpp`
**Targets:** 5
**Priority:** P2

Tests Bitcoin-style variable-length integer encoding.

### 5. Network Messages (`fuzz_network_message`)
**File:** `src/test/fuzz/fuzz_network_message.cpp`
**Targets:** 4
**Priority:** P2

Tests network protocol message parsing and creation.

### 6. Address Encoding (`fuzz_address`)
**File:** `src/test/fuzz/fuzz_address.cpp`
**Targets:** 5
**Priority:** P2

Tests Base58 and Bech32 address encoding/decoding.

### 7. Difficulty Calculation (`fuzz_difficulty`)
**File:** `src/test/fuzz/fuzz_difficulty.cpp`
**Targets:** 6
**Priority:** P1 HIGH

Tests proof-of-work difficulty adjustment (consensus-critical).

**Run:**
```bash
./fuzz_difficulty -max_total_time=3600
```

### 8. Block Subsidy (`fuzz_subsidy`)
**File:** `src/test/fuzz/fuzz_subsidy.cpp`
**Targets:** 7
**Priority:** P2

Tests coinbase reward calculation and halving logic.

### 9. Merkle Tree (`fuzz_merkle`)
**File:** `src/test/fuzz/fuzz_merkle.cpp`
**Targets:** 7
**Priority:** P1 HIGH

Tests merkle tree construction and validation.

### 10. Transaction Validation (`fuzz_tx_validation`) ⭐ NEW
**File:** `src/test/fuzz/fuzz_tx_validation.cpp`
**Targets:** 4
**Priority:** P0 CRITICAL

Tests:
- `tx_validation_basic` - CheckTransactionBasic validation
- `tx_validation_inputs` - UTXO-based input validation
- `tx_validation_coinbase` - Coinbase maturity checks
- `tx_validation_fees` - Fee calculation with overflow conditions

**Run:**
```bash
./fuzz_tx_validation -max_total_time=7200 fuzz_corpus/validation/
```

**Why critical:** Recently had bugs in Phase 2, consensus-critical validation logic.

### 11. UTXO Set Operations (`fuzz_utxo`) ⭐ NEW
**File:** `src/test/fuzz/fuzz_utxo.cpp`
**Targets:** 4
**Priority:** P0 CRITICAL

Tests:
- `utxo_operations` - AddUTXO, SpendUTXO, HaveUTXO, GetUTXO operations
- `utxo_cache_sync` - Cache synchronization (critical post-Phase 2 fixes)
- `utxo_block_ops` - ApplyBlock and UndoBlock operations

**Run:**
```bash
./fuzz_utxo -max_total_time=7200 fuzz_corpus/utxo/
```

**Why critical:** Cache synchronization bugs fixed in Phase 2, state management is critical.

---

## Corpus Management

### What is a Corpus?

A **seed corpus** is a collection of input files that provide good starting coverage for fuzzing. The fuzzer will mutate these seeds to explore new code paths.

### Corpus Structure

```
fuzz_corpus/
├── transaction/      # Transaction test cases
│   ├── valid_basic.bin
│   ├── coinbase.bin
│   ├── multi_input.bin
│   └── ...
├── block/           # Block test cases
│   ├── genesis.bin
│   ├── single_tx.bin
│   └── ...
├── validation/      # Validation test cases
├── utxo/           # UTXO operation sequences
└── difficulty/     # Difficulty test cases
```

### Creating Corpus Files

**From test cases:**
```cpp
// In test file
CTransaction tx = CreateTestTransaction();
std::vector<uint8_t> data = tx.Serialize();

// Write to file
std::ofstream out("fuzz_corpus/transaction/valid_basic.bin", std::ios::binary);
out.write(reinterpret_cast<const char*>(data.data()), data.size());
```

**Manually:**
```bash
# Create a minimal transaction (example)
echo -ne '\x01\x00\x00\x00' > fuzz_corpus/transaction/minimal.bin  # version
echo -ne '\x00' >> fuzz_corpus/transaction/minimal.bin              # 0 inputs
echo -ne '\x00' >> fuzz_corpus/transaction/minimal.bin              # 0 outputs
echo -ne '\x00\x00\x00\x00' >> fuzz_corpus/transaction/minimal.bin  # locktime
```

### Corpus Best Practices

1. **Start Small:** 5-10 seed files per fuzzer is sufficient
2. **Include Edge Cases:**
   - Minimum size (empty/minimal)
   - Maximum size (large transactions/blocks)
   - Boundary values (zero, MAX_UINT64)
   - Malformed inputs (truncated, invalid)
3. **Use Real Data:** Extract from actual tests or mainnet
4. **Minimize Corpus:** Use `libFuzzer -merge` to remove redundant inputs

### Corpus Minimization

After fuzzing, minimize the corpus to remove redundant files:

```bash
mkdir fuzz_corpus/transaction_min
./fuzz_transaction -merge=1 fuzz_corpus/transaction_min fuzz_corpus/transaction
```

---

## Interpreting Results

### Normal Output

```
#1      INITED cov: 245 ft: 245 corp: 1/1b exec/s: 0 rss: 30Mb
#2      NEW    cov: 251 ft: 252 corp: 2/3b lim: 4 exec/s: 0 rss: 30Mb
#1000   pulse  cov: 312 ft: 389 corp: 23/456b lim: 11 exec/s: 500 rss: 32Mb
#10000  pulse  cov: 324 ft: 412 corp: 45/1234b lim: 105 exec/s: 5000 rss: 35Mb
```

**Key Metrics:**
- `cov`: Coverage (edges covered)
- `ft`: Features (unique code paths)
- `corp`: Corpus (number of interesting inputs / total size)
- `exec/s`: Executions per second (speed)
- `rss`: Memory usage

**Good Signs:**
- Coverage increases over time (especially early on)
- High exec/s (>1000 for simple harnesses, >100 for complex)
- Corpus grows initially then stabilizes

**Bad Signs:**
- Coverage stops growing quickly (<1 minute)
- Very low exec/s (<10) - harness may be too slow
- Memory usage grows unbounded - memory leak

### Crash Detection

When fuzzer finds a crash:

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 4 at 0x... thread T0
    #0 0x... in CTransaction::Deserialize ...
    #1 0x... in LLVMFuzzerTestOneInput ...

SUMMARY: AddressSanitizer: heap-buffer-overflow
```

**Crash file saved:** `crash-<hash>`

### Reproducing Crashes

```bash
# Run fuzzer on crash file
./fuzz_transaction crash-a1b2c3d4e5f6

# With more debugging info
./fuzz_transaction -print_final_stats=1 crash-a1b2c3d4e5f6

# Under GDB
gdb --args ./fuzz_transaction crash-a1b2c3d4e5f6
```

---

## Crash Triage

### Severity Classification

**CRITICAL (Fix Immediately):**
- Memory corruption (heap/stack buffer overflow, use-after-free)
- Crashes in validated code paths (after passing all checks)
- Consensus bugs (invalid transactions accepted, double-spend allowed)
- State corruption (database inconsistency, cache desync)

**HIGH (Fix Soon):**
- Null pointer dereferences in edge cases
- Assertion failures in production code
- Memory leaks in error paths
- Integer overflows affecting behavior

**MEDIUM (Fix When Convenient):**
- Assertion failures in debug-only code
- Timeout on pathological inputs (if properly bounded)
- Minor memory leaks

**LOW/EXPECTED (Document Only):**
- Crashes on completely malformed input with proper error handling
- Fuzzer reaching maximum memory/time limits
- Assertion failures in fuzzer harness itself (not production code)

### Triage Checklist

For each crash:
1. **Reproduce:** Run fuzzer on crash file
2. **Categorize:** Which severity level?
3. **Minimize:** Use `-minimize_crash=1` to create minimal reproducer
4. **Document:** Save stack trace, analysis, severity
5. **Create Test:** Add reproducer to regression test suite
6. **Fix:** Patch root cause (for CRITICAL/HIGH)
7. **Verify:** Re-run fuzzer, confirm no crash
8. **Regression Check:** Run full test suite (`make test`)

---

## Advanced Usage

### Parallel Fuzzing

Run multiple fuzzer instances in parallel:

```bash
# Terminal 1
./fuzz_transaction -max_total_time=3600 fuzz_corpus/transaction/ &

# Terminal 2
./fuzz_block -max_total_time=3600 fuzz_corpus/block/ &

# Terminal 3
./fuzz_utxo -max_total_time=3600 fuzz_corpus/utxo/ &

# Wait for all
wait
```

### Coverage-Guided Campaigns

```bash
# Generate coverage data
./fuzz_transaction \
  -print_pcs=1 \
  -print_coverage=1 \
  -max_total_time=3600 \
  fuzz_corpus/transaction/ \
  > coverage.txt

# Analyze coverage
grep "cov:" coverage.txt | tail -1
```

### Dictionary Hints

Create a dictionary file with known tokens:

```
# transaction.dict
"version"
"locktime"
"vin"
"vout"
"\x01\x00\x00\x00"  # Version 1
"\xff\xff\xff\xff"  # Null prevout
```

**Use dictionary:**
```bash
./fuzz_transaction -dict=transaction.dict fuzz_corpus/transaction/
```

### Continuous Integration

Add to CI pipeline:

```yaml
# .github/workflows/fuzz.yml
- name: Build fuzzers
  run: make fuzz

- name: Run short fuzzing campaign
  run: |
    ./fuzz_transaction -max_total_time=60 -timeout=10
    ./fuzz_block -max_total_time=60 -timeout=10
    ./fuzz_utxo -max_total_time=60 -timeout=10
```

---

## Creating New Fuzz Targets

### Step 1: Create Harness File

```cpp
// src/test/fuzz/fuzz_mynewfeature.cpp
#include "fuzz.h"
#include "util.h"
#include "../../mynewfeature.h"

/**
 * Fuzz target: My New Feature
 * Tests: [what it tests]
 * Coverage: [what files]
 * Priority: [P0-P2]
 */

FUZZ_TARGET(mynewfeature_basic)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Use fuzzed_data to create inputs
        uint32_t value = fuzzed_data.ConsumeIntegral<uint32_t>();

        // Call function under test
        MyNewFeature(value);

    } catch (const std::exception& e) {
        // Expected for invalid inputs
        return;
    }
}
```

### Step 2: Add to Makefile

```makefile
# Add source variable
FUZZ_MYNEWFEATURE_SOURCE := src/test/fuzz/fuzz_mynewfeature.cpp

# Add binary variable
FUZZ_MYNEWFEATURE := fuzz_mynewfeature

# Add to fuzz target
fuzz: ... fuzz_mynewfeature

# Add build target
fuzz_mynewfeature: $(FUZZ_MYNEWFEATURE_SOURCE) [dependencies] $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ]$(COLOR_RESET) Building $@..."
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) $^ -o $@
```

### Step 3: Create Seed Corpus

```bash
mkdir -p fuzz_corpus/mynewfeature
# Add seed files...
```

### Step 4: Test

```bash
make fuzz_mynewfeature
./fuzz_mynewfeature -max_total_time=60
```

---

## Troubleshooting

### Fuzzer Won't Compile

**Error:** `clang++: command not found`

**Fix:**
```bash
# Ubuntu/WSL2
sudo apt-get install clang

# macOS
brew install llvm
export PATH="/usr/local/opt/llvm/bin:$PATH"
```

**Error:** `-fsanitize=fuzzer: unsupported`

**Fix:** Install libFuzzer support:
```bash
sudo apt-get install libfuzzer-14-dev
```

### Fuzzer Runs Too Slowly

**Symptoms:** exec/s < 10

**Possible Causes:**
1. Harness does expensive operations (disk I/O, database writes)
2. Harness creates large objects
3. Too many iterations per input

**Fixes:**
- Use in-memory operations where possible
- Limit input size: `-max_len=1000`
- Simplify harness logic
- Profile with `perf` to find hotspots

### No Coverage Growth

**Symptoms:** Coverage stops at <50% within 1 minute

**Possible Causes:**
1. Missing seed corpus (fuzzer exploring blindly)
2. Function under test has limited code paths
3. Harness not exercising function properly

**Fixes:**
- Add diverse seed corpus
- Use dictionary hints
- Verify harness actually calls target function
- Check function implementation complexity

### Out of Memory

**Symptoms:** Fuzzer crashes with OOM

**Possible Causes:**
1. Memory leak in target function
2. Fuzzer finding pathological inputs
3. Corpus files too large

**Fixes:**
- Limit RSS: `-rss_limit_mb=2048`
- Limit input size: `-max_len=100000`
- Fix memory leaks in code
- Minimize corpus

### Fuzzer Hangs

**Symptoms:** No output, high CPU, but no progress

**Possible Causes:**
1. Infinite loop in target function
2. Timeout too high

**Fixes:**
- Set timeout: `-timeout=10` (10 seconds per input)
- Add progress output to code
- Review target function for loops

---

## Resources

### libFuzzer Documentation
- Official docs: https://llvm.org/docs/LibFuzzer.html
- Tutorial: https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md

### Sanitizers
- AddressSanitizer: https://clang.llvm.org/docs/AddressSanitizer.html
- UndefinedBehaviorSanitizer: https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html

### Best Practices
- Google fuzzing best practices: https://github.com/google/fuzzing
- LLVM fuzzing techniques: https://llvm.org/docs/FuzzingLLVM.html

---

## FAQ

**Q: How long should I fuzz?**
A: Start with 1 hour per harness. For critical components (P0), fuzz for 4+ hours. For comprehensive testing, 24-48 hours.

**Q: How do I know when I've fuzzed enough?**
A: When coverage plateaus (no growth for >1 hour) and no new crashes for several hours.

**Q: Should I fuzz on every commit?**
A: Run short campaigns (60 seconds) in CI. Run longer campaigns (hours) before releases.

**Q: What's a good exec/s rate?**
A: Depends on complexity:
- Simple functions (crypto primitives): 100K-1M+ exec/s
- Medium functions (deserialization): 10K-100K exec/s
- Complex functions (validation with DB): 100-10K exec/s

**Q: Are all crashes bugs?**
A: No! Many crashes are expected (invalid input rejected properly). Only crashes that bypass validation or corrupt state are bugs.

**Q: Can fuzzing prove correctness?**
A: No. Fuzzing finds bugs but can't prove absence of bugs. Use with formal verification, code review, and comprehensive testing.

---

**Document Version:** 1.0 (Week 6 Phase 3)
**Last Updated:** November 5, 2025
**Maintained By:** Dilithion Core Developers
