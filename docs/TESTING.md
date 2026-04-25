# Testing Guide

Comprehensive testing strategy and guide for Dilithion development.

---

## Table of Contents

1. [Overview](#overview)
2. [Test Types](#test-types)
3. [Running Tests](#running-tests)
4. [Writing Tests](#writing-tests)
5. [Test Coverage](#test-coverage)
6. [CI/CD Integration](#cicd-integration)

---

## Overview

### Testing Philosophy

**Every line of code must be tested. No exceptions.**

Testing is not optional—it's the foundation of reliability and security for a cryptocurrency system.

### Test Pyramid

```
           /\
          /  \     E2E Tests (Few)
         /____\
        /      \   Integration Tests (Some)
       /________\
      /          \ Unit Tests (Many)
     /____________\
```

### Coverage Targets

| Code Type | Line Coverage | Branch Coverage |
|-----------|---------------|-----------------|
| New Code | 100% | 100% |
| Modified Code | Maintain/Improve | Maintain/Improve |
| Critical Code | 100% | 100% |
| Total Project | >90% | >85% |

---

## Test Types

### 1. Unit Tests

**Purpose:** Test individual functions and classes
**Framework:** Boost Test
**Location:** `src/test/`
**Run Time:** <5 minutes
**When:** Every commit

**Example:**
```cpp
BOOST_AUTO_TEST_SUITE(dilithium_tests)

BOOST_AUTO_TEST_CASE(key_generation_creates_valid_key) {
    CKey key;
    BOOST_CHECK(key.MakeNewKey());
    BOOST_CHECK(key.IsValid());
    BOOST_CHECK_EQUAL(key.size(), 2560);
}

BOOST_AUTO_TEST_SUITE_END()
```

### 2. Functional Tests

**Purpose:** Test node behavior and features
**Framework:** Python (Bitcoin Core framework)
**Location:** `test/functional/`
**Run Time:** 30-60 minutes
**When:** Before merge

**Example:**
```python
class DilithiumFeatureTest(BitcoinTestFramework):
    def run_test(self):
        # Test feature end-to-end
        self.test_transaction_creation()
        self.test_block_validation()
```

### 3. Integration Tests

**Purpose:** Test system as a whole
**Location:** `test/integration/`
**Run Time:** 1-2 hours
**When:** Weekly, before releases

### 4. Fuzz Tests

**Purpose:** Find edge cases and crashes
**Framework:** AFL, libFuzzer
**Location:** `src/test/fuzz/`
**Run Time:** Continuous
**When:** Always running in background

### 5. Performance Tests

**Purpose:** Ensure acceptable performance
**Framework:** Google Benchmark
**Location:** `src/bench/`
**Run Time:** 5-10 minutes
**When:** Before releases, after optimizations

---

## Running Tests

### Quick Start

```bash
# Build with tests
./autogen.sh
./configure
make -j$(nproc)

# Run all unit tests
make check

# Run all functional tests
test/functional/test_runner.py

# Run specific unit test
./src/test/test_bitcoin --run_test=dilithium_tests

# Run specific functional test
test/functional/feature_dilithium.py
```

### Unit Tests

```bash
# All unit tests
make check

# Specific test suite
./src/test/test_bitcoin --run_test=dilithium_tests

# Specific test case
./src/test/test_bitcoin --run_test=dilithium_tests/key_generation

# With verbose output
./src/test/test_bitcoin --log_level=all

# List all tests
./src/test/test_bitcoin --list_content
```

### Functional Tests

```bash
# All functional tests
test/functional/test_runner.py

# Specific test
test/functional/feature_dilithium.py

# With verbose output
test/functional/feature_dilithium.py --loglevel=debug

# Parallel execution (faster)
test/functional/test_runner.py -j4

# Extended tests (longer running)
test/functional/test_runner.py --extended
```

### Coverage Analysis

```bash
# Build with coverage
./configure --enable-coverage
make clean
make -j$(nproc)

# Run tests
make check

# Generate coverage report
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage.info
lcov --remove coverage.info '*/test/*' --output-file coverage.info
genhtml coverage.info --output-directory coverage-report

# View report
open coverage-report/index.html
```

---

## Writing Tests

### Unit Test Template

```cpp
// src/test/dilithium_tests.cpp
#include <boost/test/unit_test.hpp>
#include <key.h>
#include <pubkey.h>

BOOST_AUTO_TEST_SUITE(dilithium_tests)

BOOST_AUTO_TEST_CASE(descriptive_test_name) {
    // Arrange: Set up test data
    CKey key;
    key.MakeNewKey();

    // Act: Perform the operation
    CPubKey pubkey = key.GetPubKey();

    // Assert: Verify results
    BOOST_CHECK(pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), 1312);
}

BOOST_AUTO_TEST_SUITE_END()
```

### Functional Test Template

```python
# test/functional/feature_dilithium.py
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class DilithiumTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        self.log.info("Starting Dilithium test...")

        # Test logic here
        addr = self.nodes[0].getnewaddress()
        assert_equal(len(addr), 52)  # Dilithion addresses are longer

if __name__ == '__main__':
    DilithiumTest().main()
```

### Test Best Practices

**DO:**
- Test one thing per test case
- Use descriptive test names
- Test both success and failure paths
- Test edge cases and boundaries
- Keep tests fast and focused
- Make tests deterministic

**DON'T:**
- Test multiple things in one test
- Use vague names like `test1`
- Only test happy paths
- Make tests depend on each other
- Make tests slow
- Use random values without seeds

---

## Test Coverage

### Critical Code (100% Required)

- `src/key.cpp` - Private key operations
- `src/pubkey.cpp` - Public key operations
- `src/crypto/dilithium/*` - Dilithium implementation
- `src/script/interpreter.cpp` - Signature verification
- `src/validation.cpp` - Consensus rules
- `src/consensus/*` - All consensus code

### Coverage Tools

```bash
# Generate coverage
lcov --capture --directory . --output-file coverage.info

# Filter coverage
lcov --remove coverage.info '/usr/*' '*/test/*' --output-file coverage.info

# Generate HTML report
genhtml coverage.info --output-directory coverage-report

# Check coverage threshold
lcov --summary coverage.info | grep "lines......" | awk '{print $2}'
```

### Coverage Metrics

**Line Coverage:**
```
Lines executed: 95.2% of 12543 lines
```

**Branch Coverage:**
```
Branches executed: 87.4% of 4521 branches
```

**Function Coverage:**
```
Functions executed: 98.1% of 1842 functions
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y build-essential libboost-all-dev

    - name: Build
      run: |
        ./autogen.sh
        ./configure
        make -j$(nproc)

    - name: Unit Tests
      run: make check

    - name: Functional Tests
      run: test/functional/test_runner.py

    - name: Coverage
      run: |
        lcov --capture --directory . --output-file coverage.info
        bash <(curl -s https://codecov.io/bash)
```

### Test Stages

**Stage 1: Fast Tests (< 5 min)**
- Linting
- Unit tests
- Quick smoke tests

**Stage 2: Integration (< 30 min)**
- Functional tests
- Integration tests

**Stage 3: Extended (< 2 hours)**
- Fuzz tests
- Performance tests
- Coverage analysis

---

## Test Data

### Test Vectors

```cpp
// NIST test vectors for Dilithium
struct DilithiumTestVector {
    std::string seed;
    std::string public_key;
    std::string secret_key;
    std::string message;
    std::string signature;
};

// Load from file
std::vector<DilithiumTestVector> LoadNISTVectors() {
    // Parse NIST test vector file
}

// Test against vectors
BOOST_AUTO_TEST_CASE(nist_test_vectors) {
    auto vectors = LoadNISTVectors();
    for (const auto& vec : vectors) {
        // Verify implementation matches NIST
    }
}
```

### Test Utilities

```cpp
// test/util/dilithium_test_util.h
namespace DilithiumTestUtil {
    CKey CreateTestKey();
    CTransaction CreateTestTx();
    CBlock CreateTestBlock();
}
```

---

## Troubleshooting

### Tests Fail Randomly

**Problem:** Flaky tests
**Solution:**
- Avoid time-dependent tests
- Use deterministic random seeds
- Increase timeouts if needed
- Fix race conditions

### Tests Are Slow

**Problem:** Test suite takes too long
**Solution:**
- Run unit tests in parallel
- Optimize slow tests
- Move slow tests to extended suite
- Use test fixtures to reuse setup

### Coverage Not Improving

**Problem:** Can't reach coverage target
**Solution:**
- Identify uncovered lines: `lcov --list coverage.info`
- Write tests for uncovered code
- Remove dead code
- Test error paths

---

## Resources

- [Boost Test Documentation](https://www.boost.org/doc/libs/release/libs/test/)
- [Bitcoin Core Test Framework](https://github.com/bitcoin/bitcoin/tree/master/test)
- [Google Test Best Practices](https://google.github.io/googletest/)

---

**Remember:** Tests are not a burden—they're your safety net. Write them early, run them often, trust them completely.
