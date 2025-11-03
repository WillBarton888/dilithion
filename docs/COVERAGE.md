# Code Coverage Guide

**Last Updated:** November 3, 2025 (Week 4)
**Coverage Tool:** LCOV with genhtml
**Target Coverage:** 60% by Week 4, 80%+ for mainnet

---

## Quick Start

### Run Coverage Locally

```bash
# Build with coverage instrumentation and generate report
make coverage

# View report
open coverage_html/index.html  # macOS
xdg-open coverage_html/index.html  # Linux
start coverage_html/index.html  # Windows

# Clean coverage data
make coverage-clean
```

### Prerequisites

**Install LCOV:**
```bash
# Ubuntu/Debian
sudo apt-get install lcov

# macOS
brew install lcov

# Windows (MSYS2)
pacman -S mingw-w64-x86_64-lcov
```

---

## Understanding Coverage

### Coverage Metrics

**Line Coverage:**
- Percentage of code lines executed during tests
- Primary metric tracked
- Target: 60% by Week 4, 80%+ for mainnet

**Branch Coverage:**
- Percentage of conditional branches taken
- Important for testing edge cases
- Target: 70%+ for critical code

**Function Coverage:**
- Percentage of functions called
- Ensures all functions are tested
- Target: 85%+ for critical code

### Reading the Report

**Coverage HTML Report Structure:**
```
coverage_html/
├── index.html          # Main summary page
├── src/
│   ├── consensus/
│   │   ├── pow.cpp.gcov.html     # Per-file coverage
│   │   └── validation.cpp.gcov.html
│   ├── net/
│   ├── wallet/
│   └── ...
└── gcov.css            # Styling
```

**Color Coding:**
- **Green:** Line executed during tests ✅
- **Red:** Line not executed ❌
- **Orange:** Branch partially covered ⚠️
- **Gray:** Non-executable line (comments, braces)

---

## Coverage Targets by Component

### P0 Components (Consensus-Critical) - 80%+ Required

```
src/consensus/pow.cpp              Target: 90%+
src/consensus/validation.cpp       Target: 90%+
src/consensus/subsidy.cpp          Target: 95%+
src/primitives/block.cpp           Target: 85%+
src/primitives/transaction.cpp     Target: 85%+
src/crypto/dilithium3.cpp          Target: 90%+
```

### P1 Components (High Priority) - 70%+ Required

```
src/net/protocol.cpp               Target: 75%+
src/net/serialize.cpp              Target: 80%+
src/wallet/wallet.cpp              Target: 70%+
src/rpc/*.cpp                      Target: 70%+
src/node/mempool.cpp               Target: 75%+
```

### P2 Components (Medium Priority) - 60%+ Desired

```
src/util/*.cpp                     Target: 60%+
src/base58.cpp                     Target: 70%+
src/support/*.cpp                  Target: 60%+
```

### P3 Components (Low Priority) - 40%+ Acceptable

```
src/cli/*.cpp                      Target: 40%+
src/test/*.cpp                     Target: N/A (test code)
depends/*                          Target: N/A (external)
```

---

## How to Improve Coverage

### 1. Identify Gaps

**Find uncovered code:**
```bash
# Run coverage
make coverage

# Look at coverage_html/index.html
# Sort by coverage % (ascending)
# Focus on files with < 50% coverage in P0/P1 components
```

**Example Gap Analysis:**
```
File                              Coverage  Priority  Action
──────────────────────────────────────────────────────────────
src/consensus/pow.cpp             30%       P0        URGENT
src/wallet/wallet.cpp             25%       P1        HIGH
src/net/protocol.cpp              45%       P1        MEDIUM
src/util/string.cpp               20%       P2        LOW
```

### 2. Write Tests for Gaps

**Focus Areas:**
- **Consensus code:** Add unit tests in `src/test/`
- **Network code:** Add functional tests in `test/functional/`
- **Edge cases:** Boundary conditions, error paths
- **Error handling:** Force error conditions

**Example: Covering Error Paths**
```cpp
// This error path is likely uncovered:
if (signature.size() != DILITHIUM3_SIGNATURE_SIZE) {
    return error("Invalid signature size");  // ← Add test for this
}
```

**Test to Add:**
```cpp
BOOST_AUTO_TEST_CASE(test_invalid_signature_size) {
    std::vector<uint8_t> invalid_sig(100);  // Wrong size
    BOOST_CHECK(!VerifySignature(message, invalid_sig, pubkey));
}
```

### 3. Run Coverage Again

```bash
make coverage-clean
make coverage
```

### 4. Verify Improvement

Check the report:
- Did coverage increase?
- Are critical paths now covered?
- Are edge cases tested?

---

## Integration with CI/CD

### GitHub Actions

Coverage is automatically run on every push/PR:

```yaml
- name: Build with Coverage
  run: make coverage

- name: Upload Coverage Report
  uses: actions/upload-artifact@v4
  with:
    name: coverage-report
    path: coverage_html/

- name: Upload to Codecov
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage_filtered.info
```

### Codecov Dashboard

View coverage trends at: `https://codecov.io/gh/WillBarton888/dilithion`

**Features:**
- Coverage over time graph
- PR coverage comparison
- File-by-file breakdown
- Coverage badge for README
- Component-based tracking (consensus, network, wallet, etc.)
- Automated PR comments with coverage reports

**Setup:** See [docs/CODECOV-SETUP.md](CODECOV-SETUP.md) for complete setup guide

---

## Coverage Best Practices

### DO:
✅ Focus on consensus-critical code first (P0)
✅ Test both success and failure paths
✅ Test boundary conditions (0, 1, max, max+1)
✅ Test error handling
✅ Run coverage locally before pushing
✅ Aim for 80%+ on new code

### DON'T:
❌ Write tests just to hit 100% coverage
❌ Ignore hard-to-test code (refactor it instead)
❌ Test trivial getters/setters excessively
❌ Skip error path testing
❌ Commit code without running tests

---

## Troubleshooting

### Problem: "lcov: command not found"

**Solution:** Install LCOV
```bash
sudo apt-get install lcov  # Ubuntu
brew install lcov          # macOS
```

### Problem: No coverage data generated

**Solution:** Ensure you built with coverage flags
```bash
make coverage-clean
make coverage  # This rebuilds with --coverage
```

### Problem: Coverage report shows 0%

**Solution:** Run tests before generating report
```bash
make coverage-clean
make coverage
./test_dilithion  # Run your test suite
make coverage-html
```

### Problem: Coverage files persist

**Solution:** Clean before rebuilding
```bash
make coverage-clean
make coverage
```

---

## Coverage and Development Workflow

### Before Starting Work

```bash
# See current coverage
make coverage
open coverage_html/index.html
```

### During Development

```bash
# Write code
vim src/consensus/pow.cpp

# Write tests
vim src/test/pow_tests.cpp

# Check coverage improved
make coverage-clean && make coverage
```

### Before Submitting PR

```bash
# Final coverage check
make coverage-clean
make coverage

# Ensure critical code has 80%+ coverage
# Check coverage_html/index.html

# If too low, add more tests
vim src/test/additional_tests.cpp
```

---

## Coverage Requirements for PRs

### New Code

**Requirement:** 80%+ coverage for P0/P1 code

**Exceptions:**
- External dependencies
- Platform-specific code (document why)
- Deprecated code (schedule removal)

### Modified Code

**Requirement:** Don't decrease overall coverage

**PR Check:**
- Codecov will comment on PR
- Shows coverage change (+X% or -X%)
- -5%+ change will be flagged

---

## Advanced Coverage Analysis

### Branch Coverage

```bash
# Enable branch coverage tracking
make coverage COVERAGE_CXXFLAGS="--coverage -O0 -g --branch-probabilities"
```

### Function Coverage

```bash
# View function coverage
lcov --summary coverage_filtered.info | grep -A 5 "Function"
```

### Coverage by Directory

```bash
# Show coverage per directory
lcov --summary coverage_filtered.info --list-full-path
```

---

## Coverage Milestones

### Week 4 (Current)
- **Target:** 50-60% overall coverage
- **Focus:** P0 consensus code
- **Infrastructure:** LCOV + Codecov integrated

### Week 6
- **Target:** 65-70% overall coverage
- **Focus:** P1 network and wallet code
- **Infrastructure:** Coverage enforcement in CI

### Week 8 (Pre-Mainnet)
- **Target:** 80%+ overall coverage
- **Focus:** All critical paths covered
- **Infrastructure:** Coverage part of release criteria

### Mainnet Launch
- **Requirement:** 80%+ P0/P1 coverage
- **Requirement:** All critical paths tested
- **Requirement:** No untested consensus code

---

## Resources

### Documentation
- [LCOV Documentation](http://ltp.sourceforge.net/coverage/lcov.php)
- [Codecov Documentation](https://docs.codecov.com/)
- [GCC Coverage Options](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html)

### Tools
- **LCOV:** Line coverage visualization
- **gcov:** GCC coverage tool
- **Codecov:** Coverage tracking service
- **genhtml:** HTML report generator

### Best Practices
- [Google Test Coverage](https://google.github.io/styleguide/cppguide.html#Test_Coverage)
- [Bitcoin Core Testing](https://github.com/bitcoin/bitcoin/blob/master/doc/developer-notes.md#unit-tests)
- [LLVM Coverage Mapping](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html)

---

## FAQ

**Q: What coverage percentage should I aim for?**
A: 80%+ for consensus code, 70%+ for other code. 100% is not necessary.

**Q: Should I test every getter/setter?**
A: No, focus on logic and edge cases. Simple getters/setters can be skipped.

**Q: How do I test error conditions?**
A: Use mocks, inject failures, test boundary conditions.

**Q: What if code is hard to test?**
A: Refactor it! Hard-to-test code is often poorly designed code.

**Q: Can I exclude code from coverage?**
A: Yes, but document why. Use sparingly for platform-specific or external code.

**Q: How often should I run coverage?**
A: Locally before each commit. CI runs on every push.

---

## Contact

For questions about coverage:
- Review coverage documentation: `docs/COVERAGE.md`
- Check CI coverage reports: GitHub Actions artifacts
- View Codecov dashboard: codecov.io/gh/dilithion/dilithion
- Ask in #development: Discord/GitHub Discussions

---

**Remember:** Coverage is a tool, not a goal. The goal is well-tested, reliable code. 80% well-tested code is better than 100% poorly-tested code.
