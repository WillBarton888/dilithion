# Week 4 Implementation Plan

**Week:** November 10-14, 2025 (Week 4 of 10)
**Phase:** Phase 2 - Comprehensive Testing (Coverage & Validation)
**Status:** Planning Complete, Ready to Execute
**Estimated Effort:** 40 hours (5 days × 8 hours)

---

## Executive Summary

Week 4 focuses on two critical parallel tracks:
1. **Code Coverage Infrastructure** - LCOV integration, CI reporting, coverage tracking
2. **Difficulty Determinism Validation** - Cross-platform testing of CRITICAL consensus issue

Both tracks are essential for production readiness and must complete successfully before proceeding.

---

## Dual-Track Approach

### Track A: Code Coverage Infrastructure (20 hours)
**Priority:** HIGH (Roadmap requirement)
**Blocking:** Week 4 decision point (50%+ coverage required)

### Track B: Difficulty Determinism Validation (20 hours)
**Priority:** CRITICAL (Consensus fork prevention)
**Blocking:** Mainnet launch (must verify determinism)

---

## Track A: Code Coverage Infrastructure

### Day 1: LCOV Setup & Configuration (8 hours)

#### Task A1.1: Install LCOV Dependencies (1 hour)
**Objective:** Set up coverage tooling

**Tasks:**
- Install LCOV on development machine
- Install genhtml for HTML report generation
- Verify lcov version ≥ 1.14
- Test basic lcov commands

**Deliverables:**
- LCOV installed and tested
- Basic lcov workflow verified

**Commands:**
```bash
# Ubuntu/Debian
sudo apt-get install -y lcov

# macOS
brew install lcov

# Verify
lcov --version
```

#### Task A1.2: Update Makefile for Coverage (3 hours)
**Objective:** Add coverage build targets

**Tasks:**
- Add coverage compilation flags
- Create `make coverage` target
- Create `make coverage-html` target
- Add coverage clean target
- Test coverage build

**Deliverables:**
- Makefile with coverage targets
- Working coverage compilation

**Makefile additions:**
```makefile
# Coverage flags
COVERAGE_CXXFLAGS := --coverage -O0 -g
COVERAGE_LDFLAGS := --coverage

# Coverage build
coverage: CXXFLAGS += $(COVERAGE_CXXFLAGS)
coverage: LDFLAGS += $(COVERAGE_LDFLAGS)
coverage: clean all test
	@echo "Building with coverage instrumentation..."
	@mkdir -p coverage_html
	@lcov --capture --directory . --output-file coverage.info
	@lcov --remove coverage.info '/usr/*' '*/test/*' '*/depends/*' --output-file coverage_filtered.info
	@genhtml coverage_filtered.info --output-directory coverage_html
	@echo "Coverage report: coverage_html/index.html"

coverage-clean:
	@rm -rf *.gcda *.gcno coverage.info coverage_filtered.info coverage_html
```

#### Task A1.3: Create Initial Coverage Report (2 hours)
**Objective:** Generate baseline coverage report

**Tasks:**
- Build with coverage instrumentation
- Run all existing tests
- Generate coverage report
- Analyze initial coverage percentage
- Identify untested areas

**Deliverables:**
- Baseline coverage report
- Coverage percentage documented
- List of untested critical files

**Expected Baseline:**
- Likely 15-30% coverage (Week 3 tests just created)
- Target by end of week: 50-60%

#### Task A1.4: Document Coverage Workflow (2 hours)
**Objective:** Enable team to track coverage

**Tasks:**
- Create `docs/COVERAGE.md` with:
  - How to run coverage locally
  - How to interpret reports
  - Coverage targets by component
  - How to improve coverage
- Update CONTRIBUTING.md with coverage expectations
- Add coverage commands to README

**Deliverables:**
- docs/COVERAGE.md
- Updated CONTRIBUTING.md
- README coverage section

---

### Day 2: CI/CD Coverage Integration (8 hours)

#### Task A2.1: Add Coverage Job to GitHub Actions (3 hours)
**Objective:** Automated coverage reporting

**Tasks:**
- Add `coverage` job to `.github/workflows/ci.yml`
- Configure coverage upload
- Set up coverage artifact storage
- Test CI coverage run

**Deliverables:**
- CI coverage job working
- Coverage reports available in CI

**GitHub Actions addition:**
```yaml
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y lcov g++ make libleveldb-dev

      - name: Build with Coverage
        run: make coverage

      - name: Upload Coverage Report
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: coverage_html/

      - name: Display Coverage Summary
        run: |
          lcov --summary coverage_filtered.info
```

#### Task A2.2: Set Up Codecov Integration (3 hours)
**Objective:** Track coverage over time

**Tasks:**
- Sign up for Codecov (free for open source)
- Add Codecov token to GitHub secrets
- Add Codecov upload to CI
- Configure codecov.yml
- Verify first upload

**Deliverables:**
- Codecov integrated
- Coverage tracking active
- Badge available

**Codecov integration:**
```yaml
      - name: Upload to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage_filtered.info
          flags: unittests
          name: codecov-dilithion
          fail_ci_if_error: true
```

**codecov.yml:**
```yaml
coverage:
  status:
    project:
      default:
        target: 60%
        threshold: 5%
    patch:
      default:
        target: 70%
```

#### Task A2.3: Add Coverage Badge to README (1 hour)
**Objective:** Public coverage visibility

**Tasks:**
- Add Codecov badge to README
- Add CI status badges
- Update README with coverage info

**Deliverables:**
- README with coverage badge
- Public coverage visibility

**Badge:**
```markdown
[![codecov](https://codecov.io/gh/dilithion/dilithion/branch/main/graph/badge.svg)](https://codecov.io/gh/dilithion/dilithion)
```

#### Task A2.4: Coverage Enforcement Rules (1 hour)
**Objective:** Prevent coverage regression

**Tasks:**
- Configure Codecov to comment on PRs
- Set up coverage decrease alerts
- Document coverage requirements for PRs
- Test on sample PR

**Deliverables:**
- Coverage enforcement active
- PR comments working

---

### Day 3: Improve Coverage to 50%+ (4 hours for Track A portion)

#### Task A3.1: Identify Critical Gaps (2 hours)
**Objective:** Find untested critical code

**Tasks:**
- Analyze coverage report
- List all files with <20% coverage
- Prioritize by criticality:
  - P0: Consensus code (pow.cpp, validation.cpp)
  - P1: Network code (protocol.cpp, net.cpp)
  - P2: Wallet code (wallet.cpp)
  - P3: Utility code (util.cpp)
- Create coverage improvement plan

**Deliverables:**
- Coverage gap analysis
- Prioritized improvement list

#### Task A3.2: Write Additional Unit Tests (2 hours)
**Objective:** Increase coverage of critical code

**Tasks:**
- Add tests for uncovered consensus code
- Add tests for uncovered network code
- Re-run coverage
- Verify improvement

**Deliverables:**
- New unit tests
- Improved coverage percentage

**Target:** Achieve 50%+ coverage by end of Day 3

---

## Track B: Difficulty Determinism Validation

### Day 1: Platform Test Execution Preparation (4 hours of Track B)

#### Task B1.1: Review Test Files (1 hour)
**Objective:** Understand test implementation

**Tasks:**
- Review `src/test/difficulty_determinism_test.cpp`
- Review `scripts/compare_difficulty_results.py`
- Understand test vectors
- Verify compilation requirements

**Deliverables:**
- Test files understood
- Requirements documented

#### Task B1.2: Set Up Test Environments (3 hours)
**Objective:** Prepare platforms for testing

**Tasks:**
- **Ubuntu + GCC:**
  - Verify GCC version
  - Install dependencies
  - Test compilation

- **Ubuntu + Clang:**
  - Install Clang
  - Verify version
  - Test compilation

- **Windows + MSVC:**
  - Verify MSVC installation
  - Verify dependencies
  - Test compilation

**Deliverables:**
- 3 platforms ready for testing
- Compilation verified on each

---

### Day 2: Platform Test Execution (4 hours of Track B)

#### Task B2.1: Execute on Ubuntu + GCC (1 hour)
**Objective:** Get baseline results

**Tasks:**
- Compile difficulty_determinism_test
- Run all 10 test vectors
- Save results as `difficulty_results_ubuntu_gcc.json`
- Verify JSON format
- Document platform info

**Deliverables:**
- `difficulty_results_ubuntu_gcc.json`
- Test execution log

#### Task B2.2: Execute on Ubuntu + Clang (1 hour)
**Objective:** Test with different compiler

**Tasks:**
- Compile with Clang
- Run all 10 test vectors
- Save results as `difficulty_results_ubuntu_clang.json`
- Document platform info

**Deliverables:**
- `difficulty_results_ubuntu_clang.json`
- Test execution log

#### Task B2.3: Execute on Windows + MSVC (2 hours)
**Objective:** Test on different OS + compiler

**Tasks:**
- Compile with MSVC
- Run all 10 test vectors
- Save results as `difficulty_results_windows_msvc.json`
- Document platform info
- Handle any Windows-specific issues

**Deliverables:**
- `difficulty_results_windows_msvc.json`
- Test execution log

---

### Day 3: Cross-Platform Comparison (4 hours of Track B)

#### Task B3.1: Run Comparison Tool (1 hour)
**Objective:** Verify cross-platform determinism

**Tasks:**
- Run `scripts/compare_difficulty_results.py`
- Pass all 3 result files
- Analyze output
- Check exit code

**Deliverables:**
- Comparison report
- Pass/Fail result

**Command:**
```bash
python3 scripts/compare_difficulty_results.py \
    difficulty_results_ubuntu_gcc.json \
    difficulty_results_ubuntu_clang.json \
    difficulty_results_windows_msvc.json
```

**Expected Outcomes:**
- **PASS (exit 0):** All platforms agree → Safe for mainnet
- **FAIL (exit 1):** Platforms disagree → CRITICAL ISSUE

#### Task B3.2: Document Results (1 hour)
**Objective:** Create validation report

**Tasks:**
- Create `DIFFICULTY-VALIDATION-WEEK4-RESULTS.md`
- Document all platform results
- Include comparison analysis
- Provide GO/NO-GO recommendation

**Deliverables:**
- Week 4 validation report
- GO/NO-GO decision

#### Task B3.3: Address Discrepancies (if found) (2 hours)
**Objective:** Fix any determinism issues

**If platforms disagree:**
- Analyze which test vectors failed
- Debug arithmetic differences
- Implement Option B (Bitcoin Core ArithU256)
- Re-test on all platforms
- Verify fix

**If platforms agree:**
- Proceed to Week 5 validation (more platforms)
- Document success

**Deliverables:**
- Fix implemented (if needed)
- Re-validation results (if needed)

---

### Days 4-5: Extended Validation & Documentation (12 hours Track B)

#### Task B4.1: Create Fuzz Seed Corpora (4 hours)
**Objective:** Initial corpus for continuous fuzzing

**Tasks:**
- Create `test/fuzz/corpus/` directory structure:
  ```
  test/fuzz/corpus/
  ├── transaction/
  ├── block/
  ├── compactsize/
  ├── network_message/
  ├── address/
  ├── difficulty/
  ├── subsidy/
  └── merkle/
  ```
- Generate seed inputs for each fuzz target:
  - Valid transactions (5-10 examples)
  - Valid blocks (5-10 examples)
  - CompactSize values (boundary cases)
  - Network messages (all message types)
  - Valid addresses (various formats)
  - Difficulty values (various targets)
  - Block heights (halving boundaries)
  - Transaction lists (various sizes)
- Document corpus in `test/fuzz/CORPUS.md`

**Deliverables:**
- Seed corpus for all 8 fuzz harnesses
- ~50-80 seed files total
- Corpus documentation

#### Task B4.2: Run Initial Fuzzing Campaigns (4 hours)
**Objective:** Discover early issues

**Tasks:**
- Run each fuzz harness for 30-60 minutes
- Monitor for crashes
- Collect interesting inputs
- Document any issues found
- Fix critical issues

**Deliverables:**
- Initial fuzzing results
- Crash reports (if any)
- Fixes for discovered issues

**Commands:**
```bash
# Run each harness for 1 hour
./fuzz_transaction -max_total_time=3600 test/fuzz/corpus/transaction/
./fuzz_block -max_total_time=3600 test/fuzz/corpus/block/
./fuzz_compactsize -max_total_time=3600 test/fuzz/corpus/compactsize/
./fuzz_network_message -max_total_time=3600 test/fuzz/corpus/network_message/
./fuzz_address -max_total_time=3600 test/fuzz/corpus/address/
./fuzz_difficulty -max_total_time=3600 test/fuzz/corpus/difficulty/
./fuzz_subsidy -max_total_time=3600 test/fuzz/corpus/subsidy/
./fuzz_merkle -max_total_time=3600 test/fuzz/corpus/merkle/
```

#### Task B4.3: Week 4 Completion Documentation (4 hours)
**Objective:** Comprehensive week summary

**Tasks:**
- Create `WEEK-4-COMPLETE.md`:
  - Coverage infrastructure status
  - Baseline coverage percentage
  - Difficulty determinism results
  - Fuzz corpus status
  - Issues discovered and fixed
  - Week 5 readiness assessment
- Update project status
- Create Week 5 transition plan

**Deliverables:**
- WEEK-4-COMPLETE.md
- Status update
- Week 5 preview

---

## Success Criteria

### Track A: Coverage Infrastructure
- ✅ LCOV integrated and working
- ✅ CI coverage reporting active
- ✅ Codecov tracking enabled
- ✅ Coverage badge on README
- ✅ Baseline coverage ≥ 50%
- ✅ Coverage documentation complete

### Track B: Difficulty Determinism
- ✅ Tests executed on 3 P0 platforms
- ✅ Cross-platform comparison complete
- ✅ All platforms produce IDENTICAL results
- ✅ GO/NO-GO decision made
- ✅ Validation report published
- ✅ Any issues fixed and re-validated

### Bonus: Fuzzing
- ✅ Seed corpus created (50-80 files)
- ✅ Initial fuzzing campaigns run
- ✅ Any crashes fixed
- ✅ Corpus documented

---

## Deliverables Summary

### Documentation (6 files):
1. `docs/COVERAGE.md` - Coverage workflow guide
2. `DIFFICULTY-VALIDATION-WEEK4-RESULTS.md` - Platform validation results
3. `test/fuzz/CORPUS.md` - Fuzz corpus documentation
4. `WEEK-4-COMPLETE.md` - Week summary
5. Updated `CONTRIBUTING.md` - Coverage requirements
6. Updated `README.md` - Coverage badge

### Code/Configuration (3 files):
7. Updated `Makefile` - Coverage targets
8. Updated `.github/workflows/ci.yml` - Coverage CI
9. `codecov.yml` - Codecov configuration

### Data Files (multiple):
10. `difficulty_results_ubuntu_gcc.json`
11. `difficulty_results_ubuntu_clang.json`
12. `difficulty_results_windows_msvc.json`
13. `test/fuzz/corpus/**/*.dat` - Seed corpus files (50-80 files)
14. `coverage_html/**` - Coverage reports

---

## Timeline

```
Day 1 (Mon):
├─ Track A: LCOV setup & initial report (8h)
└─ Track B: Platform prep (4h) → 12h total

Day 2 (Tue):
├─ Track A: CI integration (8h)
└─ Track B: Execute tests on 3 platforms (4h) → 12h total

Day 3 (Wed):
├─ Track A: Coverage improvement (4h)
└─ Track B: Cross-platform comparison (4h) → 8h total

Day 4 (Thu):
└─ Track B: Fuzz corpus creation (8h)

Day 5 (Fri):
├─ Track B: Initial fuzzing campaigns (4h)
└─ Track B: Documentation (4h) → 8h total

Total: 48 hours (8h contingency included)
```

---

## Decision Points

### Day 2 Decision: Coverage Trajectory
**Question:** Is coverage ≥ 40%?
- **YES:** Continue as planned
- **NO:** Add 1-2 days to coverage improvement

### Day 3 Decision: Difficulty Determinism
**Question:** Do all platforms agree?
- **YES:** Proceed to Week 5 (more platforms)
- **NO:** Implement fix (Option B: Bitcoin ArithU256), re-test

### Day 5 Decision: Week 4 Complete
**Question:** All success criteria met?
- **YES:** Proceed to Week 5
- **NO:** Extend Week 4 or adjust scope

---

## Risk Assessment

### High Risk:
1. **Platforms disagree on difficulty**
   - Mitigation: Option B ready (Bitcoin ArithU256)
   - Time: 1-2 days to implement and re-test

2. **Coverage < 50% by Day 3**
   - Mitigation: Focus on critical consensus code
   - Accept: May need to extend to Week 5

### Medium Risk:
3. **Fuzzing discovers critical bugs**
   - Mitigation: Fix immediately, delay other work
   - Timeline impact: 0-2 days

4. **CI integration issues**
   - Mitigation: Test locally first
   - Fallback: Manual coverage tracking

### Low Risk:
5. **Corpus creation takes longer**
   - Mitigation: Start with minimal corpus
   - Can expand post-Week 4

---

## Blocking Issues

**Week 5 is BLOCKED if:**
- Difficulty determinism validation FAILS and is not fixed
- Coverage infrastructure not functional
- Critical consensus bugs found and not fixed

**Week 5 can proceed if:**
- Coverage ≥ 40% (can improve during Week 5)
- Difficulty validation PASSES on 3 platforms
- No critical bugs found

---

## Resource Requirements

### Development Machine:
- Ubuntu (native or WSL) for GCC/Clang testing
- Windows for MSVC testing
- Sufficient disk space for coverage files (~500MB)

### External Services:
- Codecov account (free for open source)
- GitHub Actions (included with repository)

### Time:
- 48 hours estimated (40h planned + 8h buffer)
- 5 working days
- No external dependencies on other people

---

## Next Steps (Week 5 Preview)

### Week 5 Will Focus On:
1. **Extended platform testing:**
   - Windows + MinGW
   - macOS + Clang
   - ARM64 + GCC
   - RISC-V (if available)

2. **Difficulty validation CI integration:**
   - Automate cross-platform comparison
   - Add to GitHub Actions matrix

3. **Coverage improvement:**
   - Target: 60-70% coverage
   - Focus on wallet and network code

4. **Extended fuzzing:**
   - 24-hour campaigns
   - Corpus expansion
   - Bug fixes

---

## Conclusion

Week 4 is a critical validation week that establishes:
1. **Coverage tracking infrastructure** - Essential for ongoing quality
2. **Cross-platform determinism** - Essential for consensus safety
3. **Fuzzing foundation** - Essential for security

Both tracks must succeed for production readiness. The difficulty determinism validation is CRITICAL and BLOCKING for mainnet launch.

**Week 4 Status:** Ready to Execute
**Next Action:** Begin Day 1 - LCOV Setup & Platform Prep

---

**Document Version:** 1.0
**Created:** November 3, 2025
**Status:** Planning Complete
**Timeline:** November 10-14, 2025 (5 days)
