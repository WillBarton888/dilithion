# Dilithion: Roadmap to Bitcoin-Level Excellence

**Created:** November 3, 2025
**Target Mainnet Launch:** January 1, 2026 (8 weeks)
**Current Status:** 4.5/10 | **Target:** 8.5/10

---

## Executive Summary

This roadmap transforms Dilithion from a working testnet (4.5/10) to a production-ready, Bitcoin-level cryptocurrency (8.5/10). Based on comprehensive analysis of Bitcoin Core's practices, we've identified **20 critical improvements** organized into 4 phases.

**Timeline:** 10-12 weeks of focused development
**Reality Check:** Mainnet launch may need delay to January 15 or February 1, 2026

---

## Critical Path Analysis

### Must-Have for Mainnet (8 weeks minimum):
1. ✅ Testing infrastructure (unit + functional + fuzz)
2. ✅ Deterministic builds with multi-party verification
3. ✅ Code signing certificates (Windows + macOS)
4. ✅ Security infrastructure (fuzzing + sanitizers + GPG)
5. ✅ Professional security audit

### Can Launch Without (Post-Mainnet):
- Benchmark framework
- Full architecture documentation
- Bug bounty program
- Advanced CI configurations

---

## Phase 1: Critical Foundations (Weeks 1-2)

**Goal:** Establish basic quality infrastructure
**Effort:** 2 weeks full-time
**Priority:** ⭐⭐⭐⭐⭐ CRITICAL

### Week 1: Security & Community Basics

#### 1.1 Security Infrastructure Setup (2 days)
**Tasks:**
- [ ] Generate GPG keys for 2-3 security contacts
- [ ] Publish keys to keyservers (keys.openpgp.org, pgp.mit.edu)
- [ ] Update SECURITY.md with:
  - GPG key fingerprints
  - Explicit disclosure timeline (Low: 2 weeks, Medium/High: 1 year)
  - Pre-announcement policy (2 weeks)
  - Severity classifications with examples
- [ ] Create security@dilithion.org email alias
- [ ] Test encrypted communication workflow

**Deliverable:** `SECURITY.md` with published GPG infrastructure

#### 1.2 Community Standards (1 day)
**Tasks:**
- [ ] Add CODE_OF_CONDUCT.md (use Contributor Covenant 2.1)
- [ ] Update CONTRIBUTING.md with:
  - ACK/NACK terminology
  - Component prefix requirements (consensus:, net:, wallet:, rpc:, test:, doc:)
  - Atomic commit requirements
  - Review expectations
- [ ] Create PR template (`.github/pull_request_template.md`) with:
  - Component prefix reminder
  - Testing checklist
  - Documentation update checkbox
  - Breaking changes notification

**Deliverable:** CODE_OF_CONDUCT.md + enhanced CONTRIBUTING.md + PR template

#### 1.3 Code Quality Automation (2 days)
**Tasks:**
- [ ] Create `.clang-tidy` configuration:
  ```yaml
  Checks: >
    clang-diagnostic-*,
    clang-analyzer-*,
    cppcoreguidelines-*,
    modernize-*,
    readability-*,
    -modernize-use-trailing-return-type
  WarningsAsErrors: ''
  HeaderFilterRegex: 'src/.*'
  ```
- [ ] Add clang-tidy to CI pipeline
- [ ] Create `.codespellrc` configuration
- [ ] Add codespell check to CI
- [ ] Document running locally in CONTRIBUTING.md

**Deliverable:** Automated linting in CI

### Week 2: Core Testing Infrastructure

#### 1.4 Unit Test Framework Setup (3 days)
**Tasks:**
- [ ] Add Boost Unit Test Framework to dependencies
- [ ] Create `src/test/test_dilithion.cpp` main file:
  ```cpp
  #define BOOST_TEST_MODULE Dilithion Test Suite
  #include <boost/test/included/unit_test.hpp>
  // Global test setup here
  ```
- [ ] Create initial test files:
  - `src/test/crypto_tests.cpp` - Dilithium signature tests
  - `src/test/transaction_tests.cpp` - Transaction validation
  - `src/test/block_tests.cpp` - Block validation
  - `src/test/util_tests.cpp` - Utility function tests
- [ ] Update Makefile to build test_dilithion executable
- [ ] Add `make test` target
- [ ] Document test running in README

**Target:** 20% code coverage by end of week 2

**Deliverable:** Working unit test framework with 4 test suites

#### 1.5 CI/CD Enhancement (2 days)
**Tasks:**
- [ ] Expand `.github/workflows/ci.yml`:
  ```yaml
  name: CI
  on: [push, pull_request]
  jobs:
    test-linux:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v3
        - name: Install dependencies
          run: sudo apt-get install -y libleveldb-dev libboost-test-dev
        - name: Build
          run: make
        - name: Run tests
          run: make test
        - name: Run clang-tidy
          run: make lint
    test-windows:
      runs-on: windows-latest
      # ... similar steps
    test-macos:
      runs-on: macos-latest
      # ... similar steps
  ```
- [ ] Add sanitizer builds:
  - AddressSanitizer (ASan)
  - UndefinedBehaviorSanitizer (UBSan)
- [ ] Require all CI checks pass before merge

**Deliverable:** Multi-platform CI with sanitizers

---

## Phase 2: Comprehensive Testing (Weeks 3-4)

**Goal:** Achieve 60%+ code coverage
**Effort:** 2 weeks full-time
**Priority:** ⭐⭐⭐⭐⭐ CRITICAL

### Week 3: Functional Test Framework

#### 2.1 Python Test Infrastructure (3 days)
**Tasks:**
- [ ] Create `test/functional/` directory
- [ ] Create `test/functional/test_framework/` with:
  - `test_node.py` - Node control class
  - `util.py` - Test utilities
  - `messages.py` - Network protocol messages
- [ ] Create `test/functional/test_runner.py`:
  - Parallel test execution
  - Test discovery
  - Result aggregation
  - Failure reporting
- [ ] Add Python dependencies (requirements.txt):
  ```
  pytest>=7.0.0
  python-bitcoinlib>=0.11.0
  requests>=2.28.0
  ```
- [ ] Document in `test/functional/README.md`

**Deliverable:** Functional test framework

#### 2.2 Core Functional Tests (4 days)
**Tasks:**
- [ ] Create initial functional tests:
  - `test_blockchain.py` - Blockchain sync and validation
  - `test_mining.py` - Mining functionality
  - `test_wallet.py` - Wallet operations
  - `test_p2p.py` - Peer-to-peer networking
  - `test_rpc.py` - RPC functionality
  - `test_mempool.py` - Mempool management
  - `test_reorg.py` - Blockchain reorganization
- [ ] Each test should:
  - Start/stop nodes
  - Perform operations
  - Verify expected state
  - Clean up resources
- [ ] Add to CI pipeline

**Target:** 40% coverage by end of week 3

**Deliverable:** 7 functional test suites

### Week 4: Fuzz Testing & Coverage

#### 2.3 Fuzz Testing Setup (3 days)
**Tasks:**
- [ ] Create `src/test/fuzz/` directory
- [ ] Add libFuzzer build configuration to Makefile:
  ```makefile
  fuzz: CXXFLAGS += -fsanitize=fuzzer,address,undefined
  fuzz: src/test/fuzz/*.cpp
  	$(CXX) $(CXXFLAGS) -o fuzz_$@ $^
  ```
- [ ] Create initial fuzz targets:
  - `fuzz_transaction.cpp` - Transaction deserialization
  - `fuzz_block.cpp` - Block deserialization
  - `fuzz_script.cpp` - Script parsing
  - `fuzz_net_message.cpp` - Network message parsing
  - `fuzz_dilithium.cpp` - Dilithium signature parsing
- [ ] Create seed corpus directory `test/fuzz/corpus/`
- [ ] Document fuzzing in `test/fuzz/README.md`

**Deliverable:** 5 fuzz targets with initial corpus

#### 2.4 Code Coverage Tracking (2 days)
**Tasks:**
- [ ] Add LCOV to CI:
  ```bash
  lcov --capture --directory . --output-file coverage.info
  lcov --remove coverage.info '/usr/*' --output-file coverage.info
  lcov --remove coverage.info '*/test/*' --output-file coverage.info
  genhtml coverage.info --output-directory coverage_html
  ```
- [ ] Add coverage badge to README
- [ ] Set up coverage reporting in CI
- [ ] Create coverage target: `make coverage`
- [ ] Track coverage over time

**Target:** 60% coverage by end of week 4

**Deliverable:** Coverage tracking infrastructure

---

## Phase 3: Build & Release Infrastructure (Weeks 5-6)

**Goal:** Reproducible, signed releases
**Effort:** 2 weeks full-time
**Priority:** ⭐⭐⭐⭐⭐ CRITICAL

### Week 5: Deterministic Builds

#### 3.1 Docker-Based Reproducible Builds (3 days)
**Tasks:**
- [ ] Create `contrib/docker/` directory
- [ ] Create `Dockerfile.build`:
  ```dockerfile
  FROM ubuntu:22.04
  RUN apt-get update && apt-get install -y \
      build-essential cmake git \
      libleveldb-dev libboost-all-dev \
      mingw-w64 # for Windows cross-compile
  WORKDIR /dilithion
  CMD ["./contrib/docker/build.sh"]
  ```
- [ ] Create `contrib/docker/build.sh`:
  - Deterministic timestamps (`SOURCE_DATE_EPOCH`)
  - Reproducible builds for Linux, Windows, macOS
  - SHA256 checksum generation
  - Build attestation output
- [ ] Create `contrib/docker/README.md`
- [ ] Test builds on 3 different machines

**Deliverable:** Dockerized reproducible builds

#### 3.2 Guix Build System (4 days)
**Tasks:**
- [ ] Create `contrib/guix/` directory
- [ ] Create `manifest.scm` with dependencies
- [ ] Create `guix-build` script:
  ```bash
  #!/bin/bash
  guix time-machine --commit=<COMMIT> -- \
    build -f contrib/guix/manifest.scm
  ```
- [ ] Test Guix builds
- [ ] Create build attestation format
- [ ] Set up `dilithion-guix-sigs` repository for attestations
- [ ] Document process in `contrib/guix/README.md`

**Deliverable:** Guix-based deterministic builds

### Week 6: Code Signing & Release Process

#### 3.3 Code Signing Certificates (2 days)
**Tasks:**
- [ ] Purchase Windows code signing certificate:
  - Research providers (Sectigo, DigiCert, Comodo)
  - Choose EV certificate for SmartScreen bypass
  - Complete business verification (DUNS number, documents)
  - Estimated cost: $200-700/year
  - Estimated time: 3-7 days processing
- [ ] Purchase macOS code signing certificate:
  - Enroll in Apple Developer Program ($99/year)
  - Generate certificate signing request
  - Download certificates
- [ ] Set up signing infrastructure:
  - Secure storage for private keys
  - HSM or hardware token for EV cert
  - Document signing procedures
- [ ] Create signing scripts:
  - `contrib/sign/sign-windows.sh`
  - `contrib/sign/sign-macos.sh`

**Deliverable:** Code signing certificates and scripts

#### 3.4 Release Automation (3 days)
**Tasks:**
- [ ] Create `contrib/release/release.sh`:
  ```bash
  #!/bin/bash
  VERSION=$1
  # Build all platforms
  # Generate checksums
  # Sign binaries
  # Create release notes
  # Upload to GitHub
  # Verify signatures
  ```
- [ ] Create release checklist in `doc/release-process.md`:
  - Pre-release steps (update versions, translations, seeds)
  - Build process
  - Multi-party verification
  - Signing process
  - Upload process
  - Announcement process
- [ ] Document in CONTRIBUTING.md
- [ ] Test dry-run release

**Deliverable:** Automated release process

---

## Phase 4: Security & Polish (Weeks 7-8)

**Goal:** Professional security standards
**Effort:** 2 weeks full-time
**Priority:** ⭐⭐⭐⭐⭐ CRITICAL

### Week 7: Security Hardening

#### 4.1 Fuzzing Infrastructure (3 days)
**Tasks:**
- [ ] Set up OSS-Fuzz integration (if eligible):
  - Create project.yaml
  - Submit application
  - Configure continuous fuzzing
- [ ] Create local fuzzing infrastructure:
  - Docker container for fuzzing
  - Corpus management scripts
  - Crash analysis workflow
- [ ] Run 24-hour fuzzing on all targets
- [ ] Fix any discovered issues
- [ ] Document findings

**Target:** 1 billion executions per target

**Deliverable:** Continuous fuzzing infrastructure

#### 4.2 Sanitizer Coverage (2 days)
**Tasks:**
- [ ] Add sanitizer builds to CI:
  ```yaml
  asan-build:
    env:
      CXXFLAGS: "-fsanitize=address -fno-omit-frame-pointer"
      LDFLAGS: "-fsanitize=address"
  ubsan-build:
    env:
      CXXFLAGS: "-fsanitize=undefined"
  tsan-build:
    env:
      CXXFLAGS: "-fsanitize=thread"
  ```
- [ ] Run full test suite with each sanitizer
- [ ] Fix any issues discovered
- [ ] Make sanitizer builds required in CI

**Deliverable:** Sanitizer-clean codebase

#### 4.3 Dilithium Timing Analysis (2 days)
**Tasks:**
- [ ] Create timing analysis tests:
  - Measure signature verification time variance
  - Test with different key/message combinations
  - Detect data-dependent branches
  - Verify constant-time operations
- [ ] Document findings in `docs/SECURITY-DILITHIUM-TIMING.md`
- [ ] Address any timing leaks found
- [ ] Add timing tests to CI

**Deliverable:** Verified constant-time crypto

### Week 8: Professional Audit & Documentation

#### 4.4 Professional Security Audit (5 days)
**Tasks:**
- [ ] Research audit firms:
  - Trail of Bits
  - NCC Group
  - Kudelski Security
  - Cure53
  - Halborn
- [ ] Request quotes (budget: $10k-50k)
- [ ] Select auditor based on:
  - Post-quantum crypto expertise
  - Cryptocurrency experience
  - Timeline compatibility
  - Cost
- [ ] Provide codebase access
- [ ] Schedule kickoff meeting
- [ ] Provide documentation
- [ ] **Note:** Audit typically takes 2-4 weeks after kickoff

**Deliverable:** Professional security audit initiated (results in weeks 10-12)

#### 4.5 Final Documentation Pass (2 days)
**Tasks:**
- [ ] Update README.md with:
  - Clear project description
  - Build instructions for all platforms
  - Testing instructions
  - Contributing guidelines link
  - Security policy link
  - Code signing verification instructions
- [ ] Create `ARCHITECTURE.md`:
  - System design overview
  - Component relationships
  - Dependency hierarchy
  - Design decisions and rationale
- [ ] Review all docs/ files for accuracy
- [ ] Ensure all processes documented
- [ ] Create mainnet launch checklist

**Deliverable:** Complete, accurate documentation

---

## Phase 5: Mainnet Preparation (Weeks 9-10)

**Goal:** Final testing and community preparation
**Effort:** 2 weeks full-time
**Priority:** ⭐⭐⭐⭐ HIGH

### Week 9: Final Testing & Bug Fixes

#### 5.1 Comprehensive Testing (3 days)
**Tasks:**
- [ ] Run full test suite on all platforms
- [ ] 48-hour stress test on testnet
- [ ] Multi-node network simulation
- [ ] Blockchain sync from genesis
- [ ] Wallet import/export testing
- [ ] RPC endpoint validation
- [ ] P2P network resilience testing
- [ ] Fix all discovered issues

**Target:** 80%+ code coverage, zero critical bugs

**Deliverable:** Stable, tested codebase

#### 5.2 Security Audit Response (4 days)
**Tasks:**
- [ ] Review audit findings
- [ ] Prioritize issues (Critical/High/Medium/Low)
- [ ] Fix all Critical and High issues
- [ ] Address Medium issues if time permits
- [ ] Document rationale for any accepted risks
- [ ] Request re-audit of fixes
- [ ] Publish audit results (after mainnet launch)

**Deliverable:** Audit issues addressed

### Week 10: Launch Preparation

#### 5.3 Release Candidate Process (3 days)
**Tasks:**
- [ ] Create RC1 release
- [ ] Multi-party build verification (3+ builders)
- [ ] Verify all checksums match
- [ ] Sign binaries
- [ ] Public RC testing period (3-7 days)
- [ ] Collect feedback
- [ ] Fix any issues → RC2 if needed
- [ ] Final RC verification

**Deliverable:** Verified release candidate

#### 5.4 Community Preparation (2 days)
**Tasks:**
- [ ] Prepare mainnet announcement:
  - Release notes
  - Migration guide from testnet
  - What's new document
  - Known issues document
  - Support channels
- [ ] Update website for mainnet
- [ ] Prepare social media posts
- [ ] Schedule announcement timing
- [ ] Coordinate with exchanges (if any)
- [ ] Set up mainnet seed nodes
- [ ] Prepare monitoring infrastructure

**Deliverable:** Launch communications ready

#### 5.5 Final Mainnet Checklist (2 days)
**Tasks:**
- [ ] All CI checks passing
- [ ] 80%+ test coverage achieved
- [ ] Security audit complete and findings addressed
- [ ] Code signing certificates active
- [ ] Multi-party build verification successful
- [ ] Documentation complete and accurate
- [ ] Seed nodes operational
- [ ] Monitoring infrastructure live
- [ ] Support channels staffed
- [ ] Backup plans documented
- [ ] Rollback procedures documented

**Deliverable:** GO/NO-GO decision

---

## Timeline Summary

```
Week 1-2  [████████] Phase 1: Critical Foundations
Week 3-4  [████████] Phase 2: Comprehensive Testing
Week 5-6  [████████] Phase 3: Build & Release Infrastructure
Week 7-8  [████████] Phase 4: Security & Polish
Week 9-10 [████████] Phase 5: Mainnet Preparation
─────────────────────────────────────────────────
          10 weeks | Jan 15, 2026 target
```

**Original target:** January 1, 2026 (8 weeks from Nov 3)
**Realistic target:** January 15-30, 2026 (10-12 weeks)

---

## Resource Requirements

### Development Team:
- **Lead Developer:** Full-time (10 weeks)
- **Security Engineer:** Part-time (4 weeks equivalent)
- **QA Engineer:** Part-time (2 weeks equivalent)
- **Technical Writer:** Part-time (1 week equivalent)

### External Services:
- **Code Signing Certificates:** $300-800/year
- **Security Audit:** $10,000-50,000 (one-time)
- **Apple Developer:** $99/year
- **Infrastructure:** $100-500/month (seed nodes, CI runners)

### Total Estimated Cost:
- **Minimum:** $12,000 (lean approach)
- **Recommended:** $25,000-35,000 (professional approach)
- **Premium:** $50,000+ (comprehensive audit + ongoing security)

---

## Success Metrics

### Code Quality:
- [ ] 80%+ test coverage
- [ ] Zero critical security issues
- [ ] All code passes static analysis
- [ ] Consistent coding style enforced

### Security:
- [ ] Professional security audit completed
- [ ] All high/critical issues resolved
- [ ] GPG key infrastructure operational
- [ ] Fuzzing infrastructure producing results
- [ ] Code signing implemented

### Infrastructure:
- [ ] CI/CD running all tests on every PR
- [ ] Deterministic builds working
- [ ] Multi-party verification process established
- [ ] Release process automated

### Community:
- [ ] CODE_OF_CONDUCT adopted
- [ ] Clear contribution guidelines
- [ ] Active communication channels
- [ ] Contributor recognition system

---

## Risk Assessment

### High Risk (Must Mitigate):
1. **Timeline too aggressive** → Delay mainnet if necessary
2. **Security audit finds critical issues** → Allow 2-4 weeks for fixes
3. **Code signing delays** → Start process immediately (Week 1)
4. **Testing reveals instability** → Increase testing duration

### Medium Risk (Monitor Closely):
5. **Developer bandwidth insufficient** → Hire contractors
6. **Budget constraints** → Prioritize security audit above all else
7. **Community pushback on delay** → Communicate quality rationale
8. **Third-party dependencies** → Vendor critical dependencies

### Low Risk (Accept):
9. **Perfect test coverage** → 80% is acceptable
10. **All optional features** → Can be post-mainnet

---

## Decision Points

### Week 2 Decision: Test Coverage Trajectory
- **If** coverage < 20%: **Add week to Phase 2**
- **If** coverage ≥ 20%: **Continue as planned**

### Week 4 Decision: Testing Adequacy
- **If** coverage < 50%: **Delay mainnet to Feb 1**
- **If** coverage ≥ 60%: **Proceed to Phase 3**

### Week 6 Decision: Build Infrastructure
- **If** reproducible builds failing: **Add week to Phase 3**
- **If** all builders match: **Proceed to Phase 4**

### Week 8 Decision: Security Audit
- **If** critical issues found: **Delay mainnet, fix issues first**
- **If** only medium/low issues: **Proceed, fix in parallel**

### Week 10 Decision: GO/NO-GO
- **All critical tasks complete:** GO for mainnet
- **Any critical gap remains:** NO-GO, set new date

---

## Contingency Plans

### If Timeline Slips 2 Weeks:
- **New target:** February 1, 2026
- **Communicate early and honestly**
- **Explain quality rationale**
- **Maintain testnet for extended period**

### If Budget Constrained:
- **Must-have:** Security audit (find cheaper option)
- **Can defer:** Bug bounty program
- **Can defer:** Professional QA engineer
- **DIY:** More thorough internal testing

### If Critical Bug Found:
- **Before mainnet:** Delay launch, fix properly
- **After mainnet:** Emergency patch process
- **Communication plan:** Transparent disclosure

---

## Post-Mainnet Roadmap (Weeks 11+)

### Ongoing Improvements:
- [ ] Increase test coverage to 90%+
- [ ] Expand fuzzing corpus
- [ ] Add benchmark framework
- [ ] Launch bug bounty program
- [ ] Regular security audits (annual)
- [ ] Performance optimizations
- [ ] User experience improvements
- [ ] Block explorer development
- [ ] Light wallet development
- [ ] Hardware wallet integration

---

## Conclusion

This roadmap provides a **realistic, achievable path** to Bitcoin-level excellence. Key insights:

1. **Quality over speed** - Delay mainnet if necessary for security
2. **Testing is paramount** - This is the biggest gap and highest priority
3. **Security is non-negotiable** - Audit and fuzzing are critical
4. **Community matters** - Professional standards attract contributors
5. **Infrastructure investment pays off** - Automated quality checks prevent bugs

**Current state:** Working testnet (4.5/10)
**10-week target:** Production-ready mainnet (8.5/10)
**Ultimate goal:** Bitcoin-level excellence (9.5/10) - ongoing

The path is clear. The effort is substantial. The outcome is worth it. Let's build a cryptocurrency that deserves to exist in the post-quantum era.

---

**Next Step:** Review this roadmap with stakeholders and commit to the timeline. Quality cryptocurrency software cannot be rushed.
