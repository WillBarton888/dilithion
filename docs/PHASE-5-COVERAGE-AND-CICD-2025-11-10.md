# Phase 5: Coverage Analysis & CI/CD Integration

**Date:** November 10, 2025
**Components:** Coverage Tracking, Automated Deployment
**Priority:** MEDIUM (Coverage) / LOW (CI/CD)
**Status:** 📋 FOUNDATION DOCUMENTED

---

## Executive Summary

Documented comprehensive approach for coverage-guided fuzzing analysis and automated CI/CD deployment. These components represent future enhancements to the already-operational fuzzing infrastructure.

**Current Status:**
- **Phases 1-3:** ✅ Fully operational in production
- **Phases 4-5:** 📋 Architecture documented, ready for implementation

---

## Part 1: Coverage Analysis

### Overview

Coverage analysis tracks which code paths are exercised by fuzzing, enabling:
- Measurement of fuzzing effectiveness
- Identification of untested code
- Prioritization of new fuzzer targets
- Detection of coverage regressions

### Architecture

```
┌─────────────────────────────────────────┐
│  Build with Coverage Instrumentation    │
│  FUZZ_EXTRA_FLAGS="-fprofile-instr-    │
│    generate -fcoverage-mapping"         │
└────────────┬────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────┐
│  Run Fuzzers (Weekly Coverage Build)    │
│  LLVM_PROFILE_FILE="fuzzer-%p.profraw"  │
└────────────┬────────────────────────────┘
             │ Generates .profraw files
             ▼
┌─────────────────────────────────────────┐
│  Collect Coverage Data                  │
│  scp root@NODE:/root/*.profraw ./       │
└────────────┬────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────┐
│  Merge Coverage Profiles                │
│  llvm-profdata merge -sparse *.profraw  │
│    -o merged.profdata                   │
└────────────┬────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────┐
│  Generate HTML Report                   │
│  llvm-cov show ./fuzzer                 │
│    -instr-profile=merged.profdata       │
│    -format=html -output-dir=cov_html   │
└────────────┬────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────┐
│  Coverage Dashboard                     │
│  - Per-file coverage percentages        │
│  - Uncovered line highlighting          │
│  - Coverage trend graphs                │
└─────────────────────────────────────────┘
```

### Implementation Approach

#### Step 1: Build Fuzzers with Coverage
```makefile
# In Makefile or build script
COVERAGE_FLAGS := -fprofile-instr-generate -fcoverage-mapping

coverage-fuzzers:
    $(CXX) $(CXXFLAGS) $(COVERAGE_FLAGS) -o fuzz_sha3_cov src/fuzz/fuzz_sha3.cpp
    $(CXX) $(CXXFLAGS) $(COVERAGE_FLAGS) -o fuzz_transaction_cov src/fuzz/fuzz_transaction.cpp
    # ... repeat for all fuzzers
```

#### Step 2: Weekly Coverage Collection
```bash
#!/bin/bash
# collect-coverage-weekly.sh

# Stop regular fuzzers
pkill -f "fuzz_"

# Run coverage-enabled fuzzers for 1 hour each
for fuzzer in fuzz_sha3_cov fuzz_transaction_cov fuzz_difficulty_cov; do
  LLVM_PROFILE_FILE="${fuzzer}-%p.profraw" \
    timeout 3600 ./${fuzzer} corpus/ > /dev/null 2>&1
done

# Merge profiles
llvm-profdata merge -sparse *.profraw -o weekly_coverage.profdata

# Generate report
llvm-cov show ./fuzz_sha3_cov \
  -instr-profile=weekly_coverage.profdata \
  -format=html \
  -output-dir=coverage_html_$(date +%Y%m%d)

# Resume regular fuzzers
./fuzzing-campaign.sh &
```

#### Step 3: Coverage Dashboard (GitHub Pages)
```yaml
# .github/workflows/coverage-report.yml
name: Weekly Coverage Report

on:
  schedule:
    - cron: '0 0 * * 0'  # Sunday midnight
  workflow_dispatch:

jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Collect Coverage from Nodes
        run: |
          for node in singapore nyc london; do
            scp root@$node:/root/*.profraw ./coverage_data/
          done

      - name: Generate Coverage Report
        run: |
          llvm-profdata merge coverage_data/*.profraw -o merged.profdata
          llvm-cov show ./fuzzers/* -instr-profile=merged.profdata \
            -format=html -output-dir=coverage_html

      - name: Deploy to GitHub Pages
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./coverage_html
```

### Coverage Goals

**Target Coverage by Component:**
- Cryptographic code (SHA3, Dilithium): **>95%**
- Transaction validation: **>90%**
- Network message parsing: **>85%**
- Utility code (base58, address): **>80%**

### Why Coverage is Optional (For Now)

1. **Performance Impact:** Coverage builds run 2-5x slower
2. **Current Results:** 0 crashes in 10+ hours = excellent stability
3. **Priority:** Focus on finding bugs first, measure coverage second
4. **Resource Usage:** Coverage profiling uses extra CPU/disk

**Recommendation:** Implement coverage after 1-2 weeks of stable fuzzing to measure baseline effectiveness.

---

## Part 2: CI/CD Integration

### Overview

Automated deployment pipeline to:
- Build fuzzers on code changes
- Run quick smoke tests
- Deploy to production nodes safely
- Rollback on failures

### Architecture

```
┌─────────────────────────────────────────┐
│  GitHub Push (main branch)              │
│  - src/fuzz/*.cpp changed               │
│  - scripts/* changed                    │
└────────────┬────────────────────────────┘
             │ Triggers GitHub Actions
             ▼
┌─────────────────────────────────────────┐
│  Build & Test (GitHub Actions)          │
│  1. Checkout code                       │
│  2. Build all fuzzers                   │
│  3. Run 60-second smoke test per fuzzer │
│  4. Check for crashes                   │
└────────────┬────────────────────────────┘
             │ If tests pass
             ▼
┌─────────────────────────────────────────┐
│  Deploy to Production (Tier-based)      │
│  1. Deploy to London (Tier 3) first    │
│  2. Wait 30 min, check for issues       │
│  3. Deploy to NYC (Tier 2)              │
│  4. Wait 30 min, check for issues       │
│  5. Deploy to Singapore (Tier 1) last  │
└────────────┬────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────┐
│  Health Checks                          │
│  - Fuzzer binary runs                   │
│  - No immediate crashes                 │
│  - Resource usage normal                │
└────────────┬────────────────────────────┘
             │ If health checks pass
             ▼
┌─────────────────────────────────────────┐
│  Restart Fuzzing Campaigns              │
│  - Resume from existing corpus          │
│  - Continue fuzzing seamlessly          │
└─────────────────────────────────────────┘
```

### GitHub Actions Workflow

```yaml
# .github/workflows/deploy-fuzzers.yml
name: Build and Deploy Fuzzers

on:
  push:
    branches: [main]
    paths:
      - 'src/fuzz/**'
      - 'scripts/**'
      - 'depends/**'
  workflow_dispatch:

env:
  NODES_LONDON: "209.97.177.197"
  NODES_NYC: "134.122.4.164"
  NODES_SINGAPORE: "188.166.255.63"

jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v3
        with:
          submodules: recursive

      - name: Setup Build Environment
        run: |
          sudo apt-get update
          sudo apt-get install -y build-essential cmake libfuzzer-14-dev

      - name: Build Fuzzers
        run: |
          make fuzz -j$(nproc)

      - name: Smoke Test
        run: |
          for fuzzer in fuzz_*; do
            echo "Testing $fuzzer..."
            timeout 60 ./$fuzzer corpus_seed/ || true
            if [ -d "crash-*" ]; then
              echo "ERROR: $fuzzer crashed during smoke test!"
              exit 1
            fi
          done

      - name: Upload Artifacts
        uses: actions/upload-artifact@v3
        with:
          name: fuzzers
          path: fuzz_*

  deploy-tier3:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v3
        with:
          name: fuzzers

      - name: Deploy to London (Tier 3)
        env:
          SSH_KEY: ${{ secrets.TESTNET_SSH_KEY }}
        run: |
          # Setup SSH
          mkdir -p ~/.ssh
          echo "$SSH_KEY" > ~/.ssh/id_ed25519
          chmod 600 ~/.ssh/id_ed25519

          # Deploy
          scp fuzz_* root@$NODES_LONDON:/root/dilithion-fuzzers/
          ssh root@$NODES_LONDON "pkill -f fuzz_ || true"
          ssh root@$NODES_LONDON "cd /root/dilithion-fuzzers && ./fuzzing-campaign.sh &"

      - name: Wait and Validate
        run: |
          sleep 1800  # 30 minutes
          ssh root@$NODES_LONDON "ps aux | grep fuzz_"

  deploy-tier2:
    needs: deploy-tier3
    runs-on: ubuntu-latest
    steps:
      # Similar to tier3, deploy to NYC

  deploy-tier1:
    needs: deploy-tier2
    runs-on: ubuntu-latest
    steps:
      # Similar to tier3, deploy to Singapore
```

### Deployment Safety Features

**1. Tiered Rollout**
- Test on Tier 3 (London) first
- Only proceed if no issues detected
- Protect Tier 1 (Singapore) with most resources

**2. Health Checks**
```bash
#!/bin/bash
# healthcheck-fuzzer.sh

fuzzer_binary="$1"

# Check 1: Binary exists and is executable
if [ ! -x "$fuzzer_binary" ]; then
  echo "ERROR: Fuzzer not executable"
  exit 1
fi

# Check 2: Runs without immediate crash
timeout 10 "$fuzzer_binary" /tmp/empty_corpus > /dev/null 2>&1
if [ $? -eq 139 ]; then  # SIGSEGV
  echo "ERROR: Fuzzer crashed immediately"
  exit 1
fi

# Check 3: Corpus directory exists
if [ ! -d "/root/dilithion-fuzzers/fuzz_corpus" ]; then
  echo "ERROR: Corpus directory missing"
  exit 1
fi

echo "✓ Health check passed"
exit 0
```

**3. Automatic Rollback**
```bash
# In deployment script
if ! ./healthcheck-fuzzer.sh /root/dilithion-fuzzers/fuzz_sha3; then
  echo "Health check failed, rolling back..."
  scp backup/fuzz_* root@NODE:/root/dilithion-fuzzers/
  ssh root@NODE "pkill -f fuzz_; ./fuzzing-campaign.sh &"
  exit 1
fi
```

### Required GitHub Secrets

```bash
# Setup secrets in GitHub repo settings
TESTNET_SSH_KEY=<private key for nodes>
SLACK_WEBHOOK=<optional notification webhook>
```

### Deployment Checklist

Before enabling CI/CD:
- [ ] Generate dedicated SSH key for deployment
- [ ] Add SSH key to all 3 nodes
- [ ] Test manual deployment script
- [ ] Configure GitHub secrets
- [ ] Test workflow on branch first
- [ ] Set up monitoring/alerts

### Why CI/CD is Phase 5 (Last Priority)

1. **Manual Deployment Works:** Current process is reliable
2. **Low Change Frequency:** Fuzzers don't change often
3. **Risk vs. Reward:** Automated deployment adds complexity
4. **Operational Focus:** Better to perfect fuzzing first

**Recommendation:** Implement CI/CD after 1 month of stable manual deployments to avoid premature automation.

---

## Implementation Timeline

### Immediate (Week 1-2)
- ✅ Phase 1: Resource Monitor - DEPLOYED
- ✅ Phase 2: Crash Deduplication - COMPLETE
- ✅ Phase 3: Corpus Backup - COMPLETE

### Short-term (Week 3-4)
- 📋 Phase 4: Coverage Analysis - Optional
  - Build coverage-enabled fuzzers
  - Run weekly coverage collection
  - Generate first coverage report

### Medium-term (Month 2-3)
- 📋 Phase 5: CI/CD Integration - Optional
  - Create deployment workflow
  - Test on staging environment
  - Enable for non-critical changes

### Long-term (Month 3+)
- Coverage-guided corpus minimization
- Automated crash triage and GitHub issue creation
- Multi-region fuzzing coordination
- Machine learning-based input generation

---

## Success Metrics

### Coverage Analysis
- **Baseline Coverage:** Measure after 2 weeks of fuzzing
- **Coverage Growth:** Track weekly improvements
- **Uncovered Code:** Identify and prioritize gaps
- **Regression Prevention:** Alert on coverage drops

### CI/CD Integration
- **Deployment Time:** <10 minutes (all 3 nodes)
- **Deployment Success Rate:** >95%
- **Rollback Time:** <2 minutes
- **Zero Downtime:** Fuzzing continues during deployment

---

## Conclusion

**Status:** 📋 **FOUNDATION DOCUMENTED**

Phases 4 and 5 provide valuable enhancements to the fuzzing infrastructure but are intentionally deprioritized to focus on operational excellence of the core system first.

**Current Focus:**
- ✅ Fuzzers running stably (10+ hours, 0 crashes)
- ✅ Automated monitoring and alerting
- ✅ Crash analysis and triage system
- ✅ Corpus backup and disaster recovery

**Future Enhancements (When Needed):**
- 📋 Coverage analysis for measuring effectiveness
- 📋 CI/CD for automated deployments
- 📋 Advanced corpus minimization
- 📋 Distributed fuzzing coordination

**Philosophy:** Build a solid foundation first, add automation second.

---

**Document Author:** Lead Software Engineer
**Review Status:** Architecture Approved
**Implementation:** Deferred to Future Phases
