# WEEK 7 FUZZING ENHANCEMENTS - COMPREHENSIVE EXECUTION PLAN

**Date:** November 6-8, 2025 (Week 7 Day 1-3)
**Duration:** ~12-16 hours execution, ~24 hours wall-clock
**Prerequisites:** Week 6 Phase 3 COMPLETE - 3 P0/P1 fuzzers operational, 374M+ executions, ZERO crashes
**Status:** READY TO EXECUTE

---

## EXECUTIVE SUMMARY

Week 7 transforms the fuzzing infrastructure from proof-of-concept (3 working fuzzers) to production-grade comprehensive testing (11 operational fuzzers with extended campaigns and CI integration).

**Current State:**
- 3/11 fuzzers operational: `fuzz_tx_validation`, `fuzz_utxo`, `fuzz_sha3`
- 8/11 fuzzers broken: API compatibility issues (CDataStream, multiple FUZZ_TARGET macros)
- 374M+ successful executions, ZERO crashes found
- No CI integration, no parallel execution, no extended campaigns

**Target State:**
- 11/11 fuzzers operational with corrected APIs
- 24+ hour extended campaigns completed
- Parallel fuzzing with multi-core execution
- CI integration with 5-minute smoke tests
- Comprehensive crash triage documentation

**Risk Assessment:** LOW
- API fixes are well-understood (working fuzzers provide templates)
- Infrastructure already validated (374M executions)
- Clang 14.0.6 confirmed operational
- No consensus changes required

---

## TIMELINE

### Day 1 (6 hours)
- **Morning (3h):** Fix first 5 fuzzers
- **Afternoon (3h):** Fix remaining 3 fuzzers + validation

### Day 2 (4 hours + overnight)
- **Morning (2h):** Campaign strategy + corpus prep
- **Afternoon (2h):** Launch extended campaigns
- **Overnight:** Extended campaigns run (12-16 hours)

### Day 3 (6 hours)
- **Morning (2h):** Results analysis
- **Midday (2h):** Parallel infrastructure
- **Afternoon (2h):** CI integration

### Day 4 (2 hours)
- **Morning (2h):** Final documentation

**Total Effort:** 18 hours active work + 12-16 hours unattended execution
**Wall Clock:** 3-4 days

---

## PHASE 1: API COMPATIBILITY FIXES (4-5 hours)

### Priority Order:
1. fuzz_transaction (45 min) - HIGH priority
2. fuzz_block (45 min) - HIGH priority
3. fuzz_difficulty (45 min) - CRITICAL priority
4. fuzz_merkle (45 min) - HIGH priority
5. fuzz_compactsize (30 min) - MEDIUM priority
6. fuzz_subsidy (30 min) - MEDIUM priority
7. fuzz_network_message (30 min) - MEDIUM priority
8. fuzz_address (30 min) - MEDIUM priority

### Common API Issues to Fix:
- **CDataStream obsolete** → Use `CTransaction::Deserialize(data, size, &error)`
- **Multiple FUZZ_TARGET macros** → Keep only ONE per file
- **Missing includes** → Add required headers
- **Wrong function names** → e.g., `sha3_256` → `SHA3_256`

---

## PHASE 2: EXTENDED FUZZING CAMPAIGNS (12-16 hours execution, 24 hours wall-clock)

### Campaign Strategy:

**Tier 1 - Critical (8 hours each):**
1. `fuzz_tx_validation` - P0 CRITICAL
2. `fuzz_utxo` - P0 CRITICAL
3. `fuzz_difficulty` - P0 CRITICAL

**Tier 2 - High Priority (4 hours each):**
4. `fuzz_transaction` - P1 HIGH
5. `fuzz_block` - P1 HIGH
6. `fuzz_merkle` - P1 HIGH

**Tier 3 - Medium Priority (2 hours each):**
7. `fuzz_sha3` - P2
8. `fuzz_compactsize` - P2
9. `fuzz_subsidy` - P2

**Tier 4 - Lower Priority (1 hour each):**
10. `fuzz_network_message` - P2
11. `fuzz_address` - P2

### Expected Results:
```
Total Executions: ~14.4 billion
Coverage Growth: +12% average
Expected Crashes:
  - CRITICAL: 0
  - HIGH: 0-2
  - MEDIUM: 1-5
  - LOW: 5-10 (expected edge cases)
```

---

## PHASE 3: PARALLEL FUZZING INFRASTRUCTURE (2 hours)

### Deliverables:
1. `scripts/run_parallel_fuzz.sh` - Multi-core fuzzing orchestration
2. `scripts/monitor_fuzz_campaign.sh` - Real-time monitoring dashboard
3. `scripts/stop_all_fuzzers.sh` - Emergency stop all
4. `scripts/analyze_results.sh` - Results aggregation

### Features:
- Core affinity for optimal performance
- Staggered starts to avoid resource contention
- Real-time monitoring with 30-second updates
- Automatic crash detection
- Performance metrics (exec/s, coverage, memory)

---

## PHASE 4: CI INTEGRATION (2-3 hours)

### CI Strategy:
1. **Smoke Tests (PR/Push):** 5-minute runs per fuzzer
2. **Extended Campaigns (Nightly):** 6-hour parallel campaigns
3. **Crash Detection:** Automatic artifact upload on failure
4. **Matrix Strategy:** Parallel execution of all 9 fuzzers

### Workflow: `.github/workflows/fuzz.yml`
- 9 fuzzer jobs × 5 minutes = ~45 minutes total (parallel)
- Nightly extended campaigns: 6 hours
- Crash artifacts automatically uploaded
- Integration with existing CI pipeline

---

## SUCCESS CRITERIA

### Phase 1: API Fixes ✅
- All 11 fuzzers compile without errors
- All pass 60-second smoke tests
- exec/s within expected ranges

### Phase 2: Extended Campaigns ✅
- Minimum 10 billion total executions
- Coverage growth for each fuzzer
- Zero CRITICAL crashes

### Phase 3: Parallel Infrastructure ✅
- Works on 4+ cores
- Real-time monitoring operational
- Clean stop/restart capability

### Phase 4: CI Integration ✅
- All smoke tests pass in < 60 minutes
- Nightly campaigns configured
- Crash detection and artifact upload works

---

## DELIVERABLES

### Code (11 files)
1. 8 fixed fuzzer source files
2. 3 parallel execution scripts
3. 1 CI workflow file

### Documentation (3 files)
1. Updated `docs/FUZZING.md`
2. New `docs/FUZZING-RUNBOOK.md`
3. `WEEK-7-FUZZING-RESULTS.md`

### Results
1. Build logs (all 11 fuzzers)
2. Campaign logs (12-16 hours each)
3. Coverage statistics
4. Performance metrics
5. Crash reports (if any)

---

## IMMEDIATE NEXT STEPS

1. Create work branch: `git checkout -b week7-fuzzing-enhancements`
2. Create directories: `mkdir -p build_logs smoke_test logs fuzz_corpus/{tx_validation,utxo,difficulty,transaction,block,merkle,sha3,compactsize,subsidy,network,address}`
3. Start Phase 1.1: Diagnostic assessment of broken fuzzers
4. Begin fixing fuzzers in priority order

---

## RISK MITIGATION

**Low Risks:**
- API compatibility - Working examples exist
- Infrastructure - Already validated
- Tooling - Clang 14.0.6 confirmed

**Medium Risks:**
- Time overrun on API fixes → Start with highest priority
- CI resource limits → Use 5-min smoke tests, nightly extended

**Addressed:**
- Compiler availability ✅
- libFuzzer support ✅
- Multi-target strategy ✅

---

**PLAN STATUS:** READY FOR EXECUTION
**ESTIMATED COMPLETION:** November 9, 2025 (3-4 days)
**PRIORITY:** HIGH - Comprehensive fuzzing validates production readiness

---

## APPENDIX: COMMAND REFERENCE

### Build Commands
```bash
make fuzz                          # Build all 11 fuzzers
make fuzz_transaction              # Build individual fuzzer
make clean && make fuzz            # Clean rebuild
```

### Extended Campaign
```bash
# 8-hour campaign with monitoring
./fuzz_NAME -max_total_time=28800 -timeout=30 -rss_limit_mb=2048 \
    fuzz_corpus/NAME/ 2>&1 | tee logs/NAME.log &
```

### Parallel Execution
```bash
./scripts/run_parallel_fuzz.sh 3600         # 1-hour campaign
./scripts/run_parallel_fuzz.sh 28800        # 8-hour campaign
./scripts/monitor_fuzz_campaign.sh &        # Live monitoring
./scripts/stop_all_fuzzers.sh               # Emergency stop
```

### Crash Reproduction
```bash
./fuzz_NAME crash-HASH                      # Reproduce crash
./fuzz_NAME -minimize_crash=1 crash-HASH    # Minimize crash input
gdb --args ./fuzz_NAME crash-HASH           # Debug crash
```

---

**Prepared by:** Plan Agent (Sonnet 4.5)
**Date:** November 6, 2025
**Status:** Comprehensive plan ready for execution
