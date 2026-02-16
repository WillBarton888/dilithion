# Fuzzing Extended Campaigns Guide

## Quick Start

### Option 1: Run via GitHub Web Interface (Easiest)

1. Go to your repo: https://github.com/dilithion/dilithion
2. Click **Actions** tab
3. Select **Fuzzing Extended Campaigns** workflow
4. Click **Run workflow** button
5. Choose duration (2, 4, or 6 hours)
6. Click **Run workflow**

**That's it!** All 9 fuzzers will start running in parallel.

---

## Campaign Configuration

### Tier 1 (Consensus-Critical) - 6 hours default
- **fuzz_difficulty** - Difficulty adjustment algorithm
- **fuzz_tx_validation** - Transaction validation
- **fuzz_utxo** - UTXO set management

**Expected:** ~20-30 billion executions

### Tier 2 (High Priority) - 4 hours default
- **fuzz_block** - Block header + RandomX hashing
- **fuzz_merkle** - Merkle tree construction
- **fuzz_transaction** - Transaction parsing

**Expected:** ~5-10 billion executions

### Tier 3 (Fast Fuzzers) - 2 hours default
- **fuzz_subsidy** - Block subsidy calculation
- **fuzz_compactsize** - CompactSize encoding
- **fuzz_sha3** - SHA3-256 hashing

**Expected:** ~5-7 billion executions

**Total Expected:** ~50 billion fuzzing executions

---

## Monitoring the Campaign

### Watch Live Progress

1. Go to **Actions** tab in your repo
2. Click on the running workflow
3. Click on individual fuzzer jobs to see live logs
4. Look for lines like:
   ```
   #1048576  pulse  cov: 45 ft: 52 corp: 7/22b lim: 4096 exec/s: 524288
   ```

### What the numbers mean:
- `#1048576` - Total executions so far
- `cov: 45` - Code coverage (edges covered)
- `ft: 52` - Features covered
- `corp: 7/22b` - Corpus size (7 files, 22 bytes total)
- `exec/s: 524288` - Executions per second

---

## Checking Results

### After Campaign Completes

1. Go to completed workflow run
2. Scroll to **Artifacts** section at bottom
3. Download artifacts:
   - `fuzz-difficulty-results`
   - `fuzz-tx-validation-results`
   - ... (one per fuzzer)
   - `campaign-summary` - Overall summary report

### If Crashes Were Found

Artifacts will contain files like:
```
crash-<hash>         - Input that caused crash
leak-<hash>          - Memory leak trigger
timeout-<hash>       - Input that caused timeout
```

**To analyze crashes:**
```bash
# Download artifact, then:
./fuzz_difficulty crash-abc123

# You'll see the crash with stack trace
```

---

## Cost Analysis

### GitHub Actions (FREE for public repos)
- ✅ Unlimited minutes for public repos
- ✅ 20 concurrent jobs
- ✅ No credit card needed

### What We're Using
- 9 parallel jobs
- Tier 1: 3 jobs × 6 hours = 18 hours compute
- Tier 2: 3 jobs × 4 hours = 12 hours compute
- Tier 3: 3 jobs × 2 hours = 6 hours compute
- **Total: 36 hours compute (FREE!)**

---

## Scheduled Runs (Optional)

The workflow includes a nightly schedule:
```yaml
schedule:
  - cron: '0 2 * * *'  # 2 AM UTC daily
```

To disable: Comment out the `schedule:` section in `.github/workflows/fuzz-extended-campaigns.yml`

---

## Troubleshooting

### "Workflow not found"
**Problem:** Workflow file not on main/master branch
**Fix:** Push `.github/workflows/fuzz-extended-campaigns.yml` to main branch

### "Job failed: Build error"
**Problem:** Dependencies missing or build failed
**Fix:** Check build logs, may need to update Makefile or dependencies

### "No crashes but low coverage"
**Problem:** Fuzzer not exploring new paths
**Fix:** Seed corpus with real-world inputs (mainnet blocks, transactions)

### "Timeout exceeded"
**Problem:** Job ran longer than timeout setting
**Fix:** This is normal - libFuzzer will save progress. Reduce duration or split into multiple runs.

---

## Advanced: Running Locally (Backup Option)

If GitHub Actions has issues, run locally:

```bash
# Tier 1 (6 hours each)
./fuzz_difficulty -max_total_time=21600 -workers=4 fuzz_corpus/difficulty/ &
./fuzz_tx_validation -max_total_time=21600 -workers=4 fuzz_corpus/tx_validation/ &
./fuzz_utxo -max_total_time=21600 -workers=4 fuzz_corpus/utxo/ &

# Monitor progress
watch -n 60 'pgrep -a fuzz_ | wc -l'

# Check for crashes
ls -lh crash-* leak-* timeout-* 2>/dev/null
```

**Warning:** This will run for 6 hours and use your local compute resources.

---

## Expected Results

### Likely Outcomes (Based on Similar Projects)

**Best Case:** No crashes found ✅
- Means code is robust
- Good news for security

**Realistic:** 2-5 edge case bugs found 🔧
- Typical for first fuzzing campaign
- Usually non-critical (e.g., parsing edge cases, overflow checks)
- Easy to fix

**Worst Case:** Critical consensus bug found 🚨
- Rare but valuable to find now vs. production
- This is exactly why we're fuzzing!

### Common Bugs Found by Fuzzing
1. **Integer overflows** - Unchecked arithmetic
2. **Buffer overruns** - Off-by-one errors
3. **Division by zero** - Edge case inputs
4. **Assertion failures** - Invalid state assumptions
5. **Memory leaks** - Resource cleanup issues

---

## Next Steps After Campaign

### If No Crashes Found
1. ✅ Celebrate - code is robust!
2. Document results in WEEK-7-FUZZING-RESULTS.md
3. Consider extending campaigns to 12-24 hours
4. Seed corpus with mainnet data for better coverage

### If Crashes Found
1. Download crash inputs from artifacts
2. Reproduce locally: `./fuzz_X crash-abc123`
3. Debug with gdb/lldb to understand root cause
4. Write unit test that catches the bug
5. Fix the bug
6. Verify fix: Re-run fuzzer with crash input
7. Commit fix + test
8. Re-run extended campaign to verify

### Creating Bug Report
```markdown
## Fuzzing Bug Report

**Fuzzer:** fuzz_difficulty
**Input:** crash-abc123def (attached)
**Impact:** Crash on specific nBits value
**Root Cause:** Integer overflow in CompactToBig()
**Fix:** Add bounds check before shift operation
**Test Added:** test_difficulty_overflow()
```

---

## Performance Tuning

### If Fuzzer is Too Slow
```yaml
# Reduce workers to 1 (uses less RAM)
-workers=1

# Reduce RSS limit
-rss_limit_mb=1024

# Add timeout for slow inputs
-timeout=30
```

### If You Want Faster Results
```yaml
# Increase workers (uses more RAM)
-workers=4

# Increase RSS limit
-rss_limit_mb=4096

# Run shorter campaigns more frequently
duration: 2 hours, 3x per day
```

---

## Campaign Checklist

Before starting:
- [ ] Code pushed to GitHub (`week7-fuzzing-enhancements` branch)
- [ ] Workflow file committed
- [ ] Branch built successfully (check previous CI runs)
- [ ] Ready to wait 2-6 hours for results

After completion:
- [ ] Download all artifacts
- [ ] Review campaign-summary.md
- [ ] Check each fuzzer's logs for stats
- [ ] Investigate any crashes found
- [ ] Document results

---

**Last Updated:** November 6, 2025
**Author:** Claude (with human guidance)
**Branch:** week7-fuzzing-enhancements
