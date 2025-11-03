# Difficulty Determinism Testing - Platform Preparation Guide

**Date:** November 3, 2025 (Week 4 Day 1)
**Objective:** Prepare 3 P0 platforms for cross-platform difficulty validation
**Timeline:** Day 1-2 (November 10-11, 2025)
**Priority:** CRITICAL (Consensus fork prevention)

---

## Executive Summary

This guide prepares the test execution environments for validating cross-platform determinism of the difficulty adjustment algorithm. Success requires ALL platforms to produce IDENTICAL results for all 10 test vectors.

**Platforms to Test (P0):**
1. Ubuntu 24.04 + GCC 13.x
2. Ubuntu 24.04 + Clang 17.x
3. Windows 11 + MSVC 2022

**Test Files:**
- `src/test/difficulty_determinism_test.cpp` (400+ lines, 10 test vectors)
- `scripts/compare_difficulty_results.py` (370+ lines, comparison tool)

**Success Criteria:**
- All platforms compile test successfully
- All platforms execute all 10 test vectors
- All platforms produce IDENTICAL JSON output
- Comparison tool reports CONSENSUS (exit code 0)

**Failure Scenario:**
- If platforms disagree → Implement Option B (Bitcoin Core ArithU256)
- Re-test all platforms
- Validate consensus

---

## Test File Overview

### difficulty_determinism_test.cpp

**Location:** `src/test/difficulty_determinism_test.cpp`

**Purpose:** Execute 10 critical test vectors for difficulty adjustment

**Test Vectors:**
1. `basic_001_no_change` - Exact 2 weeks, no adjustment
2. `basic_002_2x_faster` - Difficulty should double
3. `basic_003_2x_slower` - Difficulty should halve
4. `edge_004_max_increase` - 4x clamp enforcement
5. `edge_005_max_decrease` - 4x clamp enforcement
6. `edge_006_faster_than_4x` - Clamping beyond 4x
7. `edge_007_slower_than_4x` - Clamping beyond 4x
8. `edge_008_high_difficulty` - Real-world high diff
9. `edge_009_low_difficulty` - Testnet low diff
10. `boundary_010_min_diff` - Minimum boundary

**Output:** JSON file with platform info and results

### compare_difficulty_results.py

**Location:** `scripts/compare_difficulty_results.py`

**Purpose:** Compare results from multiple platforms

**Function:**
- Loads JSON from all platforms
- Groups by test_id
- Compares output_compact and output_target_hex
- Reports any discrepancies

**Exit Codes:**
- `0` - All platforms agree (PASS)
- `1` - Platforms disagree (FAIL - CRITICAL)
- `2` - Invalid input files

---

## Platform 1: Ubuntu 24.04 + GCC

### Prerequisites

**System Requirements:**
- Ubuntu 24.04 LTS (or 22.04)
- 4 GB RAM minimum
- 10 GB disk space
- Internet connection

**Install Required Packages:**
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    git \
    libleveldb-dev \
    python3 \
    python3-pip

# Verify GCC version
gcc --version
# Expected: gcc (Ubuntu 13.2.0) or later

g++ --version
# Expected: g++ (Ubuntu 13.2.0) or later
```

### Clone Repository

```bash
# Clone (if not already done)
git clone https://github.com/dilithion/dilithion.git
cd dilithion

# Or update existing
cd dilithion
git pull origin main
```

### Build Test

**Compilation:**
```bash
# Compile difficulty test
g++ -std=c++17 -I. -I./src \
    src/test/difficulty_determinism_test.cpp \
    src/consensus/pow.cpp \
    -o difficulty_determinism_test

# Verify binary exists
ls -lh difficulty_determinism_test
# Expected: ~50-100 KB executable
```

**Test Run:**
```bash
# Execute test
./difficulty_determinism_test

# Expected output:
# Platform: x86-64, OS: Linux, Compiler: GCC 13.2.0
# Running 10 test vectors...
# All tests passed!
# Results saved to: difficulty_results.json
```

**Verify Output:**
```bash
# Check JSON created
ls -lh difficulty_results.json
# Expected: ~2-3 KB

# View JSON (first few lines)
head -20 difficulty_results.json

# Validate JSON syntax
python3 -m json.tool difficulty_results.json > /dev/null
echo $?  # Should be 0
```

**Rename for Clarity:**
```bash
# Rename to identify platform
mv difficulty_results.json difficulty_results_ubuntu_gcc.json
```

### Troubleshooting

**Problem: g++ not found**
```bash
sudo apt-get install g++
```

**Problem: C++17 not supported**
```bash
g++ --version
# If < 7.0, upgrade:
sudo apt-get install g++-13
g++-13 --version
# Use g++-13 instead of g++
```

**Problem: Missing headers**
```bash
# Ensure you're in project root
pwd
# Should end with /dilithion

# Check src/ exists
ls src/consensus/pow.cpp
```

**Problem: Compilation errors**
```bash
# Save full error output
g++ -std=c++17 -I. -I./src \
    src/test/difficulty_determinism_test.cpp \
    src/consensus/pow.cpp \
    -o difficulty_determinism_test 2>&1 | tee compile_error.txt

# Review errors
cat compile_error.txt
```

---

## Platform 2: Ubuntu 24.04 + Clang

### Prerequisites

**Install Clang:**
```bash
sudo apt-get update
sudo apt-get install -y \
    clang \
    clang-17 \
    libc++-dev \
    libc++abi-dev

# Verify Clang version
clang++ --version
# Expected: clang version 17.0 or later
```

### Build Test

**Compilation:**
```bash
# Compile with Clang
clang++ -std=c++17 -I. -I./src \
    src/test/difficulty_determinism_test.cpp \
    src/consensus/pow.cpp \
    -o difficulty_determinism_test_clang

# Verify binary
ls -lh difficulty_determinism_test_clang
```

**Test Run:**
```bash
# Execute
./difficulty_determinism_test_clang

# Rename output
mv difficulty_results.json difficulty_results_ubuntu_clang.json
```

### Verify Different Binary

```bash
# Compare binaries (should be different)
diff difficulty_determinism_test difficulty_determinism_test_clang
# Expected: Binary files differ

# But results should be identical
diff difficulty_results_ubuntu_gcc.json difficulty_results_ubuntu_clang.json
# Expected: No difference (CRITICAL!)
```

---

## Platform 3: Windows 11 + MSVC 2022

### Prerequisites

**System Requirements:**
- Windows 10/11 (64-bit)
- Visual Studio 2022 (Community Edition or higher)
- 8 GB RAM minimum
- 20 GB disk space

**Install Visual Studio:**
1. Download Visual Studio 2022 Community
   - https://visualstudio.microsoft.com/downloads/
2. Run installer
3. Select "Desktop development with C++"
4. Install

**Verify Installation:**
```powershell
# Open "Developer PowerShell for VS 2022"
cl.exe
# Should show Microsoft C/C++ Compiler version

# Check version
cl.exe /?
# Expected: Version 19.30 or later (MSVC 2022)
```

### Clone Repository

```powershell
# Clone (if not done)
git clone https://github.com/dilithion/dilithion.git
cd dilithion

# Or update
cd dilithion
git pull origin main
```

### Build Test

**Compilation (PowerShell):**
```powershell
# Compile with MSVC
cl.exe /EHsc /std:c++17 /I. /Isrc `
    src\test\difficulty_determinism_test.cpp `
    src\consensus\pow.cpp `
    /Fe:difficulty_determinism_test.exe

# Verify executable
dir difficulty_determinism_test.exe
```

**Test Run:**
```powershell
# Execute
.\difficulty_determinism_test.exe

# Rename output
ren difficulty_results.json difficulty_results_windows_msvc.json
```

### Alternative: MSYS2/MinGW

**If MSVC not available:**
```bash
# Install MSYS2
# Download from: https://www.msys2.org/

# In MSYS2 terminal:
pacman -S mingw-w64-x86_64-gcc

# Compile
g++ -std=c++17 -I. -I./src \
    src/test/difficulty_determinism_test.cpp \
    src/consensus/pow.cpp \
    -o difficulty_determinism_test_mingw.exe

# Run
./difficulty_determinism_test_mingw.exe

# Rename
mv difficulty_results.json difficulty_results_windows_mingw.json
```

### Troubleshooting Windows

**Problem: cl.exe not found**
- Open "Developer PowerShell for VS 2022" (not regular PowerShell)
- Or run: `"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"`

**Problem: Compilation errors**
```powershell
# Check file paths
dir src\consensus\pow.cpp
dir src\test\difficulty_determinism_test.cpp

# Ensure correct directory
cd C:\Users\YourName\dilithion
pwd
```

**Problem: Python not found (for comparison)**
```powershell
# Install Python 3
winget install Python.Python.3.11

# Verify
python --version
```

---

## Cross-Platform Comparison

### Collect Results

**Ensure you have 3 files:**
```bash
ls -lh difficulty_results_*.json

# Expected:
# difficulty_results_ubuntu_gcc.json
# difficulty_results_ubuntu_clang.json
# difficulty_results_windows_msvc.json
```

### Run Comparison

**Execute Python Script:**
```bash
python3 scripts/compare_difficulty_results.py \
    difficulty_results_ubuntu_gcc.json \
    difficulty_results_ubuntu_clang.json \
    difficulty_results_windows_msvc.json
```

**Expected Output (SUCCESS):**
```
Loading results from 3 platforms...

Comparing 10 test vectors across 3 platforms...

Test basic_001_no_change: ✓ CONSENSUS
  All 3 platforms agree: 0x1d00ffff

Test basic_002_2x_faster: ✓ CONSENSUS
  All 3 platforms agree: 0x1c7fffff

...

✓ VALIDATION PASSED
✓ Cross-platform determinism verified
✓ No consensus fork risk detected
✓ Safe for mainnet deployment

Exit code: 0
```

**Expected Output (FAILURE):**
```
Loading results from 3 platforms...

Comparing 10 test vectors across 3 platforms...

Test basic_001_no_change: ✓ CONSENSUS
  All 3 platforms agree: 0x1d00ffff

Test basic_002_2x_faster: ✗ MISMATCH
  CRITICAL: Platforms disagree on difficulty!

  Input parameters:
    Input compact: 0x1d00ffff
    Actual timespan: 604800
    Target timespan: 1209600

  Platform results:
    x86-64, OS: Linux, Compiler: GCC 13.2 → 0x1c7fffff
    x86-64, OS: Windows, Compiler: MSVC 2022 → 0x1c800000  ← DIFFERENT!

...

✗ VALIDATION FAILED
⚠ CRITICAL CONSENSUS FORK RISK!
⚠ MAINNET LAUNCH BLOCKED

A detailed mismatch report has been written to: difficulty_mismatch.txt

Exit code: 1
```

### Interpret Results

**Exit Code 0 (PASS):**
- ✅ All platforms produce identical results
- ✅ Difficulty algorithm is deterministic
- ✅ Safe to proceed to Week 5 (more platforms)
- ✅ No immediate action needed

**Exit Code 1 (FAIL):**
- ❌ Platforms disagree on difficulty calculation
- ❌ CRITICAL consensus fork risk
- ❌ Mainnet launch BLOCKED
- ⚠️ Immediate remediation required

**Remediation if FAIL:**
1. Review `difficulty_mismatch.txt`
2. Identify failing test vectors
3. Debug arithmetic differences
4. Implement Option B (Bitcoin Core ArithU256)
5. Re-test all platforms
6. Validate consensus

---

## Validation Checklist

### Pre-Test Checklist

**For Each Platform:**
- [ ] OS and compiler versions verified
- [ ] Required tools installed (gcc/clang/msvc, python3)
- [ ] Repository cloned and up-to-date
- [ ] Test files exist (difficulty_determinism_test.cpp, compare_difficulty_results.py)
- [ ] Compilation successful
- [ ] Test executable runs without crash

### Test Execution Checklist

**For Each Platform:**
- [ ] Test executed successfully
- [ ] All 10 test vectors passed
- [ ] JSON output generated
- [ ] JSON is valid (python3 -m json.tool)
- [ ] Platform info correct in JSON
- [ ] File renamed with platform identifier

### Comparison Checklist

**Cross-Platform:**
- [ ] All 3 JSON files collected
- [ ] Comparison script executed
- [ ] Exit code recorded (0 or 1)
- [ ] Results documented
- [ ] If FAIL: mismatch report saved

---

## Timeline

### Day 1: Platform Setup (4 hours)

**Hours 1-2: Ubuntu + GCC**
- Install dependencies
- Compile test
- Execute and collect results
- **Deliverable:** difficulty_results_ubuntu_gcc.json

**Hours 3-4: Ubuntu + Clang / Windows + MSVC**
- Set up second platform
- Compile test
- Execute and collect results
- **Deliverable:** difficulty_results_ubuntu_clang.json or difficulty_results_windows_msvc.json

### Day 2: Complete Testing (4 hours)

**Hours 1-2: Complete Remaining Platform**
- Set up third platform
- Compile test
- Execute and collect results
- **Deliverable:** All 3 JSON files

**Hours 3-4: Cross-Platform Comparison**
- Run comparison script
- Analyze results
- Document findings
- Create GO/NO-GO decision
- **Deliverable:** DIFFICULTY-VALIDATION-WEEK4-RESULTS.md

---

## Success Criteria

### Platform Preparation Success

**Each Platform:**
- ✅ Compiles difficulty_determinism_test successfully
- ✅ Executes without crashes
- ✅ Produces valid JSON output
- ✅ All 10 test vectors pass
- ✅ Platform info correctly detected

**Overall:**
- ✅ 3 P0 platforms tested
- ✅ All platforms execute successfully
- ✅ JSON files collected and valid

### Validation Success

**Comparison:**
- ✅ Comparison script executes
- ✅ All platforms agree on all 10 test vectors
- ✅ Exit code: 0 (CONSENSUS)
- ✅ No discrepancies found

**Documentation:**
- ✅ Results documented
- ✅ Platform info recorded
- ✅ GO decision made

---

## Failure Handling

### If Compilation Fails

1. **Check prerequisites:** Verify all tools installed
2. **Check file paths:** Ensure src/ directory structure correct
3. **Check compiler version:** May need newer compiler
4. **Document error:** Save full error output
5. **Ask for help:** GitHub Issues or project channel

### If Tests Crash

1. **Check platform info:** Architecture, OS, compiler
2. **Run in debugger:** gdb (Linux) or Visual Studio debugger (Windows)
3. **Check test vector:** Which test causes crash?
4. **Document crash:** Stack trace, error message
5. **Report issue:** This is a bug that needs fixing

### If Platforms Disagree

1. **Don't panic:** This is why we test!
2. **Review mismatch report:** difficulty_mismatch.txt
3. **Identify pattern:** Which test vectors fail?
4. **Check arithmetic:** Integer overflow? Division rounding?
5. **Implement Option B:** Bitcoin Core's ArithU256
6. **Re-test:** All platforms must agree
7. **Document fix:** What changed? Why?

---

## Reference

### Test File Locations

```
dilithion/
├── src/
│   ├── test/
│   │   └── difficulty_determinism_test.cpp  ← Test implementation
│   └── consensus/
│       └── pow.cpp                          ← Difficulty algorithm
├── scripts/
│   └── compare_difficulty_results.py        ← Comparison tool
└── CRITICAL-DIFFICULTY-DETERMINISM-PLAN.md  ← Full validation plan
```

### Related Documentation

- `CRITICAL-DIFFICULTY-DETERMINISM-PLAN.md` - Complete validation plan
- `DIFFICULTY-DETERMINISM-REMEDIATION-COMPLETE.md` - Remediation summary
- `WEEK-4-IMPLEMENTATION-PLAN.md` - Week 4 overall plan

### Support

- **Technical Issues:** GitHub Issues
- **Platform Problems:** Platform-specific documentation
- **Test Failures:** Document in DIFFICULTY-VALIDATION-WEEK4-RESULTS.md

---

## Conclusion

Platform preparation is critical for consensus validation. Take time to set up each platform correctly. Accurate results require proper compilation and execution.

**Remember:** Even ONE platform disagreement = consensus fork risk = mainnet BLOCKED

Be thorough. Be accurate. Document everything.

---

**Document Version:** 1.0
**Date:** November 3, 2025
**Status:** Ready for Execution
**Timeline:** Day 1-2 (November 10-11, 2025)
