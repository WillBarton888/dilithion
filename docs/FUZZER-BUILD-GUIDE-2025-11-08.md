# Dilithion Fuzzer Build Guide
**Date:** November 8, 2025
**Author:** Dilithion Core Development Team
**Status:** Production Ready

---

## Table of Contents
1. [Overview](#overview)
2. [Environment Requirements](#environment-requirements)
3. [Build Methods](#build-methods)
4. [Deployment Instructions](#deployment-instructions)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)
7. [Production Node Details](#production-node-details)
8. [Test Results](#test-results)

---

## 1. Overview

This guide documents the build and deployment process for Dilithion's libFuzzer-based fuzzing harnesses on production testnet infrastructure. It covers GLIBC compatibility requirements, build procedures, and validation methodologies to ensure fuzzing binaries execute correctly across all deployment targets.

### What This Guide Covers

- Building 11 fuzzing harnesses with GLIBC 2.35 compatibility
- Two deployment methods: Docker-based local builds and remote native builds
- 60-second smoke test validation procedures
- Production deployment to 3 geographical testnet nodes

### Why GLIBC Compatibility Matters

LibFuzzer binaries built with newer GLIBC versions (2.36+) cannot execute on systems with older GLIBC (2.35). Since testnet production nodes run Ubuntu 22.04 LTS with GLIBC 2.35, all fuzzers must be built targeting this environment to avoid runtime errors like:

```
./fuzz_sha3: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.36' not found
```

This guide ensures 100% compatibility across all production deployments.

---

## 2. Environment Requirements

### GLIBC Version Requirements

**Target Environment:**
- GLIBC 2.35 (Ubuntu 22.04 LTS baseline)
- All production testnet nodes verified with GLIBC 2.35-0ubuntu3.11

**Build Environment:**
- Must use GLIBC 2.35 or compatible toolchain
- Clang-14 with libFuzzer support
- Ubuntu 22.04 LTS recommended

### Compiler Requirements

**Clang Version:**
```bash
clang-14 (Ubuntu 14.0.0-1ubuntu1.1)
```

**Required Packages:**
- `clang-14`
- `libc++-14-dev`
- `libc++abi-14-dev`
- `build-essential`
- `cmake`
- `libleveldb-dev`
- `git`

### System Dependencies

**Build Dependencies:**
```bash
# RandomX dependencies
cmake >= 3.5

# Dilithium dependencies
gcc >= 9.0

# General build tools
make
git
```

---

## 3. Build Methods

Two build methods are available, each with specific use cases:

### Method A: Docker Build (Local)

**Use Case:** Future deployment when Docker is available on production nodes

**Advantages:**
- Consistent build environment
- Isolated from host system
- Reproducible builds

**Limitations:**
- Docker not currently installed on production nodes
- Larger binary sizes due to static linking
- Additional deployment step to copy binaries

**Dockerfile:** `C:\Users\will\dilithion\Dockerfile.fuzzer`

### Method B: Remote Build (Production - USED)

**Use Case:** Current production deployment method

**Advantages:**
- Native builds optimized for target environment
- No Docker dependency
- Direct deployment to final location
- Guaranteed GLIBC compatibility

**Limitations:**
- Requires SSH access to production nodes
- Build time dependent on node resources
- Must install clang-14 on first deployment

**Scripts:**
- `scripts/build-fuzzers-remote-2025-11-08.sh` - Remote build execution
- `scripts/deploy-and-build-fuzzers-2025-11-08.sh` - Deployment orchestration

---

## 4. Deployment Instructions

### Method A: Docker Build (For Future Use)

**Step 1: Build Docker Image**
```bash
cd C:\Users\will\dilithion
docker build -f Dockerfile.fuzzer -t dilithion-fuzzer-builder .
```

**Step 2: Extract Binaries**
```bash
docker create --name fuzzer-extract dilithion-fuzzer-builder
docker cp fuzzer-extract:/build/fuzzer_binaries ./fuzzer_binaries
docker rm fuzzer-extract
```

**Step 3: Deploy to Nodes**
```bash
# Upload binaries to production node
scp -i ~/.ssh/id_ed25519_windows fuzzer_binaries/fuzz_* root@NODE_IP:/root/dilithion-fuzzers/
```

### Method B: Remote Build (Current Production Method)

**Prerequisites:**
1. SSH key configured for production nodes
2. SSH key located at: `~/.ssh/id_ed25519_windows` (WSL)
3. Network access to all 3 testnet nodes

**Deploy to Singapore Node:**
```bash
wsl bash -c "cd /mnt/c/Users/will/dilithion && bash scripts/deploy-and-build-fuzzers-2025-11-08.sh singapore"
```

**Deploy to New York Node:**
```bash
wsl bash -c "cd /mnt/c/Users/will/dilithion && bash scripts/deploy-and-build-fuzzers-2025-11-08.sh newyork"
```

**Deploy to London Node:**
```bash
wsl bash -c "cd /mnt/c/Users/will/dilithion && bash scripts/deploy-and-build-fuzzers-2025-11-08.sh london"
```

**Deploy to All Nodes:**
```bash
wsl bash -c "cd /mnt/c/Users/will/dilithion && bash scripts/deploy-and-build-fuzzers-2025-11-08.sh all"
```

**Deployment Process (Automated):**
1. Test SSH connectivity
2. Verify environment (GLIBC, GCC, Clang versions)
3. Package source code (excludes .git, build artifacts)
4. Upload source tarball to node
5. Extract source on remote
6. Upload build script
7. Execute remote build:
   - Install clang-14 if needed
   - Build RandomX dependency
   - Build Dilithium dependency
   - Build all 11 fuzzers
   - Copy to `/root/dilithion-fuzzers/`
8. Run 60-second smoke tests on all 11 fuzzers
9. Report results

---

## 5. Verification

### Smoke Test Procedure

Each fuzzer undergoes a 60-second execution test to verify:
- No GLIBC compatibility errors
- No segmentation faults
- No immediate crashes
- Basic fuzzing engine initialization

**Manual Smoke Test:**
```bash
# SSH into production node
ssh -i ~/.ssh/id_ed25519_windows root@NODE_IP

# Navigate to fuzzer directory
cd /root/dilithion-fuzzers

# Run 60-second test
timeout 60 ./fuzz_sha3

# Expected output (no errors):
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 123456789
INFO: Loaded 1 modules   (1234 inline 8-bit counters): ...
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 123 ft: 456 corp: 1/1b exec/s: 0 rss: 45Mb
#4      NEW    cov: 130 ft: 470 corp: 2/3b lim: 4 exec/s: 0 rss: 45Mb
...
```

**Automated Verification:**
The deployment script automatically runs smoke tests and checks for:
- GLIBC errors (immediate failure)
- Crash indicators (segfault, abort)
- Successful fuzzer initialization

**Success Criteria:**
- All 11 fuzzers must pass smoke tests (11/11 PASS)
- Zero GLIBC compatibility errors
- No unexplained crashes or errors

---

## 6. Troubleshooting

### Common GLIBC Errors

**Error:** `version 'GLIBC_2.36' not found`

**Cause:** Fuzzer built with newer GLIBC than target system

**Solution:**
1. Verify target GLIBC version:
   ```bash
   ldd --version | head -n1
   ```
2. Rebuild using Method B (Remote Build) on target system
3. Ensure clang-14 is used (not newer versions)

**Error:** `GLIBCXX version not found`

**Cause:** C++ standard library version mismatch

**Solution:**
```bash
# Install matching libc++ on target
apt-get install libc++-14-dev libc++abi-14-dev
```

### SSH Connection Issues

**Error:** `Permission denied (publickey)`

**Cause:** SSH key not configured or wrong key path

**Solution:**
1. Verify SSH key exists:
   ```bash
   ls ~/.ssh/id_ed25519_windows
   ```
2. Test SSH connection:
   ```bash
   ssh -i ~/.ssh/id_ed25519_windows root@NODE_IP 'echo Success'
   ```
3. Check key permissions:
   ```bash
   chmod 600 ~/.ssh/id_ed25519_windows
   ```

### Build Failures

**Error:** `clang-14: command not found`

**Cause:** Clang-14 not installed on build system

**Solution:**
```bash
# Remote build script automatically handles this
# Manual installation:
apt-get update
apt-get install -y clang-14 libc++-14-dev libc++abi-14-dev
```

**Error:** Compilation errors in source files

**Cause:** Missing dependencies or corrupted source

**Solution:**
1. Verify source upload:
   ```bash
   ssh root@NODE_IP "ls -lh /root/dilithion"
   ```
2. Check for missing dependencies:
   ```bash
   apt-get install -y build-essential cmake libleveldb-dev
   ```
3. Clean and rebuild:
   ```bash
   rm -rf /root/dilithion-fuzzer-build
   # Re-run deployment script
   ```

### Smoke Test Failures

**Symptom:** Fuzzer crashes immediately

**Diagnostic Steps:**
1. Run with verbose output:
   ```bash
   ./fuzz_sha3 -verbosity=2 -max_total_time=10
   ```
2. Check for missing shared libraries:
   ```bash
   ldd ./fuzz_sha3
   ```
3. Verify binary architecture:
   ```bash
   file ./fuzz_sha3
   ```

---

## 7. Production Node Details

### Singapore Node

**IP Address:** 188.166.255.63
**Hostname:** dilithion-testnet-sgp
**Location:** Singapore (Digital Ocean)
**OS:** Ubuntu 22.04 LTS
**GLIBC Version:** ldd (Ubuntu GLIBC 2.35-0ubuntu3.11) 2.35
**GCC Version:** gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0
**Clang Version:** clang-14 (1:14.0.0-1ubuntu1.1)

**SSH Access:**
```bash
ssh -i ~/.ssh/id_ed25519_windows root@188.166.255.63
```

**Fuzzer Location:** `/root/dilithion-fuzzers/`

### New York Node

**IP Address:** 134.122.4.164
**Hostname:** ubuntu-s-1vcpu-2gb-nyc3-01
**Location:** New York City (Digital Ocean)
**OS:** Ubuntu 22.04 LTS
**GLIBC Version:** ldd (Ubuntu GLIBC 2.35-0ubuntu3.11) 2.35
**GCC Version:** gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0
**Clang Version:** clang-14 (1:14.0.0-1ubuntu1.1)

**SSH Access:**
```bash
ssh -i ~/.ssh/id_ed25519_windows root@134.122.4.164
```

**Fuzzer Location:** `/root/dilithion-fuzzers/`

### London Node

**IP Address:** 209.97.177.197
**Hostname:** Dilithion-seed-London-1
**Location:** London (Digital Ocean)
**OS:** Ubuntu 22.04 LTS
**GLIBC Version:** ldd (Ubuntu GLIBC 2.35-0ubuntu3.11) 2.35
**GCC Version:** gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0
**Clang Version:** clang-14 (1:14.0.0-1ubuntu1.1)

**SSH Access:**
```bash
ssh -i ~/.ssh/id_ed25519_windows root@209.97.177.197
```

**Fuzzer Location:** `/root/dilithion-fuzzers/`

### Common Configuration

All nodes share identical configuration:
- Ubuntu 22.04 LTS (Jammy Jellyfish)
- GLIBC 2.35-0ubuntu3.11
- Clang-14 with libFuzzer support
- Fuzzer binaries located at `/root/dilithion-fuzzers/`
- 60-second smoke tests validated on all nodes

---

## 8. Test Results

### Deployment Summary

**Date:** November 8, 2025
**Total Nodes:** 3
**Total Fuzzers:** 11 per node
**Total Smoke Tests:** 33 (11 fuzzers × 3 nodes)

### Singapore Node Results

**Node:** 188.166.255.63 (dilithion-testnet-sgp)
**GLIBC:** 2.35-0ubuntu3.11
**Build Status:** SUCCESS
**Smoke Test Results:** 11/11 PASS

| Fuzzer | Binary Size | Status |
|--------|-------------|--------|
| fuzz_sha3 | 1.8M | PASS |
| fuzz_transaction | 2.0M | PASS |
| fuzz_block | 2.0M | PASS |
| fuzz_compactsize | 1.8M | PASS |
| fuzz_network_message | 2.0M | PASS |
| fuzz_address | 1.9M | PASS |
| fuzz_difficulty | 2.0M | PASS |
| fuzz_subsidy | 1.8M | PASS |
| fuzz_merkle | 1.9M | PASS |
| fuzz_tx_validation | 2.3M | PASS |
| fuzz_utxo | 2.6M | PASS |

**GLIBC Errors:** 0
**Status:** PRODUCTION READY

### New York Node Results

**Node:** 134.122.4.164 (ubuntu-s-1vcpu-2gb-nyc3-01)
**GLIBC:** 2.35-0ubuntu3.11
**Build Status:** SUCCESS
**Smoke Test Results:** 11/11 PASS

| Fuzzer | Binary Size | Status |
|--------|-------------|--------|
| fuzz_sha3 | 1.8M | PASS |
| fuzz_transaction | 2.0M | PASS |
| fuzz_block | 2.0M | PASS |
| fuzz_compactsize | 1.8M | PASS |
| fuzz_network_message | 2.0M | PASS |
| fuzz_address | 1.9M | PASS |
| fuzz_difficulty | 2.0M | PASS |
| fuzz_subsidy | 1.8M | PASS |
| fuzz_merkle | 1.9M | PASS |
| fuzz_tx_validation | 2.3M | PASS |
| fuzz_utxo | 2.6M | PASS |

**GLIBC Errors:** 0
**Status:** PRODUCTION READY

### London Node Results

**Node:** 209.97.177.197 (Dilithion-seed-London-1)
**GLIBC:** 2.35-0ubuntu3.11
**Build Status:** SUCCESS
**Smoke Test Results:** 11/11 PASS

| Fuzzer | Binary Size | Status |
|--------|-------------|--------|
| fuzz_sha3 | 1.8M | PASS |
| fuzz_transaction | 2.0M | PASS |
| fuzz_block | 2.0M | PASS |
| fuzz_compactsize | 1.8M | PASS |
| fuzz_network_message | 2.0M | PASS |
| fuzz_address | 1.9M | PASS |
| fuzz_difficulty | 2.0M | PASS |
| fuzz_subsidy | 1.8M | PASS |
| fuzz_merkle | 1.9M | PASS |
| fuzz_tx_validation | 2.3M | PASS |
| fuzz_utxo | 2.6M | PASS |

**GLIBC Errors:** 0
**Status:** PRODUCTION READY

### Final Validation Summary

**Overall Results:**
- Total Smoke Tests: **33/33 PASS (100%)**
- GLIBC Compatibility Errors: **0**
- Failed Tests: **0**
- All Nodes: **PRODUCTION READY**

**Key Achievements:**
- Zero GLIBC compatibility errors across all nodes
- 100% smoke test pass rate
- Consistent binary sizes across all deployments
- All fuzzers execute successfully on production infrastructure

**Deployment Method:** Remote Build (Method B)
**Build Toolchain:** Clang-14 with libFuzzer
**Target GLIBC:** 2.35 (Ubuntu 22.04 LTS)
**Validation:** 60-second smoke tests per fuzzer

---

## Fuzzer Inventory

### Complete Fuzzer List

1. **fuzz_sha3** - SHA-3 cryptographic hash function fuzzing
2. **fuzz_transaction** - Transaction structure and validation fuzzing
3. **fuzz_block** - Block header and structure fuzzing
4. **fuzz_compactsize** - Variable-length integer encoding fuzzing
5. **fuzz_network_message** - P2P network message parsing fuzzing
6. **fuzz_address** - Base58 address encoding/decoding fuzzing
7. **fuzz_difficulty** - Difficulty adjustment algorithm fuzzing
8. **fuzz_subsidy** - Block subsidy calculation fuzzing
9. **fuzz_merkle** - Merkle tree construction fuzzing
10. **fuzz_tx_validation** - Transaction validation logic fuzzing
11. **fuzz_utxo** - UTXO set operations fuzzing

### Running Fuzzers

**Basic Usage:**
```bash
cd /root/dilithion-fuzzers
./fuzz_sha3 -max_total_time=3600  # Run for 1 hour
```

**With Corpus:**
```bash
./fuzz_transaction fuzz_corpus/transaction/
```

**Continuous Fuzzing:**
```bash
./fuzz_block -max_total_time=0  # Run indefinitely
```

---

## Conclusion

This guide documents the successful deployment of 11 libFuzzer harnesses across 3 production testnet nodes with 100% compatibility. All fuzzers execute without GLIBC errors and are ready for production fuzzing campaigns.

**Phase 1: GLIBC Compatibility - COMPLETE**

**Next Steps:**
- Phase 2: Expand fuzzer coverage to 20 harnesses
- Phase 3: Implement continuous fuzzing infrastructure
- Phase 4: Integrate with CI/CD pipeline
- Phase 5: Production fuzzing campaigns

---

**Document Version:** 1.0
**Last Updated:** November 8, 2025
**Status:** Production Ready
**Maintainer:** Dilithion Core Development Team
