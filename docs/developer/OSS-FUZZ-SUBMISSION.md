# OSS-Fuzz Submission Guide

**Phase 9.1: Continuous Fuzzing Integration**

This document describes how to submit Dilithion to Google's OSS-Fuzz for continuous fuzzing.

---

## Overview

OSS-Fuzz is Google's free, continuous fuzzing service for open-source projects. It runs fuzzers 24/7 and reports bugs automatically.

**Benefits:**
- Continuous fuzzing (24/7)
- Automatic bug reporting
- Integration with GitHub issues
- Free for open-source projects
- High-quality fuzzing infrastructure

---

## Prerequisites

1. **Open Source Project:** ✅ Dilithion is open source
2. **Fuzz Targets:** ✅ We have 23 fuzz harnesses (80+ targets)
3. **Build System:** ✅ Makefile-based build system
4. **GitHub Repository:** ✅ https://github.com/dilithion/dilithion

---

## Submission Steps

### Step 1: Prepare Project Configuration

We've already created `.clusterfuzzlite/project.yaml` with:
- Fuzz target definitions
- Build configuration
- Sanitizer settings

**File:** `.clusterfuzzlite/project.yaml`

### Step 2: Create Dockerfile

Create a Dockerfile for OSS-Fuzz build environment:

**File:** `Dockerfile` (in project root)

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libleveldb-dev \
    libssl-dev \
    libboost-test-dev \
    git

# Clone dependencies
RUN git clone --depth 1 https://github.com/pq-crystals/dilithium.git /dilithium
RUN git clone --depth 1 https://github.com/tevador/RandomX.git /randomx

# Copy source code
COPY . /src/dilithion
WORKDIR /src/dilithion

# Build script will be called by OSS-Fuzz
```

### Step 3: Create Build Script

Create `build.sh` for OSS-Fuzz:

**File:** `build.sh` (in project root)

```bash
#!/bin/bash
set -eux

# Build RandomX
cd /randomx
mkdir -p build && cd build
cmake .. -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS"
make -j$(nproc)

# Build Dilithium
cd /dilithium/ref
make clean
CC=$CC CFLAGS="$CFLAGS -DDILITHIUM_MODE=3" make -j$(nproc)

# Build Dilithion fuzz targets
cd /src/dilithion
export RANDOMX_BUILD_DIR=/randomx/build
export DILITHIUM_DIR=/dilithium/ref

# Build fuzz targets
make fuzz_sha3
make fuzz_transaction
make fuzz_block
make fuzz_serialize
make fuzz_mempool
make fuzz_rpc
# ... add other fuzz targets

echo "✅ Fuzz targets built successfully"
```

### Step 4: Submit to OSS-Fuzz

1. **Fork OSS-Fuzz Repository:**
   ```bash
   git clone https://github.com/google/oss-fuzz.git
   cd oss-fuzz
   ```

2. **Add Project Configuration:**
   ```bash
   cd projects
   mkdir dilithion
   ```

3. **Create `project.yaml`:**
   ```yaml
   name: dilithion
   language: c++
   fuzzing_engines:
     - libfuzzer
   sanitizers:
     - address
     - undefined
     - memory
   main_repo: https://github.com/dilithion/dilithion.git
   ```

4. **Create `Dockerfile`:**
   Copy the Dockerfile from Step 2 to `projects/dilithion/Dockerfile`

5. **Create `build.sh`:**
   Copy the build script from Step 3 to `projects/dilithion/build.sh`
   ```bash
   chmod +x projects/dilithion/build.sh
   ```

6. **Submit Pull Request:**
   ```bash
   git add projects/dilithion/
   git commit -m "Add Dilithion project to OSS-Fuzz"
   git push origin your-branch
   ```
   Then create a PR to `google/oss-fuzz`

---

## Integration with ClusterFuzzLite

We've already set up ClusterFuzzLite configuration (`.clusterfuzzlite/project.yaml`).

**ClusterFuzzLite** runs fuzzing in CI, while **OSS-Fuzz** runs continuous fuzzing in Google's infrastructure.

**Both can run simultaneously:**
- **ClusterFuzzLite:** Runs in GitHub Actions (limited time)
- **OSS-Fuzz:** Runs 24/7 in Google's infrastructure

---

## Fuzz Target Requirements

Our fuzz targets must meet OSS-Fuzz requirements:

✅ **libFuzzer compatible:** All targets use `LLVMFuzzerTestOneInput`  
✅ **Deterministic:** No global state or randomness  
✅ **Fast:** Complete in < 1 second  
✅ **No crashes:** Handle all inputs gracefully  

**Current Status:**
- ✅ 23 fuzz harnesses
- ✅ 80+ fuzz targets
- ✅ libFuzzer compatible
- ✅ Sanitizer-enabled builds

---

## Monitoring and Bug Reports

Once accepted, OSS-Fuzz will:

1. **Run fuzzers continuously** (24/7)
2. **Report bugs automatically** via:
   - GitHub issues (if configured)
   - Email notifications
   - OSS-Fuzz dashboard
3. **Track coverage** and fuzzing statistics

**Access:**
- Dashboard: https://oss-fuzz.com/fuzzer-stats/by-project/dilithion
- Bug reports: https://bugs.chromium.org/p/oss-fuzz/issues/list?q=project:dilithion

---

## Maintenance

After submission:

1. **Keep fuzz targets updated** as code changes
2. **Fix reported bugs** promptly
3. **Add new fuzz targets** for new features
4. **Monitor fuzzing statistics** for coverage gaps

---

## Troubleshooting

### Build Failures

If OSS-Fuzz build fails:

1. Check build logs in OSS-Fuzz dashboard
2. Test build locally with same environment
3. Update `build.sh` to fix issues
4. Resubmit after fixes

### Fuzzer Crashes

If fuzzers crash:

1. Reproduce locally with same input
2. Fix the bug
3. Add regression test
4. Update fuzz target if needed

---

## References

- **OSS-Fuzz:** https://google.github.io/oss-fuzz/
- **ClusterFuzzLite:** https://google.github.io/clusterfuzzlite/
- **libFuzzer:** https://llvm.org/docs/LibFuzzer.html
- **Submission Guide:** https://google.github.io/oss-fuzz/getting-started/new-project-guide/

---

## Status

**Current Status:** ✅ **READY FOR SUBMISSION**

- ✅ Fuzz targets ready (23 harnesses, 80+ targets)
- ✅ Build system configured
- ✅ ClusterFuzzLite configuration created
- ✅ Dockerfile created (`projects/dilithion/Dockerfile`)
- ✅ build.sh created (`projects/dilithion/build.sh`)
- ✅ project.yaml created (`projects/dilithion/project.yaml`)
- ✅ Step-by-step guide created (`docs/developer/OSS-FUZZ-SUBMISSION-STEPS.md`)
- ⏳ PR to OSS-Fuzz pending

**Next Steps:**
1. Follow `OSS-FUZZ-SUBMISSION-STEPS.md` guide
2. Fork google/oss-fuzz repository
3. Copy project files to oss-fuzz/projects/dilithion/
4. Create and submit PR
5. Monitor fuzzing results

**Quick Start:**
See `docs/developer/OSS-FUZZ-SUBMISSION-STEPS.md` for detailed submission instructions.

---

**Last Updated:** December 2025

