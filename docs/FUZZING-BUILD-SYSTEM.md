# Fuzzing Build System Architecture

**Document Version**: 1.0
**Last Updated**: November 6, 2025
**Author**: Build System Team
**Status**: Production

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Why This Approach](#why-this-approach)
4. [Build Process](#build-process)
5. [Adding New Fuzzers](#adding-new-fuzzers)
6. [Troubleshooting](#troubleshooting)
7. [Technical Details](#technical-details)

---

## Overview

The Dilithion fuzzing infrastructure uses **libFuzzer** (LLVM's coverage-guided fuzzer) with a pre-compiled object file architecture. This design ensures consistent builds across local development and CI environments.

### Key Principles

- **Separation of Concerns**: Fuzzer harnesses compiled WITH sanitizers, dependencies compiled WITHOUT
- **Dependency Resolution**: Make automatically builds all required object files
- **CI Compatibility**: No reliance on cached state or manual pre-build steps
- **Proven Pattern**: Mirrors the working `test_dilithion` binary architecture

---

## Architecture

### Component Layers

```
┌─────────────────────────────────────────────────┐
│   Fuzzer Binary (e.g., fuzz_block)             │
│   - Linked with -fsanitize=fuzzer,address,ub   │
└─────────────────────────────────────────────────┘
                      ▲
                      │ Links
         ┌────────────┴────────────┐
         │                         │
┌────────┴─────────┐    ┌─────────┴──────────┐
│ Fuzzer Harness   │    │  Dependency Objects │
│ (WITH sanitizers)│    │ (NO sanitizers)     │
│                  │    │                     │
│ build/obj/test/  │    │ build/obj/crypto/  │
│   fuzz/*.o       │    │ build/obj/consensus/│
│                  │    │ build/obj/primitives/│
│ Compiled with:   │    │                     │
│ $(FUZZ_CXX)      │    │ Compiled with:     │
│ $(FUZZ_CXXFLAGS) │    │ $(CXX) $(CXXFLAGS) │
└──────────────────┘    └────────────────────┘
         │                         │
         └────────────┬────────────┘
                      │ Also links
         ┌────────────┴────────────┐
         │                         │
┌────────┴──────────┐   ┌─────────┴─────────┐
│ Dilithium Library │   │ RandomX Library   │
│ (C objects)       │   │ (CMake built)     │
│                   │   │                   │
│ depends/dilithium/│   │ depends/randomx/  │
│   ref/*.o         │   │   build/          │
│                   │   │                   │
│ Compiled with:    │   │ Built with:       │
│ gcc (no sanitize) │   │ cmake + make      │
└───────────────────┘   └───────────────────┘
```

### Object File Groups

The Makefile defines reusable object file groups:

```makefile
# Common dependencies (most fuzzers need these)
FUZZ_COMMON_OBJECTS := $(OBJ_DIR)/crypto/sha3.o \
                       $(OBJ_DIR)/primitives/transaction.o \
                       $(OBJ_DIR)/primitives/block.o \
                       $(OBJ_DIR)/core/chainparams.o \
                       $(OBJ_DIR)/crypto/randomx_hash.o

# Consensus-specific (difficulty, validation fuzzers)
FUZZ_CONSENSUS_OBJECTS := $(OBJ_DIR)/consensus/pow.o \
                          $(OBJ_DIR)/consensus/fees.o \
                          $(OBJ_DIR)/consensus/tx_validation.o \
                          $(OBJ_DIR)/consensus/validation.o

# Node-specific (UTXO fuzzers)
FUZZ_NODE_OBJECTS := $(OBJ_DIR)/node/utxo_set.o
```

---

## Why This Approach

### Problem: Direct .cpp Compilation

**Previous approach (BROKEN)**:
```makefile
fuzz_block: src/test/fuzz/fuzz_block.cpp src/primitives/block.cpp ...
    @$(FUZZ_CXX) $(FUZZ_CXXFLAGS) $^ -o $@ ...
```

**Why it failed**:
1. Clang compiles each `.cpp` as separate translation unit
2. Only the fuzzer harness `.cpp` gets proper instrumentation
3. Dependency `.cpp` files compiled to temporary `.o` files
4. Linker only sees fuzzer harness object + incomplete dependency objects
5. Result: `undefined reference` errors in CI

**Why it "worked" locally**:
- Cached `.o` files from previous `make all` builds existed
- Make reused properly-built objects from `build/obj/`
- CI had no cached objects → clean build failed

### Solution: Pre-Compiled Objects

**Current approach (WORKING)**:
```makefile
fuzz_block: $(FUZZ_BLOCK_OBJ) $(FUZZ_COMMON_OBJECTS) $(DILITHIUM_OBJECTS)
    @$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ ...
```

**Why it works**:
1. Make builds all dependency `.o` files FIRST (normal build rules)
2. Fuzzer harness compiled SEPARATELY with sanitizers
3. Linker receives complete set of properly-built objects
4. Works identically in local and CI (no cached state needed)
5. Matches proven `test_dilithion` pattern

### Sanitizer Strategy

**Fuzzer Harness**: Compiled WITH sanitizers
- Enables fuzzer instrumentation (`-fsanitize=fuzzer`)
- Catches memory errors (`-fsanitize=address`)
- Detects undefined behavior (`-fsanitize=undefined`)

**Dependencies**: Compiled WITHOUT sanitizers
- Avoids ABI incompatibilities
- Prevents false positives in library code
- Standard optimization for production code

**Dilithium (C library)**: gcc WITHOUT sanitizers
- C has stable ABI across compilers
- No C++/sanitizer interactions
- Well-tested upstream code

---

## Build Process

### Automatic Dependency Resolution

When you run `make fuzz_block`, Make automatically:

1. **Checks dependencies**: Scans `fuzz_block` target prerequisites
2. **Builds missing objects**:
   - `build/obj/test/fuzz/fuzz_block.o` (with sanitizers)
   - `build/obj/primitives/block.o` (standard)
   - `build/obj/crypto/sha3.o` (standard)
   - etc.
3. **Builds Dilithium**: `depends/dilithium/ref/*.o` (if missing)
4. **Links everything**: Creates `fuzz_block` binary

### Manual Build Steps (if needed)

```bash
# Clean build
make clean
rm -rf build/obj

# Build RandomX (external dependency)
cd depends/randomx && mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
cd ../../..

# Build a single fuzzer (Make handles rest)
make fuzz_block

# Build all fuzzers
make fuzz
```

### CI Build Steps

GitHub Actions workflow:
```yaml
- name: Build dependencies
  run: |
    # RandomX (only external dependency needing manual build)
    cd depends/randomx && mkdir -p build && cd build
    cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)

- name: Build fuzz_block
  run: |
    # Make automatically builds Dilithium + all object files
    FUZZ_CXX=clang++-14 make fuzz_block
```

---

## Adding New Fuzzers

### Step-by-Step Guide

#### 1. Create Fuzzer Harness

Create `src/test/fuzz/fuzz_newfeature.cpp`:

```cpp
#include <cstdint>
#include <cstddef>
#include "test/fuzz/util.h"
#include "primitives/transaction.h"  // Your dependencies

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Your fuzzing logic here
    // Exercise your code with fuzzed inputs

    return 0;
}
```

#### 2. Update Makefile

Add these lines to `Makefile` (around line 550):

```makefile
# Source file definition
FUZZ_NEWFEATURE_SOURCE := src/test/fuzz/fuzz_newfeature.cpp

# Object file (compiled WITH sanitizers)
FUZZ_NEWFEATURE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_newfeature.o

# Fuzzer target
fuzz_newfeature: $(FUZZ_NEWFEATURE_OBJ) <DEPENDENCIES> $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ <LIBRARIES>
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"
```

Replace `<DEPENDENCIES>` with required object files:
- Minimal: Just `$(DILITHIUM_OBJECTS)`
- Crypto: Add `$(OBJ_DIR)/crypto/sha3.o`
- Blockchain: Add `$(FUZZ_COMMON_OBJECTS)`
- Consensus: Add `$(FUZZ_CONSENSUS_OBJECTS)`
- UTXO: Add `$(FUZZ_NODE_OBJECTS)`

Replace `<LIBRARIES>` with linker flags:
- Basic: (none)
- RandomX: `-L depends/randomx/build -lrandomx -lpthread`
- LevelDB: Add `-lleveldb`

#### 3. Add to `fuzz` Target

Update the `fuzz` target list (around line 595):

```makefile
fuzz: fuzz_sha3 fuzz_transaction ... fuzz_newfeature
```

#### 4. Test Locally

```bash
# Build
make fuzz_newfeature

# Run quick test
./fuzz_newfeature -max_total_time=60

# Run with corpus
mkdir -p fuzz_corpus/newfeature
./fuzz_newfeature fuzz_corpus/newfeature/ -max_total_time=600
```

#### 5. Add to CI (Optional)

To add extended CI fuzzing, edit `.github/workflows/fuzz-extended-campaigns.yml`:

```yaml
fuzz-newfeature:
  name: "New Feature (Tier 2)"
  runs-on: ubuntu-latest
  timeout-minutes: 240

  steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        submodules: recursive

    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y clang-14 libfuzzer-14-dev cmake build-essential libleveldb-dev

    - name: Build dependencies
      run: |
        cd depends/randomx && mkdir -p build && cd build
        cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)

    - name: Build and run fuzzer
      run: |
        FUZZ_CXX=clang++-14 make fuzz_newfeature
        mkdir -p fuzz_corpus/newfeature
        DURATION=${{ github.event.inputs.duration_hours || '4' }}
        DURATION_SECONDS=$((DURATION * 3600))

        timeout ${DURATION_SECONDS}s ./fuzz_newfeature \
          -max_total_time=${DURATION_SECONDS} \
          -workers=2 \
          -print_final_stats=1 \
          fuzz_corpus/newfeature/ \
          2>&1 | tee fuzz_newfeature_campaign.log || true

    - name: Check for crashes
      run: |
        if ls crash-* leak-* timeout-* 2>/dev/null; then
          echo "⚠️ CRASHES FOUND!" && exit 1
        else
          echo "✅ No crashes"
        fi

    - name: Upload results
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: fuzz-newfeature-results
        path: |
          fuzz_newfeature_campaign.log
          crash-*
          leak-*
          timeout-*
        retention-days: 30
```

---

## Troubleshooting

### Build Errors

#### `undefined reference to <symbol>`

**Symptom**: Linker can't find function/class implementations

**Cause**: Missing dependency object file in fuzzer target

**Fix**: Add required `.o` file to fuzzer target in Makefile

```makefile
# BEFORE (missing dependency)
fuzz_mytest: $(FUZZ_MYTEST_OBJ) $(DILITHIUM_OBJECTS)

# AFTER (added missing object)
fuzz_mytest: $(FUZZ_MYTEST_OBJ) $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
```

#### `No rule to make target 'depends/dilithium/ref/sign.o'`

**Symptom**: Dilithium objects not building

**Cause**: Submodule not initialized or wrong working directory

**Fix**:
```bash
git submodule update --init --recursive
cd /correct/project/root
make fuzz_block
```

#### `clang++-14: command not found`

**Symptom**: Fuzzer compiler not found

**Cause**: Clang 14 not installed or wrong compiler version

**Fix**:
```bash
# Ubuntu/Debian
sudo apt-get install clang-14 libfuzzer-14-dev

# macOS
brew install llvm@14
export FUZZ_CXX=/usr/local/opt/llvm@14/bin/clang++

# Or use system clang (if recent enough)
export FUZZ_CXX=clang++
```

### Runtime Errors

#### Fuzzer crashes immediately

**Symptom**: `ABORTING` or segfault on first input

**Cause**: Usually uninitialized state or missing setup

**Fix**: Add initialization code to harness:
```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Initialize global state ONCE
    static bool initialized = false;
    if (!initialized) {
        SetupGlobalState();
        initialized = true;
    }

    // Your fuzzing logic
    return 0;
}
```

#### Sanitizer errors

**Symptom**: `AddressSanitizer: heap-buffer-overflow` or similar

**Cause**: Real bug found! (This is good)

**Fix**:
1. Examine stack trace in output
2. Fix the underlying bug
3. Add regression test
4. Re-run fuzzer to confirm fix

#### Slow fuzzing (< 100 exec/s)

**Symptom**: Very low execution speed

**Cause**: Expensive operations or large state

**Fix**:
- Limit input size: `-max_len=1024`
- Reduce setup overhead
- Profile with `-print_pcs=1`
- Consider splitting into multiple focused fuzzers

---

## Technical Details

### Compilation Flags

#### Fuzzer Harness Objects
```makefile
FUZZ_CXXFLAGS := -fsanitize=fuzzer,address,undefined -std=c++17 -O1 -g $(INCLUDES)
```

- `-fsanitize=fuzzer`: Enable libFuzzer instrumentation
- `-fsanitize=address`: Detect memory corruption (heap/stack/global overflows, use-after-free)
- `-fsanitize=undefined`: Detect undefined behavior (signed overflow, null derefs, etc.)
- `-O1`: Light optimization (balance speed vs debuggability)
- `-g`: Debug symbols for better stack traces

#### Standard Objects
```makefile
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -I src -I depends/randomx/src
```

- `-O2`: Production optimization level
- No sanitizers (avoids ABI issues)

#### Dilithium Objects
```makefile
gcc $(CFLAGS) -DDILITHIUM_MODE=3 -I $(DILITHIUM_DIR) -c
```

- gcc (not clang): Mature C compiler for C library
- `-DDILITHIUM_MODE=3`: Dilithium3 parameters (NIST Level 3)
- No sanitizers (C library, false positive risk)

### Linker Order

Libraries must be linked in correct order (dependencies last):

```makefile
$(FUZZ_CXX) -o fuzzer harness.o deps.o -L<path> -lleveldb -lrandomx -lpthread
#                                                   ^        ^         ^
#                                                   |        |         |
#                                             Higher level  |    System lib
#                                                       Lower level
```

### Directory Structure

```
dilithion/
├── build/obj/                  # Compiled object files
│   ├── consensus/             # Consensus logic objects
│   ├── core/                  # Core blockchain objects
│   ├── crypto/                # Cryptography objects
│   ├── primitives/            # Block/transaction objects
│   ├── node/                  # Node logic objects
│   └── test/fuzz/             # Fuzzer harness objects (WITH sanitizers)
├── depends/
│   ├── dilithium/ref/         # Dilithium C objects
│   └── randomx/build/         # RandomX compiled library
├── fuzz_corpus/               # Fuzzing corpora (inputs)
│   ├── block/
│   ├── transaction/
│   └── ...
├── fuzz_sha3                  # Fuzzer binaries (executable)
├── fuzz_block
└── ...
```

### Make Dependency Graph Example

```
fuzz_block
├── build/obj/test/fuzz/fuzz_block.o (compiled WITH sanitizers)
│   └── src/test/fuzz/fuzz_block.cpp
├── build/obj/primitives/block.o (compiled WITHOUT sanitizers)
│   └── src/primitives/block.cpp
├── build/obj/crypto/sha3.o
│   └── src/crypto/sha3.cpp
├── depends/dilithium/ref/sign.o (gcc, no sanitizers)
│   └── depends/dilithium/ref/sign.c
├── depends/dilithium/ref/poly.o
│   └── depends/dilithium/ref/poly.c
└── ... (Makefile automatically resolves all dependencies)
```

---

## Performance Characteristics

### Build Times

| Component | Clean Build | Incremental |
|-----------|-------------|-------------|
| RandomX | ~30s | 0s (cached) |
| Dilithium objects | ~2s | ~0.3s (if changed) |
| Core objects | ~15s | ~1s (if changed) |
| Single fuzzer | ~45s total | ~2s |
| All fuzzers | ~3min | ~20s |

### Fuzzing Performance

| Fuzzer | Exec/sec | Memory | Complexity |
|--------|----------|--------|------------|
| fuzz_sha3 | 200k+ | Low | Minimal |
| fuzz_compactsize | 100k+ | Low | Simple |
| fuzz_transaction | 1k-10k | Medium | Moderate |
| fuzz_block | 500-5k | Medium | Moderate |
| fuzz_utxo | 10-100 | High | Complex |
| fuzz_tx_validation | 10-100 | High | Complex |

---

## References

- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)
- [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- [OSS-Fuzz Best Practices](https://google.github.io/oss-fuzz/getting-started/new-project-guide/)

---

**Document End**
