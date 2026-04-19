# Building Dilithion

How to build `dilithion-node`, `dilv-node`, and the supporting tools from
source on Linux, macOS, and Windows.

> If you just want to run Dilithion, download a pre-built binary from
> [GitHub Releases](https://github.com/dilithion/dilithion/releases) instead.
> This document is for contributors and distributors.

---

## Supported platforms

| Platform | Toolchain | Status |
|----------|-----------|--------|
| Linux (Ubuntu 22.04 LTS, Debian 12) | GCC 11+, Make | ✅ CI |
| macOS 13+ (Intel & Apple Silicon) | Clang 14+, Make | ✅ CI |
| Windows 10/11 | MSYS2 MinGW-w64, Make | ✅ CI |
| Other (Alpine, Arch, FreeBSD) | GCC or Clang | Community-supported |

---

## Prerequisites

### Common (all platforms)

- **Git** with submodule support
- **GCC 11+** or **Clang 14+** with C++17 support
- **GNU Make** 4.0+
- **CMake** 3.16+ (for RandomX)
- **LevelDB** 1.22+
- **OpenSSL** 3.0+
- **GMP** (for chiavdf) — `libgmp-dev` / `gmp` / `libgmpxx`
- **pkg-config**

### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential git cmake pkg-config \
    libleveldb-dev libssl-dev \
    libgmp-dev libgmpxx4ldbl \
    libboost-all-dev \
    python3 python3-pip
```

### macOS

```bash
# With Homebrew
brew install cmake leveldb openssl@3 gmp boost pkg-config
```

If linking fails, `OpenSSL` may need explicit paths:
```bash
export LDFLAGS="-L$(brew --prefix openssl@3)/lib"
export CPPFLAGS="-I$(brew --prefix openssl@3)/include"
```

### Windows (MSYS2 — required)

Install [MSYS2](https://www.msys2.org/), then open the **MSYS2 MinGW64** shell
(not the default MSYS shell — the environment differs):

```bash
pacman -Syu                                # close + reopen shell if asked
pacman -S --needed \
    git mingw-w64-x86_64-gcc \
    mingw-w64-x86_64-make \
    mingw-w64-x86_64-cmake \
    mingw-w64-x86_64-pkg-config \
    mingw-w64-x86_64-leveldb \
    mingw-w64-x86_64-openssl \
    mingw-w64-x86_64-gmp \
    mingw-w64-x86_64-boost
```

Always run `make` from the **MinGW64** shell (`C:\msys64\msys2_shell.cmd -mingw64`).
Running from Git Bash, PowerShell, or the default MSYS shell will fail with
cryptic link errors.

---

## Clone

The repository uses git submodules for cryptographic dependencies (RandomX,
chiavdf). **Always clone with `--recursive`**:

```bash
git clone --recursive https://github.com/dilithion/dilithion.git
cd dilithion
```

Already cloned without `--recursive`? Fix it:

```bash
git submodule update --init --recursive
```

---

## Build

```bash
# Default: builds dilithion-node, dilv-node, genesis_gen, check-wallet-balance
make -j$(nproc)        # Linux
make -j$(sysctl -n hw.ncpu)   # macOS
make -j4               # Windows (MSYS2)
```

First build takes 10–15 minutes on a modern machine. Subsequent incremental
builds finish in seconds once submodules are compiled.

### Build only the main node

```bash
make dilithion-node
```

### Build the DilV chain node

```bash
make dilv-node
```

### Build the test suite

```bash
make tests
```

This builds ~30 test binaries including `phase1_test`, `wallet_tests`,
`rpc_tests`, `consensus_tests`, `net_tests`, `tx_validation_tests`,
`dfmp_mik_tests`, `dna_propagation_tests`, and more.

### Run the tests

```bash
# Run everything
make run-tests

# Or run one suite
./wallet_tests
./rpc_tests
```

### Clean build

```bash
make clean    # remove build artifacts
make -j4      # rebuild
```

Always `make clean && make` when:
- Switching branches with different consensus params
- Updating `src/chainparams.h` or other headers
- Upgrading submodules

The Makefile tracks `.cpp` → `.o` dependencies automatically via `-MMD`, but
header-only changes to foreign submodules sometimes need a clean build.

---

## Build targets reference

| Target | Output | Purpose |
|--------|--------|---------|
| `dilithion-node` | Node binary | Mainnet DIL chain node + miner + wallet + RPC |
| `dilv-node` | Node binary | DilV chain node (VDF) |
| `genesis_gen` | Tool | Regenerates genesis blocks during development |
| `check-wallet-balance` | Tool | Reads balance from a wallet.dat offline |
| `inspect_db` | Tool | Inspects LevelDB chainstate / blocks |
| `dilv-genesis-vdf` | Tool | Generates DilV genesis VDF proof |
| `tests` | ~30 binaries | Full test suite |
| `fuzz_*` | Fuzz harnesses | LibFuzzer-based fuzzing campaigns (see [FUZZING.md](FUZZING.md)) |

---

## Build options

Environment variables passed to `make`:

| Variable | Effect |
|----------|--------|
| `CXX` | Override the C++ compiler (e.g. `CXX=clang++`) |
| `CXXFLAGS` | Override compiler flags entirely (default: `-std=c++17 -Wall -Wextra -O2 -pipe -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security`) |
| `CFLAGS` | Same, for C code |
| `LDFLAGS` | Linker flags |

Debug build with sanitizers:

```bash
make clean
make CXXFLAGS="-std=c++17 -O0 -g -fsanitize=address,undefined" \
     LDFLAGS="-fsanitize=address,undefined"
```

Coverage build:

```bash
make clean
make CXXFLAGS="-std=c++17 -O0 -g --coverage" LDFLAGS="--coverage"
# Run your tests, then:
lcov --capture --directory . --output-file coverage.info
```

See [COVERAGE.md](COVERAGE.md) for the full workflow.

---

## Troubleshooting

### `undefined reference to gmp_*` / chiavdf link errors
Make sure `libgmp` and `libgmpxx` are installed (both — `libgmpxx` is the
C++ wrapper, often a separate package).

### `leveldb/db.h: No such file or directory`
Install `libleveldb-dev` (Linux) / `leveldb` (macOS) /
`mingw-w64-x86_64-leveldb` (Windows).

### `randomx.h: No such file or directory`
Submodule didn't initialize. Run `git submodule update --init --recursive`.

### Windows: "Permission denied" / strange link errors
You're running make from the wrong shell. Use the **MSYS2 MinGW64** shell
exactly, not the default MSYS shell.

### Windows: missing DLLs at runtime
See `package-windows-release-github.sh` for the list of 6 DLLs the binary
depends on (`libwinpthread-1.dll`, `libgcc_s_seh-1.dll`, `libstdc++-6.dll`,
`libleveldb.dll`, `libcrypto-3-x64.dll`, `libssl-3-x64.dll`). Ship them
alongside the `.exe`.

### macOS: `ld: symbol(s) not found for architecture arm64`
You're cross-building. Make sure you're on an Apple Silicon machine running
natively, not under Rosetta.

---

## What next

- [DEVELOPMENT.md](DEVELOPMENT.md) — setting up a dev environment
- [TESTING.md](TESTING.md) — running the full test suite
- [FUZZING.md](FUZZING.md) — fuzzing campaigns
- [RELEASING.md](RELEASING.md) — cutting a release
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — contribution guidelines
