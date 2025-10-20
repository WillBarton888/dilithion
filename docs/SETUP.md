# Development Environment Setup Guide

Complete guide for setting up the Dilithion development environment.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Detailed Setup](#detailed-setup)
4. [Verification](#verification)
5. [Troubleshooting](#troubleshooting)
6. [Next Steps](#next-steps)

---

## Prerequisites

### System Requirements

**Minimum:**
- 4 CPU cores
- 8 GB RAM
- 100 GB free disk space
- Stable internet connection

**Recommended:**
- 8+ CPU cores
- 16+ GB RAM
- 500 GB SSD
- 100+ Mbps internet

### Supported Operating Systems

- Ubuntu 20.04 LTS or later
- Debian 11 or later
- macOS 12 (Monterey) or later
- Windows 10/11 with WSL2

**Note:** Linux is strongly recommended for Bitcoin Core development.

### Required Knowledge

- C++ programming
- Command line/terminal usage
- Git version control
- Basic cryptography concepts

---

## Quick Start

For experienced developers (Ubuntu/Debian):

```bash
# 1. Install dependencies
sudo apt-get update && sudo apt-get install -y \
    build-essential libtool autotools-dev automake pkg-config \
    libssl-dev libevent-dev libboost-all-dev libdb-dev libdb++-dev \
    git ccache python3

# 2. Clone repositories
git clone https://github.com/bitcoin/bitcoin.git ~/bitcoin-core
git clone https://github.com/WillBarton888/dilithion.git ~/dilithion
cd ~/dilithion
git submodule add https://github.com/pq-crystals/dilithium.git depends/dilithium

# 3. Build Bitcoin Core baseline
cd ~/bitcoin-core
./autogen.sh && ./configure && make -j$(nproc)

# 4. Verify
./src/bitcoind --version
```

---

## Detailed Setup

### Step 1: Install System Dependencies

#### Ubuntu / Debian

```bash
# Update package list
sudo apt-get update

# Install build tools
sudo apt-get install -y \
    build-essential \
    libtool \
    autotools-dev \
    automake \
    pkg-config \
    bsdmainutils

# Install required libraries
sudo apt-get install -y \
    libssl-dev \
    libevent-dev \
    libboost-system-dev \
    libboost-filesystem-dev \
    libboost-chrono-dev \
    libboost-test-dev \
    libboost-thread-dev

# Install database library
sudo apt-get install -y \
    libdb-dev \
    libdb++-dev

# Install optional dependencies (recommended)
sudo apt-get install -y \
    libminiupnpc-dev \
    libzmq3-dev \
    libqt5gui5 \
    libqt5core5a \
    libqt5dbus5 \
    qttools5-dev \
    qttools5-dev-tools

# Install development tools
sudo apt-get install -y \
    git \
    ccache \
    python3 \
    python3-pip \
    valgrind \
    gdb

# Install Python testing dependencies
pip3 install --user \
    pyzmq \
    requests
```

#### macOS

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install \
    automake \
    libtool \
    boost \
    pkg-config \
    libevent \
    berkeley-db@4 \
    qt@5 \
    miniupnpc \
    zeromq \
    ccache \
    python3

# Add Qt to path
echo 'export PATH="/usr/local/opt/qt@5/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

#### Windows (WSL2)

```bash
# First, install WSL2 and Ubuntu from Microsoft Store
# Then follow Ubuntu instructions above

# Or use MSYS2/MinGW (advanced):
# Download from: https://www.msys2.org/
# Follow Bitcoin Core Windows build instructions
```

### Step 2: Clone Bitcoin Core

```bash
# Create working directory
mkdir -p ~/crypto-projects
cd ~/crypto-projects

# Clone Bitcoin Core
git clone https://github.com/bitcoin/bitcoin.git bitcoin-core
cd bitcoin-core

# Checkout stable version
git checkout v25.0  # Or latest stable

# View tags to see available versions
git tag -l
```

### Step 3: Build Bitcoin Core (Baseline)

This verifies your environment can compile Bitcoin Core before modifications.

```bash
cd ~/crypto-projects/bitcoin-core

# Generate build scripts
./autogen.sh

# Configure build (minimal, no wallet, no GUI)
./configure \
    --disable-wallet \
    --without-gui \
    --with-incompatible-bdb

# Or configure with all features
./configure

# Build (use all CPU cores)
make -j$(nproc)

# This will take 15-45 minutes depending on your system
```

**Expected output:**
```
Making all in src
  CXX      bitcoin-cli.o
  CXX      bitcoin-tx.o
  ...
  CXXLD    bitcoind
  CXXLD    bitcoin-cli
  CXXLD    bitcoin-tx
```

### Step 4: Verify Bitcoin Core Build

```bash
# Check version
./src/bitcoind --version

# Should output:
# Bitcoin Core version v25.0.0
# Copyright (C) 2009-2023 The Bitcoin Core developers
# ...

# Run unit tests
make check

# Should output:
# PASS: test/test_bitcoin
# ...
# All tests passed

# Run functional tests (optional, takes ~1 hour)
test/functional/test_runner.py
```

If all tests pass, your environment is ready!

### Step 5: Clone Dilithion Repository

```bash
cd ~/crypto-projects

# Clone your Dilithion fork
git clone https://github.com/WillBarton888/dilithion.git dilithion
cd dilithion

# Verify structure
ls -la
# Should see: docs/, .claude/, src/, tests/, README.md, etc.
```

### Step 6: Add Dilithium Library

```bash
cd ~/crypto-projects/dilithion

# Create depends directory if it doesn't exist
mkdir -p depends

# Add Dilithium as git submodule
git submodule add https://github.com/pq-crystals/dilithium.git depends/dilithium

# Initialize and update submodules
git submodule update --init --recursive

# Verify
ls depends/dilithium/
# Should see: ref/, avx2/, LICENSE, README.md, etc.
```

### Step 7: Build Dilithium Library

```bash
cd ~/crypto-projects/dilithion/depends/dilithium

# Build reference implementation
cd ref
make clean
make

# Should create libpqcrystals_dilithium2_ref.a

# Test it
make test
./test/test_dilithium2

# Should output test results
```

### Step 8: Set Up Development Tools

#### Configure Git

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
git config --global core.editor "nano"  # or vim, emacs, code
git config --global init.defaultBranch main
```

#### Set Up ccache (Faster Rebuilds)

```bash
# ccache speeds up recompilation significantly
export PATH="/usr/lib/ccache:$PATH"
echo 'export PATH="/usr/lib/ccache:$PATH"' >> ~/.bashrc

# Set cache size
ccache --max-size=5G

# Verify
ccache --show-stats
```

#### Install VS Code (Recommended)

```bash
# Ubuntu/Debian
sudo snap install code --classic

# Or download from: https://code.visualstudio.com/

# Recommended extensions:
# - C/C++ (Microsoft)
# - C/C++ Extension Pack
# - GitLens
# - Markdown All in One
```

### Step 9: Create Project Links

```bash
# Link Bitcoin Core into Dilithion project for reference
cd ~/crypto-projects/dilithion
ln -s ~/crypto-projects/bitcoin-core bitcoin-core-reference

# Create convenience aliases
cat >> ~/.bashrc << 'EOF'

# Dilithion Development Aliases
alias dil='cd ~/crypto-projects/dilithion'
alias dilcore='cd ~/crypto-projects/bitcoin-core'
alias dilbuild='cd ~/crypto-projects/bitcoin-core && make -j$(nproc)'
alias diltest='cd ~/crypto-projects/bitcoin-core && make check'
alias dilclean='cd ~/crypto-projects/bitcoin-core && make clean'

EOF

# Reload bashrc
source ~/.bashrc
```

---

## Verification

### Checklist

After setup, verify everything works:

- [ ] Bitcoin Core compiles without errors
- [ ] `make check` passes all unit tests
- [ ] Dilithium library compiles
- [ ] Dilithium tests pass
- [ ] Git is configured
- [ ] ccache is working
- [ ] Editor/IDE is set up

### Test Your Setup

Create a trivial modification to verify your workflow:

```bash
# Navigate to Bitcoin Core
cd ~/crypto-projects/bitcoin-core

# Create a test branch
git checkout -b test-setup

# Make a trivial change
echo "// Test modification" >> src/version.h

# Rebuild
make -j$(nproc)

# Should recompile quickly with ccache
# If successful, revert
git checkout src/version.h
git checkout master
```

### Performance Benchmarks

Your system should achieve similar build times:

**Bitcoin Core full build:**
- 4 cores / 8 GB RAM: ~30-45 minutes
- 8 cores / 16 GB RAM: ~15-25 minutes
- 16 cores / 32 GB RAM: ~8-15 minutes

**Incremental rebuild (with ccache):**
- 1-5 minutes depending on changes

---

## Troubleshooting

### Issue: `./autogen.sh` fails

```bash
# Error: "autoreconf: command not found"
# Fix: Install autotools
sudo apt-get install autotools-dev automake
```

### Issue: Configure fails with missing dependencies

```bash
# Error: "libboost_system not found"
# Fix: Install boost libraries
sudo apt-get install libboost-all-dev

# Error: "Berkeley DB not found"
# Fix: Install db libraries
sudo apt-get install libdb-dev libdb++-dev
```

### Issue: Build fails with "g++: internal compiler error"

```bash
# Likely out of memory
# Fix: Reduce parallel jobs
make -j2  # Instead of -j$(nproc)

# Or add swap space
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Issue: Tests fail

```bash
# Check specific test failure
make check VERBOSE=1

# Run specific test
./src/test/test_bitcoin --log_level=all --run_test=<test_name>

# Check for missing Python dependencies
pip3 install --user pyzmq requests
```

### Issue: ccache not working

```bash
# Verify ccache is in PATH
which ccache

# Clear cache and restart
ccache --clear
ccache --show-stats
```

### Issue: Dilithium library won't compile

```bash
# Make sure you're in the right directory
cd ~/crypto-projects/dilithion/depends/dilithium/ref

# Check for compiler
gcc --version

# Clean and rebuild
make clean
make CC=gcc

# If still fails, check pq-crystals repository issues
```

### Issue: Permission denied

```bash
# Don't run configure or make with sudo
# If you did, reset permissions:
sudo chown -R $USER:$USER ~/crypto-projects
```

---

## Next Steps

After successful setup:

### 1. Study the Codebase

```bash
# Read Bitcoin Core documentation
cd ~/crypto-projects/bitcoin-core
ls doc/

# Key files to understand:
# - doc/developer-notes.md
# - doc/build-unix.md
# - src/README.md
```

### 2. Read Technical Specifications

```bash
cd ~/crypto-projects/dilithion

# Essential reading:
# - docs/technical-specification.md
# - docs/implementation-roadmap.md
# - docs/research/initial-planning-discussion.md
```

### 3. Study CRYSTALS-Dilithium

```bash
# Download NIST spec
wget https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Dilithium-Round3.zip

# Read Dilithium paper
# https://pq-crystals.org/dilithium/index.shtml

# Explore reference implementation
cd ~/crypto-projects/dilithion/depends/dilithium
cat README.md
```

### 4. Start Development

Follow the implementation workflow:

```bash
# See: .claude/workflows/crypto-implementation.md
cd ~/crypto-projects/dilithion
cat .claude/workflows/crypto-implementation.md
```

### 5. Join Development

- Review open issues
- Read contributing guidelines
- Set up testing environment
- Start with small tasks

---

## Development Workflow

### Typical Daily Workflow

```bash
# 1. Navigate to project
dil  # alias for cd ~/crypto-projects/dilithion

# 2. Pull latest changes
git pull origin main

# 3. Create feature branch
git checkout -b feature/dilithium-keygen

# 4. Make changes
# ... edit files ...

# 5. Build and test
cd ~/crypto-projects/bitcoin-core
make -j$(nproc)
make check

# 6. Commit changes
git add .
git commit -m "Implement Dilithium key generation"

# 7. Push to GitHub
git push origin feature/dilithium-keygen

# 8. Create pull request on GitHub
```

### Before Committing

Always run:

```bash
# Build
make -j$(nproc)

# Run tests
make check

# Run linter (if configured)
./contrib/verify-commits/verify-commits.py

# Check for common issues
./contrib/devtools/lint-all.sh
```

---

## Additional Resources

### Documentation

- [Bitcoin Core Developer Docs](https://github.com/bitcoin/bitcoin/tree/master/doc)
- [Dilithion Technical Spec](./technical-specification.md)
- [Implementation Roadmap](./implementation-roadmap.md)

### Tools

- [Compiler Explorer](https://godbolt.org/) - Analyze compiled code
- [Valgrind](https://valgrind.org/) - Memory debugging
- [GDB](https://www.gnu.org/software/gdb/) - Debugger
- [ccache](https://ccache.dev/) - Compiler cache

### Communities

- Bitcoin Core IRC: #bitcoin-core-dev on Libera.Chat
- Bitcoin Stack Exchange: https://bitcoin.stackexchange.com/
- Cryptography Stack Exchange: https://crypto.stackexchange.com/

---

## Maintenance

### Keep Dependencies Updated

```bash
# Update system packages
sudo apt-get update && sudo apt-get upgrade

# Update submodules
cd ~/crypto-projects/dilithion
git submodule update --remote

# Pull Bitcoin Core updates
cd ~/crypto-projects/bitcoin-core
git fetch origin
git merge origin/master
```

### Clean Build Artifacts

```bash
# Clean Bitcoin Core
cd ~/crypto-projects/bitcoin-core
make clean

# Deep clean (removes all generated files)
make distclean

# Clear ccache
ccache --clear
```

---

## Support

If you encounter issues:

1. Check this troubleshooting guide
2. Review Bitcoin Core build documentation
3. Search existing GitHub issues
4. Ask in developer channels
5. Create detailed issue report

---

**Setup complete! You're ready to begin Dilithion development.**

See [implementation-roadmap.md](./implementation-roadmap.md) for next steps.
