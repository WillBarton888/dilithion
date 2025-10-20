# Command: Setup Development Environment

Set up complete development environment for Dilithion project.

## Usage
```
/setup-dev-env
```

## What This Does

1. Clones Bitcoin Core
2. Sets up build dependencies
3. Compiles Bitcoin Core (baseline)
4. Adds Dilithium library
5. Configures development tools
6. Creates project structure
7. Initializes git repository

## Prerequisites

- Linux (Ubuntu/Debian) or macOS
- At least 4GB RAM
- 50GB disk space
- Internet connection
- Basic development tools (git, build-essential)

## Steps

### 1. Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libtool \
    autotools-dev \
    automake \
    pkg-config \
    bsdmainutils \
    python3 \
    libssl-dev \
    libevent-dev \
    libboost-all-dev \
    libdb-dev \
    libdb++-dev \
    libminiupnpc-dev \
    libzmq3-dev \
    libqt5gui5 \
    libqt5core5a \
    libqt5dbus5 \
    qttools5-dev \
    qttools5-dev-tools \
    git \
    ccache
```

**macOS:**
```bash
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
    ccache
```

### 2. Clone Bitcoin Core

```bash
cd ~/
git clone https://github.com/bitcoin/bitcoin.git bitcoin-core-baseline
cd bitcoin-core-baseline

# Checkout specific version (recommended for stability)
git checkout v25.0  # Or latest stable version

# Build baseline Bitcoin Core
./autogen.sh
./configure --disable-wallet --without-gui  # Minimal build for testing
make -j$(nproc)

# Verify it works
./src/bitcoind --version
# Should output: Bitcoin Core version v25.0.0
```

### 3. Create Dilithion Fork

```bash
cd ~/
git clone https://github.com/bitcoin/bitcoin.git dilithion-core
cd dilithion-core

# Create development branch
git checkout -b quantum-resistant

# Rename remotes
git remote rename origin bitcoin-upstream
git remote add origin https://github.com/yourusername/dilithion.git  # Your repo

# Tag the fork point
git tag -a bitcoin-fork-v25.0 -m "Forked from Bitcoin Core v25.0"
```

### 4. Add Dilithium Library

```bash
cd ~/dilithion-core

# Create depends directory if needed
mkdir -p depends

# Add Dilithium as submodule
git submodule add https://github.com/pq-crystals/dilithium.git depends/dilithium
git submodule update --init --recursive

# Or use liboqs for multiple PQ algorithms
# git submodule add https://github.com/open-quantum-safe/liboqs.git depends/liboqs
```

### 5. Set Up Project Structure

```bash
cd ~/
# Use the Dilithion project structure we already created
# This includes docs/, .claude/, etc.

# Link to the Bitcoin Core fork
ln -s ~/dilithion-core ~/dilithion/bitcoin-core
```

### 6. Configure Development Tools

**Set up ccache for faster builds:**
```bash
export PATH="/usr/lib/ccache:$PATH"
echo 'export PATH="/usr/lib/ccache:$PATH"' >> ~/.bashrc
ccache --max-size=5G
```

**Configure git:**
```bash
cd ~/dilithion-core
git config user.name "Your Name"
git config user.email "your.email@example.com"
git config core.editor "nano"  # or vim, emacs, etc.
```

**Set up editor (VS Code recommended):**
```bash
# Install VS Code
# Add recommended extensions:
# - C/C++ (Microsoft)
# - C/C++ Extension Pack
# - CMake Tools
# - GitLens
# - Bitcoin Script Highlighter (if available)

code ~/dilithion-core
```

### 7. Verify Setup

```bash
cd ~/dilithion-core

# Test build
./autogen.sh
./configure
make -j$(nproc)

# Run tests
make check

# If everything passes, environment is ready
```

### 8. Create Development Aliases

```bash
# Add to ~/.bashrc or ~/.zshrc
cat >> ~/.bashrc << 'EOF'

# Dilithion Development Aliases
alias dil='cd ~/dilithion'
alias dilcore='cd ~/dilithion-core'
alias dilbuild='cd ~/dilithion-core && make -j$(nproc)'
alias diltest='cd ~/dilithion-core && make check'
alias dilclean='cd ~/dilithion-core && make clean'

EOF

source ~/.bashrc
```

## Verification Checklist

After setup, verify:

- [ ] Bitcoin Core compiles without errors
- [ ] All unit tests pass (`make check`)
- [ ] Dilithium library is accessible
- [ ] Git repository is properly configured
- [ ] Development tools are installed
- [ ] Editor/IDE is configured
- [ ] Can make trivial code change and rebuild

## Test Your Setup

Make a trivial modification to verify environment:

```bash
cd ~/dilithion-core

# Edit genesis block message
nano src/chainparams.cpp

# Find the line:
# const char* pszTimestamp = "The Times 03/Jan/2009...";
# Change to:
# const char* pszTimestamp = "Testing Dilithion Development Environment";

# Rebuild
make -j$(nproc)

# If it compiles, your environment works!

# Revert the change
git checkout src/chainparams.cpp
```

## Troubleshooting

### Issue: Build fails with missing dependencies
```bash
# Check error message for missing library
# Install missing dependency:
sudo apt-get install <missing-library>-dev
```

### Issue: Out of memory during build
```bash
# Reduce parallel jobs
make -j2  # Instead of -j$(nproc)

# Or use swap
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Issue: Dilithium library not found
```bash
# Verify submodule is initialized
git submodule update --init --recursive

# Check path exists
ls depends/dilithium/
```

## Next Steps

After successful setup:

1. Read through `docs/implementation-roadmap.md`
2. Study CRYSTALS-Dilithium specification
3. Review Bitcoin Core architecture
4. Start with crypto implementation workflow
5. Begin Phase 1 development

## Resources

- [Bitcoin Core Build Docs](https://github.com/bitcoin/bitcoin/blob/master/doc/build-unix.md)
- [Dilithium Repository](https://github.com/pq-crystals/dilithium)
- [Development Best Practices](../docs/development-best-practices.md)

## Success Criteria

✅ **Environment ready when:**
- Bitcoin Core compiles cleanly
- All tests pass
- Dilithium library accessible
- Git configured properly
- Development tools working
- You can make and test code changes

---

**Estimated Time:** 1-2 hours
**Difficulty:** Intermediate
**Prerequisites:** Basic Linux/Unix knowledge, C++ development experience
