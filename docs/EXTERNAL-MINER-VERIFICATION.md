# External Miner Verification Guide

This guide helps external users verify that Dilithion binary packages work correctly before mining.

## Quick 5-Minute Verification

### Windows (v1.0.9)

```batch
# 1. Extract the ZIP file
# Extract dilithion-testnet-v1.0.9-windows-x64.zip to C:\Dilithion

# 2. Open Command Prompt and navigate to directory
cd C:\Dilithion\dilithion-testnet-v1.0.9-windows-x64

# 3. Test binary directly (should show help text)
dilithion-node.exe --help

# 4. Run one-click miner (should start mining within 10 seconds)
START-MINING.bat

# 5. Verify output shows:
#    ✓ "Connected to seed node"
#    ✓ "Mining started" or "Hash rate: X H/s"
#    ✓ "Block height: X"

# 6. Stop mining (Ctrl+C) and verify clean exit
```

**Expected Hash Rate:** ~9-66 H/s per CPU core (Intel i5/i7)

---

### Linux (v1.0.9)

```bash
# 1. Download and extract
wget https://github.com/WillBarton888/dilithion/releases/download/v1.0.9/dilithion-testnet-v1.0.9-linux-x64.tar.gz
tar -xzf dilithion-testnet-v1.0.9-linux-x64.tar.gz
cd dilithion-testnet-v1.0.9-linux-x64

# 2. Install dependencies (if needed)
# Ubuntu/Debian:
sudo apt-get update && sudo apt-get install -y libleveldb-dev libsnappy-dev

# Fedora/RHEL:
sudo dnf install leveldb-devel snappy-devel

# Arch:
sudo pacman -S leveldb snappy

# 3. Make executable
chmod +x dilithion-node start-mining.sh

# 4. Test binary directly
./dilithion-node --help
# Should show: "Dilithion - Post-Quantum Cryptocurrency"

# 5. Test version
./dilithion-node --version
# Should show: "v1.0.9" or similar

# 6. Run dependency check script
./start-mining.sh
# Should either start mining OR show clear dependency error messages

# 7. Verify mining output shows:
#    ✓ "✓ All dependencies found"
#    ✓ "Connected to seed node" or peer count > 0
#    ✓ "Mining started" or "Hash rate: X H/s"
#    ✓ "Block height: X"

# 8. Stop mining (Ctrl+C) and verify:
#    ✓ Clean shutdown message
#    ✓ No segfaults or crashes
#    ✓ .dilithion-testnet directory created in home directory
```

---

### macOS (v1.0.9)

```bash
# 1. Download and extract
curl -LO https://github.com/WillBarton888/dilithion/releases/download/v1.0.9/dilithion-testnet-v1.0.9-macos-x64.tar.gz
tar -xzf dilithion-testnet-v1.0.9-macos-x64.tar.gz
cd dilithion-testnet-v1.0.9-macos-x64

# 2. Install dependencies
# Install Homebrew (if not installed):
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install LevelDB:
brew install leveldb

# 3. Make executable
chmod +x dilithion-node start-mining.sh

# 4. Handle macOS Gatekeeper (unsigned binary warning)
# Method 1: Right-click dilithion-node → Open → Open (confirm)
# Method 2: System Settings → Privacy & Security → Allow Anyway
# Method 3: Remove quarantine attribute
xattr -d com.apple.quarantine dilithion-node

# 5. Test binary directly
./dilithion-node --help
# Should show: "Dilithion - Post-Quantum Cryptocurrency"

# 6. Run one-click miner
./start-mining.sh

# 7. Verify mining output shows:
#    ✓ "✓ All dependencies found"
#    ✓ "Connected to seed node" or peer count > 0
#    ✓ "Mining started" or "Hash rate: X H/s"
#    ✓ "Block height: X"

# 8. Stop mining (Ctrl+C) and verify clean exit
```

---

## Comprehensive Verification Checklist

Use this for thorough testing before committing to long-term mining:

### Phase 1: Binary Integrity (2 minutes)

- [ ] **SHA256 checksum matches** (see releases/dilithion-testnet-v1.0.9-SHA256SUMS.txt)
  ```bash
  # Linux/macOS
  sha256sum dilithion-testnet-v1.0.9-*-x64.tar.gz

  # Windows (PowerShell)
  Get-FileHash dilithion-testnet-v1.0.9-windows-x64.zip -Algorithm SHA256
  ```

- [ ] **File extraction successful** (no corruption errors)
- [ ] **All expected files present:**
  - `dilithion-node` or `dilithion-node.exe`
  - `start-mining.sh` / `START-MINING.bat`
  - `setup-and-start.sh` / `SETUP-AND-START.bat`
  - `README.txt`
  - `check-wallet-balance` (Linux/macOS)
  - DLL files (Windows only): libcrypto, libssl, libstdc++, libgcc, libwinpthread, libleveldb

### Phase 2: Binary Execution (3 minutes)

- [ ] **Binary shows help text**
  ```bash
  # Linux/macOS
  ./dilithion-node --help

  # Windows
  dilithion-node.exe --help
  ```

- [ ] **Binary shows version**
  ```bash
  ./dilithion-node --version
  ```

- [ ] **No immediate crashes or errors**

### Phase 3: Launcher Script Validation (5 minutes)

- [ ] **Script detects missing dependencies correctly**
  - For Linux: Try without libleveldb installed (should show install instructions)
  - For macOS: Try without Homebrew (should show install instructions)

- [ ] **Script starts successfully**
  ```bash
  # Linux/macOS
  ./start-mining.sh

  # Windows
  START-MINING.bat
  ```

- [ ] **No false "file not found" errors**
- [ ] **Clean, readable output (no garbled text)**

### Phase 4: Network Connectivity (5 minutes)

- [ ] **Connects to at least 1 seed node:**
  - NYC: 134.122.4.164:18444
  - Singapore: 188.166.255.63:18444
  - London: 209.97.177.197:18444

- [ ] **Peer count increases** (check RPC or log output)
  ```bash
  # If RPC is enabled:
  curl -X POST -H "Content-Type: application/json" \
       -H "X-Dilithion-RPC: 1" \
       -d '{"jsonrpc":"2.0","id":1,"method":"getpeerinfo","params":[]}' \
       http://127.0.0.1:18332/
  ```

- [ ] **Blockchain sync starts** (block height increases)

### Phase 5: Mining Validation (10 minutes)

- [ ] **Mining initialization successful**
  - Should show: "Mining started" or similar message

- [ ] **Hash rate displayed**
  - Expected: ~9-66 H/s per CPU core
  - Auto-detect should use 50-75% of available cores

- [ ] **Mining continues for 5+ minutes without crash**

- [ ] **Database directory created:**
  - Windows: `C:\Users\<username>\.dilithion-testnet\`
  - Linux/macOS: `~/.dilithion-testnet/`

- [ ] **Log files created** (if logging enabled)

### Phase 6: Graceful Shutdown (2 minutes)

- [ ] **Ctrl+C stops mining cleanly**
- [ ] **No crashes, segfaults, or corruption errors**
- [ ] **Clean exit message displayed**
- [ ] **Can restart mining successfully**

---

## Common Issues and Solutions

### Windows

**Issue:** "dilithion-node.exe not found" but file exists
**Solution:** This was fixed in v1.0.9. Ensure you're using the latest version.

**Issue:** DLL errors (libcrypto-3-x64.dll not found)
**Solution:** Ensure ALL files were extracted from the ZIP (including 6 DLL files).

**Issue:** Windows Defender warning
**Solution:** Binaries are unsigned during testnet. Verify SHA256 checksum and add exception.

### Linux

**Issue:** "libleveldb.so: cannot open shared object file"
**Solution:** Install LevelDB:
```bash
# Ubuntu/Debian
sudo apt-get install libleveldb-dev libsnappy-dev

# Fedora/RHEL
sudo dnf install leveldb-devel snappy-devel

# Arch
sudo pacman -S leveldb snappy
```

**Issue:** "Permission denied" when running dilithion-node
**Solution:** Make executable: `chmod +x dilithion-node start-mining.sh`

**Issue:** No peers connecting
**Solution:** Check firewall allows outbound connections on port 18444.

### macOS

**Issue:** "dilithion-node cannot be opened because the developer cannot be verified"
**Solution:**
1. Right-click dilithion-node → Open → Open
2. Or: System Settings → Privacy & Security → Allow Anyway
3. Or: `xattr -d com.apple.quarantine dilithion-node`

**Issue:** "dyld: Library not loaded: libleveldb.dylib"
**Solution:** Install via Homebrew: `brew install leveldb`

**Issue:** Homebrew not installed
**Solution:** Install Homebrew first:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

---

## Reporting Issues

If you encounter issues not listed here:

1. **Check GitHub Issues:** https://github.com/WillBarton888/dilithion/issues
2. **Search existing issues** for your error message
3. **Create new issue** with:
   - Operating system and version
   - Release version (e.g., v1.0.9)
   - Exact error message
   - Output of `./dilithion-node --version`
   - Steps to reproduce

4. **Join Discord:** https://discord.gg/c25WwRNg for community support

---

## Success Criteria

Your installation is verified when:

✅ Binary runs without errors
✅ Script launches successfully
✅ Connects to 2+ seed nodes
✅ Hash rate shows 9-66 H/s per core
✅ Block height increases (blockchain syncing)
✅ Can stop/restart cleanly
✅ `.dilithion-testnet` directory created

**Estimated time to full verification: 15-20 minutes**

---

## Security Best Practices

- ✅ **Always verify SHA256 checksums** before running binaries
- ✅ **Download only from official GitHub releases:** https://github.com/WillBarton888/dilithion/releases
- ✅ **Review source code** if building from source
- ⚠️ **Testnet coins have NO value** - do not buy/sell them
- ⚠️ **Experimental software** - not audited, use at own risk

---

*Last updated: November 17, 2025 (v1.0.9)*
