# 🚀 Dilithion v1.0-testnet - Public Testnet Launch

> **⚠️ IMPORTANT UPDATE (November 2, 2025):** Use the **-FIXED** packages below! They contain critical first-user experience fixes.

## 📦 Downloads - Use These FIXED Versions!

**✅ Recommended Downloads (Nov 2 Updates):**
- **Windows:** `dilithion-testnet-v1.0.0-windows-x64-FIXED.zip` ⭐
- **Linux:** `dilithion-testnet-v1.0.0-linux-x64-fixed.tar.gz` ⭐
- **macOS:** `dilithion-testnet-v1.0.0-macos-x64-fixed.tar.gz` ⭐

**What's Fixed in -FIXED Packages:**
- ✅ Robust curl detection (Windows PATH issues resolved)
- ✅ Wallet CLI tool included (send/receive DIL)
- ✅ Dependency checks on Linux (LevelDB validation)
- ✅ Better error messages with platform-specific instructions
- ✅ Discord support links in all error messages

**Checksums:** See `FIXED-packages-SHA256SUMS.txt`

---

First public testnet release of Dilithion, a post-quantum cryptocurrency.

## What's New

### Critical User Experience Fixes (November 2, 2025)
- ✅ **FIXED**: Windows curl detection (multi-location fallback)
- ✅ **FIXED**: Missing wallet CLI wrapper in release packages
- ✅ **FIXED**: Linux dependency checks (LevelDB validation before launch)
- ✅ **ADDED**: Platform-specific error messages for all OSes
- ✅ **IMPROVED**: First-time user experience significantly enhanced

Full details: [CRITICAL-FIXES-NOV2-2025.md](https://github.com/dilithion/dilithion/blob/main/CRITICAL-FIXES-NOV2-2025.md)

### Critical Bug Fixes (October 28, 2025)
- ✅ **FIXED**: UTXO serialization format mismatch (consensus-critical)
- ✅ **FIXED**: Wallet unlock for unencrypted wallets
- ✅ **FIXED**: DNS seed node initialization
- ✅ **Test pass rate**: Improved from 79% to 93%

Full details: [DEFICIENCY-FIXES-SUMMARY.md](https://github.com/dilithion/dilithion/blob/main/DEFICIENCY-FIXES-SUMMARY.md)

### Features
- CRYSTALS-Dilithium3 post-quantum signatures (NIST-approved)
- RandomX CPU-friendly proof-of-work
- Full UTXO transaction model
- SHA3-256 quantum-resistant hashing
- Comprehensive security hardening (4 phases)

## Getting Started

### Option 1: Pre-Built Binaries (Easiest!)

**Download the -FIXED package for your platform** (see Downloads above), then:

**Windows:**
```batch
# Extract the zip, then double-click:
START-MINING.bat
```

**Linux/macOS:**
```bash
tar -xzf dilithion-testnet-v1.0.0-*-fixed.tar.gz
cd dilithion-testnet-v1.0.0-*-x64/
./start-mining.sh
```

### Option 2: Build from Source
```bash
git clone https://github.com/dilithion/dilithion.git
cd dilithion
make
./dilithion-node --testnet --mine --threads=4
```

### Wallet Operations (NEW!)

Check balance:
```bash
# Windows
dilithion-wallet.bat balance

# Linux/macOS
./dilithion-wallet balance
```

Send DIL:
```bash
# Windows
dilithion-wallet.bat send DLT1address... 10.5

# Linux/macOS
./dilithion-wallet send DLT1address... 10.5
```

### Full Guide
See [TESTNET-LAUNCH.md](https://github.com/dilithion/dilithion/blob/main/TESTNET-LAUNCH.md)

## What to Test

- Mining stability (24+ hour tests)
- Wallet operations (create, send, encrypt)
- Network connectivity (peer discovery)
- Transaction validation
- Edge cases and stress testing

## Known Issues

- 1 test with minor non-critical failures (wallet_tests - 2/16 subtests)
- Original packages missing wallet wrapper (use -FIXED versions)

## Support

- **Discord:** https://discord.gg/dilithion
- **GitHub Issues:** Report bugs here
- **Website:** https://dilithion.org

## Documentation

- [TESTNET-LAUNCH.md](https://github.com/dilithion/dilithion/blob/main/TESTNET-LAUNCH.md) - Testnet guide
- [CRITICAL-FIXES-NOV2-2025.md](https://github.com/dilithion/dilithion/blob/main/CRITICAL-FIXES-NOV2-2025.md) - Latest fixes
- [WHITEPAPER.md](https://github.com/dilithion/dilithion/blob/main/WHITEPAPER.md) - Technical specification

---

**Network:** TESTNET (coins have NO monetary value)
**Genesis Time:** 1730080000 (October 28, 2025)
**Seed Node:** 170.64.203.134:18444
