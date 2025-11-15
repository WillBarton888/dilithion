# Dilithion v1.0.9-testnet Release Notes

**Release Date:** November 15, 2025
**Tag:** v1.0.9-testnet

## Overview

This release fixes critical bugs from v1.0.8 that prevented Windows users from running the software from common locations like Desktop. v1.0.8 has been unpublished and replaced with this fixed version.

## Critical Bug Fixes

### Bug #1: Windows Database Path Validation
**Problem:** Database path validation incorrectly rejected ALL Windows absolute paths (C:\, D:\, etc) as containing "forbidden characters" due to the colon in drive letters.

**Impact:** Complete failure to start on Windows when running from any location with a drive letter.

**Fix:** Modified `src/node/blockchain_storage.cpp` to exclude drive letter colons (first 2 characters if pattern matches "X:") from forbidden character validation on Windows builds.

**Commit:** fe45ea9

### Bug #2: Old Seed Node References
**Problem:** Launcher scripts (SETUP-AND-START.bat, START-MINING.bat) still displayed and used deprecated seed node `170.64.203.134:18444` that was no longer active.

**Impact:** Confusing user messaging claiming to connect to deprecated infrastructure.

**Fix:** Removed all hardcoded seed node references from launcher script templates. Node now starts with clean command allowing automatic peer discovery through DNS seeds.

**Commit:** fe45ea9 (templates updated)

## Changes from v1.0.8

v1.0.8 was released with critical bugs and has been:
- Set back to draft status
- Replaced with v1.0.9
- All binaries rebuilt with fixes

## Supported Platforms

- ✅ **Linux x64** (tested on Ubuntu 20.04+)
- ✅ **Windows x64** (tested on Windows 10/11)
- ✅ **macOS x64** (tested on macOS 10.15+)

## Installation Instructions

### Linux
```bash
tar -xzf dilithion-testnet-v1.0.9-linux-x64.tar.gz
cd dilithion-testnet-v1.0.9-linux-x64
chmod +x dilithion-node
./dilithion-node --testnet
```

### Windows
```cmd
# Extract dilithion-testnet-v1.0.9-windows-x64.zip
cd dilithion-testnet-v1.0.9-windows-x64
SETUP-AND-START.bat
```

**Note:** Can now be run from ANY location including Desktop!

### macOS
```bash
tar -xzf dilithion-testnet-v1.0.9-macos-x64.tar.gz
cd dilithion-testnet-v1.0.9-macos-x64
chmod +x dilithion-node
./dilithion-node --testnet
```

## Verification

### SHA256 Checksums

Verify your download integrity:

```bash
# Linux/macOS
sha256sum -c dilithion-testnet-v1.0.9-SHA256SUMS.txt

# Windows (PowerShell)
Get-FileHash dilithion-testnet-v1.0.9-windows-x64.zip -Algorithm SHA256
```

**Expected checksums:**
```
c519466f6e383b3a31612d6368cd685ae30302f555bc390140999620b06a0052 *dilithion-testnet-v1.0.9-linux-x64.tar.gz
18607e9b0735854fc14992c412505c1a37003d5f168791bcc36d51401a56745c *dilithion-testnet-v1.0.9-macos-x64.tar.gz
d46cd1bcff5f6e7949e1de0fe565baf659f273bfa9216c053370c0380b886b5a *dilithion-testnet-v1.0.9-windows-x64.zip
```

## Network Configuration

**Testnet Parameters:**
- Network Magic: 0xf1c8d2b3
- Default P2P Port: 18444
- Default RPC Port: 18332

**DNS Seeds:**
- Built-in automatic peer discovery

**Active Seed Nodes:**
- 134.122.4.164:18444 (NYC)
- 188.166.255.63:18444 (Singapore)
- 209.97.177.197:18444 (London)

## Upgrade Notes

This is a critical bugfix release. Users affected by v1.0.8 startup issues should immediately upgrade to v1.0.9.

No blockchain reset or configuration changes are required.

## Known Issues

None reported at this time.

## Technical Details

### Build Process
- **Linux:** Built on NYC server (134.122.4.164) with GCC
- **macOS:** Built on Singapore server (188.166.255.63) with Clang
- **Windows:** Built via GitHub Actions with MSYS2/MinGW64

### Dependencies
- RandomX (for mining)
- LevelDB (for blockchain storage)
- OpenSSL (for cryptography)
- Post-quantum Dilithium signatures

## Credits

Built with post-quantum cryptography (Dilithium) integration into the Bitcoin Core codebase.

Special thanks to the user who reported the Windows path validation bug by testing from Desktop.

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
