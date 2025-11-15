# Dilithion v1.0.8-testnet Release Notes

**Release Date:** November 15, 2025
**Tag:** v1.0.8-testnet

## Overview

This release removes all remaining hardcoded old seed node references from setup scripts and documentation, ensuring clean network connectivity to the current testnet infrastructure.

## Changes

### Fixed
- **Removed hardcoded old seed node (170.64.203.134)** from all launcher scripts and setup wizards
- **Cleaned documentation** of all references to deprecated seed nodes
- **Updated setup scripts** to use built-in DNS seeds exclusively

### Improved
- Binaries now auto-connect to current active nodes:
  - NYC: 134.122.4.164:18444
  - Singapore: 188.166.255.63:18444
  - London: 209.97.177.197:18444
- Simplified setup process with automatic peer discovery

## Supported Platforms

- ✅ **Linux x64** (tested on Ubuntu 20.04+)
- ✅ **Windows x64** (tested on Windows 10/11)
- ✅ **macOS x64** (tested on macOS 10.15+)

## Installation Instructions

### Linux
```bash
tar -xzf dilithion-testnet-v1.0.8-linux-x64.tar.gz
cd dilithion-testnet-v1.0.8-linux-x64
chmod +x dilithion-node
./dilithion-node --testnet
```

### Windows
```cmd
# Extract dilithion-testnet-v1.0.8-windows-x64.zip
cd dilithion-testnet-v1.0.8-windows-x64
SETUP-AND-START.bat
```

### macOS
```bash
tar -xzf dilithion-testnet-v1.0.8-macos-x64.tar.gz
cd dilithion-testnet-v1.0.8-macos-x64
chmod +x dilithion-node
./dilithion-node --testnet
```

## Verification

### SHA256 Checksums

Verify your download integrity:

```bash
# Linux/macOS
sha256sum -c dilithion-testnet-v1.0.8-SHA256SUMS.txt

# Windows (PowerShell)
Get-FileHash dilithion-testnet-v1.0.8-windows-x64.zip -Algorithm SHA256
```

**Expected checksums:**
```
0b7a377a9cfc70523951e71f379a710be358a44f7a750b97dd2c8a559d35e9fe *dilithion-testnet-v1.0.8-linux-x64.tar.gz
59c2d59fbcc29896e3f0102c5b070b9dd4325df69e06334c285ddb711954fe99 *dilithion-testnet-v1.0.8-macos-x64.tar.gz
bc8ec00bc1dd3d44ef9baad914f5a2121f3d6ea0f0507dff102f2489489d2daa *dilithion-testnet-v1.0.8-windows-x64.zip
```

## Network Configuration

**Testnet Parameters:**
- Network Magic: 0xf1c8d2b3
- Default P2P Port: 18444
- Default RPC Port: 18332
- Genesis Block: `0x0000000000000000000000000000000000000000000000000000000000000000`

**DNS Seeds:**
- Built-in automatic peer discovery

**Known Seed Nodes:**
- 134.122.4.164:18444 (NYC)
- 188.166.255.63:18444 (Singapore)
- 209.97.177.197:18444 (London)

## Upgrade Notes

This is a recommended upgrade for all testnet participants. No blockchain reset or configuration changes are required.

## Known Issues

None reported at this time.

## Credits

Built with post-quantum cryptography (Dilithium) integration into the Bitcoin Core codebase.

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
