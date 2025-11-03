# Dilithion Testnet v1.0.1 - Critical Hotfix Release

**Release Date:** November 3, 2025
**Release Type:** Critical Hotfix
**Network:** Testnet

## Overview

This is a critical hotfix release that addresses startup failures reported by Windows users. All users should upgrade to v1.0.1 immediately to ensure a smooth mining experience.

## Critical Fixes

This release implements **6 critical fixes** to the Windows batch files (`START-MINING.bat` and `SETUP-AND-START.bat`):

### 1. Node Exit Code Checking
- **Issue:** Silent failures when node crashes or exits with error
- **Fix:** Capture and display exit codes with helpful error messages
- **Impact:** Users now see clear error messages instead of generic "Mining stopped"

### 2. Stale LOCK File Detection
- **Issue:** Database lock file persists after crashes, preventing restart
- **Fix:** Detect stale LOCK files and prompt user to delete safely
- **Impact:** Eliminates "Failed to open database" errors after crashes

### 3. Port Conflict Detection
- **Issue:** Node fails silently if ports 18444 or 18332 are in use
- **Fix:** Check port availability before starting node
- **Impact:** Clear error messages explaining port conflicts

### 4. Running-from-ZIP Detection
- **Issue:** Users double-clicking batch files inside ZIP archives
- **Fix:** Detect temp directory paths and provide extraction instructions
- **Impact:** Prevents "path not found" errors for new users

### 5. Disk Space Checking
- **Issue:** Database corruption when disk runs out of space
- **Fix:** Check for minimum 1GB free space before starting
- **Impact:** Prevents data corruption and node failures

### 6. DLL Dependency Verification
- **Issue:** Missing runtime DLLs cause instant crashes
- **Fix:** Check for required DLLs (libgcc_s_seh-1.dll, libstdc++-6.dll, libwinpthread-1.dll)
- **Impact:** Clear guidance if ZIP extraction was incomplete

## Additional Improvements

- Enhanced error messages with specific troubleshooting steps
- Visual checkmarks (✓) for passed validation checks
- Better guidance for common issues (antivirus, permissions, extraction)
- Comprehensive write permission checking
- Improved duplicate instance detection with user choice

## What's Changed

**Modified Files:**
- `START-MINING.bat` - One-click mining with comprehensive validation
- `SETUP-AND-START.bat` - Interactive setup wizard with all critical fixes

**No Changes to:**
- Core executables (dilithion-node.exe, check-wallet-balance.exe, genesis_gen.exe)
- DLL files
- Functionality or network parameters

## Upgrade Instructions

### For New Users
Simply download and extract `dilithion-testnet-v1.0.1-windows-x64.zip` and run `SETUP-AND-START.bat`

### For Existing Users
You have two options:

**Option 1: Download New Package (Recommended)**
1. Download `dilithion-testnet-v1.0.1-windows-x64.zip`
2. Extract to your existing location
3. Your blockchain data (`.dilithion-testnet/`) will be preserved
4. Continue mining

**Option 2: Update Batch Files Only**
1. Download just the new batch files from the release
2. Replace `START-MINING.bat` and `SETUP-AND-START.bat` in your existing folder
3. Continue mining

## Verification

**SHA256 Checksums:**
```
ec95fdb57749ce97ba02a999271e27dcd526d3612f0f290a6fb9cf8c5ad692d1  dilithion-testnet-v1.0.1-windows-x64.zip
```

**Verify with PowerShell:**
```powershell
Get-FileHash dilithion-testnet-v1.0.1-windows-x64.zip -Algorithm SHA256
```

## Known Issues

**Non-Critical:**
- Initial P2P connection may show "Failed to add node" error - this auto-resolves within 1-2 minutes as the connection retry mechanism engages
- Antivirus false positives on unsigned executables - add folder to exclusions (EV code signing planned for mainnet)

## Support

- Discord: https://discord.gg/dilithion
- GitHub Issues: https://github.com/WillBarton888/dilithion/issues
- Website: https://dilithion.org

## Network Status

**Testnet is LIVE:**
- Seed Node: 170.64.203.134:18444
- Network Stats: https://dilithion.org
- Block Explorer: Coming soon

---

**Full Changelog:** v1.0.0...v1.0.1
