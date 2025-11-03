# Dilithion Testnet v1.0.2 - Windows Defender Compatibility Fix

**Release Date:** November 3, 2025
**Release Type:** Critical Hotfix
**Network:** Testnet

## Overview

This release fixes Windows Defender compatibility issues that prevented v1.0.1 from running on systems with strict security settings. If you experienced batch files closing immediately without error messages, this release fixes that issue.

## Critical Fix

**Windows Defender Write Permission Check:**
- **Issue:** Windows Defender's Controlled Folder Access blocked the write permission test (`echo test >`) causing silent failures
- **Fix:** Changed write permission validation to use `mkdir` instead of file creation
- **Impact:** Batch files now work correctly even with Windows Defender enabled

**Additional Improvements:**
- Added clear firewall prompt warnings (expect 2 prompts for ports 18444 and 18332)
- Improved error messages for Windows security scenarios
- Better guidance for first-time users about expected Windows prompts

## What's Changed

**Modified Files:**
- `START-MINING.bat` - Fixed write check + firewall warnings
- `SETUP-AND-START.bat` - Fixed write check + firewall warnings

**No Changes to:**
- Core executables (dilithion-node.exe, check-wallet-balance.exe, genesis_gen.exe)
- DLL files
- Network parameters or functionality

## v1.0.1 vs v1.0.2

**If v1.0.1 worked for you:** No need to upgrade - both versions are functionally identical
**If v1.0.1 failed silently:** Upgrade to v1.0.2 - this fixes your issue

## Upgrade Instructions

### For New Users
Download and extract `dilithion-testnet-v1.0.2-windows-x64.zip` and run `SETUP-AND-START.bat`

### For v1.0.1 Users
**Option 1: Download New Package**
1. Download `dilithion-testnet-v1.0.2-windows-x64.zip`
2. Extract to your existing location
3. Your blockchain data (`.dilithion-testnet/`) will be preserved
4. Continue mining

**Option 2: Update Batch Files Only**
1. Download just the new batch files
2. Replace `START-MINING.bat` and `SETUP-AND-START.bat`
3. Continue mining

## Expected Windows Prompts

When you run the software for the first time, you will see:

**1. Windows Firewall Prompts (2 total):**
- Port 18444 (P2P networking) - Click "Allow access"
- Port 18332 (RPC server) - Click "Allow access"

These prompts are normal and required for cryptocurrency mining. The software needs network access to connect to the testnet.

**2. SmartScreen Warning (unsigned software):**
- This appears because the executables are not yet code-signed
- Click "More info" → "Run anyway"
- EV code signing is planned for mainnet launch (requires business verification)

## Verification

**SHA256 Checksums:**
```
1fbc23e24c88c37ef26d6cefd335a204cbe3d25dc82f97eed9f7a8d34b89b922  dilithion-testnet-v1.0.2-windows-x64.zip
```

**Verify with PowerShell:**
```powershell
Get-FileHash dilithion-testnet-v1.0.2-windows-x64.zip -Algorithm SHA256
```

## Known Issues

**Non-Critical:**
- Initial P2P connection may show "Failed to add node" error - auto-resolves within 1-2 minutes
- Antivirus false positives on unsigned executables - add folder to exclusions
- SmartScreen warnings - click "Run anyway" (EV signing planned for mainnet)

## Technical Details

**Root Cause Analysis:**

Windows Defender's "Controlled Folder Access" feature blocks batch files from creating test files using `echo test > file.tmp` as a ransomware protection measure. However, it ALLOWS `mkdir` commands and normal directory operations.

**The Fix:**

Changed from:
```batch
echo test > ".dilithion-test-write.tmp" 2>nul
if errorlevel 1 (
    REM Write permission check failed
)
```

To:
```batch
if not exist ".dilithion-testnet" (
    mkdir ".dilithion-testnet" 2>nul
    if errorlevel 1 (
        REM Write permission check failed
    )
    rmdir ".dilithion-testnet" 2>nul
)
```

This approach bypasses the false positive while still validating write permissions.

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

**Full Changelog:** v1.0.1...v1.0.2
