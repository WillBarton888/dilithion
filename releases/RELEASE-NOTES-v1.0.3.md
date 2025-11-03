# Dilithion Testnet v1.0.3 - Professional Display Fix

**Release Date:** November 3, 2025
**Release Type:** Display/UX Fix
**Network:** Testnet

## Overview

This release fixes the unprofessional character encoding issue where UTF-8 checkmarks (✓) and crosses (✗) displayed as garbled text (`Γ£ô`, `Γ£ù`) on Windows Command Prompt. All console output now uses clean ASCII characters that display correctly on all Windows systems.

## Display Improvements

**Before (v1.0.0-v1.0.2):**
```
  Γ£ô Blockchain database opened
  Γ£ô Mempool initialized
  Γ£ô Mining started
  Γ£ù Failed to add node
```

**After (v1.0.3):**
```
  [OK] Blockchain database opened
  [OK] Mempool initialized
  [OK] Mining started
  [FAIL] Failed to add node
```

## Changes

**Modified:**
- `dilithion-node.exe` - All status indicators now use ASCII `[OK]` and `[FAIL]` instead of UTF-8 symbols
- `check-wallet-balance.exe` - Rebuilt with same improvements
- `genesis_gen.exe` - Rebuilt with same improvements

**No Changes to:**
- Batch files (still using v1.0.2 fixes)
- DLL files
- Network parameters or functionality
- Any core logic or consensus rules

## Upgrade Priority

**Cosmetic upgrade - not critical:**
- v1.0.2 works perfectly fine - only difference is display
- Upgrade when convenient for cleaner, more professional output
- Recommended for all users for best visual experience

## Upgrade Instructions

### For New Users
Download and extract `dilithion-testnet-v1.0.3-windows-x64.zip` and run `SETUP-AND-START.bat`

### For Existing Users
**Option 1: Full Package**
1. Download `dilithion-testnet-v1.0.3-windows-x64.zip`
2. Extract to existing location (overwrites old files)
3. Your blockchain data (`.dilithion-testnet/`) preserved
4. Continue mining

**Option 2: Binary-Only Update**
1. Stop mining (Ctrl+C)
2. Download just the `.exe` files
3. Replace: `dilithion-node.exe`, `check-wallet-balance.exe`, `genesis_gen.exe`
4. Resume mining

## Verification

**SHA256 Checksums:**
```
56d4b5a230e6bf79e5112f17bbb0f6cafa6e7587a26ed3778da6888e5ddd8464  dilithion-testnet-v1.0.3-windows-x64.zip
```

**Verify with PowerShell:**
```powershell
Get-FileHash dilithion-testnet-v1.0.3-windows-x64.zip -Algorithm SHA256
```

## Technical Details

**Root Cause:**
Windows Command Prompt uses CP-437 (DOS) or CP-850 (Western European) character encoding by default, not UTF-8. When C++ programs output UTF-8 characters like ✓ (U+2713) and ✗ (U+2717), they get misinterpreted as multi-byte CP-437 characters.

**The Fix:**
Changed all console output from UTF-8 symbols to ASCII-safe indicators:
- `✓` (U+2713) → `[OK]` (ASCII 91, 79, 75, 93)
- `✗` (U+2717) → `[FAIL]` (ASCII 91, 70, 65, 73, 76, 93)

These display correctly on all Windows systems regardless of code page settings.

**Alternative Approaches Considered:**
1. Add `chcp 65001` to batch files (rejected - requires admin on some systems)
2. Use Windows-specific console API (rejected - adds complexity)
3. **Use ASCII characters (selected - simple, universal, professional)**

## Cumulative Changes Since v1.0.0

v1.0.3 includes all fixes from previous releases:

**From v1.0.1:**
- 6 critical batch file fixes (directory creation, port checking, lock files, etc.)
- Comprehensive error handling and validation
- Clear error messages for common issues

**From v1.0.2:**
- Windows Defender compatibility (mkdir instead of echo test)
- Firewall prompt warnings
- Improved first-time user guidance

**New in v1.0.3:**
- Professional ASCII console output
- Universal Windows compatibility for display

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

**Full Changelog:** v1.0.2...v1.0.3
