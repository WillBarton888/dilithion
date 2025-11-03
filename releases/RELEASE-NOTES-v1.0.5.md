# Dilithion Testnet v1.0.5 - Enhanced Stability Fix

**Release Date:** November 3, 2025
**Release Type:** Critical Bug Fix (Enhanced)
**Network:** Testnet

## Overview

This release further improves the batch file stability fixes from v1.0.4. While v1.0.4 resolved the issue for most users, some Windows configurations continued to experience crashes. v1.0.5 adds additional robustness and includes a diagnostic tool to help identify any remaining environment-specific issues.

## What's New in v1.0.5

### Enhanced Batch File Robustness

**Additional Fixes:**
- Added delayed expansion support for more reliable variable handling
- Implemented space removal in addition to comma removal for number parsing
- Enhanced error suppression throughout the disk space detection logic
- Triple-layer validation before any numeric comparisons

**Technical Improvements:**
```batch
# Old approach (v1.0.4):
set FREE_BYTES=%FREE_BYTES:,=%
set /a "FREE_GB=FREE_BYTES / 1073741824" 2>nul

# New approach (v1.0.5):
setlocal enabledelayedexpansion
set FREE_BYTES=!FREE_BYTES:,=!
set FREE_BYTES=!FREE_BYTES: =!
set /a "FREE_GB=FREE_BYTES / 1073741824" 2>nul

# Then triple validation:
if "%FREE_GB%"=="unknown" goto :skip_disk_check
if "%FREE_GB%"=="" goto :skip_disk_check
set /a TEST_GB=%FREE_GB% 2>nul
if errorlevel 1 goto :skip_disk_check
# Only then perform comparison
```

### New Diagnostic Tool: ULTRA-DEBUG.bat

**Purpose:**
If you're still experiencing crashes (even with v1.0.5), run `ULTRA-DEBUG.bat` instead of `SETUP-AND-START.bat`. This will create `ULTRA-DEBUG-LOG.txt` with extremely detailed logging of every operation.

**What It Logs:**
- Exact variable values before and after each operation (with brackets to show whitespace)
- Success/failure of each validation check
- The exact command being executed before it runs
- Timestamps for every step
- Error output from all operations

**How to Use:**
1. Double-click `ULTRA-DEBUG.bat`
2. Press Enter when prompted
3. If it crashes, the log file will show the last successful operation
4. Send `ULTRA-DEBUG-LOG.txt` to support for analysis

**Example Log Output:**
```
[17:46:03.61] After comma removal: [304198500352]
[17:46:03.61] After space removal: [304198500352]
[17:46:03.61] Attempting arithmetic division
[17:46:03.63] Arithmetic succeeded
[17:46:03.63] After processing, FREE_GB=[304]
[17:46:03.64] VALIDATION 1: Checking if FREE_GB equals 'unknown'
[17:46:03.64] VALIDATION 1 PASSED: FREE_GB is not 'unknown'
[17:46:03.64] VALIDATION 2: Checking if FREE_GB is empty
[17:46:03.64] VALIDATION 2 PASSED: FREE_GB is not empty, value=[304]
[17:46:03.64] VALIDATION 3: Testing numeric validity
[17:46:03.64] VALIDATION 3 PASSED: TEST_GB=[304]
[17:46:03.64] FINAL COMPARISON: About to check if 304 is less than 1
```

## Files Changed

**Modified:**
- `SETUP-AND-START.bat` - Enhanced stability with delayed expansion
- `START-MINING.bat` - Same enhancements applied
- `TEST-DEBUG.bat` - Same enhancements applied

**New:**
- `ULTRA-DEBUG.bat` - Diagnostic tool with verbose logging

**Unchanged:**
- All .exe binaries (no code changes)
- All .dll files
- README.txt, TESTNET-GUIDE.md, dilithion-wallet.bat

## Upgrade Priority

**CRITICAL for users experiencing crashes:**
- If v1.0.0-v1.0.4 crashes for you → **UPGRADE IMMEDIATELY**
- This is the most robust version yet with extensive error handling

**Recommended for all users:**
- Even if v1.0.4 works, v1.0.5 provides additional stability
- The ULTRA-DEBUG.bat tool is valuable for troubleshooting

## Upgrade Instructions

### For New Users
Download and extract `dilithion-testnet-v1.0.5-windows-x64.zip` and run `SETUP-AND-START.bat`

### For Existing Users (All Versions)

**Full Package Upgrade (Recommended):**
1. Stop any running Dilithion node (Ctrl+C)
2. Download `dilithion-testnet-v1.0.5-windows-x64.zip`
3. Extract to your existing location (overwrites old files)
4. Your blockchain data (`.dilithion-testnet/`) is preserved
5. Run `SETUP-AND-START.bat`
6. If it still crashes, run `ULTRA-DEBUG.bat` and send us the log

**Binary-Only Update:**
- Not needed - only batch files changed in this release
- No .exe or .dll files were modified

## Verification

**SHA256 Checksums:**
```
c1a979af438f2f9d634fd862a30fb30a60c81c70c477b83fe777ba8980cb48d6  dilithion-testnet-v1.0.5-windows-x64.zip
```

**Verify with PowerShell:**
```powershell
Get-FileHash dilithion-testnet-v1.0.5-windows-x64.zip -Algorithm SHA256
```

**Verify with Command Prompt:**
```cmd
certutil -hashfile dilithion-testnet-v1.0.5-windows-x64.zip SHA256
```

## Technical Details: What Could Still Cause Crashes?

Even with v1.0.5's robust fixes, crashes could occur due to:

1. **Antivirus/Security Software**
   - Blocking file operations
   - Quarantining executables mid-execution
   - Solution: Add exclusion for Dilithion directory

2. **File System Permissions**
   - Read-only directories
   - Network drives with sync issues
   - Solution: Run from a local, writable directory

3. **Console/Terminal Issues**
   - Some Windows Terminal replacements
   - Custom console emulators
   - Solution: Use standard `cmd.exe`

4. **System Resources**
   - Extreme low memory
   - Disk I/O errors
   - Solution: Check Event Viewer, run disk check

If crashes persist after v1.0.5, run `ULTRA-DEBUG.bat` and share the log file.

## Cumulative Changes Since v1.0.0

**From v1.0.1:**
- 6 critical batch file fixes (directory creation, port checking, lock files, etc.)
- Comprehensive error handling and validation
- Clear error messages for common issues

**From v1.0.2:**
- Windows Defender compatibility (mkdir instead of echo test)
- Firewall prompt warnings
- Improved first-time user guidance

**From v1.0.3:**
- Professional ASCII console output (`[OK]` / `[FAIL]`)
- Universal Windows compatibility for display
- No UTF-8 encoding issues

**From v1.0.4:**
- WMIC-based robust disk space checking
- Language-independent operation
- Proper error handling and graceful degradation

**New in v1.0.5:**
- **ENHANCED:** Delayed expansion for safer variable handling
- **ENHANCED:** Space removal in addition to comma removal
- **NEW:** ULTRA-DEBUG.bat diagnostic tool with verbose logging
- **ENHANCED:** Triple-layer validation before numeric comparisons
- **IMPROVED:** Better error suppression throughout

## Troubleshooting Guide

### If SETUP-AND-START.bat Crashes

1. **Run ULTRA-DEBUG.bat** instead
   - Creates detailed log file
   - Shows exact crash point
   - Logs all variable values

2. **Check the last logged line** in `ULTRA-DEBUG-LOG.txt`
   - The crash occurs immediately after the last logged line
   - Share this information when requesting support

3. **Common Solutions:**
   - Extract to `C:\Dilithion-Testnet\` (avoid deep/long paths)
   - Disable antivirus temporarily
   - Run as Administrator
   - Use native Windows Command Prompt (not PowerShell or third-party terminals)

4. **Get Help:**
   - Discord: https://discord.gg/dilithion
   - GitHub Issues: https://github.com/WillBarton888/dilithion/issues
   - Include `ULTRA-DEBUG-LOG.txt` when reporting issues

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

**Full Changelog:** v1.0.4...v1.0.5
**GitHub Release:** https://github.com/WillBarton888/dilithion/releases/tag/v1.0.5-testnet
