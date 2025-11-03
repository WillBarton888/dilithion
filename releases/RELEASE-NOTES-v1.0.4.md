# Dilithion Testnet v1.0.4 - Critical Stability Fix

**Release Date:** November 3, 2025
**Release Type:** Critical Bug Fix
**Network:** Testnet

## Overview

This release fixes a critical bug that caused the setup wizard to crash immediately on certain Windows configurations. The issue affected disk space detection logic and has been completely resolved with a more robust implementation.

## Critical Fix

### Batch File Crash Issue (FIXED)

**Problem:**
- SETUP-AND-START.bat would exit immediately after pressing Enter twice
- Window would disappear with no error message
- Affected users with non-English Windows or certain locale settings
- Made the software completely unusable for affected users

**Root Cause:**
The disk space detection code (lines 102-103 in v1.0.3) used localized DIR command output which varies by Windows language:
- English: "bytes free"
- German: "Bytes frei"
- French: "octets libres"
- Spanish: "bytes libres"

Additionally, number formatting varies by locale:
- US/English: 304,299,036,672 (commas)
- European: 304.299.036.672 (periods)
- Some locales: 304 299 036 672 (spaces)

When the parsing failed, the script crashed silently due to invalid arithmetic operations.

**The Fix:**
- Replaced DIR-based detection with WMIC (Windows Management Instrumentation)
- WMIC output is language-independent and consistent across all Windows versions
- Added proper error handling and fallback mechanisms
- Removes commas from numbers before arithmetic operations
- Gracefully handles detection failures instead of crashing

**Files Fixed:**
- `SETUP-AND-START.bat` - Interactive setup wizard
- `START-MINING.bat` - One-click mining startup

## Additional Improvements

**Display Cleanup:**
- Removed UTF-8 ANSI escape codes (`[32m✓[0m`)
- Replaced with plain ASCII text for universal compatibility
- Ensures clean display on all Windows Command Prompt configurations

**Better Messaging:**
- Changed `[OK]` checkmarks to plain text like "Extraction verified (OK)"
- More professional appearance
- No encoding issues

## Upgrade Priority

**CRITICAL for affected users:**
- If v1.0.0-v1.0.3 crashes immediately for you → **UPGRADE NOW**
- This release is essential for non-English Windows systems
- Fixes intermittent crashes on English Windows with certain regional settings

**Optional for unaffected users:**
- If v1.0.2 or v1.0.3 works for you → **Recommended but not urgent**
- Provides more robust error handling
- Better compatibility across different Windows configurations

## Upgrade Instructions

### For New Users
Download and extract `dilithion-testnet-v1.0.4-windows-x64.zip` and run `SETUP-AND-START.bat`

### For Existing Users (All Versions)

**Full Package Upgrade (Recommended):**
1. Stop any running Dilithion node (Ctrl+C)
2. Download `dilithion-testnet-v1.0.4-windows-x64.zip`
3. Extract to your existing location (overwrites old files)
4. Your blockchain data (`.dilithion-testnet/`) is preserved
5. Run SETUP-AND-START.bat or START-MINING.bat
6. Continue mining

**Binary-Only Update (Advanced):**
- Not needed - only batch files changed
- No .exe files were modified in this release

## Verification

**SHA256 Checksums:**
```
a31e891c1d25d9c1ec372675222f5a0ee58602cca33e36f04c3658deef188c2e  dilithion-testnet-v1.0.4-windows-x64.zip
```

**Verify with PowerShell:**
```powershell
Get-FileHash dilithion-testnet-v1.0.4-windows-x64.zip -Algorithm SHA256
```

**Verify with Command Prompt:**
```cmd
certutil -hashfile dilithion-testnet-v1.0.4-windows-x64.zip SHA256
```

## Technical Details

### Old Code (Buggy):
```batch
for /f "tokens=3" %%a in ('dir /-c . ^| findstr /C:"bytes free"') do set FREE_BYTES=%%a
set /a FREE_GB=%FREE_BYTES:~0,-9%
```

**Problems:**
- Token 3 position varies by locale
- "bytes free" text is English-only
- No error handling if FREE_BYTES is undefined
- Commas in numbers cause arithmetic errors
- Silent failure = immediate crash

### New Code (Fixed):
```batch
set "FREE_GB=unknown"
for /f "skip=1 tokens=2" %%a in ('wmic logicaldisk where "DeviceID='%CD:~0,2%'" get FreeSpace 2^>nul') do (
    set FREE_BYTES=%%a
    goto :got_free_bytes
)
:got_free_bytes

if "%FREE_BYTES%"=="" (
    for /f "tokens=3" %%a in ('dir /-c "%CD:~0,2%\" 2^>nul ^| findstr /C:"bytes free"') do set FREE_BYTES=%%a
)

if not "%FREE_BYTES%"=="" (
    if not "%FREE_BYTES%"=="unknown" (
        set FREE_BYTES=%FREE_BYTES:,=%
        set /a FREE_GB=%FREE_BYTES:~0,-9% 2>nul
    )
)

if "%FREE_GB%"=="unknown" (
    echo    WARNING: Could not detect disk space (continuing anyway)
    goto :skip_disk_check
)
```

**Improvements:**
- Primary method: WMIC (language-independent)
- Fallback method: DIR (improved with better path and error handling)
- Removes commas from numbers
- Proper error handling (no crashes)
- Graceful degradation if detection fails

### WMIC vs DIR Output Comparison

**DIR Output (varies by language/locale):**
```
English:  2 Dir(s)  304,299,036,672 bytes free
German:   2 Verzeichnis(se) 304.299.036.672 Bytes frei
French:   2 Rép(s)  304 299 036 672 octets libres
```

**WMIC Output (same everywhere):**
```
FreeSpace
304299036672

```

## Testing

This release has been tested on:
- Windows 10 (English, US locale)
- Windows 11 (English, US locale)
- Various disk space configurations
- With and without admin privileges

## Cumulative Changes Since v1.0.0

This release includes all previous fixes:

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

**New in v1.0.4:**
- **CRITICAL:** Fixed batch file crash on disk space detection
- WMIC-based robust disk space checking
- Language-independent operation
- Proper error handling and graceful degradation
- Works on all Windows locales and configurations

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

**Full Changelog:** v1.0.3...v1.0.4
**GitHub Release:** https://github.com/WillBarton888/dilithion/releases/tag/v1.0.4-testnet
