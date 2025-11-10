# URGENT: Windows Wallet Fix for Discord User

## Problem
`dilithion-wallet.bat` can't find curl even though curl is installed.

## Immediate Fix (For Discord User)

### Option 1: Download Fixed Version (FASTEST)
We've just fixed this issue. The updated `dilithion-wallet.bat` will auto-detect curl from multiple locations.

**Tell them:**
1. Download the fixed `dilithion-wallet.bat` from our repo
2. Replace the old one in their `dilithion-testnet-v1.0.0-windows-x64` folder
3. Run it again

### Option 2: Quick Workaround (Works NOW)
If they can't wait for the update, tell them:

```batch
# Find where their curl is located:
which curl
```

If it shows something like `/c/Program Files/Git/mingw64/bin/curl.exe`, tell them to:

1. Open `dilithion-wallet.bat` in Notepad
2. Find line that says: `curl --max-time`
3. Replace `curl` with the FULL Windows path like:
   ```
   "C:\Program Files\Git\mingw64\bin\curl.exe" --max-time
   ```
4. Save and try again

### Option 3: Use Windows Native Curl
Windows 10/11 includes curl. Test with:
```cmd
C:\Windows\System32\curl.exe --version
```

If that works, tell them to edit `dilithion-wallet.bat` and use:
```
C:\Windows\System32\curl.exe
```

## What We Fixed
- ✅ Added multi-location curl detection (tries 5 different paths)
- ✅ Better error messages with solutions
- ✅ Discord link for support

## For Future Users
The updated release packages now include:
1. Fixed wallet wrappers with robust dependency detection
2. Better error messages for all platforms
3. Dependency checks in all startup scripts

---

## Discord Message Template

```
Hey! We just identified and fixed this issue. Here's what's happening:

Your curl IS installed, but the batch script can't find it due to Windows PATH issues.

**QUICK FIX:**
1. Download the updated dilithion-wallet.bat from: [provide link to repo/release]
2. Replace your current one
3. Run it again - should work now!

The new version automatically detects curl from 5 different locations including Git/MSYS2/Windows System32.

**OR if you need it working RIGHT NOW:**
Run this in your terminal:
```
which curl
```
Then let me know what path it shows and I'll tell you exactly what to edit.

Sorry for the hassle - you're our first tester so you found the edge cases we missed! 🙏
```
