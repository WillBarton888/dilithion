# Windows DLL Mismatch Fix - COMPLETE ✅

**Date:** November 17, 2025
**Issue:** Windows binary crashed with "libcrypto-1_1-x64.dll was not found"
**Status:** ✅ **FIXED AND TESTED**

---

## The Problem

When you ran the Windows binary from the downloaded package, it crashed with this error:

```
The code execution cannot proceed because libcrypto-1_1-x64.dll was not found.
Reinstalling the program may fix this problem.
```

**The file existed** but the error still occurred - this was the critical clue!

---

## Root Cause Analysis

Using `strings` to inspect the binary revealed:
- **Binary expected:** `libcrypto-1_1-x64.dll` (OpenSSL 1.1.x)
- **Package contained:** `libcrypto-3-x64.dll` (OpenSSL 3.x)

**Why this happened:**
The binaries were compiled months ago against OpenSSL 1.1 from `depends/openssl`, but the current build environment only has OpenSSL 3.x available.

---

## The Solution

### 1. Updated Build System
**File:** `Makefile`
- Removed old `depends/openssl` include path
- Added system OpenSSL 3.x paths:
  - Include: `C:/ProgramData/mingw64/mingw64/opt/include`
  - Library: `C:/ProgramData/mingw64/mingw64/opt/lib`

### 2. Rebuilt All Binaries
Rebuilt against OpenSSL 3.5.2:
- `dilithion-node.exe` (2.0 MB)
- `genesis_gen.exe` (1.9 MB)
- `check-wallet-balance.exe` (1.9 MB)

**Verified with strings:**
```bash
$ strings dilithion-node.exe | grep libcrypto
libcrypto-3-x64.dll  ✅
```

### 3. Updated Packaging
**File:** `package-windows-release.bat`
- Changed from 6 DLLs to 5 DLLs
- Updated OpenSSL DLL source:
  - **Old:** `C:\Program Files\Git\mingw64\bin\libcrypto-3-x64.dll`
  - **New:** `C:\ProgramData\mingw64\mingw64\opt\bin\libcrypto-3-x64.dll`
- Removed `libssl-3-x64.dll` (not needed)

### 4. Updated Test Script
**File:** `TEST-DEBUG.bat`
- Changed from checking 6 DLLs to 5 DLLs
- Removed check for `libssl-3-x64.dll`

---

## Final Package Contents

### Binaries (3):
- `dilithion-node.exe` (2.0 MB) - Main node
- `check-wallet-balance.exe` (1.9 MB) - Wallet utility
- `genesis_gen.exe` (1.9 MB) - Genesis generator

### Runtime Libraries (5):
1. **libgcc_s_seh-1.dll** (147 KB) - GCC runtime
2. **libwinpthread-1.dll** (63 KB) - Threading support
3. **libstdc++-6.dll** (2.4 MB) - C++ standard library
4. **libleveldb.dll** (372 KB) - Database library
5. **libcrypto-3-x64.dll** (6.9 MB) - OpenSSL 3.x cryptography ✨

### Scripts & Documentation:
- Batch files: SETUP-AND-START.bat, START-MINING.bat, TEST-DEBUG.bat, etc.
- Documentation: README.txt, TESTNET-GUIDE.md, ANTIVIRUS-SOLUTION.md

**Total Package Size:** 6.6 MB compressed

---

## Testing Performed

### ✅ Test 1: Local Package Test
```bash
$ cd C:/Users/will/Desktop/test-v1.0.9/dilithion-testnet-v1.0.9-windows-x64
$ ./TEST-DEBUG.bat
```

**Results:**
```
[PASS] Not running from ZIP
[PASS] Write permission OK
[PASS] Disk space available
[PASS] dilithion-node.exe found
[PASS] All 5 DLLs found
[PASS] No duplicate instance
[PASS] Port 18444 available
[PASS] Port 18332 available
```

### ✅ Test 2: GitHub Download Test
```bash
$ curl -L -o dilithion-testnet-v1.0.9-windows-x64.zip \
  https://github.com/dilithion/dilithion/releases/download/v1.0.9/dilithion-testnet-v1.0.9-windows-x64.zip

$ sha256sum dilithion-testnet-v1.0.9-windows-x64.zip
dda15e0dc01cb4bedd99068dee1f7a3997513b7b4d9847cdc8b5952213950859 ✅
```

Extracted and tested - **all checks passed!**

### ✅ Test 3: Binary Execution
```bash
$ ./dilithion-node.exe --help
```
**Result:** Binary executed successfully (no DLL errors!)

---

## What Changed on GitHub

### Updated Files on v1.0.9 Release:
1. **dilithion-testnet-v1.0.9-windows-x64.zip**
   - Old SHA256: `9b5680377505c4567d6953d32a9d0fc608efb00b45165795d8a3d97395dc750d`
   - **New SHA256:** `dda15e0dc01cb4bedd99068dee1f7a3997513b7b4d9847cdc8b5952213950859` ✅

2. **dilithion-testnet-v1.0.9-SHA256SUMS.txt**
   - Updated with new Windows package checksum

### Git Commit:
```
ab81021 - fix: Rebuild Windows binaries with OpenSSL 3.x (fixes DLL mismatch)
```

---

## For Users Who Downloaded the Old Package

If you previously downloaded v1.0.9 and got the DLL error:

1. **Delete the old package:**
   - Delete `dilithion-testnet-v1.0.9-windows-x64.zip`
   - Delete the extracted folder

2. **Download the new package:**
   ```
   https://github.com/dilithion/dilithion/releases/download/v1.0.9/dilithion-testnet-v1.0.9-windows-x64.zip
   ```

3. **Verify the checksum:**
   ```powershell
   Get-FileHash dilithion-testnet-v1.0.9-windows-x64.zip -Algorithm SHA256
   ```
   Should show: `DDA15E0DC01CB4BEDD99068DEE1F7A3997513B7B4D9847CDC8B5952213950859`

4. **Extract and run:**
   - Extract the ZIP
   - Run `SETUP-AND-START.bat`
   - **It will now work!** ✅

---

## Why This Happened (Technical Details)

### Timeline:
1. **Months ago:** Binaries were built with OpenSSL 1.1 from `depends/openssl`
2. **System evolved:** Build environment upgraded to OpenSSL 3.x
3. **Packaging mismatch:** Old binaries + new DLLs = incompatibility
4. **User downloads:** Binary expects 1.1, finds 3.x, crashes

### The Fix:
- Rebuild binaries to match current environment (OpenSSL 3.x)
- Update packaging to use correct DLL versions
- Ensures binaries and DLLs are synchronized

---

## Lessons Learned

### ✅ What Worked:
1. **Diagnostic Approach:** Using `strings` to inspect binary dependencies
2. **Rebuild Strategy:** Syncing binaries with current environment
3. **Testing Protocol:** Local test → Package → GitHub test
4. **Clear Communication:** Screenshot from user was the breakthrough!

### 🔮 Future Prevention:
1. **CI/CD:** Automate binary building with fixed OpenSSL version
2. **Version Locking:** Document exact dependency versions
3. **Testing:** Always test downloaded package from GitHub
4. **Static Linking:** Consider Bitcoin Core's approach (future task)

---

## Download Link (FIXED)

**GitHub Release:**
```
https://github.com/dilithion/dilithion/releases/tag/v1.0.9
```

**Direct Download:**
```
https://github.com/dilithion/dilithion/releases/download/v1.0.9/dilithion-testnet-v1.0.9-windows-x64.zip
```

**SHA256 Verification:**
```
dda15e0dc01cb4bedd99068dee1f7a3997513b7b4d9847cdc8b5952213950859
```

---

## Summary

**Problem:** DLL version mismatch (binary wanted 1.1, package had 3.x)
**Solution:** Rebuilt binaries with OpenSSL 3.x
**Result:** Package now works perfectly!
**Status:** ✅ **FIXED, TESTED, UPLOADED, AND VERIFIED**

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
