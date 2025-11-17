# Windows Binary Troubleshooting Guide

## Known Issues & Solutions

### Issue: Batch File "if exist" Checks Fail
**Symptoms:** Error message "dilithion-node.exe not found" even though file exists
**Root Cause:** Windows batch `if exist` command fails in certain execution contexts
**Solution:** Remove all `if exist` file checks from batch files - Windows shows its own error if binary is missing
**Files Affected:** SETUP-AND-START.bat, START-MINING.bat
**Fixed In:** v1.0.9 (commit 7b3fb90)

### Issue: DLL Not Found Errors
**Symptoms:** "libcrypto-X-x64.dll was not found"
**Root Cause:** Binary compiled with different OpenSSL version than packaged DLLs
**Solution:** Ensure ALL DLLs come from same toolchain location as build
**Files Affected:** package-windows-release.bat
**Fixed In:** v1.0.9

## Debugging Protocol

When users report Windows binary issues:

1. **First (5 min):** Ask user to run `dilithion-node.exe --help` directly from CMD
   - If this works → Problem is batch file
   - If this fails → Problem is binary/DLLs

2. **Second (5 min):** Check which error they see:
   - "File not found" → Likely batch file issue, not real missing file
   - "DLL not found" → Check DLL versions match binary
   - Window closes silently → Check Windows Event Viewer

3. **Third (10 min):** Test minimal reproduction:
   - Remove all checks/logic from batch file
   - Just run the binary directly
   - If this works → Problem was in batch file logic

4. **Never spend >30 minutes** on speculative fixes without minimal reproduction

## Testing Checklist (Before Release)

- [ ] Download zip from GitHub (not local copy)
- [ ] Extract to fresh directory (e.g., C:\TestDilithion)
- [ ] Double-click SETUP-AND-START.bat
- [ ] Verify mining starts within 10 seconds
- [ ] Check connections to seed nodes
- [ ] Test on clean Windows VM if possible

## Build Verification

```batch
REM Verify binary can run
dilithion-node.exe --help

REM Check DLL dependencies match
strings dilithion-node.exe | grep libcrypto

REM Verify all required DLLs present
dir *.dll

REM Test from batch file
echo dilithion-node.exe --help > test.bat
test.bat
```

## Contact

If you encounter issues not covered here, create an issue on GitHub with:
- Exact error message
- Output of `dilithion-node.exe --help`
- Windows version
- Whether binary works from CMD directly
