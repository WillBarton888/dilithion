# Complete User Testing Guide for v1.0.9

## What You're Going to Test

I've created multiple versions to help diagnose the issue:

1. **SETUP-AND-START.bat** (original with colors)
2. **SETUP-AND-START-NO-COLOR.bat** (no ANSI colors)
3. **FIX-WINDOWS-DEFENDER.bat** (adds antivirus exclusions)
4. **TEST-DEBUG.bat** (diagnostic tool)

---

## Step-by-Step Testing Process

### Step 1: Clean Start

1. **Delete** the folder `C:\Dilithion4\dilithion-testnet-v1.0.9-windows-x64`
2. **Download fresh** from: https://github.com/WillBarton888/dilithion/releases/download/v1.0.9/dilithion-testnet-v1.0.9-windows-x64.zip
3. **Verify SHA256**:
   ```
   7da26734cfd701d5dd3d9857ef9663d05056408a8ca37cb2b10d68b2df0fce03
   ```

### Step 2: Add Windows Defender Exclusion BEFORE Extraction

1. Open **Windows Security**
2. Go to **"Virus & threat protection"**
3. Click **"Manage settings"**
4. Scroll to **"Exclusions"**
5. Click **"Add or remove exclusions"**
6. Click **"Add an exclusion" → "Folder"**
7. Select **`C:\Dilithion4`** (the parent folder)

### Step 3: Extract the ZIP

1. **Right-click** the ZIP file
2. Select **"Extract All..."**
3. Extract to **`C:\Dilithion4`**
4. Wait for extraction to complete

### Step 4: Verify Files Extracted

Open Command Prompt and run:
```cmd
cd C:\Dilithion4\dilithion-testnet-v1.0.9-windows-x64
dir
```

**You should see:**
```
dilithion-node.exe          (2,909 KB)
check-wallet-balance.exe     (2,909 KB)
genesis_gen.exe             (2,912 KB)
libcrypto-3-x64.dll         (5,791 KB)
libssl-3-x64.dll            (1,025 KB)
libleveldb.dll                (380 KB)
libstdc++-6.dll             (2,461 KB)
libgcc_s_seh-1.dll            (150 KB)
libwinpthread-1.dll            (64 KB)
SETUP-AND-START.bat
START-MINING.bat
TEST-DEBUG.bat
... (other files)
```

**If dilithion-node.exe is MISSING:**
- Windows Defender quarantined it during extraction
- Go to **Windows Security → Protection history**
- Find **dilithion-node.exe**
- Click **"Restore"**
- Re-extract the ZIP

### Step 5: Run Diagnostic Test

```cmd
TEST-DEBUG.bat
```

**Expected output:**
```
[PASS] Not running from ZIP
[PASS] Write permission OK
[PASS] Disk space OK: XXX GB
[PASS] dilithion-node.exe found
[PASS] All 6 DLLs found
[PASS] No duplicate instance
[PASS] Port 18444 available
[PASS] Port 18332 available
```

**If ANY check fails:**
- Read the error message carefully
- Fix the issue before proceeding
- Most common: dilithion-node.exe was quarantined

### Step 6: Test Without Colors (Recommended)

Since you're seeing garbled output with color codes:

```cmd
SETUP-AND-START-NO-COLOR.bat
```

**Expected flow:**
1. Welcome screen → **Press any key**
2. System checks → Should show all [OK]
3. CPU cores prompt → **Press ENTER** for auto
4. Ready to start → **Press any key**
5. Node starts mining

**Take a screenshot at EACH "Press any key" point** so we can see exactly where it fails.

### Step 7: If It Still Closes After Second Button

Run this to see the EXACT error:

```cmd
cmd /k "SETUP-AND-START-NO-COLOR.bat"
```

The `/k` flag keeps the window open even after the script exits.

---

## What to Report Back

Please provide:

1. **Screenshot** of each pause point
2. **Output** of TEST-DEBUG.bat
3. **Output** of this command:
   ```cmd
   dir *.exe *.dll
   ```
4. **Exact point** where window closes (first button? second? third?)
5. **Last message** you see before it closes

---

## Expected Behavior (Success)

1. First pause: Welcome message
2. Second pause: After all checks pass (all [OK])
3. Third pause: After CPU core selection
4. Fourth pause: Before starting mining
5. Mining starts: You see "Dilithion Testnet Node" and connection messages

---

## Common Issues & Solutions

### Issue: "window disappears after first button"
**Cause:** Batch syntax error or missing :label
**Fix:** Applied in latest version

### Issue: "window disappears after second button"
**Cause:** Binary check fails (dilithion-node.exe missing)
**Fix:** Restore from Windows Defender quarantine

### Issue: "Garbled output with [32mΓ£ô[0m"
**Cause:** Terminal doesn't support ANSI colors
**Fix:** Use SETUP-AND-START-NO-COLOR.bat instead

### Issue: "All checks pass but node crashes immediately"
**Cause:** Missing DLL not checked by validation
**Fix:** All 6 DLLs now validated in latest version

---

## Files You Have Access To

In `C:\Users\will\dilithion`:
- `SETUP-AND-START-NO-COLOR.bat` ← Try this one
- `FIX-WINDOWS-DEFENDER.bat` ← Run as Admin first
- `TEST-DEBUG.bat` ← Run this for diagnostics
- `ANTIVIRUS-SOLUTION.md` ← Full antivirus guide
- `PACKAGE-VERIFICATION-REPORT.md` ← What I tested

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
