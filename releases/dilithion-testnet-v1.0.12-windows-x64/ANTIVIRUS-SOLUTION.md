# Windows Defender Is Blocking dilithion-node.exe

## The Problem

Windows Defender (or your antivirus) is **quarantining `dilithion-node.exe` during extraction**. The ZIP file contains the binary, but when you extract it, Windows Defender removes it immediately.

**This is a FALSE POSITIVE.** Dilithion is legitimate open-source software.

---

## Quick Fix (Recommended)

### Step 1: Add Windows Defender Exclusion

1. **Right-click** `FIX-WINDOWS-DEFENDER.bat`
2. Select **"Run as Administrator"**
3. Click **"Yes"** on UAC prompt
4. Let it add the exclusions

### Step 2: Restore Quarantined File

1. Open **Windows Security** (search in Start menu)
2. Go to **"Virus & threat protection"**
3. Click **"Protection history"**
4. Find **dilithion-node.exe** in the list
5. Click **"Actions" → "Restore"**

### Step 3: Re-extract ZIP

1. **Delete** the current extracted folder
2. **Re-download** the ZIP (or use existing one)
3. **Right-click ZIP** → "Extract All..."
4. Extract to a **permanent location** (e.g., `C:\Dilithion`)
5. Files should now extract without being quarantined

### Step 4: Run Setup

1. Navigate to extracted folder
2. Run **SETUP-AND-START.bat**
3. Should work now!

---

## Manual Fix (Alternative)

If the automatic script doesn't work:

### Add Folder Exclusion Manually:

1. Open **Windows Security**
2. Go to **"Virus & threat protection"**
3. Click **"Manage settings"** under "Virus & threat protection settings"
4. Scroll to **"Exclusions"**
5. Click **"Add or remove exclusions"**
6. Click **"Add an exclusion" → "Folder"**
7. Select your Dilithion folder: `C:\Dilithion4\dilithion-testnet-v1.0.9-windows-x64`

### Add Process Exclusions:

Same steps, but choose **"Process"** instead and add:
- `dilithion-node.exe`
- `check-wallet-balance.exe`
- `genesis_gen.exe`

---

## Why This Happens

**Cryptocurrency miners are often flagged as PUAs (Potentially Unwanted Applications)** because:
1. Real malware sometimes includes cryptocurrency miners
2. Windows Defender uses heuristics that can't distinguish legitimate miners
3. Our binary is compiled with MinGW and uses cryptography libraries (triggers heuristics)

**Dilithion is NOT malware:**
- ✅ Open source: https://github.com/WillBarton888/dilithion
- ✅ No obfuscation
- ✅ No network backdoors
- ✅ Only connects to known seed nodes
- ✅ Testnet coins have NO monetary value

---

## Verification

After fixing, verify the files are present:

```batch
cd C:\Dilithion4\dilithion-testnet-v1.0.9-windows-x64
dir *.exe
```

You should see:
```
dilithion-node.exe          2,909 KB
check-wallet-balance.exe    2,912 KB
genesis_gen.exe             2,912 KB
```

If you see all 3 exe files, run `SETUP-AND-START.bat` and it will work!

---

## Still Having Issues?

Run `TEST-DEBUG.bat` to see exactly what's missing:

```batch
TEST-DEBUG.bat
```

Look for:
```
[PASS] dilithion-node.exe found
[PASS] All 6 DLLs found
```

If you see `[FAIL]`, that file is missing and needs to be restored from quarantine.

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
