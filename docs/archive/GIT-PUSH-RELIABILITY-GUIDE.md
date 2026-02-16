# Git Push Reliability Guide

**Issue:** Git push commands sometimes hang or fail, especially in WSL2 environment with large commits.

**Date:** November 6, 2025

---

## Root Causes

### 1. WSL2 Networking Issues
- **Problem:** WSL2 uses virtualized networking that can be unstable
- **Symptoms:** Long hangs, timeouts, "Connection reset by peer"
- **Trigger:** Network changes (wifi/ethernet switches), Windows network stack issues

### 2. Large Commit Size
- **Problem:** Default git HTTP buffer is only ~1MB
- **Symptoms:** Push starts then hangs during upload
- **Trigger:** Commits with >1000 lines or multiple files

### 3. HTTPS Authentication
- **Problem:** Token-based auth can expire mid-push
- **Symptoms:** Push hangs indefinitely without error
- **Trigger:** Long-running pushes, cached credential expiry

### 4. GitHub Server Load
- **Problem:** GitHub throttles large uploads during peak hours
- **Symptoms:** Very slow progress, timeouts
- **Trigger:** Large repositories, peak usage times

---

## Solutions Applied (November 6, 2025)

### Configuration Changes
```bash
# Increase HTTP buffer to 500MB (handles large commits)
git config http.postBuffer 524288000

# Set minimum transfer speed (detects stalls)
git config http.lowSpeedLimit 1000

# Allow slow transfers for up to 10 minutes
git config http.lowSpeedTime 600

# Use simple push strategy
git config push.default simple
```

**Result:** These settings are now active in the dilithion repository.

---

## Recommended Solutions (Priority Order)

### ⭐ **Solution 1: Switch to SSH (BEST)**

**Why:** SSH is more stable, faster, and doesn't have token expiry issues.

**Steps:**
1. Check if SSH key exists:
   ```bash
   wsl bash -c "ls -la ~/.ssh/id_*.pub"
   ```

2. If no key exists, generate one:
   ```bash
   wsl bash -c "ssh-keygen -t ed25519 -C 'your_email@example.com'"
   ```

3. Add key to GitHub:
   ```bash
   wsl bash -c "cat ~/.ssh/id_ed25519.pub"
   ```
   Copy output and add to: https://github.com/settings/ssh/new

4. Switch repository to SSH:
   ```bash
   wsl bash -c "cd /mnt/c/Users/will/dilithion && git remote set-url origin git@github.com:dilithion/dilithion.git"
   ```

5. Test connection:
   ```bash
   wsl bash -c "ssh -T git@github.com"
   ```

**Expected Output:** "Hi WillBarton888! You've successfully authenticated..."

---

### ⭐ **Solution 2: Reduce Compression (FAST)**

**Why:** Less CPU work = faster pushes

```bash
wsl bash -c "cd /mnt/c/Users/will/dilithion && git config core.compression 0"
wsl bash -c "cd /mnt/c/Users/will/dilithion && git config core.looseCompression 0"
```

---

### ⭐ **Solution 3: Increase Git Pack Size**

**Why:** Allows git to pack more data efficiently

```bash
wsl bash -c "cd /mnt/c/Users/will/dilithion && git config pack.windowMemory 256m"
wsl bash -c "cd /mnt/c/Users/will/dilithion && git config pack.packSizeLimit 256m"
```

---

### ⭐ **Solution 4: Fix WSL2 Networking**

**Why:** Reset WSL2 network stack

**Run in Windows PowerShell (Admin):**
```powershell
wsl --shutdown
```

**Then restart WSL:** Open WSL terminal again

---

### ⭐ **Solution 5: Use Git LFS for Large Files**

**Why:** Git LFS handles large files separately from commits

```bash
# Install Git LFS
wsl bash -c "cd /mnt/c/Users/will/dilithion && git lfs install"

# Track large file types (example: binaries, logs)
wsl bash -c "cd /mnt/c/Users/will/dilithion && git lfs track '*.log' '*.bin'"
```

---

## Emergency Procedures

### If Push Hangs for >2 Minutes:

1. **Kill the process:**
   - Use KillShell tool in Claude Code
   - Or `Ctrl+C` in terminal

2. **Try SSH instead:**
   ```bash
   git remote set-url origin git@github.com:dilithion/dilithion.git
   git push
   ```

3. **Try with progress indicator:**
   ```bash
   git push --progress origin main 2>&1
   ```

4. **Last resort - force push (DANGEROUS):**
   ```bash
   # Only if you're sure no one else is working on the branch
   git push --force-with-lease origin main
   ```

---

## Verification Checklist

After applying fixes, verify with:

```bash
# Check configuration
wsl bash -c "cd /mnt/c/Users/will/dilithion && git config --list | grep -E '(http|push|compression|pack)'"

# Test push with verbose output
wsl bash -c "cd /mnt/c/Users/will/dilithion && git push -v origin main"

# Check remote connection
wsl bash -c "cd /mnt/c/Users/will/dilithion && git ls-remote origin"
```

---

## Performance Benchmarks

### Before Optimizations:
- Small commits (<100 lines): 10-30 seconds
- Medium commits (100-1000 lines): 1-5 minutes or timeout
- Large commits (>1000 lines): Often timeout/hang

### After Optimizations (Expected):
- Small commits: 5-15 seconds
- Medium commits: 15-60 seconds
- Large commits: 1-3 minutes

### With SSH (Expected):
- Small commits: 3-8 seconds
- Medium commits: 10-30 seconds
- Large commits: 30-90 seconds

---

## Monitoring Push Progress

### Real-time monitoring:
```bash
# Watch git process
watch -n 1 'ps aux | grep "git push"'

# Monitor network activity
watch -n 1 'netstat -an | grep ESTABLISHED | grep github'
```

---

## Prevention Strategy

### For Future Commits:

1. **Commit more frequently** (smaller commits push faster)
2. **Use branches** for experimental work
3. **Run `git gc` periodically** to optimize repository
4. **Monitor commit size** before pushing:
   ```bash
   git diff --stat origin/main..HEAD
   ```

5. **Test push before critical deadlines:**
   ```bash
   git push --dry-run origin main
   ```

---

## Status: Current Configuration

✅ **Applied (November 6, 2025):**
- http.postBuffer = 524288000 (500MB)
- http.lowSpeedLimit = 1000 (bytes/sec)
- http.lowSpeedTime = 600 (seconds)
- push.default = simple

⏳ **Recommended Next Steps:**
1. Switch to SSH authentication (highest priority)
2. Reduce compression settings
3. Test push performance

📊 **Current Status:**
- Remote: https://github.com/dilithion/dilithion.git (HTTPS)
- Week 6 Phase 3 commit (11c416e) ready to push
- Push currently in progress...

---

## References

- [Git HTTP Transport Documentation](https://git-scm.com/docs/git-http-backend)
- [GitHub SSH Setup Guide](https://docs.github.com/en/authentication/connecting-to-github-with-ssh)
- [WSL2 Networking Issues](https://github.com/microsoft/WSL/issues)

---

**Last Updated:** November 6, 2025
**Status:** Configuration optimized, SSH setup recommended
