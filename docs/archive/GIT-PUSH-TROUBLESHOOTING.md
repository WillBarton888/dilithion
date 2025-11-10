# Git Push Troubleshooting Guide

## Problem: Git Push Hangs Indefinitely in WSL

**Symptoms:**
- `git push` command hangs with no output
- Background push processes never complete
- No error messages displayed

**Root Cause:**
Git is trying to prompt for credentials in a non-interactive shell, causing the command to hang waiting for input that never comes.

---

## ✅ Solution: Configure Windows Git Credential Manager

### One-Time Setup

Run this command in WSL to configure Git to use Windows credential manager:

```bash
git config --global credential.helper '/mnt/c/Program\ Files/Git/mingw64/bin/git-credential-manager.exe'
```

**What this does:**
- Tells WSL Git to use Windows Git Credential Manager for authentication
- Windows credential manager caches your GitHub credentials securely
- No more credential prompts in WSL

---

## Safe Push Script

Use the provided `git-push-safe.sh` script for all pushes:

```bash
# Make executable (one-time)
chmod +x git-push-safe.sh

# Usage
./git-push-safe.sh origin branch-name

# Examples
./git-push-safe.sh origin main
./git-push-safe.sh origin week7-fuzzing-enhancements
./git-push-safe.sh -u origin feature-branch
```

**Script features:**
- ✅ Automatically configures credential helper if missing
- ✅ Uses `GIT_TERMINAL_PROMPT=0` to prevent hanging
- ✅ 30-second timeout as safety net
- ✅ Clear error messages if push fails
- ✅ Supports all standard git push options

---

## Alternative Methods

### Method 1: GitHub CLI (Recommended for automation)

```bash
# Install GitHub CLI
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install gh

# Authenticate
gh auth login

# Push using gh (never hangs)
gh repo view  # Verify authentication
git push origin branch-name  # Now uses gh credentials
```

### Method 2: Personal Access Token (PAT)

1. Create PAT on GitHub:
   - Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Generate new token with `repo` scope
   - Copy the token (shown only once!)

2. Configure Git to use PAT:
   ```bash
   # Store credentials (one-time, will prompt for username/token)
   git config --global credential.helper store
   git push origin main
   # Enter username: YourGitHubUsername
   # Password: paste_your_PAT_here
   ```

3. Credentials are stored in `~/.git-credentials`

**Security Note:** PAT is stored in plain text with `credential.helper store`. Use Windows Credential Manager (Method 1) for better security.

---

## Testing Your Setup

Run these commands to verify everything works:

```bash
# 1. Check credential helper is configured
git config --global credential.helper
# Should output: /mnt/c/Program\ Files/Git/mingw64/bin/git-credential-manager.exe

# 2. Test push with no-prompt mode
cd /path/to/repo
GIT_TERMINAL_PROMPT=0 timeout 10 git push origin branch-name

# If it fails immediately → credentials not cached
# If it succeeds → perfect! ✅
# If it hangs → credential helper not working, try Method 2 (PAT)
```

---

## Troubleshooting Push Failures

### Error: "fatal: could not read Username"
**Cause:** No credentials cached
**Fix:** Run `git push` once in Windows Git Bash to cache credentials, then try WSL again

### Error: "fatal: Authentication failed"
**Cause:** Cached credentials are invalid/expired
**Fix:**
1. Clear credentials: `git credential-manager delete https://github.com`
2. Push again in Windows Git Bash to re-authenticate

### Error: "timeout after 30 seconds"
**Cause:** Credential manager trying to show GUI prompt
**Fix:** Use Method 2 (PAT) instead for non-interactive environments

---

## Best Practices for Dilithion Project

### For Claude Code (automated pushes):
```bash
# Always use the safe push script
./git-push-safe.sh origin branch-name

# Or use explicit environment variable
GIT_TERMINAL_PROMPT=0 timeout 30 git push origin branch-name
```

### For manual pushes:
```bash
# In WSL (preferred)
git push origin branch-name  # Uses Windows credential manager

# In Windows Git Bash (fallback)
# Open Git Bash, navigate to repo, push normally
```

### For CI/CD (GitHub Actions):
```yaml
# Use GITHUB_TOKEN (automatically provided)
- name: Push changes
  run: |
    git config --global user.name "github-actions[bot]"
    git config --global user.email "github-actions[bot]@users.noreply.github.com"
    git push
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Summary

**Current Configuration (as of Nov 6, 2025):**
- ✅ WSL Git configured to use Windows Git Credential Manager
- ✅ Credentials cached from previous Windows Git usage
- ✅ `git-push-safe.sh` script created for reliable pushes
- ✅ `GIT_TERMINAL_PROMPT=0` prevents hanging

**To push safely going forward:**
```bash
./git-push-safe.sh origin your-branch
```

**If push still hangs:**
1. Kill the process: `pkill -f "git push"`
2. Check credentials: `git config --global credential.helper`
3. Try pushing from Windows Git Bash once to refresh credentials
4. Use `GIT_TERMINAL_PROMPT=0 timeout 30 git push ...` as fallback

---

**Last Updated:** November 6, 2025
**Author:** Claude (with human guidance)
**Tested on:** WSL 2 (Ubuntu) + Windows Git 2.x
