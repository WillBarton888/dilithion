# Codecov Activation - Step-by-Step Guide

**Duration:** 5-10 minutes
**Status:** Ready to activate
**Files Ready:** All Codecov files created and configured

---

## Quick Activation Steps

### Step 1: Create Codecov Account (2 minutes)

1. Open browser and go to: **https://codecov.io/**
2. Click **"Sign Up"** button
3. Click **"Sign up with GitHub"**
4. Click **"Authorize codecov"** when prompted
5. Grant access to the `dilithion` repository when asked

### Step 2: Get Upload Token (2 minutes)

1. Once logged in, you should see the dashboard
2. Navigate to: **https://codecov.io/gh/dilithion/dilithion**
   - Or click "Add Repository" and select `dilithion`
3. Click **"Settings"** (left sidebar)
4. Click **"General"** tab
5. Find **"Repository Upload Token"** section
6. Copy the token (starts with `codecov_` or similar)
   - **IMPORTANT:** Keep this secure! Don't share publicly

### Step 3: Add Token to GitHub Secrets (2 minutes)

1. Open: **https://github.com/dilithion/dilithion/settings/secrets/actions**
2. Click **"New repository secret"**
3. Name: **`CODECOV_TOKEN`** (exactly this, case-sensitive)
4. Value: Paste the token from Step 2
5. Click **"Add secret"**

### Step 4: Commit and Push Changes (2 minutes)

**I can do this for you once the token is added!**

Changes to commit:
- `.github/workflows/ci.yml` (Codecov upload step)
- `codecov.yml` (configuration)
- `README.md` (badge update)
- `docs/CODECOV-SETUP.md` (setup guide)
- `docs/COVERAGE.md` (documentation update)
- All Track B files (test improvements)

### Step 5: Verify Activation (2 minutes)

1. After pushing, go to: **https://github.com/dilithion/dilithion/actions**
2. Wait for the "Coverage" job to complete
3. Check for **"✅ Upload successful"** in the Codecov upload step
4. Go to: **https://codecov.io/gh/dilithion/dilithion**
5. You should see coverage data appearing
6. Check README badge at: **https://github.com/dilithion/dilithion**
   - Badge should show coverage percentage

---

## What To Tell Me

**After completing Steps 1-3, tell me:**

1. ✅ "Token added to GitHub Secrets" - Then I'll commit and push
2. Or if you encounter any issues, describe them

**After Step 4 (after I push), check:**

1. GitHub Actions shows coverage job succeeded
2. Codecov dashboard shows data
3. README badge displays percentage

---

## Troubleshooting

**Problem: Can't find upload token**
- Look for "Repository Upload Token" or "Upload Token" in Settings → General
- It may also be under Settings → YAML or Settings → Badge

**Problem: Token doesn't work**
- Make sure it's added as `CODECOV_TOKEN` (exact name)
- Check there are no extra spaces before/after the token
- Regenerate token if needed and update secret

**Problem: Upload fails in CI**
- Check GitHub Actions logs for error message
- Verify token is not expired
- Verify token has correct permissions

---

## Ready to Proceed?

**Complete Steps 1-3 above, then tell me:**
- "Codecov token added" or "Token is ready"

**Then I will:**
1. Commit all changes with proper commit message
2. Push to GitHub
3. Monitor the CI run
4. Verify Codecov receives data
5. Confirm badge is working
6. Then proceed to Option 2 (Track B execution)

---

**Estimated Time:** 5-10 minutes for Steps 1-3, then I handle the rest

**Next:** After Codecov activated → Track B difficulty validation → Week 4 Days 3-5
