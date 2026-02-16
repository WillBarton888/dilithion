# Coverity Scan Setup Guide

**Phase 9.3: Static Analysis Integration**

This guide explains how to set up Coverity Scan for Dilithion to enable automated static analysis scans.

---

## Overview

Coverity Scan is a free static analysis service for open-source projects. It helps find defects and security vulnerabilities in code.

**Benefits:**
- Free for open-source projects
- Automated scans on every commit
- Detailed defect reports
- Integration with GitHub

---

## Prerequisites

1. **Open Source Project:** ✅ Dilithion is open source
2. **GitHub Repository:** ✅ https://github.com/dilithion/dilithion
3. **Coverity Account:** ⏳ Need to create

---

## Step 1: Create Coverity Account

1. **Visit Coverity Scan:**
   - Go to https://scan.coverity.com/
   - Click "Sign Up" or "Register"

2. **Register with GitHub:**
   - Use "Sign in with GitHub" option
   - Authorize Coverity to access your GitHub account

3. **Create Project:**
   - Click "Add a Project"
   - Project name: `dilithion`
   - Repository URL: `https://github.com/dilithion/dilithion`
   - Language: C/C++
   - Build system: Make

4. **Get Token:**
   - After creating project, go to project settings
   - Copy your "Coverity Token" (keep it secret!)
   - Copy your email address used for registration

---

## Step 2: Configure GitHub Secrets

1. **Go to GitHub Repository:**
   - Navigate to: https://github.com/dilithion/dilithion/settings/secrets/actions

2. **Add Secrets:**
   - Click "New repository secret"
   - Add `COVERITY_TOKEN`:
     - Name: `COVERITY_TOKEN`
     - Value: (paste your Coverity token)
   - Add `COVERITY_EMAIL`:
     - Name: `COVERITY_EMAIL`
     - Value: (your Coverity account email)

3. **Verify Secrets:**
   - Secrets should appear in the list
   - They will be encrypted and only accessible in CI workflows

---

## Step 3: Verify CI Workflow

The Coverity scan job is already configured in `.github/workflows/ci.yml`.

**Job Configuration:**
- Runs on: `main` branch pushes only
- Condition: Automatically skips if secrets not set
- Builds: `dilithion-node` with Coverity instrumentation
- Submits: Results to Coverity Scan automatically

**To Test:**
1. Push a commit to `main` branch
2. Check GitHub Actions tab
3. Look for "Coverity Static Analysis" job
4. If secrets are set, it will run and submit

---

## Step 4: View Results

1. **Coverity Dashboard:**
   - Go to https://scan.coverity.com/projects/dilithion
   - View defect reports
   - See scan history

2. **Defect Reports:**
   - Categorized by severity
   - Includes file location and line numbers
   - Provides fix suggestions

3. **Email Notifications:**
   - Receive emails when new defects are found
   - Configure in Coverity project settings

---

## Troubleshooting

### Job Doesn't Run

**Problem:** Coverity job doesn't appear in GitHub Actions

**Solutions:**
- Check if you're on `main` branch
- Verify secrets are set correctly
- Check workflow file syntax

### Build Fails

**Problem:** Coverity build fails

**Solutions:**
- Check build logs in GitHub Actions
- Verify dependencies are installed
- Test build locally first

### Submission Fails

**Problem:** Scan submission fails

**Solutions:**
- Verify `COVERITY_TOKEN` is correct
- Check `COVERITY_EMAIL` matches account
- Ensure project name matches Coverity project

### No Results in Dashboard

**Problem:** Scans run but no results appear

**Solutions:**
- Wait a few minutes (processing takes time)
- Check Coverity project name matches
- Verify token has correct permissions

---

## Manual Submission (Alternative)

If CI integration doesn't work, you can submit manually:

1. **Download Coverity Build Tool:**
   ```bash
   curl -sSL https://scan.coverity.com/download/linux64 \
     --form token=YOUR_TOKEN \
     --form project=dilithion \
     --form platform=linux64 \
     -o cov-analysis.tar.gz
   tar -xzf cov-analysis.tar.gz
   ```

2. **Build with Coverity:**
   ```bash
   export PATH=$PATH:$(pwd)/cov-analysis-linux64/bin
   cov-build --dir cov-int make dilithion-node -j$(nproc)
   ```

3. **Analyze:**
   ```bash
   cov-analyze --dir cov-int --all --enable-constraint-fpp
   ```

4. **Submit:**
   ```bash
   tar czf cov-int.tar.gz cov-int
   curl --form token=YOUR_TOKEN \
        --form email=YOUR_EMAIL \
        --form file=@cov-int.tar.gz \
        --form version="$(git rev-parse --short HEAD)" \
        --form description="Manual scan" \
        https://scan.coverity.com/builds?project=dilithion
   ```

---

## Best Practices

1. **Regular Scans:**
   - Scans run automatically on every push to `main`
   - Review results weekly
   - Fix high-severity defects promptly

2. **Defect Management:**
   - Prioritize security-related defects
   - Fix false positives (mark as intentional)
   - Track defect trends over time

3. **Team Collaboration:**
   - Share Coverity dashboard access
   - Assign defects to team members
   - Document fixes in commit messages

---

## References

- **Coverity Scan:** https://scan.coverity.com/
- **Documentation:** https://scan.coverity.com/help
- **CI Integration:** See `.github/workflows/ci.yml` (coverity-scan job)

---

## Status

**Current Status:** ⏳ **READY FOR SETUP**

- ✅ CI workflow configured
- ✅ Build script ready
- ⏳ Account creation pending
- ⏳ Secrets configuration pending

**Next Steps:**
1. Create Coverity account
2. Configure GitHub secrets
3. Test first scan
4. Review results

---

**Last Updated:** December 2025

