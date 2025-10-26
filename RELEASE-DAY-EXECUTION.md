# Release Day Execution - Quick Reference
**When genesis mining completes, follow these steps in order**

---

## ⚡ IMMEDIATE ACTIONS (When Mining Completes)

### Step 1: Verify Mining Success (2 minutes)
```bash
# Check output shows:
# "Verification passed! Genesis block is valid."

# Record these values:
NONCE=[value from output]
HASH=[value from output]
HASHES_TRIED=[value from output]
```

### Step 2: Update Genesis Header (1 minute)
```bash
# Edit src/node/genesis.h
nano src/node/genesis.h

# Change line:
const uint32_t NONCE = 0;
# To:
const uint32_t NONCE = [NONCE_VALUE];
```

### Step 3: Rebuild Binaries (5 minutes)
```bash
wsl bash -c "cd /mnt/c/Users/will/dilithion && make clean && make"
```

### Step 4: Verify Genesis Block (1 minute)
```bash
wsl bash -c "cd /mnt/c/Users/will/dilithion && ./genesis_gen"
# Should show correct nonce and hash
```

### Step 5: Commit Genesis Block (2 minutes)
```bash
git add src/node/genesis.h
git commit -m "Add mined genesis block for mainnet launch

Genesis Block:
- Timestamp: 1767225600 (Jan 1, 2026 00:00:00 UTC)
- Nonce: $NONCE
- Hash: $HASH
- Hashes Tried: $HASHES_TRIED

Verified with CheckProofOfWork() - ready for mainnet launch."

git tag v1.0.0-genesis
git push origin standalone-implementation
git push origin v1.0.0-genesis
```

**Elapsed Time: ~11 minutes**

---

## 🔨 BUILD & PACKAGE (30-60 minutes)

### Step 6: Build Release Package
```bash
chmod +x build-release.sh
wsl bash -c "cd /mnt/c/Users/will/dilithion && ./build-release.sh v1.0.0"
```

Expected output:
- `releases/v1.0.0/dilithion-v1.0.0-linux-x64.tar.gz`
- `releases/v1.0.0/SHA256SUMS`

### Step 7: Test Release Package (5 minutes)
```bash
cd /tmp
tar -xzf /mnt/c/Users/will/dilithion/releases/v1.0.0/dilithion-v1.0.0-linux-x64.tar.gz
cd dilithion-v1.0.0-linux-x64
./bin/dilithion-node --help
./bin/genesis_gen
```

Verify:
- [  ] Binaries execute
- [  ] Genesis hash matches
- [  ] Documentation included

**Elapsed Time: ~40-60 minutes total**

---

## 🌐 GITHUB RELEASE (10 minutes)

### Step 8: Update Release Notes
```bash
# Edit RELEASE-NOTES-v1.0.0.md
# Update [TO_BE_UPDATED] fields with:
# - Genesis nonce
# - Genesis hash
# - Release date
```

### Step 9: Create GitHub Release
```bash
# Install gh CLI if needed
# sudo apt install gh

# Login
gh auth login

# Create release
gh release create v1.0.0 \
  --title "Dilithion v1.0.0 - Mainnet Launch" \
  --notes-file RELEASE-NOTES-v1.0.0.md \
  releases/v1.0.0/*
```

### Step 10: Verify Release
Visit: https://github.com/WillBarton888/dilithion/releases/tag/v1.0.0

Check:
- [  ] Release is public
- [  ] All files uploaded
- [  ] Download links work
- [  ] Release notes display correctly

**Elapsed Time: ~50-70 minutes total**

---

## 🌍 WEBSITE DEPLOYMENT (10 minutes)

### Step 11: Update Website Download Links
```bash
# Edit website/index.html
# Change download button hrefs from:
href="https://github.com/WillBarton888/dilithion/releases"

# To actual download links:
href="https://github.com/WillBarton888/dilithion/releases/download/v1.0.0/dilithion-v1.0.0-windows-x64.zip"
# etc.
```

### Step 12: Deploy Website
**Option A: GitHub Pages**
```bash
git checkout -b gh-pages
git add website/*
git commit -m "Deploy website v1.0.0"
git push origin gh-pages
```

**Option B: Netlify**
- Drag `website/` folder to netlify.com
- Configure custom domain: dilithion.org

### Step 13: Verify Website
Visit your deployment URL and check:
- [  ] All download links work
- [  ] Countdown shows correct date
- [  ] All pages load
- [  ] Mobile responsive

**Elapsed Time: ~60-80 minutes total**

---

## 📢 ANNOUNCEMENTS (15 minutes)

### Step 14: Social Media

**Twitter:**
```
🚀 Dilithion v1.0.0 Released!

The world's first standalone post-quantum cryptocurrency is ready for mainnet launch!

🔐 CRYSTALS-Dilithium3 (NIST standard)
⚡ RandomX CPU mining
📅 Launch: Jan 1, 2026

Download: https://github.com/WillBarton888/dilithion/releases

#Dilithion #PostQuantum #Crypto
```

**Reddit (r/dilithion, r/cryptocurrency):**
Title: "Dilithion v1.0.0 Released - First Post-Quantum Cryptocurrency Ready for Mainnet"

Body: Link to release notes

### Step 15: Update README
```bash
# Edit README.md
# Add release badge
# Update status from "Pre-release" to "Released"
# Add download links

git add README.md
git commit -m "Update README for v1.0.0 release"
git push
```

**Elapsed Time: ~75-95 minutes total**

---

## 🎯 FINAL CHECKLIST

Before announcing widely:
- [  ] Genesis block verified
- [  ] Binaries built and tested
- [  ] GitHub release published
- [  ] Website deployed
- [  ] Download links work
- [  ] Documentation updated
- [  ] Social media posted
- [  ] Team notified

---

## 🚨 IF SOMETHING GOES WRONG

### Build Fails
```bash
# Clean everything
make clean
rm -rf build/
rm -rf depends/randomx/build
rm -rf depends/dilithium/ref/*.o

# Rebuild dependencies
cd depends/randomx && mkdir build && cd build && cmake .. && make
cd ../../dilithium/ref && make

# Try again
cd ../../..
make
```

### GitHub Release Fails
```bash
# Delete and retry
gh release delete v1.0.0
gh release create v1.0.0 ...
```

### Website Deployment Fails
- Revert changes
- Test locally first
- Check DNS settings
- Verify hosting service

---

## 📞 EMERGENCY CONTACTS

If critical issues found after release:
1. Post on GitHub issues
2. Update website with warning
3. Post on all social media
4. Email security@dilithion.org

---

## ⏱️ TIMELINE SUMMARY

| Step | Task | Time |
|------|------|------|
| 1-5 | Genesis verification & commit | 11 min |
| 6-7 | Build & test release | 35-55 min |
| 8-10 | GitHub release | 10 min |
| 11-13 | Website deployment | 10 min |
| 14-15 | Announcements | 15 min |
| **Total** | **End-to-end release** | **~80-100 min** |

**From genesis completion to public release: ~1.5-2 hours**

---

## 🎉 POST-RELEASE (First 24 Hours)

### Monitor
- GitHub release downloads
- Website traffic
- Community feedback
- Bug reports
- Network activity (after Jan 1 launch)

### Respond To
- Questions on social media
- GitHub issues
- Support emails
- Community Discord/Telegram

### Track
- Download statistics
- Community growth
- Media coverage
- Developer interest

---

## ✅ DONE!

Once all steps complete:
- Update RELEASE-CHECKLIST.md with completion status
- Create post-release report
- Plan for v1.0.1 (bug fixes if needed)

**Congratulations! Dilithion v1.0.0 is live!** 🎉

---

*Last Updated: October 26, 2025*
*Ready to execute when genesis mining completes*
