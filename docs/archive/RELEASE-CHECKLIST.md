# Release Checklist - Dilithion v1.0.0
**Status:** Ready to execute when genesis mining completes

---

## Phase 1: Genesis Block Completion ⏳ IN PROGRESS

- [x] Fix critical bugs (4 bugs fixed)
- [x] Build test binaries
- [ ] **Complete genesis mining** ← CURRENT STEP
- [ ] Verify CheckProofOfWork() passes
- [ ] Record nonce and hash

---

## Phase 2: Mainnet Genesis Block

After test mining completes:

### Step 1: Update Genesis Header
```bash
# Edit src/node/genesis.h
# Update: const uint32_t NONCE = [mined_value];
```

### Step 2: Rebuild with Genesis
```bash
cd /mnt/c/Users/will/dilithion
make clean
make dilithion-node
make genesis_gen
```

### Step 3: Verify Genesis Hash
```bash
./genesis_gen
# Should display valid genesis block with mined nonce
```

### Step 4: Commit Genesis Block
```bash
git add src/node/genesis.h
git commit -m "Add mined genesis block for mainnet launch

Genesis Block:
- Timestamp: 1767225600 (Jan 1, 2026 00:00:00 UTC)
- Nonce: [NONCE_VALUE]
- Hash: [HASH_VALUE]
- Target: 0x1d00ffff

Verified with CheckProofOfWork() - ready for mainnet launch.

🤖 Generated with Claude Code

Co-Authored-By: Claude <noreply@anthropic.com>"

git tag v1.0.0-genesis
git push origin standalone-implementation
git push origin v1.0.0-genesis
```

---

## Phase 3: Release Builds

### Step 1: Run Release Build Script
```bash
chmod +x build-release.sh
./build-release.sh v1.0.0
```

**Expected output:**
- `releases/v1.0.0/dilithion-v1.0.0-linux-x64.tar.gz`
- `releases/v1.0.0/SHA256SUMS`

### Step 2: Build for Other Platforms (if available)

**Windows (from WSL/Linux):**
```bash
# Cross-compile or build on Windows machine
# Output: dilithion-v1.0.0-windows-x64.zip
```

**macOS (requires Mac):**
```bash
# Build on macOS machine
# Output: dilithion-v1.0.0-macos-universal.tar.gz
```

### Step 3: Test Release Packages
```bash
# Extract and test on clean system
cd /tmp
tar -xzf dilithion-v1.0.0-linux-x64.tar.gz
cd dilithion-v1.0.0-linux-x64
./bin/dilithion-node --help
./bin/genesis_gen
```

**Verify:**
- [ ] Binaries execute without errors
- [ ] Genesis hash matches expected value
- [ ] Help text displays correctly
- [ ] All documentation files included

---

## Phase 4: GitHub Release

### Step 1: Create Release Draft
```bash
# Using GitHub CLI (gh)
gh release create v1.0.0 \
  --title "Dilithion v1.0.0 - Mainnet Launch" \
  --notes-file RELEASE-NOTES-v1.0.0.md \
  --draft
```

### Step 2: Upload Release Assets
```bash
cd releases/v1.0.0
gh release upload v1.0.0 \
  dilithion-v1.0.0-linux-x64.tar.gz \
  dilithion-v1.0.0-windows-x64.zip \
  dilithion-v1.0.0-macos-universal.tar.gz \
  SHA256SUMS
```

### Step 3: Publish Release
```bash
gh release edit v1.0.0 --draft=false
```

---

## Phase 5: Website Update

### Step 1: Update Download Links
Edit `website/index.html`:
```html
<!-- Change from "Coming Soon" to actual download links -->
<a href="https://github.com/WillBarton888/dilithion/releases/download/v1.0.0/dilithion-v1.0.0-windows-x64.zip"
   class="btn btn-download">Download for Windows</a>

<a href="https://github.com/WillBarton888/dilithion/releases/download/v1.0.0/dilithion-v1.0.0-linux-x64.tar.gz"
   class="btn btn-download">Download for Linux</a>

<a href="https://github.com/WillBarton888/dilithion/releases/download/v1.0.0/dilithion-v1.0.0-macos-universal.tar.gz"
   class="btn btn-download">Download for macOS</a>
```

### Step 2: Deploy Website
```bash
# Copy website files to hosting
# Option 1: GitHub Pages
git checkout -b gh-pages
git add website/*
git commit -m "Deploy website v1.0.0"
git push origin gh-pages

# Option 2: Netlify
# Drag & drop website/ folder to netlify.com

# Option 3: Your own hosting
scp -r website/* user@dilithion.org:/var/www/dilithion/
```

### Step 3: Verify Website
- [ ] Visit https://dilithion.org (or your URL)
- [ ] Test all download links work
- [ ] Verify countdown timer shows correct date
- [ ] Check mobile responsiveness
- [ ] Test all navigation links

---

## Phase 6: Community Announcement

### Step 1: Prepare Announcement
**Subject:** Dilithion v1.0.0 Released - Mainnet Launches January 1, 2026

**Key Points:**
- First post-quantum cryptocurrency ready for mainnet
- CRYSTALS-Dilithium3 signatures (NIST standard)
- Fair launch - no premine, no ICO
- CPU mining with RandomX
- Download links available

### Step 2: Post Announcements
- [ ] Twitter @DilithionCoin
- [ ] Reddit r/dilithion, r/cryptocurrency
- [ ] Discord (if created)
- [ ] Telegram (if created)
- [ ] GitHub release notes
- [ ] Email list (if available)

### Step 3: Technical Communities
- [ ] Bitcoin Talk forum
- [ ] Crypto development forums
- [ ] Post-quantum cryptography communities
- [ ] Mining communities

---

## Phase 7: Infrastructure Setup

### Step 1: Deploy Seed Nodes (3 servers)
Follow: `INFRASTRUCTURE-SETUP-GUIDE.md`

**Locations:**
- seed1.dilithion.org (New York)
- seed2.dilithion.org (London)
- seed3.dilithion.org (Singapore)

### Step 2: Configure DNS
```
A Record: seed1.dilithion.org → [IP1]
A Record: seed2.dilithion.org → [IP2]
A Record: seed3.dilithion.org → [IP3]
```

### Step 3: Start Seed Nodes
```bash
# On each server
sudo systemctl start dilithion
sudo systemctl enable dilithion
```

### Step 4: Verify Network
```bash
# Check peers
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"getpeerinfo","id":1}'
```

---

## Phase 8: Monitoring & Support

### Launch Day Checklist (Jan 1, 2026)
- [ ] All seed nodes running
- [ ] Website accessible
- [ ] Downloads working
- [ ] Mining pool (if applicable) ready
- [ ] Block explorer (if available) live
- [ ] Support channels monitored
- [ ] Backup systems ready

### Monitor:
- Network hash rate
- Block production (1 block every 4 minutes)
- Peer connections
- Website traffic
- Download counts
- Community feedback

### Support Channels:
- GitHub issues
- security@dilithion.org
- team@dilithion.org
- Discord support channel
- Reddit community

---

## Rollback Plan (Emergency)

If critical issues found:
1. Announce halt via all channels
2. Stop all seed nodes
3. Fix issues
4. Create v1.0.1 with fixes
5. New genesis block (if required)
6. Re-launch with clear communication

---

## Success Criteria

**Release v1.0.0 considered successful when:**
- [ ] Genesis block mined and verified
- [ ] Binaries built for all platforms
- [ ] GitHub release published
- [ ] Website deployed with download links
- [ ] At least 3 seed nodes operational
- [ ] Network accepting blocks
- [ ] Miners can connect and mine
- [ ] No critical bugs in first 48 hours

---

## Post-Launch Tasks (Week 1)

### Immediate (24 hours)
- [ ] Monitor network stability
- [ ] Respond to community questions
- [ ] Fix any critical bugs
- [ ] Update documentation as needed

### Short-term (Week 1)
- [ ] Publish mining guide
- [ ] Create video tutorials
- [ ] List on CoinGecko/CoinMarketCap
- [ ] Contact mining pools
- [ ] Reach out to exchanges

### Medium-term (Month 1)
- [ ] Professional security audit
- [ ] Block explorer development
- [ ] Mobile wallet development
- [ ] Exchange listings
- [ ] Community growth

---

## Current Status

**Completed:**
- ✅ Critical bug fixes
- ✅ Code quality improvements
- ✅ Website development
- ✅ Documentation
- ✅ Release automation

**In Progress:**
- ⏳ Genesis block mining (17.71M+ hashes)

**Blocked Until Genesis Complete:**
- Mainnet builds
- GitHub release
- Website deployment
- Infrastructure setup

**Estimated Time to Release:**
- Genesis mining: Unknown (probabilistic)
- After genesis: 2-4 hours
- Total: Ready same day genesis completes

---

**Last Updated:** October 26, 2025
**Next Review:** After genesis mining completes
**Status:** On track for January 1, 2026 launch
