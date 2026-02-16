# Dilithion Infrastructure Setup Guide
**Target:** Testnet Launch by November 10, 2025
**Timeline:** 2 weeks intensive setup
**Goal:** Production-ready infrastructure for January 1, 2026 launch

---

## Table of Contents

1. [Phase 1: Local Build & Genesis Block](#phase-1-local-build--genesis-block)
2. [Phase 2: VPS Seed Node Setup](#phase-2-vps-seed-node-setup)
3. [Phase 3: Testnet Deployment](#phase-3-testnet-deployment)
4. [Phase 4: Testing & Validation](#phase-4-testing--validation)
5. [Phase 5: Production Preparation](#phase-5-production-preparation)

---

## Phase 1: Local Build & Genesis Block

**Timeline:** Days 1-2 (October 27-28, 2025)
**Location:** Your local development machine

### Step 1.1: Rebuild Binaries with Security Fixes

**Prerequisites:**
- ✅ Development machine with g++ compiler
- ✅ All dependencies installed (LevelDB, RandomX, Dilithium)
- ✅ Latest code from standalone-implementation branch

**Commands:**

```bash
# Navigate to project directory
cd C:\Users\will\dilithion

# Ensure we're on the right branch
git checkout standalone-implementation

# Clean previous builds
make clean

# Rebuild RandomX (if needed)
cd depends/randomx/build
cmake ..
make
cd ../../..

# Rebuild Dilithium (if needed)
cd depends/dilithium/ref
make clean
make
cd ../../..

# Build all binaries
make dilithion-node
make genesis_gen
make dilithion-miner

# Build test suites
make tests
```

**Expected Results:**
```
✅ dilithion-node compiled successfully
✅ genesis_gen compiled successfully
✅ dilithion-miner compiled successfully
✅ Test executables built
```

**Verify Security Fixes Included:**
```bash
# Check that rate limiter is linked
grep -r "CRateLimiter" dilithion-node

# Check binary size (should be slightly larger)
ls -lh dilithion-node
# Expected: ~600KB or larger (includes rate limiting code)
```

**⚠️ CRITICAL:** Do NOT proceed until all binaries compile without errors.

### Step 1.2: Run Test Suite

**Execute all tests:**

```bash
# Run Phase 1 tests
./build/phase1_test
# Expected: All tests PASSED

# Run wallet tests
./build/wallet_tests
# Expected: All tests PASSED

# Run RPC tests
./build/rpc_tests
# Expected: All tests PASSED

# Run crypter tests
./crypter_tests
# Expected: All tests PASSED

# Run integration tests
./build/integration_tests
# Expected: All tests PASSED
```

**Pass Criteria:**
- ✅ ALL tests must pass
- ❌ If ANY test fails, fix before proceeding

### Step 1.3: Mine Genesis Block

**CRITICAL STEP - This is permanent for the network**

**Genesis Block Configuration:**
```
Timestamp: 1767225600 (Jan 1, 2026 00:00:00 UTC)
Difficulty: 0x1d00ffff
Coinbase: "The Guardian 01/Jan/2026: Quantum computing advances
           threaten cryptocurrency security - Dilithion launches
           with post-quantum protection for The People's Coin"
```

**Mining Process:**

```bash
# Start genesis mining
./genesis_gen --mine

# Expected output:
# Mining genesis block...
# Target: 00000000ffff0000000000000000000000000000000000000000000000000000
# This may take a while...
# Hashes: 10000
# Hashes: 20000
# ... (continues until found)
#
# Genesis block found!
# Nonce: 2083236893 (example - will be different)
# Hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
```

**⏱️ Expected Time:** 30 minutes to 6 hours (varies with CPU)

**IMPORTANT:** Write down the nonce and hash immediately!

**Update Genesis Code:**

```bash
# Edit src/node/genesis.h
# Find the line with NONCE and update it:
const uint32_t NONCE = 2083236893;  // Replace with YOUR found nonce
```

**Verify Genesis Block:**

```bash
# Rebuild genesis_gen
make genesis_gen

# Verify the hash matches
./genesis_gen

# Expected output:
# Genesis Block:
# Hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
# (Should match the hash from mining)
```

**Commit Genesis Block:**

```bash
git add src/node/genesis.h
git commit -m "Add mined genesis block for mainnet launch

Genesis Block Details:
- Timestamp: 1767225600 (Jan 1, 2026 00:00:00 UTC)
- Nonce: 2083236893
- Hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
- Difficulty: 0x1d00ffff

🤖 Generated with Claude Code

Co-Authored-By: Claude <noreply@anthropic.com>"

git tag v1.0.0-genesis
git push origin standalone-implementation
git push origin v1.0.0-genesis
```

**✅ Phase 1 Complete Checklist:**
- [ ] All binaries rebuilt with security fixes
- [ ] All tests passing
- [ ] Genesis block mined
- [ ] Genesis nonce committed to code
- [ ] Genesis hash verified
- [ ] Tagged v1.0.0-genesis

---

## Phase 2: VPS Seed Node Setup

**Timeline:** Days 3-5 (October 29-31, 2025)
**Cost:** ~$30-50/month for 3 nodes

### Step 2.1: Choose VPS Provider

**Recommended Providers:**

**Option A: DigitalOcean** (Recommended - Simple, Reliable)
- Cost: $6/month per droplet
- Regions: NYC, London, Singapore
- Setup: 5 minutes per node
- Website: https://www.digitalocean.com

**Option B: Vultr** (Good Alternative)
- Cost: $6/month per instance
- Regions: Global coverage
- Setup: Similar to DigitalOcean
- Website: https://www.vultr.com

**Option C: Linode (Akamai)** (Enterprise-Grade)
- Cost: $5/month per linode
- Regions: Global
- Setup: Slightly more complex
- Website: https://www.linode.com

**Recommended Configuration (per node):**
```
OS: Ubuntu 22.04 LTS (64-bit)
RAM: 2GB minimum
CPU: 1 vCPU (2 recommended)
Storage: 25GB SSD minimum
Bandwidth: 2TB/month
```

### Step 2.2: Provision 3 Seed Nodes

**Geographic Distribution (Recommended):**

**Seed Node 1: North America**
- Region: New York or San Francisco
- Hostname: seed1.dilithion.org
- Purpose: Primary seed, US timezone coverage

**Seed Node 2: Europe**
- Region: London or Frankfurt
- Hostname: seed2.dilithion.org
- Purpose: EU coverage, 24-hour redundancy

**Seed Node 3: Asia-Pacific**
- Region: Singapore or Tokyo
- Hostname: seed3.dilithion.org
- Purpose: APAC coverage, global reach

**Provisioning Steps (DigitalOcean Example):**

1. **Create Account:**
   - Go to digitalocean.com
   - Sign up / Log in
   - Add payment method

2. **Create First Droplet (Seed 1 - NYC):**
   - Click "Create" → "Droplets"
   - Choose Ubuntu 22.04 LTS
   - Plan: Basic ($6/month - 1GB RAM)
   - Region: New York 1
   - Add SSH key (create if needed)
   - Hostname: dilithion-seed1
   - Click "Create Droplet"

3. **Repeat for Seed 2 (London):**
   - Same process
   - Region: London
   - Hostname: dilithion-seed2

4. **Repeat for Seed 3 (Singapore):**
   - Same process
   - Region: Singapore
   - Hostname: dilithion-seed3

**Record IP Addresses:**
```
Seed 1 (NYC):       xxx.xxx.xxx.xxx
Seed 2 (London):    xxx.xxx.xxx.xxx
Seed 3 (Singapore): xxx.xxx.xxx.xxx
```

### Step 2.3: Configure DNS for Seed Nodes

**Webcentral DNS Setup:**

```
# Login to Webcentral control panel
# Navigate to DNS management for dilithion.org

# Add A records:
seed1.dilithion.org  →  [Seed 1 IP]
seed2.dilithion.org  →  [Seed 2 IP]
seed3.dilithion.org  →  [Seed 3 IP]

# Set TTL: 300 seconds (5 minutes)
```

**Verify DNS Propagation:**
```bash
# Wait 5-10 minutes, then test:
nslookup seed1.dilithion.org
nslookup seed2.dilithion.org
nslookup seed3.dilithion.org

# Should return the correct IP addresses
```

### Step 2.4: Install Dilithion on Each Seed Node

**Repeat these steps for ALL 3 seed nodes:**

**Connect via SSH:**
```bash
ssh root@[SEED_IP]
```

**Update System:**
```bash
apt update
apt upgrade -y
apt install -y build-essential git cmake libleveldb-dev htop
```

**Create Dilithion User:**
```bash
adduser dilithion
usermod -aG sudo dilithion
su - dilithion
```

**Install Dependencies:**
```bash
cd ~
git clone https://github.com/dilithion/dilithion.git
cd dilithion
git checkout v1.0.0-genesis  # Use the genesis tag
```

**Build RandomX:**
```bash
cd depends/randomx
mkdir build && cd build
cmake ..
make -j2
cd ~/dilithion
```

**Build Dilithium:**
```bash
cd depends/dilithium/ref
make -j2
cd ~/dilithion
```

**Build Dilithion Node:**
```bash
make dilithion-node
```

**Verify Build:**
```bash
./dilithion-node --version
# Expected: Dilithion v1.0.0 or similar
```

**Configure Firewall:**
```bash
# Allow P2P port
sudo ufw allow 8333/tcp
# Allow SSH
sudo ufw allow 22/tcp
# Enable firewall
sudo ufw enable
```

**Create Systemd Service:**
```bash
sudo nano /etc/systemd/system/dilithion.service
```

**Service File Content:**
```ini
[Unit]
Description=Dilithion Cryptocurrency Node
After=network.target

[Service]
Type=simple
User=dilithion
WorkingDirectory=/home/dilithion/dilithion
ExecStart=/home/dilithion/dilithion/dilithion-node --datadir=/home/dilithion/.dilithion
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Enable and Start Service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable dilithion
sudo systemctl start dilithion
```

**Verify Running:**
```bash
sudo systemctl status dilithion
# Should show "active (running)"

# Check logs
sudo journalctl -u dilithion -f
```

**✅ Repeat for all 3 seed nodes**

### Step 2.5: Update Client Code with Seed Nodes

**Edit source code to include seed nodes:**

```bash
# On local machine
cd C:\Users\will\dilithion
```

**Check if seed nodes are hardcoded in net/dns.cpp or similar:**
```bash
grep -r "seed" src/net/
```

**If needed, add seed nodes to code:**
```cpp
// In src/net/dns.cpp or src/net/net.cpp
const std::vector<std::string> DNS_SEEDS = {
    "seed1.dilithion.org",
    "seed2.dilithion.org",
    "seed3.dilithion.org"
};
```

**Rebuild and redeploy if code changed.**

**✅ Phase 2 Complete Checklist:**
- [ ] 3 VPS instances provisioned
- [ ] DNS records configured for seed1/2/3.dilithion.org
- [ ] Dilithion installed on all 3 nodes
- [ ] Systemd services configured
- [ ] Firewalls configured (port 8333 open)
- [ ] All nodes running and logging
- [ ] Client code updated with seed nodes (if needed)

---

## Phase 3: Testnet Deployment

**Timeline:** Days 6-7 (November 1-2, 2025)
**Goal:** Launch private testnet for validation

### Step 3.1: Create Testnet Genesis Block

**Option A: Same Genesis as Mainnet**
- Use the already-mined genesis block
- Testnet validates actual launch configuration
- **Recommended** for final testing

**Option B: Different Testnet Genesis**
- Mine a separate genesis block
- Allows testing without mainnet data
- Useful for early experimentation

**For our case, use Option A (same genesis)**

### Step 3.2: Launch Testnet

**On each seed node:**

```bash
# Stop the service if running
sudo systemctl stop dilithion

# Clear any existing data
rm -rf /home/dilithion/.dilithion

# Start fresh
sudo systemctl start dilithion

# Monitor logs
sudo journalctl -u dilithion -f
```

**Expected Log Output:**
```
[INFO] Starting Dilithion v1.0.0
[INFO] Data directory: /home/dilithion/.dilithion
[INFO] Loading genesis block...
[INFO] Genesis hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
[INFO] Starting P2P network on port 8333
[INFO] Starting RPC server on port 8332
[INFO] Node ready
```

### Step 3.3: Connect Seed Nodes to Each Other

**Method 1: Manual Connection (Quick Test)**

On Seed 1:
```bash
# Use RPC to connect to Seed 2 and 3
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"addnode","params":["[SEED2_IP]:8333"],"id":1}'

curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"addnode","params":["[SEED3_IP]:8333"],"id":1}'
```

**Method 2: Automatic Discovery (Production)**
- Seed nodes should auto-discover via DNS seeds
- Wait 5-10 minutes for discovery

**Verify Connections:**
```bash
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"getpeerinfo","id":1}'

# Should show 2+ connected peers
```

### Step 3.4: Start Test Mining

**On Seed Node 1 (primary miner):**

```bash
# Start mining with 2 threads
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"startmining","params":["2"],"id":1}'

# Check mining status
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","id":1}'
```

**Expected Mining Output (in logs):**
```
[MINING] Starting mining with 2 threads
[MINING] Hash rate: ~130 H/s
[MINING] Block found! Height: 1, Hash: 0000000abc...
[MINING] Block found! Height: 2, Hash: 0000000def...
```

**On Seed Nodes 2 & 3:**
- Should receive and validate blocks from Seed 1
- Check logs for "Block received" messages

**✅ Phase 3 Complete Checklist:**
- [ ] Testnet launched on all 3 nodes
- [ ] Genesis block loaded correctly
- [ ] Nodes connected to each other
- [ ] P2P communication working
- [ ] Mining started successfully
- [ ] Blocks propagating to all nodes

---

## Phase 4: Testing & Validation

**Timeline:** Days 8-14 (November 3-9, 2025)
**Duration:** 48-hour minimum continuous test

### Step 4.1: Functional Testing

**Test 1: Block Production**
```bash
# Verify consistent block production
# Target: 2-minute average block time

# Check every 10 minutes:
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"getblockcount","id":1}'

# Should increase by ~5 blocks every 10 minutes
```

**Test 2: Wallet Operations**
```bash
# On local machine or a seed node

# Create new address
curl -X POST http://[SEED1_IP]:8332 \
  -d '{"jsonrpc":"2.0","method":"getnewaddress","id":1}'

# Get balance (should be accumulating from mining)
curl -X POST http://[SEED1_IP]:8332 \
  -d '{"jsonrpc":"2.0","method":"getbalance","id":1}'

# Send transaction
curl -X POST http://[SEED1_IP]:8332 \
  -d '{"jsonrpc":"2.0","method":"sendtoaddress","params":["[ADDRESS]","10.0"],"id":1}'
```

**Test 3: P2P Synchronization**
```bash
# Connect a 4th node (your local machine)
./dilithion-node --addnode=seed1.dilithion.org:8333

# Verify it syncs the blockchain
# Should download all blocks from seed nodes
```

**Test 4: Rate Limiting (Security Test)**
```bash
# Attempt to exceed rate limit
for i in {1..70}; do
  curl -X POST http://[SEED1_IP]:8332 \
    -d '{"jsonrpc":"2.0","method":"getbalance","id":'$i'}'
done

# Expected: First 60 succeed, remaining get rate limit error
```

**Test 5: Wallet Encryption**
```bash
# Encrypt wallet
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"encryptwallet","params":["testpassword123"],"id":1}'

# Unlock wallet
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"walletpassphrase","params":["testpassword123","300"],"id":1}'

# Wait 5+ minutes (300 seconds), verify auto-lock
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"sendtoaddress","params":["[ADDR]","1"],"id":1}'
# Should fail with "wallet locked" after timeout
```

### Step 4.2: Stress Testing

**48-Hour Continuous Mining Test:**

```bash
# On all 3 seed nodes, start mining
# Seed 1: 2 threads
# Seed 2: 1 thread
# Seed 3: 1 thread

# Monitor for 48 hours:
# - No crashes
# - Consistent block production
# - Memory usage stable
# - No forks
```

**Metrics to Monitor:**

```bash
# Every hour, collect:
1. Block count
2. Hash rate
3. Peer count
4. Memory usage (htop)
5. Disk usage
6. Network bandwidth
7. Block propagation time
```

**Create monitoring script on seed nodes:**

```bash
nano ~/monitor.sh
```

```bash
#!/bin/bash
while true; do
  echo "=== $(date) ==="
  echo "Block Count:"
  curl -s -X POST http://localhost:8332 \
    -d '{"jsonrpc":"2.0","method":"getblockcount","id":1}' | jq

  echo "Peer Count:"
  curl -s -X POST http://localhost:8332 \
    -d '{"jsonrpc":"2.0","method":"getpeerinfo","id":1}' | jq 'length'

  echo "Mining Info:"
  curl -s -X POST http://localhost:8332 \
    -d '{"jsonrpc":"2.0","method":"getmininginfo","id":1}' | jq

  echo "Memory Usage:"
  free -h | grep Mem

  echo "---"
  sleep 3600  # Every hour
done
```

```bash
chmod +x ~/monitor.sh
nohup ./monitor.sh > monitor.log 2>&1 &
```

### Step 4.3: Issue Tracking

**Create a testing log:**

**C:\Users\will\dilithion\TESTNET-RESULTS.md**

Document:
- Start time
- All issues found
- Performance metrics
- Block times
- Fork incidents
- Crashes
- Memory leaks
- Any anomalies

**Pass Criteria:**
- ✅ 48+ hours continuous operation
- ✅ No crashes
- ✅ Block time average: 1.5-2.5 minutes
- ✅ No persistent forks
- ✅ All RPC methods working
- ✅ Wallet encryption working
- ✅ Rate limiting working
- ✅ Memory usage stable (no leaks)

**✅ Phase 4 Complete Checklist:**
- [ ] 48-hour stress test completed
- [ ] All functional tests passed
- [ ] No critical bugs found
- [ ] Performance metrics documented
- [ ] Issues logged and fixed
- [ ] Network stability confirmed

---

## Phase 5: Production Preparation

**Timeline:** Days 15-21 (November 10-16, 2025)
**Goal:** Finalize for mainnet launch

### Step 5.1: Merge to Main Branch

```bash
cd C:\Users\will\dilithion

# Ensure standalone-implementation is clean
git status
git add -A
git commit -m "Final testnet validation complete"

# Switch to main
git checkout main

# Merge standalone-implementation
git merge standalone-implementation -m "Merge standalone-implementation: Mainnet Launch Ready

Complete implementation with:
- Genesis block mined and validated
- 48+ hour testnet successful
- Security hardening complete (9/10)
- Legal compliance (ToS, Privacy Policy)
- Professional documentation

Ready for January 1, 2026 mainnet launch.

🤖 Generated with Claude Code

Co-Authored-By: Claude <noreply@anthropic.com>"

# Push to GitHub
git push origin main
```

### Step 5.2: Create Release Candidate

```bash
# Tag release candidate
git tag v1.0.0-rc1
git push origin v1.0.0-rc1
```

**Build final binaries on multiple platforms:**

**Linux (Ubuntu 22.04):**
```bash
make clean
make dilithion-node
make dilithion-miner
strip dilithion-node dilithion-miner
tar -czf dilithion-v1.0.0-rc1-linux-x64.tar.gz dilithion-node dilithion-miner
sha256sum dilithion-v1.0.0-rc1-linux-x64.tar.gz > SHA256SUMS
```

**Windows (if cross-compile or native):**
```bash
# Similar process for Windows builds
```

**macOS (if available):**
```bash
# Similar process for macOS builds
```

### Step 5.3: GitHub Release

**Create GitHub release:**
1. Go to https://github.com/dilithion/dilithion/releases
2. Click "Draft a new release"
3. Tag: v1.0.0-rc1
4. Title: "Dilithion v1.0.0-rc1 - Release Candidate"
5. Description:

```markdown
# Dilithion v1.0.0-rc1 - Release Candidate

**⚠️ EXPERIMENTAL SOFTWARE - USE AT YOUR OWN RISK ⚠️**

This is a release candidate for Dilithion v1.0.0, targeting mainnet launch on January 1, 2026.

## What's New in This Release

- ✅ Genesis block mined and validated
- ✅ 48+ hour testnet stress test passed
- ✅ Security hardening (9/10 security score)
- ✅ RPC rate limiting implemented
- ✅ Compiler-proof memory wiping
- ✅ Australian legal compliance (ToS, Privacy Policy)
- ✅ Comprehensive documentation

## Download

- Linux: [dilithion-v1.0.0-rc1-linux-x64.tar.gz]
- Windows: [dilithion-v1.0.0-rc1-windows-x64.zip]
- Source: [Source code (zip)]

## Checksums

See SHA256SUMS file for verification.

## Testing Period

Please help test this release candidate! Report any issues on GitHub.

## Launch Date

**Mainnet Launch:** January 1, 2026 00:00:00 UTC

## Support

- Documentation: https://dilithion.org
- GitHub Issues: https://github.com/dilithion/dilithion/issues
```

6. Upload binaries and checksums
7. Publish release

### Step 5.4: Update Website

**Upload final website to Webcentral:**
```
website/index.html
website/style.css
website/script.js
website/.htaccess
website/Dilithion-Whitepaper-v1.0.pdf
website/terms-of-service.html
website/privacy-policy.html
website/POST-QUANTUM-CRYPTO-COURSE.md
```

**Add download links for binaries**

**Update index.html with:**
- Release candidate download links
- Testnet results
- Launch countdown timer
- Community links (Discord, Twitter)

### Step 5.5: Keep Seed Nodes Running

**Until January 1, 2026:**
- Keep all 3 seed nodes operational
- Monitor daily
- Apply any critical patches
- Maintain uptime > 99%

**Monthly monitoring checklist:**
- [ ] Check disk space
- [ ] Check memory usage
- [ ] Verify nodes connected
- [ ] Check logs for errors
- [ ] Verify DNS resolution
- [ ] Test RPC endpoints

**✅ Phase 5 Complete Checklist:**
- [ ] Code merged to main branch
- [ ] Release candidate tagged
- [ ] Binaries built for all platforms
- [ ] GitHub release published
- [ ] Website updated with downloads
- [ ] Seed nodes running continuously
- [ ] Monitoring in place

---

## Infrastructure Costs Summary

**Monthly Costs:**
```
3 VPS Seed Nodes:     $18-30/month (DigitalOcean/Vultr)
Domain (dilithion.org): Already owned
Email (optional):      $0-10/month
---
TOTAL MONTHLY:         $18-40/month
```

**One-Time Costs:**
```
Initial VPS setup:     $0 (first month may be prorated)
```

**Total to Launch:** ~$20-40/month ongoing

---

## Timeline Summary

```
Day 1-2:   Rebuild binaries, mine genesis block
Day 3-5:   Provision VPS, install Dilithion
Day 6-7:   Launch testnet
Day 8-14:  48-hour stress test + validation
Day 15-21: Production preparation, release candidate
---
TOTAL: 21 days (3 weeks)
```

**Target Completion:** November 16, 2025 (46 days before launch)

---

## Success Criteria

**Infrastructure is ready when:**
- ✅ Genesis block mined and committed
- ✅ 3 seed nodes operational 24/7
- ✅ DNS configured for seed1/2/3.dilithion.org
- ✅ 48+ hour testnet completed successfully
- ✅ All binaries built and tested
- ✅ Release candidate published
- ✅ Website updated with downloads
- ✅ Monitoring in place
- ✅ No critical bugs outstanding

**Then:** Ready for mainnet launch January 1, 2026! 🚀

---

## Next Steps

**Immediate Actions (This Week):**
1. Rebuild binaries on your development machine
2. Run all test suites
3. Mine genesis block
4. Commit and tag genesis block

**Next Week:**
5. Sign up for VPS hosting (DigitalOcean recommended)
6. Provision 3 seed nodes
7. Install Dilithion on all nodes
8. Launch testnet

**Following 2 Weeks:**
9. Run 48-hour stress test
10. Monitor and fix any issues
11. Prepare release candidate
12. Update website

**Launch Day (Jan 1, 2026):**
13. Start seed nodes at T-24 hours
14. Monitor network launch
15. Provide community support

---

**Ready to start? Begin with Phase 1: Rebuild Binaries!**
