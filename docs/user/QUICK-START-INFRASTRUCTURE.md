# Quick Start: Infrastructure Setup
**For: Will (Dilithion Developer)**
**Goal: Get testnet running in 7 days**

---

## Week 1: Critical Path (Oct 27 - Nov 2)

### Day 1-2: Local Build (YOUR MACHINE)

**Step 1: Rebuild Everything**
```bash
cd C:\Users\will\dilithion
git checkout standalone-implementation
make clean
make dilithion-node
make genesis_gen
make tests
```

**Step 2: Test Everything**
```bash
# Run all test suites - ALL must pass
./build/phase1_test
./build/wallet_tests
./build/rpc_tests
./crypter_tests
./build/integration_tests
```

**Step 3: Mine Genesis Block** ⏱️ (2-6 hours)
```bash
./genesis_gen --mine

# WRITE DOWN THE NONCE AND HASH!
# Example output:
# Nonce: 2083236893
# Hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
```

**Step 4: Update Code & Commit**
```bash
# Edit src/node/genesis.h - update NONCE with your value
# Then:
git add src/node/genesis.h
git commit -m "Add mined genesis block for mainnet"
git tag v1.0.0-genesis
git push origin standalone-implementation v1.0.0-genesis
```

**✅ Day 1-2 Complete:** Genesis block ready!

---

### Day 3-5: VPS Setup

**Step 1: Sign Up for DigitalOcean**
- Go to https://www.digitalocean.com
- Create account
- Add payment method ($18-30 needed for 3 servers)

**Step 2: Create 3 Droplets**

**Droplet 1 (New York):**
- Ubuntu 22.04 LTS
- Basic plan: $6/month
- Region: New York 1
- Hostname: dilithion-seed1

**Droplet 2 (London):**
- Same settings
- Region: London
- Hostname: dilithion-seed2

**Droplet 3 (Singapore):**
- Same settings
- Region: Singapore
- Hostname: dilithion-seed3

**Step 3: Record IP Addresses**
```
Seed 1 (NYC):       ___.___.___.___ (write it down!)
Seed 2 (London):    ___.___.___.___
Seed 3 (Singapore): ___.___.___.___
```

**Step 4: Configure DNS** (Webcentral)
- Login to Webcentral
- DNS for dilithion.org
- Add A records:
  - seed1.dilithion.org → [Seed 1 IP]
  - seed2.dilithion.org → [Seed 2 IP]
  - seed3.dilithion.org → [Seed 3 IP]

**Step 5: Install Dilithion on Each Server**

For EACH of the 3 servers, SSH in and run:

```bash
# Connect
ssh root@[SERVER_IP]

# Update
apt update && apt upgrade -y
apt install -y build-essential git cmake libleveldb-dev

# Create user
adduser dilithion
usermod -aG sudo dilithion
su - dilithion

# Clone and build
cd ~
git clone https://github.com/dilithion/dilithion.git
cd dilithion
git checkout v1.0.0-genesis

# Build RandomX
cd depends/randomx && mkdir -p build && cd build
cmake .. && make -j2
cd ~/dilithion

# Build Dilithium
cd depends/dilithium/ref
make -j2
cd ~/dilithion

# Build Dilithion
make dilithion-node

# Setup firewall
sudo ufw allow 8333/tcp
sudo ufw allow 22/tcp
sudo ufw enable

# Create service
sudo nano /etc/systemd/system/dilithion.service
```

**Paste this into the service file:**
```ini
[Unit]
Description=Dilithion Node
After=network.target

[Service]
Type=simple
User=dilithion
WorkingDirectory=/home/dilithion/dilithion
ExecStart=/home/dilithion/dilithion/dilithion-node --datadir=/home/dilithion/.dilithion
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Start the service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable dilithion
sudo systemctl start dilithion
sudo systemctl status dilithion  # Should say "active (running)"
```

**✅ Repeat for all 3 servers!**

**✅ Day 3-5 Complete:** 3 seed nodes running!

---

### Day 6-7: Testnet Launch

**Step 1: Verify All Nodes Running**
```bash
# On each server:
sudo systemctl status dilithion
sudo journalctl -u dilithion -n 50
```

**Step 2: Check Connectivity**
```bash
# On Seed 1:
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"getpeerinfo","id":1}'

# Should show 2+ peers (the other seed nodes)
```

**Step 3: Start Mining on Seed 1**
```bash
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"startmining","params":["2"],"id":1}'

# Check mining status
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","id":1}'
```

**Step 4: Monitor Block Production**
```bash
# Every 5 minutes, check block count:
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"getblockcount","id":1}'

# Should increase by ~2-3 blocks every 5 minutes
```

**Step 5: Verify Block Propagation**
```bash
# On Seed 2:
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"getblockcount","id":1}'

# Should match Seed 1 (within 1-2 blocks)
```

**✅ Day 6-7 Complete:** Testnet is LIVE! 🎉

---

## Week 2: Testing (Nov 3-9)

**Run 48-Hour Stress Test:**

**Monitor Script** (run on Seed 1):
```bash
nano ~/monitor.sh
```

```bash
#!/bin/bash
while true; do
  echo "=== $(date) ===" | tee -a results.log
  curl -s -X POST http://localhost:8332 \
    -d '{"jsonrpc":"2.0","method":"getblockcount","id":1}' | tee -a results.log
  curl -s -X POST http://localhost:8332 \
    -d '{"jsonrpc":"2.0","method":"getmininginfo","id":1}' | tee -a results.log
  echo "---" | tee -a results.log
  sleep 3600  # Every hour
done
```

```bash
chmod +x ~/monitor.sh
nohup ./monitor.sh > /dev/null 2>&1 &
```

**Check Every 12 Hours:**
- [ ] All 3 nodes still running? (`systemctl status dilithion`)
- [ ] Blocks still being produced? (check block count)
- [ ] Any errors in logs? (`journalctl -u dilithion -n 100`)
- [ ] Memory usage OK? (`free -h`)

**After 48 hours:**
- [ ] Download results.log
- [ ] Calculate average block time
- [ ] Check for any forks or issues
- [ ] Document results in TESTNET-RESULTS.md

**✅ Week 2 Complete:** Testnet validated! Ready for production!

---

## Cheat Sheet: Useful Commands

**Check if node is running:**
```bash
sudo systemctl status dilithion
```

**View recent logs:**
```bash
sudo journalctl -u dilithion -n 100
```

**Follow logs in real-time:**
```bash
sudo journalctl -u dilithion -f
```

**Restart node:**
```bash
sudo systemctl restart dilithion
```

**Get block count:**
```bash
curl -s -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"getblockcount","id":1}' | jq
```

**Get mining info:**
```bash
curl -s -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","id":1}' | jq
```

**Get peer info:**
```bash
curl -s -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"getpeerinfo","id":1}' | jq
```

**Check memory usage:**
```bash
free -h
htop
```

**Check disk usage:**
```bash
df -h
du -sh /home/dilithion/.dilithion
```

---

## Troubleshooting

**Problem: Node won't start**
```bash
# Check logs
sudo journalctl -u dilithion -n 100

# Common issues:
# - Port 8333 blocked → check firewall
# - Permission issues → check user 'dilithion' owns files
# - Missing dependencies → reinstall build-essential, libleveldb-dev
```

**Problem: Nodes not connecting**
```bash
# Check DNS
nslookup seed1.dilithion.org
nslookup seed2.dilithion.org
nslookup seed3.dilithion.org

# Check firewall
sudo ufw status
# Port 8333 should be ALLOW

# Manually connect
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"addnode","params":["[OTHER_SEED_IP]:8333"],"id":1}'
```

**Problem: Mining not starting**
```bash
# Check if wallet is locked
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"walletpassphrase","params":["","300"],"id":1}'

# Start mining
curl -X POST http://localhost:8332 \
  -d '{"jsonrpc":"2.0","method":"startmining","params":["2"],"id":1}'
```

**Problem: Out of disk space**
```bash
# Check usage
df -h

# If needed, upgrade VPS or clear old logs
sudo journalctl --vacuum-time=7d
```

---

## Cost Breakdown

**DigitalOcean (Recommended):**
```
3 Droplets × $6/month = $18/month
Total first month: ~$18-20
```

**Alternative: Start with 1 seed node**
```
1 Droplet = $6/month
(Can add more later)
```

**Payment Methods:**
- Credit/debit card
- PayPal
- Prepaid balance

---

## What's Next After Infrastructure?

Once testnet is running for 48+ hours successfully:

1. **Create Release Candidate** (v1.0.0-rc1)
2. **Build binaries** for Linux/Windows
3. **Create GitHub release**
4. **Update website** with download links
5. **Create community channels** (Discord, Twitter)
6. **Register ABN** (business structure)
7. **Prepare for launch** (monitoring, team)

Then: **LAUNCH JAN 1, 2026!** 🚀

---

## Need Help?

**Check the full guide:** INFRASTRUCTURE-SETUP-GUIDE.md (detailed version)

**SSH into servers:**
```bash
ssh root@[SERVER_IP]
# or
ssh dilithion@[SERVER_IP]
```

**GitHub repo:**
https://github.com/dilithion/dilithion

**Website (once live):**
https://dilithion.org

---

## Quick Checklist

**Week 1:**
- [ ] Day 1: Rebuild binaries
- [ ] Day 1: Run all tests (must pass)
- [ ] Day 2: Mine genesis block (2-6 hours)
- [ ] Day 2: Commit genesis block + tag
- [ ] Day 3: Sign up DigitalOcean
- [ ] Day 3: Create 3 droplets
- [ ] Day 3: Configure DNS
- [ ] Day 4-5: Install Dilithion on all 3 servers
- [ ] Day 5: Verify all nodes running
- [ ] Day 6: Connect nodes
- [ ] Day 6: Start mining
- [ ] Day 7: Verify block production

**Week 2:**
- [ ] Start 48-hour test
- [ ] Monitor every 12 hours
- [ ] Log all results
- [ ] Fix any issues
- [ ] Complete 48 hours successfully
- [ ] Document results

**Result:** Testnet validated, ready for production! ✅

---

**TIME TO GET STARTED!** Begin with rebuilding the binaries on your local machine. Good luck! 🚀
