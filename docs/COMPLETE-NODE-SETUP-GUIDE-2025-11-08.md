# Complete Dilithion Testnet Node Setup Guide
**From Digital Ocean Droplet to Running Node - No Steps Skipped**

---

## Overview

This guide walks through the **complete process** of setting up a Dilithion testnet node on Digital Ocean, including every dependency and step needed. Based on real deployment experience.

**Time Required:** 45-60 minutes per node
**Cost:** $12/month per droplet
**Difficulty:** Intermediate

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Part 1: SSH Key Setup](#part-1-ssh-key-setup)
3. [Part 2: Digital Ocean Droplet Creation](#part-2-digital-ocean-droplet-creation)
4. [Part 3: Initial Server Security](#part-3-initial-server-security)
5. [Part 4: Install Dependencies](#part-4-install-dependencies)
6. [Part 5: Build Dilithion Node](#part-5-build-dilithion-node)
7. [Part 6: Configure and Start Node](#part-6-configure-and-start-node)
8. [Part 7: Verification](#part-7-verification)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you begin, ensure you have:

- [ ] Digital Ocean account (https://cloud.digitalocean.com)
- [ ] Payment method added to account
- [ ] Terminal/command prompt access on your local machine
- [ ] GitHub account (to access the Dilithion repository)

---

## Part 1: SSH Key Setup

### Step 1.1: Generate SSH Key (Local Machine)

**On Windows (Command Prompt/PowerShell):**
```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "dilithion-testnet"

# When prompted:
# - File location: Press Enter (default: C:\Users\YOUR_NAME\.ssh\id_ed25519)
# - Passphrase: Press Enter (no passphrase) or set a strong one

# Display your public key
type %USERPROFILE%\.ssh\id_ed25519.pub
```

**On Mac/Linux:**
```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "dilithion-testnet"

# When prompted:
# - File location: Press Enter (default: ~/.ssh/id_ed25519)
# - Passphrase: Press Enter (no passphrase) or set a strong one

# Display your public key
cat ~/.ssh/id_ed25519.pub
```

**Copy the entire output** (starts with `ssh-ed25519`). You'll need this in the next step.

### Step 1.2: Add SSH Key to Digital Ocean

1. Log into Digital Ocean: https://cloud.digitalocean.com
2. Click profile icon (top right) → **Settings** → **Security**
3. Scroll to **SSH keys** section
4. Click **Add SSH Key**
5. **Paste** your public key from Step 1.1
6. **Name:** `dilithion-testnet`
7. Click **Add SSH Key**

✅ **Checkpoint:** You should see your key listed in the SSH keys section.

---

## Part 2: Digital Ocean Droplet Creation

### Step 2.1: Create New Droplet

1. Click **Create** → **Droplets**

### Step 2.2: Choose Region

Select based on your needs:
- **New York 3 (NYC3)** - North America
- **London 1 (LON1)** - Europe
- **Singapore 1 (SGP1)** - Asia
- **San Francisco 3 (SFO3)** - North America West
- **Frankfurt 1 (FRA1)** - Europe Central

### Step 2.3: Choose Image

- **Distribution:** Ubuntu
- **Version:** **22.04 (LTS) x64** ✅ (recommended for stability)
  - Alternative: 24.04 (LTS) x64 also works

⚠️ **Important:** Do NOT use 25.04 or 25.10 (non-LTS, too short support)

### Step 2.4: Choose Size

- **Droplet Type:** SHARED CPU
- **Plan:** Basic
- **CPU Options:** Regular (Disk type: SSD)
- **Size:** **$12/mo** (2 GB RAM / 1 CPU / 50 GB SSD / 2 TB transfer) ✅

**Why this size:**
- 2 GB RAM is minimum for blockchain node
- 50 GB SSD sufficient for testnet
- 1 CPU adequate for non-mining seed node

### Step 2.5: Additional Storage

- **Skip** - Don't add extra volume (50 GB is sufficient)

### Step 2.6: Backups

- **⬜ Leave unchecked** for testnet (saves $1.20/mo)
- For mainnet production, consider enabling

### Step 2.7: Choose Authentication Method

⚠️ **CRITICAL:** Select **SSH Key** (NOT Password)

- Click on **SSH Key** option
- **Check the box** next to your `dilithion-testnet` key
- Do NOT use password authentication (security risk)

### Step 2.8: Advanced Options

Scroll down and enable:
- **✅ Enable IPv6** (check this)
- **✅ Enable Monitoring** (check this)

### Step 2.9: Finalize Details

- **Number of Droplets:** 1
- **Hostname:** `dilithion-testnet-nyc` (or your region: lon, sgp, etc.)
- **Tags:** Add these tags:
  - `dilithion`
  - `testnet`
  - `seed-node`
- **Project:** Select or create project

### Step 2.10: Create Droplet

Click **Create Droplet** button at the bottom.

**Wait 1-2 minutes** for the droplet to be created.

✅ **Checkpoint:** Droplet shows as "Active" with an IP address.

### Step 2.11: Document IP Address

**Copy the droplet's IP address** and save it locally:

```bash
# On your local machine, create a tracking file
notepad testnet-nodes.txt

# Add:
NYC Node: YOUR_DROPLET_IP
```

---

## Part 3: Initial Server Security

### Step 3.1: Connect to Droplet

**On Windows:**
```bash
ssh -i C:\Users\YOUR_NAME\.ssh\id_ed25519 root@YOUR_DROPLET_IP
```

**On Mac/Linux:**
```bash
ssh -i ~/.ssh/id_ed25519 root@YOUR_DROPLET_IP
```

**First time connecting:**
- You'll see: "The authenticity of host ... can't be established"
- Type `yes` and press Enter
- You should now see: `root@your-hostname:~#`

✅ **Checkpoint:** You're connected to the droplet via SSH.

### Step 3.2: Update System

```bash
# Update package lists and upgrade all packages
apt update && apt upgrade -y
```

This takes 5-10 minutes. Wait for it to complete.

**If asked about restarting services:**
- Use Tab key to select "OK" or "Yes"
- Press Enter

### Step 3.3: Configure Firewall

```bash
# Allow SSH (port 22)
ufw allow 22/tcp

# Allow Dilithion testnet P2P port
ufw allow 18444/tcp

# Enable firewall
ufw --force enable

# Verify firewall status
ufw status
```

**Expected output:**
```
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
18444/tcp                  ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
18444/tcp (v6)             ALLOW       Anywhere (v6)
```

### Step 3.4: Enable Fail2Ban (Brute Force Protection)

```bash
# Install and enable fail2ban
apt install -y fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Verify it's running
systemctl status fail2ban
```

Press `q` to exit the status view.

### Step 3.5: Enable Automatic Security Updates

```bash
# Install unattended-upgrades
apt install -y unattended-upgrades

# Enable automatic updates
dpkg-reconfigure -plow unattended-upgrades
```

**When prompted:**
- Select **"Yes"** using Tab and Enter

✅ **Checkpoint:** Server is now secured with firewall, fail2ban, and auto-updates.

---

## Part 4: Install Dependencies

⚠️ **CRITICAL:** Install ALL dependencies upfront to avoid build errors.

### Step 4.1: Install Build Tools and Libraries

```bash
# Install essential build tools
apt install -y \
    build-essential \
    git \
    curl \
    wget \
    htop

# Install CMake (IMPORTANT - often forgotten!)
apt install -y cmake

# Install cryptography libraries
apt install -y \
    libssl-dev \
    libboost-all-dev

# Install database library (IMPORTANT - often forgotten!)
apt install -y libleveldb-dev libsnappy-dev

# Install RandomX dependencies
apt install -y \
    libhwloc-dev \
    pkg-config
```

**Wait for all installations to complete** (2-3 minutes).

### Step 4.2: Verify Critical Dependencies

```bash
# Verify cmake is installed
cmake --version

# Verify compiler is installed
gcc --version

# Verify git is installed
git --version
```

**Expected:** Each command shows a version number.

✅ **Checkpoint:** All dependencies installed successfully.

---

## Part 5: Build Dilithion Node

### Step 5.1: Clone Repository

```bash
# Go to root home directory
cd /root

# Clone Dilithion repository
git clone https://github.com/dilithion/dilithion.git

# Enter directory
cd dilithion
```

### Step 5.2: Initialize Git Submodules

```bash
# Initialize and download submodules (Dilithium crypto and RandomX)
git submodule init
git submodule update
```

**This downloads:**
- CRYSTALS-Dilithium3 cryptography library
- RandomX proof-of-work library

### Step 5.3: Build Dilithium Cryptography Library

```bash
# Navigate to Dilithium directory
cd depends/dilithium/ref

# Build the library
make

# Return to main directory
cd ../../..
```

**Time:** 30-60 seconds

### Step 5.4: Build RandomX Library

```bash
# Navigate to RandomX directory
cd depends/randomx

# Create build directory
mkdir -p build
cd build

# Configure with CMake
cmake ..

# Build RandomX
make -j2

# Return to main directory
cd ../../..
```

**Time:** 2-3 minutes

### Step 5.5: Build Dilithion Node

```bash
# Clean any previous builds (if any)
make clean

# Build the node (uses 2 CPU cores)
make -j2
```

**Time:** 5-10 minutes

**You'll see lots of compilation output with warnings - this is normal.**

**Expected final output:**
```
✓ dilithion-node built successfully
✓ genesis_gen built successfully
✓ check-wallet-balance built successfully
✓ Build complete!
  dilithion-node:        956K
  genesis_gen:           889K
  check-wallet-balance:  889K
```

### Step 5.6: Verify Binaries

```bash
# Check that binaries exist
ls -lh dilithion-node genesis_gen check-wallet-balance

# Test the binary
./dilithion-node --help
```

✅ **Checkpoint:** All binaries built successfully and execute without errors.

---

## Part 6: Configure and Start Node

### Step 6.1: Create Data Directories

```bash
# Create all necessary directories
mkdir -p .dilithion-testnet/blocks
mkdir -p .dilithion-testnet/chainstate
mkdir -p .dilithion-testnet/wallet
```

### Step 6.2: Create Configuration File (Optional)

**Note:** Configuration file is optional. Node runs with defaults if no config exists.

If you want custom configuration:

```bash
# Create config directory
mkdir -p ~/.dilithion

# Create configuration file
cat > ~/.dilithion/dilithion.conf <<EOF
# Dilithion Testnet Configuration

# Network
testnet=1
listen=1
server=1

# P2P
port=18444
maxconnections=125

# RPC
rpcport=18332
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcuser=testnet_rpc_$(openssl rand -hex 8)
rpcpassword=$(openssl rand -base64 32)

# Performance
dbcache=300
maxmempool=300

# Logging
debug=0
printtoconsole=1
EOF

# Set secure permissions
chmod 600 ~/.dilithion/dilithion.conf
```

### Step 6.3: Start the Node

```bash
# Start testnet node in background
./dilithion-node --testnet &

# Wait for node to initialize
sleep 5
```

**Expected output:**
```
======================================
Dilithion Node v1.0.0
Post-Quantum Cryptocurrency
======================================

Network: TESTNET (256x easier difficulty)
Data directory: .dilithion-testnet
P2P port: 18444
RPC port: 18332

Initializing blockchain storage...
  [OK] Blockchain database opened
Initializing mempool...
  [OK] Mempool initialized
Initializing chain state...
  [OK] Chain state initialized
Initializing RandomX...
  [OK] RandomX initialized
Loading genesis block...
  Network: testnet
  Genesis hash: 924bdb80469e1185814407147bc763a62425cc400bc902ce37d73ffbc3524475
  Genesis time: 1730000000
  [OK] Genesis block verified
Initializing blockchain with genesis block...
  [OK] Genesis block saved to database
  [OK] Genesis block index saved (height 0)
[Chain] Activating genesis block at height 0
  [OK] Genesis block set as blockchain tip
Initializing P2P components...
  [OK] P2P components ready (not started)
Initializing mining controller...
  [OK] Mining controller initialized (1 threads)
Initializing wallet...
  Generating initial address...
  [OK] Initial address: DERLeqZYL5UuUramhBfEkVCRtH5T3zXqNB
Starting P2P networking server...
  [OK] P2P server listening on port 18444
Initializing RPC server...
[RPC] Started thread pool with 8 workers
  [OK] RPC server listening on port 18332

======================================
Node Status: RUNNING
======================================

RPC Interface:
  URL: http://localhost:18332
  Methods: getnewaddress, getbalance, getmininginfo, help

Press Ctrl+C to stop

  [OK] P2P maintenance thread started
  [OK] P2P receive thread started
  [OK] P2P accept thread started
```

✅ **Checkpoint:** Node is running and initialized successfully.

---

## Part 7: Verification

### Step 7.1: Check Process is Running

```bash
# Check if dilithion-node process exists
ps aux | grep dilithion-node | grep -v grep
```

**Expected output:**
```
root       12345  1.5 13.3 378280 268796 pts/0   Sl   15:00   0:01 ./dilithion-node --testnet
```

**What to check:**
- Process ID (first number)
- Memory usage (~260-270 MB is normal)
- Status "Sl" means sleeping and multithreaded (normal)

### Step 7.2: Check Network Port is Listening

```bash
# Check if P2P port is listening
ss -tulpn | grep 18444
```

**Expected output:**
```
tcp   LISTEN 0      10           0.0.0.0:18444      0.0.0.0:*    users:(("dilithion-node",pid=12345,fd=7))
```

**This confirms:**
- Port 18444 is open
- Listening on all interfaces (0.0.0.0)
- Bound to dilithion-node process

### Step 7.3: Test RPC Connection (Optional)

```bash
# Test RPC is responding
curl http://localhost:18332 -X POST \
  -d '{"method":"getblockchaininfo","params":[],"id":1}' \
  -H "Content-Type: application/json"
```

**Expected output:**
```json
{"jsonrpc":"2.0","result":{...},"id":1}
```

Or if blockchain not fully initialized:
```json
{"jsonrpc":"2.0","error":{"code":-32603,"message":"Blockchain not initialized"},"id":1}
```

Both responses indicate RPC is working.

### Step 7.4: Check Node Status

```bash
# View the node's initial wallet address
# Look for line: "[OK] Initial address: D..."
# in the startup output above

# Or check with ps
ps aux | grep dilithion-node
```

✅ **Checkpoint:** Node is fully operational and ready to accept connections.

---

## Connecting Multiple Nodes

If you've set up multiple nodes, connect them together:

### Add Peer Connections

**On each node, connect to the others:**

```bash
# Example: From NYC node, connect to London and Singapore
# (Run these while node is running)

# This requires RPC - will be implemented in future updates
# For now, nodes will discover each other via:
# 1. DNS seeds (once configured in chainparams.cpp)
# 2. Manual peer addition in future version
```

**For now:** Each node runs independently. They'll connect once seed nodes are configured in the code.

---

## Node Management Commands

### Check Node Status

```bash
# View running process
ps aux | grep dilithion-node | grep -v grep

# Check listening ports
ss -tulpn | grep 18444

# Check memory usage
free -h

# Check disk usage
df -h
```

### Stop Node

```bash
# Find process ID
ps aux | grep dilithion-node | grep -v grep

# Kill process gracefully
kill <PID>

# Or kill all dilithion-node processes
pkill dilithion-node
```

### Restart Node

```bash
# Stop node
pkill dilithion-node

# Wait for clean shutdown
sleep 3

# Start again
cd /root/dilithion
./dilithion-node --testnet &
```

### View Resource Usage

```bash
# Interactive system monitor
htop

# Press 'q' to exit
```

---

## Troubleshooting

### Issue: "Command 'cmake' not found"

**Solution:**
```bash
apt install -y cmake
```

### Issue: "fatal error: leveldb/db.h: No such file or directory"

**Solution:**
```bash
apt install -y libleveldb-dev
make -j2  # Continue build
```

### Issue: "cannot find -lrandomx"

**Cause:** RandomX library not built

**Solution:**
```bash
cd depends/randomx
mkdir -p build && cd build
cmake ..
make -j2
cd ../../..
make -j2  # Continue main build
```

### Issue: SSH Connection Refused

**Check:**
```bash
# On local machine
ping YOUR_DROPLET_IP

# If ping works, check SSH key
ssh -v -i ~/.ssh/id_ed25519 root@YOUR_DROPLET_IP
```

**Solution:**
- Verify SSH key is added to Digital Ocean
- Check firewall allows port 22
- Try password reset from Digital Ocean console

### Issue: "Permission denied (publickey)"

**Cause:** SSH key not properly configured

**Solution:**
1. Verify public key is added to Digital Ocean account
2. Use correct private key file path
3. Check key permissions: `chmod 600 ~/.ssh/id_ed25519`

### Issue: Node Not Starting

**Check:**
```bash
# Try running in foreground to see errors
./dilithion-node --testnet

# Check if data directories exist
ls -la .dilithion-testnet/

# Create if missing
mkdir -p .dilithion-testnet/{blocks,chainstate,wallet}
```

### Issue: Firewall Blocking Connections

**Check and fix:**
```bash
# Check firewall status
ufw status

# If inactive, enable it
ufw allow 22/tcp
ufw allow 18444/tcp
ufw --force enable
```

### Issue: Out of Memory

**Check memory:**
```bash
free -h
```

**Solution:**
- Upgrade to 4GB droplet ($24/mo)
- Or reduce dbcache in config:
```bash
echo "dbcache=150" >> ~/.dilithion/dilithion.conf
```

### Issue: Build Takes Forever

**Solution:**
- Use `-j2` flag (uses 2 cores): `make -j2`
- Don't use `-j$(nproc)` on 1 CPU droplet
- Be patient - first build takes 5-10 minutes

---

## Quick Reference Commands

### SSH Connection
```bash
# Windows
ssh -i C:\Users\YOUR_NAME\.ssh\id_ed25519 root@YOUR_IP

# Mac/Linux
ssh -i ~/.ssh/id_ed25519 root@YOUR_IP
```

### Complete Build Process (After Dependencies Installed)
```bash
cd /root/dilithion
git submodule init && git submodule update
cd depends/dilithium/ref && make && cd ../../..
cd depends/randomx && mkdir -p build && cd build && cmake .. && make -j2 && cd ../../..
make -j2
mkdir -p .dilithion-testnet/{blocks,chainstate,wallet}
./dilithion-node --testnet &
```

### Node Management
```bash
# Start node
./dilithion-node --testnet &

# Check status
ps aux | grep dilithion-node | grep -v grep
ss -tulpn | grep 18444

# Stop node
pkill dilithion-node

# Restart node
pkill dilithion-node && sleep 3 && ./dilithion-node --testnet &
```

---

## Complete Installation Script (All-in-One)

**Use this for快速 setup after droplet creation:**

```bash
#!/bin/bash
# Save this as: setup-dilithion-node.sh
# Run with: bash setup-dilithion-node.sh

set -e  # Exit on error

echo "=== Dilithion Testnet Node Setup ==="
echo ""

# Update system
echo "[1/8] Updating system..."
apt update && apt upgrade -y

# Configure firewall
echo "[2/8] Configuring firewall..."
ufw allow 22/tcp
ufw allow 18444/tcp
ufw --force enable

# Install security tools
echo "[3/8] Installing security tools..."
apt install -y fail2ban unattended-upgrades
systemctl enable fail2ban && systemctl start fail2ban
dpkg-reconfigure -plow unattended-upgrades

# Install dependencies
echo "[4/8] Installing dependencies..."
apt install -y build-essential git curl wget htop cmake \
    libssl-dev libboost-all-dev libleveldb-dev libsnappy-dev \
    libhwloc-dev pkg-config

# Clone repository
echo "[5/8] Cloning Dilithion repository..."
cd /root
git clone https://github.com/dilithion/dilithion.git
cd dilithion
git submodule init && git submodule update

# Build Dilithium library
echo "[6/8] Building Dilithium cryptography..."
cd depends/dilithium/ref && make && cd ../../..

# Build RandomX library
echo "[7/8] Building RandomX..."
cd depends/randomx && mkdir -p build && cd build
cmake .. && make -j2 && cd ../../..

# Build Dilithion node
echo "[8/8] Building Dilithion node..."
make -j2

# Create data directories
mkdir -p .dilithion-testnet/{blocks,chainstate,wallet}

echo ""
echo "=== Setup Complete! ==="
echo ""
echo "To start the node:"
echo "  cd /root/dilithion"
echo "  ./dilithion-node --testnet &"
echo ""
echo "To check status:"
echo "  ps aux | grep dilithion-node"
echo "  ss -tulpn | grep 18444"
echo ""
```

**To use:**
```bash
# On the droplet
cd /root
nano setup-dilithion-node.sh
# Paste the script above, save with Ctrl+X, Y, Enter

# Make executable
chmod +x setup-dilithion-node.sh

# Run it
./setup-dilithion-node.sh
```

---

## Summary Checklist

**Before starting:**
- [ ] Digital Ocean account with payment method
- [ ] SSH key generated and added to DO account

**Droplet creation:**
- [ ] Ubuntu 22.04 LTS selected
- [ ] $12/mo droplet size (2GB RAM)
- [ ] SSH key authentication selected (NOT password)
- [ ] IPv6 and Monitoring enabled
- [ ] Firewall rules applied (22, 18444)

**Security setup:**
- [ ] System updated
- [ ] Firewall configured and enabled
- [ ] Fail2ban installed and running
- [ ] Auto-updates enabled

**Dependencies installed:**
- [ ] Build tools (build-essential, git, cmake)
- [ ] Crypto libraries (libssl-dev, libboost-all-dev)
- [ ] Database library (libleveldb-dev) ⚠️
- [ ] RandomX deps (libhwloc-dev)

**Build process:**
- [ ] Repository cloned
- [ ] Submodules initialized
- [ ] Dilithium library built
- [ ] RandomX library built
- [ ] Dilithion node built successfully

**Node running:**
- [ ] Data directories created
- [ ] Node started in background
- [ ] Process visible in ps
- [ ] Port 18444 listening
- [ ] RPC responding (optional)

---

## Cost Summary

**Per Node:**
- Droplet: $12/month
- Bandwidth: Included (2TB)
- Backups: $0 (disabled for testnet)
- **Total: $12/month per node**

**3 Testnet Nodes:** $36/month
**5 Mainnet Nodes:** $60/month

---

## Next Steps

After your node is running:

1. **Set up additional nodes** in different regions
2. **Configure DNS seeds** for automatic peer discovery
3. **Deploy monitoring** (Prometheus/Grafana)
4. **Run security scans** to validate configuration
5. **Test backup procedures**
6. **Begin 7-day stability testing**

---

## Support and Documentation

- **GitHub:** https://github.com/dilithion/dilithion
- **Testnet Validation Plan:** See TESTNET-VALIDATION-PLAN-2025-11-07.md
- **Security Checklist:** See docs/SECURITY-CHECKLIST-2025-11-07.md
- **Deployment Guide:** See docs/DEPLOYMENT-GUIDE-2025-11-07.md

---

**Document Version:** 1.0.0
**Created:** November 8, 2025
**Based On:** Real deployment experience (NYC, London, Singapore nodes)
**Tested On:** Ubuntu 22.04 LTS, Digital Ocean droplets

---

*Dilithion - The World's First Production-Ready Post-Quantum Cryptocurrency* 🔐
