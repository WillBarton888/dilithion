# Dilithion Mainnet Node Setup Guide

**Version:** 1.0.0
**Network:** Mainnet
**Launch Date:** January 1, 2026 00:00:00 UTC
**Last Updated:** November 7, 2025

Welcome to Dilithion mainnet! This comprehensive guide will help you set up, configure, and run a full Dilithion node for the post-quantum cryptocurrency network.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Hardware Requirements](#hardware-requirements)
3. [Linux Installation](#linux-installation)
4. [Windows Installation](#windows-installation)
5. [macOS Installation](#macos-installation)
6. [Network Configuration](#network-configuration)
7. [Starting Your Node](#starting-your-node)
8. [Verification](#verification)
9. [Security Best Practices](#security-best-practices)
10. [Maintenance](#maintenance)
11. [Troubleshooting](#troubleshooting)

---

## Introduction

### What is a Full Node?

A Dilithion full node:
- Downloads and validates the entire blockchain
- Independently verifies all transactions and blocks using Dilithium3 post-quantum signatures
- Helps secure and decentralize the network
- Enables trustless mining with RandomX proof-of-work
- Provides complete privacy (no third-party servers)

### Why Run a Node?

✅ **Security:** Validate everything yourself with quantum-resistant cryptography
✅ **Privacy:** No reliance on external servers
✅ **Decentralization:** Support network health
✅ **Mining:** Required for mining operations
✅ **Community:** Contribute to The People's Coin

---

## Hardware Requirements

### Minimum Specifications (Non-Mining)

**CPU:** 2 cores (x64 architecture)
**RAM:** 4 GB
**Storage:** 50 GB available space (SSD recommended)
**Network:** 10+ Mbps stable connection with unlimited data

### Recommended Specifications

**CPU:** 4+ cores (Intel Core i5 / AMD Ryzen 5 or better)
**RAM:** 8 GB+
**Storage:** 100 GB+ SSD (NVMe preferred for faster sync)
**Network:** 50+ Mbps unmetered connection

### Mining Node Requirements

Add to recommended specifications:
- **CPU:** 8+ cores with AVX2 support for RandomX
- **RAM:** 16 GB+ (RandomX uses ~2GB per mining thread)
- **Cooling:** Adequate CPU cooling solution (mining generates heat)
- **Power:** Reliable PSU with surge protection

### Storage Growth Estimates

| Timeframe | Estimated Size | Notes |
|-----------|---------------|-------|
| Launch Day | ~1 MB | Genesis block only |
| Week 1 | ~50 MB | 4-minute blocks |
| Month 1 | ~200 MB | ~10,800 blocks |
| Year 1 | ~2-5 GB | Full transaction history |

**Recommendation:** Start with 100 GB free space for future growth

---

## Linux Installation

### Ubuntu 20.04 / 22.04 / 24.04

#### Step 1: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 2: Install Dependencies
```bash
sudo apt install -y build-essential cmake git libleveldb-dev libssl-dev pkg-config
```

#### Step 3: Download Dilithion

**Option A: Pre-Compiled Binary (Recommended)**
```bash
mkdir -p ~/dilithion && cd ~/dilithion
wget https://github.com/WillBarton888/dilithion/releases/download/v1.0.0/dilithion-1.0.0-linux-x64.tar.gz

# Verify checksum (CRITICAL for security!)
sha256sum dilithion-1.0.0-linux-x64.tar.gz
# Compare with official checksum from GitHub release page

tar -xzf dilithion-1.0.0-linux-x64.tar.gz
cd dilithion-1.0.0
```

**Option B: Build from Source**
```bash
git clone https://github.com/WillBarton888/dilithion.git
cd dilithion
git checkout v1.0.0
git submodule update --init --recursive

# Build RandomX dependency
cd depends/randomx && mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)
cd ../../..

# Build Dilithium library (post-quantum signatures)
cd depends/dilithium/ref && make && cd ../../..

# Build Dilithion node
make dilithion-node

# Verify compilation
./dilithion-node --version
```

#### Step 4: Install System-Wide (Optional)
```bash
sudo cp dilithion-node /usr/local/bin/
mkdir -p ~/.dilithion

# Create systemd service for auto-start
sudo tee /etc/systemd/system/dilithion.service > /dev/null <<SYSTEMD
[Unit]
Description=Dilithion Full Node
After=network.target

[Service]
Type=simple
User=$USER
ExecStart=/usr/local/bin/dilithion-node --datadir=$HOME/.dilithion
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
SYSTEMD

sudo systemctl daemon-reload
sudo systemctl enable dilithion
```

### Debian, Fedora, Arch Linux

**Debian:** Same as Ubuntu steps above

**Fedora:**
```bash
sudo dnf install -y gcc-c++ cmake git leveldb-devel openssl-devel
# Then follow build from source steps
```

**Arch Linux:**
```bash
sudo pacman -Syu
sudo pacman -S base-devel cmake git leveldb openssl
# Then follow build from source steps
```

---

## Windows Installation

### Option A: WSL2 (Recommended)

**Step 1: Enable WSL2**

Open PowerShell as Administrator:
```powershell
wsl --install
# Restart computer after installation
```

**Step 2: Install Ubuntu**
```powershell
wsl --install -d Ubuntu-22.04
```

**Step 3: Follow Ubuntu Instructions**

Open Ubuntu from Start menu and follow Linux setup instructions above.

**Step 4: Access from Windows**

Your WSL files are at: `\\wsl$\Ubuntu-22.04\home\<username>\dilithion\`

### Option B: Native Windows Build (Advanced)

**Requirements:**
- MSYS2 (https://www.msys2.org/)
- 64-bit Windows 10/11

**Installation:**

1. Install MSYS2 to `C:\msys64`
2. Open MSYS2 MINGW64 terminal
3. Install dependencies:
```bash
pacman -Syu
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-make git
pacman -S mingw-w64-x86_64-leveldb mingw-w64-x86_64-openssl
```
4. Follow Linux build instructions in MSYS2 terminal

**Windows Firewall Configuration:**

1. Windows Defender Firewall → Advanced settings
2. Inbound Rules → New Rule
3. Port → TCP 8444 → Allow → Name: "Dilithion P2P"
4. Apply to all profiles

---

## macOS Installation

### macOS 12+ (Monterey/Ventura/Sonoma)

#### Step 1: Install Homebrew
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Step 2: Install Dependencies
```bash
brew install cmake leveldb git openssl
```

#### Step 3: Download Dilithion

**Pre-compiled Binary:**
```bash
mkdir -p ~/dilithion && cd ~/dilithion

# Download (Intel x64 or Apple Silicon ARM)
curl -L -O https://github.com/WillBarton888/dilithion/releases/download/v1.0.0/dilithion-1.0.0-macos-x64.tar.gz

# Verify checksum
shasum -a 256 dilithion-1.0.0-macos-x64.tar.gz

tar -xzf dilithion-1.0.0-macos-x64.tar.gz
```

**Or Build from Source:**

Follow Linux build steps above with Homebrew-installed dependencies.

#### Step 4: Security Permissions

```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine dilithion-node

# Or allow in System Preferences
# System Preferences → Security & Privacy → Allow "dilithion-node"
```

---

## Network Configuration

### Port Requirements

| Port | Protocol | Purpose | Direction |
|------|----------|---------|-----------|
| **8444** | TCP | P2P Network (Mainnet) | Inbound/Outbound |
| **8332** | TCP | RPC Interface | Localhost only |

**Note:** Testnet uses ports 18444 (P2P) and 18332 (RPC)

### Firewall Configuration

**Ubuntu/Debian (UFW):**
```bash
sudo ufw enable
sudo ufw allow 22/tcp   # SSH (if remote server)
sudo ufw allow 8444/tcp # Dilithion P2P
sudo ufw status
```

**Fedora/RHEL (firewalld):**
```bash
sudo firewall-cmd --permanent --add-port=8444/tcp
sudo firewall-cmd --reload
```

**Check if port is listening:**
```bash
ss -tulpn | grep 8444
# or
netstat -tulpn | grep 8444
```

### Port Forwarding (Optional but Recommended)

**Why:** Allows incoming connections, improves network decentralization

**Router Setup:**
1. Access router admin panel (typically http://192.168.1.1)
2. Navigate to Port Forwarding / Virtual Server
3. Add rule:
   - External Port: 8444
   - Internal Port: 8444
   - Protocol: TCP
   - Internal IP: [Your computer's local IP]
4. Save and test

**Find your local IP:**
```bash
# Linux/macOS
ip addr show | grep "inet " | grep -v 127.0.0.1
hostname -I

# Windows (PowerShell)
ipconfig | findstr IPv4
```

**Test port forwarding:**
```bash
# From external network
nc -zv [YOUR_PUBLIC_IP] 8444
# or use online tool: https://www.yougetsignal.com/tools/open-ports/
```

---

## Starting Your Node

### Basic Start (All Platforms)

```bash
./dilithion-node
```

**Expected output:**
```
======================================
Dilithion Node v1.0.0
Post-Quantum Cryptocurrency
======================================

Initializing blockchain storage...
  ✓ Blockchain database opened
Initializing mempool...
  ✓ Mempool initialized
Initializing P2P components...
  ✓ P2P components ready
Initializing wallet...
  Generating initial address...
  ✓ Initial address: D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV
Initializing RPC server...
  ✓ RPC server listening on port 8332

======================================
Node Status: RUNNING
======================================

Connecting to network...
  Seed node: 170.64.203.134:18444 (testnet seed - will fail on mainnet)
  Connecting to mainnet seed nodes...
```

### Command-Line Options

**Custom data directory:**
```bash
./dilithion-node --datadir=/path/to/custom/data
```

**Custom RPC port:**
```bash
./dilithion-node --rpcport=9332
```

**Connect to specific peer:**
```bash
./dilithion-node --connect=45.76.98.210:8444
```

**Add seed node:**
```bash
./dilithion-node --addnode=seed1.dilithion.org:8444
```

**Start mining (see Mining Guide for details):**
```bash
./dilithion-node --mine --threads=4
```

### Run as Background Service

**Linux with systemd:**
```bash
sudo systemctl start dilithion
sudo systemctl status dilithion
sudo journalctl -u dilithion -f  # View logs in real-time
```

**Manual background process:**
```bash
nohup ./dilithion-node > dilithion.log 2>&1 &
tail -f dilithion.log
```

**Stop node:**
```bash
# systemd
sudo systemctl stop dilithion

# or find process and kill
ps aux | grep dilithion-node
kill [PID]
```

---

## Verification

### 1. Check Process is Running

```bash
# Linux/macOS
ps aux | grep dilithion-node

# Check network ports
ss -tulpn | grep 8444
netstat -tulpn | grep 8444
```

### 2. Query RPC Interface

**Get network info:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getnetworkinfo","params":[],"id":1}'
```

**Expected response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "version": "1.0.0",
    "connections": 8,
    "blockchain_height": 12045
  },
  "id": 1
}
```

### 3. Verify Blockchain Sync

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'
```

**Check:**
- `height`: Current block height
- `blocks`: Number of synced blocks
- `headers`: Known headers (should match network)

### 4. Check Peer Connections

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getpeerinfo","params":[],"id":1}'
```

**Healthy node:** 8+ peer connections

---

## Security Best Practices

### File Permissions

```bash
chmod 700 ~/.dilithion
chmod 600 ~/.dilithion/wallet.dat
chmod 600 ~/.dilithion/dilithion.conf
```

### RPC Authentication

**Create ~/.dilithion/dilithion.conf:**
```ini
# RPC Authentication (REQUIRED for security)
rpcuser=dilithion_$(openssl rand -hex 8)
rpcpassword=$(openssl rand -base64 32)

# RPC Network Binding
rpcport=8332
rpcallowip=127.0.0.1  # Localhost only!

# NEVER use:
# rpcallowip=0.0.0.0  # DANGEROUS - exposes to internet
```

**Secure the config:**
```bash
chmod 600 ~/.dilithion/dilithion.conf
```

**Use authenticated RPC:**
```bash
curl -u username:password \
  http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}'
```

### Wallet Security

- ✅ Encrypt wallet with strong passphrase (20+ characters)
- ✅ Backup wallet.dat to multiple secure locations
- ✅ Never share private keys or wallet file
- ✅ Store backups offline and encrypted
- ✅ Use hardware security for large holdings (cold storage)

### System Hardening

```bash
# Keep system updated
sudo apt update && sudo apt upgrade -y

# Enable automatic security updates (Ubuntu)
sudo apt install unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades

# Enable firewall
sudo ufw enable

# Disable unnecessary services
sudo systemctl disable bluetooth.service
```

### SSH Security (if running remote node)

```bash
# Disable password authentication
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication no
# Set: PubkeyAuthentication yes

sudo systemctl restart sshd
```

---

## Maintenance

### Regular Backups

**Backup wallet:**
```bash
# Stop node first (important!)
sudo systemctl stop dilithion

# Backup wallet
cp ~/.dilithion/wallet.dat ~/wallet-backup-$(date +%Y%m%d).dat

# Restart node
sudo systemctl start dilithion
```

**Encrypt backup:**
```bash
gpg -c wallet-backup-20260101.dat
# Passphrase required - use strong password
```

**Store securely:**
- USB drive (multiple copies)
- Encrypted cloud storage (Google Drive, Dropbox with encryption)
- Bank safe deposit box

### Updating Dilithion

**Check for updates:**
```bash
# Watch GitHub releases
watch -n 300 'curl -s https://api.github.com/repos/WillBarton888/dilithion/releases/latest | grep tag_name'
```

**Update procedure:**
```bash
# Stop node
sudo systemctl stop dilithion

# Backup (always!)
cp -r ~/.dilithion ~/.dilithion.backup.$(date +%Y%m%d)

# Download new version
cd ~/dilithion
wget https://github.com/WillBarton888/dilithion/releases/download/v1.1.0/dilithion-1.1.0-linux-x64.tar.gz

# Verify checksum
sha256sum dilithion-1.1.0-linux-x64.tar.gz

# Extract
tar -xzf dilithion-1.1.0-linux-x64.tar.gz

# Install
sudo cp dilithion-1.1.0/dilithion-node /usr/local/bin/

# Start node
sudo systemctl start dilithion

# Verify version
dilithion-node --version
```

### Monitor Node Health

**Check logs:**
```bash
sudo journalctl -u dilithion --since "1 hour ago"
tail -f ~/.dilithion/debug.log
```

**Monitor resources:**
```bash
htop           # CPU/RAM usage
df -h          # Disk space
iostat -x 1    # Disk I/O
```

**Disk space management:**
```bash
# Check blockchain size
du -sh ~/.dilithion/

# Monitor growth
watch -n 60 'du -sh ~/.dilithion/'
```

---

## Troubleshooting

### Node Won't Start

**Error:** `Failed to open blockchain database`

**Solutions:**

1. Check permissions:
```bash
ls -la ~/.dilithion/
chmod 700 ~/.dilithion
```

2. Check disk space:
```bash
df -h
```

3. If corrupted, resync:
```bash
# Backup wallet first!
cp ~/.dilithion/wallet.dat ~/wallet-backup.dat

# Remove blockchain data
rm -rf ~/.dilithion/chainstate ~/.dilithion/blocks

# Node will resync from genesis
./dilithion-node
```

### Can't Connect to Peers

**Symptoms:** 0 peer connections after 5+ minutes

**Solutions:**

1. **Check internet connection:**
```bash
ping google.com
```

2. **Check firewall:**
```bash
sudo ufw status
# Ensure 8444/tcp is allowed
```

3. **Manual peer connection:**

Edit `~/.dilithion/dilithion.conf`:
```ini
addnode=170.64.203.134:8444
addnode=seed1.dilithion.org:8444
addnode=seed2.dilithion.org:8444
```

4. **Check DNS resolution:**
```bash
nslookup seed1.dilithion.org
```

5. **Check port accessibility:**
```bash
# From external network
telnet [YOUR_PUBLIC_IP] 8444
```

### Slow Blockchain Sync

**Issue:** Sync taking very long

**Solutions:**

1. **Use SSD:** Much faster than HDD for database operations

2. **Increase database cache** in `dilithion.conf`:
```ini
dbcache=4096  # 4 GB cache (if you have 8+ GB RAM)
```

3. **More peer connections:**
```ini
maxconnections=125
```

4. **Check disk I/O:**
```bash
iostat -x 1
# High await times indicate disk bottleneck
```

5. **Verify peer quality:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getpeerinfo","params":[],"id":1}'
# Check ping times and block heights
```

### High CPU Usage

**Normal during:**
- Initial blockchain sync (verifying all signatures)
- Block validation (Dilithium3 signature verification)
- Mining (RandomX proof-of-work)

**If not mining and sustained high CPU:**

1. **Check mining status:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}'
```

2. **Stop mining if unintended:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"stopmining","params":[],"id":1}'
```

3. **Check for runaway processes:**
```bash
top -u $USER
```

### RPC Not Responding

**Error:** Connection refused on port 8332

**Solutions:**

1. **Check RPC is listening:**
```bash
netstat -tulpn | grep 8332
```

2. **Verify dilithion.conf:**
```ini
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=8332
```

3. **Check logs for errors:**
```bash
tail -50 ~/.dilithion/debug.log
```

4. **Restart node:**
```bash
sudo systemctl restart dilithion
```

### Out of Disk Space

**Error:** No space left on device

**Solutions:**

1. **Clean system temporary files:**
```bash
sudo apt clean
sudo apt autoclean
sudo apt autoremove
```

2. **Move data directory to larger disk:**
```bash
# Stop node
sudo systemctl stop dilithion

# Move data
mv ~/.dilithion /mnt/large-disk/.dilithion

# Create symlink
ln -s /mnt/large-disk/.dilithion ~/.dilithion

# Restart
sudo systemctl start dilithion
```

3. **Check for large log files:**
```bash
du -sh ~/.dilithion/*.log
```

---

## Performance Optimization

### Database Configuration

Add to `~/.dilithion/dilithion.conf`:

```ini
# Increase cache for faster sync (if RAM available)
dbcache=4096  # 4 GB cache (requires 8+ GB RAM)

# Mempool configuration
maxmempool=300  # MB
```

### Network Optimization

```ini
# Maximum connections (balance bandwidth vs decentralization)
maxconnections=125

# Bandwidth limits (optional, for metered connections)
maxuploadtarget=5000  # 5 GB/day upload limit
```

### SSD Optimization (Linux)

```bash
# Enable TRIM for SSD longevity
sudo systemctl enable fstrim.timer
sudo systemctl start fstrim.timer

# Verify TRIM is working
sudo fstrim -v /
```

---

## Next Steps

**Your Dilithion mainnet node is now running!** 🎉

### Continue Your Journey:

1. **[Mining Guide](MAINNET-MINING-GUIDE-2025-11-07.md)** - Start mining DIL with RandomX
2. **[Wallet Guide](MAINNET-WALLET-GUIDE-2025-11-07.md)** - Manage your quantum-safe wallet
3. **[Troubleshooting](TROUBLESHOOTING-2025-11-07.md)** - Detailed problem resolution

### Join the Community:

- **Website:** https://dilithion.org
- **Discord:** https://discord.gg/c25WwRNg
- **GitHub:** https://github.com/WillBarton888/dilithion
- **Reddit:** r/dilithion (coming soon)

### Support the Network:

✅ Keep your node running 24/7
✅ Enable port forwarding for inbound connections
✅ Run on a reliable server with good uptime
✅ Help newcomers in community channels

**Thank you for supporting The People's Coin!** 🛡️

---

**Document Version:** 1.0.0
**Mainnet Launch:** January 1, 2026 00:00:00 UTC
**Last Updated:** November 7, 2025

---

*Dilithion - Post-Quantum Cryptocurrency for Everyone* 🛡️
