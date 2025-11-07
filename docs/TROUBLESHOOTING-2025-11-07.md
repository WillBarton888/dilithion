# Dilithion Mainnet Troubleshooting Guide

**Version:** 1.0.0
**Network:** Mainnet
**Launch Date:** January 1, 2026 00:00:00 UTC
**Last Updated:** November 7, 2025

Comprehensive troubleshooting guide for resolving common Dilithion node, mining, and wallet issues.

---

## Table of Contents

1. [Node Issues](#node-issues)
2. [Mining Issues](#mining-issues)
3. [Wallet Issues](#wallet-issues)
4. [Network Issues](#network-issues)
5. [Platform-Specific Issues](#platform-specific-issues)
6. [Performance Issues](#performance-issues)
7. [Diagnostic Tools](#diagnostic-tools)
8. [Recovery Procedures](#recovery-procedures)
9. [Getting Help](#getting-help)

---

## Node Issues

### Node Won't Start

**Symptoms:** `dilithion-node` exits immediately or fails to initialize

#### Error: "Failed to open blockchain database"

**Cause:** Database corruption or permission issues

**Solutions:**

1. **Check file permissions:**
```bash
ls -la ~/.dilithion/
chmod 700 ~/.dilithion
chmod 600 ~/.dilithion/wallet.dat
```

2. **Check disk space:**
```bash
df -h
# Need at least 1-2 GB free
```

3. **Database corruption - resync:**
```bash
# BACKUP WALLET FIRST!
cp ~/.dilithion/wallet.dat ~/wallet-backup.dat

# Remove blockchain data
rm -rf ~/.dilithion/chainstate ~/.dilithion/blocks

# Restart node (will resync from genesis)
./dilithion-node
```

4. **Check for lock file:**
```bash
rm ~/.dilithion/.lock
```

#### Error: "Cannot obtain a lock on data directory"

**Cause:** Another instance already running

**Solutions:**

1. **Check for running processes:**
```bash
ps aux | grep dilithion-node
```

2. **Kill existing process:**
```bash
pkill dilithion-node
# Wait 5 seconds
./dilithion-node
```

3. **Remove stale lock file:**
```bash
rm ~/.dilithion/.lock
```

#### Error: "Bind to port 8444 failed"

**Cause:** Port already in use

**Solutions:**

1. **Check what's using port:**
```bash
lsof -i :8444
# or
netstat -tulpn | grep 8444
```

2. **Use different port:**
```bash
./dilithion-node --port=8445
```

3. **Kill conflicting process:**
```bash
kill [PID from lsof command]
```

### Node Crashes Randomly

**Symptoms:** Node runs for hours/days then exits

#### Memory Issues

**Check system memory:**
```bash
free -h
dmesg | grep -i "out of memory"
```

**Solutions:**

1. **Add swap space:**
```bash
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
# Make permanent
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

2. **Reduce database cache:**

Edit `~/.dilithion/dilithion.conf`:
```ini
dbcache=1024  # Reduce from default
```

#### Disk Issues

**Check disk errors:**
```bash
dmesg | grep -i error
sudo smartctl -a /dev/sda  # Replace sda with your drive
```

**Solutions:**

1. **Use SSD instead of HDD**
2. **Check disk health regularly**
3. **Move to different drive if failing**

### Blockchain Sync Stuck

**Symptoms:** Block height not increasing

**Diagnose:**

```bash
# Check current height
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' | jq .result.blocks

# Check peer count
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getpeerinfo","params":[],"id":1}' | jq length
```

**Solutions:**

1. **No peers - check network connectivity:**
```bash
ping dilithion.org
# Check firewall allows port 8444
```

2. **Few peers - add seed nodes:**

Edit `~/.dilithion/dilithion.conf`:
```ini
addnode=170.64.203.134:8444
addnode=seed1.dilithion.org:8444
addnode=seed2.dilithion.org:8444
```

3. **Slow sync - check disk I/O:**
```bash
iostat -x 1
# High await times = slow disk
```

4. **Corrupted blocks - reindex:**
```bash
./dilithion-node -reindex
```

---

## Mining Issues

### Mining Not Starting

**Symptoms:** `--mine` flag set but no hashing

**Diagnose:**

```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}'
```

**Check:**
- `"mining": true` - Should be true
- `"threads": X` - Should match --threads value
- `"hashrate": 0` - If zero, mining isn't working

**Solutions:**

1. **Node must be fully synced first:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' | jq '.result | {blocks, headers}'
# blocks should equal headers
```

2. **Restart with mining explicitly:**
```bash
pkill dilithion-node
./dilithion-node --mine --threads=8
```

3. **Check logs for errors:**
```bash
tail -f ~/.dilithion/debug.log | grep -i mining
```

### Low Hashrate

**Expected:** ~65 H/s per CPU core
**Actual:** Significantly lower

**Causes and Solutions:**

#### 1. Thermal Throttling

**Check temperature:**
```bash
# Linux
sensors | grep Core
# Should be <80°C
```

**Solutions:**
- Clean CPU heatsink/fans
- Improve case airflow
- Replace thermal paste
- Upgrade CPU cooler

#### 2. Huge Pages Not Enabled (Linux)

**Check huge pages:**
```bash
cat /proc/meminfo | grep HugePages_Free
```

**Enable:**
```bash
sudo sysctl -w vm.nr_hugepages=8192
```

Expected improvement: 10-15% hashrate

#### 3. CPU Downclocking

**Check CPU frequency:**
```bash
watch -n 1 'cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq'
```

**Solutions:**

Set performance governor:
```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

Disable C-States in BIOS

#### 4. Background Processes

**Check CPU usage:**
```bash
top
# Look for other high CPU processes
```

**Solutions:**
- Close unnecessary applications
- Disable browser/Electron apps
- Schedule backups for non-mining times

#### 5. Incorrect Thread Count

**Too many threads = overhead**

**Optimal:**
```bash
# Desktop use
./dilithion-node --mine --threads=$(nproc --ignore=1)

# Dedicated mining
./dilithion-node --mine --threads=$(nproc)
```

### Mining Errors

#### Error: "Failed to allocate RandomX dataset"

**Cause:** Insufficient RAM

**Memory required:**
- Fast mode: ~2 GB per thread
- Light mode: ~256 MB per thread

**Solutions:**

1. **Reduce threads:**
```bash
./dilithion-node --mine --threads=4
```

2. **Add RAM:**
- Upgrade to 16+ GB for serious mining

3. **Enable swap (temporary fix, slower):**
```bash
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

#### Error: "Block rejected - invalid proof of work"

**Causes:**

1. **System clock incorrect:**
```bash
# Check time
date
timedatectl

# Sync time
sudo timedatectl set-ntp true
# or
sudo ntpdate pool.ntp.org
```

2. **Stale block:**
- Another miner found same height first
- Normal occurrence, keep mining

3. **Blockchain corruption:**
```bash
./dilithion-node -reindex
```

### No Blocks Found

**Symptoms:** Mining for hours/days without finding blocks

**This is normal!**

**Calculate expected time:**
```
Time to block = (Network Hashrate / Your Hashrate) × 4 minutes
```

**Example:**
- Your hashrate: 500 H/s
- Network hashrate: 50,000 H/s
- Expected time: (50,000 / 500) × 4 = 400 minutes = 6.7 hours

**At scale:**
- Network hashrate: 1,000,000 H/s
- Your hashrate: 500 H/s
- Expected time: 133 hours = 5.5 days

**This is luck-based (Poisson distribution)**

**Solutions:**
- Increase hashrate (better CPU, more systems)
- Be patient (variance is high for small miners)
- Consider pool mining when available

---

## Wallet Issues

### Cannot Access Wallet

#### Error: "Error loading wallet.dat"

**Causes:** Corruption or encryption issues

**Solutions:**

1. **Check file exists:**
```bash
ls -l ~/.dilithion/wallet.dat
```

2. **Restore from backup:**
```bash
cp ~/wallet-backup.dat ~/.dilithion/wallet.dat
chmod 600 ~/.dilithion/wallet.dat
```

3. **Salvage wallet:**
```bash
./dilithion-node -salvagewallet
```

4. **Create new wallet (last resort):**
```bash
mv ~/.dilithion/wallet.dat ~/.dilithion/wallet.dat.corrupt
./dilithion-node
# Then import private keys from old wallet
```

#### Error: "The wallet passphrase entered was incorrect"

**Lost passphrase = lost funds** (no recovery possible)

**Try:**
1. Variations (caps lock, typos)
2. Password manager entries
3. Family members (if shared)
4. Old backup notes

**If truly lost:**
- Funds in encrypted wallet are unrecoverable
- Restore from unencrypted backup (if exists)

### Balance Not Showing

**Symptoms:** Sent funds not appearing

**Diagnose:**

1. **Check sync status:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'
```

Ensure `blocks == headers`

2. **Verify transaction broadcast:**
- Check transaction ID on block explorer
- Confirm transaction exists in network

3. **Rescan blockchain:**
```bash
./dilithion-node -rescan
# Takes time, rescans all blocks for your addresses
```

### Transaction Issues

#### Transaction Stuck (Unconfirmed)

**Causes:**
- Fee too low
- Network congestion
- Double-spend attempt

**Diagnose:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"gettransaction","params":["TXID"],"id":1}'
```

Check confirmations field.

**Solutions:**

1. **Wait:** May confirm in next block
2. **Check mempool:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getrawmempool","params":[],"id":1}'
```

3. **If not in mempool, rebroadcast:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"sendrawtransaction","params":["<hex>"],"id":1}'
```

#### Insufficient Funds

**Error:** "Insufficient funds"

**Causes:**

1. **Balance includes immature coinbase:**
```bash
# Check mature vs immature
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalances","params":[],"id":1}'
```

Mined coins need 100 confirmations (6.7 hours)

2. **Forgot transaction fees:**
- Sending 10.0 DIL requires >10.0 in balance (fees ~0.001)

3. **UTXOs locked:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"listlockunspent","params":[],"id":1}'
```

---

## Network Issues

### No Peer Connections

**Symptoms:** 0 peers after 5+ minutes

**Diagnose:**

```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getpeerinfo","params":[],"id":1}' | jq length
```

**Causes and Solutions:**

#### 1. Firewall Blocking

**Test port accessibility:**
```bash
# From external network
telnet [YOUR_PUBLIC_IP] 8444
```

**Configure firewall:**
```bash
# Ubuntu/Debian
sudo ufw allow 8444/tcp

# Fedora/RHEL
sudo firewall-cmd --permanent --add-port=8444/tcp
sudo firewall-cmd --reload
```

#### 2. ISP Blocking

Some ISPs block cryptocurrency ports.

**Solutions:**
- Use VPN
- Contact ISP support
- Use non-standard port (`--port=9444`)

#### 3. Router Not Forwarding

**Configure port forwarding:**
1. Access router (usually http://192.168.1.1)
2. Port Forwarding section
3. Forward 8444 → Your local IP

#### 4. DNS Issues

**Test DNS resolution:**
```bash
nslookup seed1.dilithion.org
```

**Manual seed nodes:**

Edit `~/.dilithion/dilithion.conf`:
```ini
addnode=170.64.203.134:8444
connect=170.64.203.134:8444
```

### Slow Block Propagation

**Symptoms:** Blocks arrive minutes after being mined

**Causes:**
- Poor network connectivity
- Low peer quality
- Bandwidth limitations

**Solutions:**

1. **Increase peer connections:**
```ini
maxconnections=125
```

2. **Add high-quality peers:**
```ini
addnode=seed1.dilithion.org:8444
addnode=seed2.dilithion.org:8444
```

3. **Check network latency:**
```bash
ping seed1.dilithion.org
# Want <100ms latency
```

4. **Upgrade internet connection** (if possible)

---

## Platform-Specific Issues

### Linux Issues

#### Permission Denied Errors

**Fix ownership:**
```bash
sudo chown -R $USER:$USER ~/.dilithion
chmod 700 ~/.dilithion
chmod 600 ~/.dilithion/wallet.dat
```

#### Missing Libraries

**Error:** "error while loading shared libraries"

**Install dependencies:**
```bash
# Ubuntu/Debian
sudo apt install -y libleveldb-dev libssl-dev

# Fedora
sudo dnf install -y leveldb-devel openssl-devel

# Arch
sudo pacman -S leveldb openssl
```

#### Systemd Service Not Starting

**Check logs:**
```bash
sudo journalctl -u dilithion -n 50
```

**Common fixes:**

1. **Fix service file permissions:**
```bash
sudo chmod 644 /etc/systemd/system/dilithion.service
sudo systemctl daemon-reload
```

2. **Check binary path:**
```bash
which dilithion-node
# Update ExecStart in service file if different
```

3. **Verify user exists:**
```bash
id dilithion  # If running as dilithion user
```

### Windows Issues

#### Windows Defender False Positive

**Symptoms:** dilithion-node.exe quarantined/deleted

**Cause:** Cryptocurrency miners often flagged (false positive)

**Solutions:**

1. **Add exclusion:**
- Windows Security → Virus & threat protection
- Manage settings → Exclusions → Add exclusion
- Add folder: `C:\Users\YourName\dilithion\`

2. **Temporarily disable real-time protection** (during download/install only)

3. **Download from official GitHub releases only**

#### WSL2 Network Issues

**Symptoms:** Can't connect to peers in WSL2

**Solutions:**

1. **Check WSL2 networking:**
```bash
ip addr show eth0
# Should have 172.x.x.x address
```

2. **Port forwarding from Windows:**
```powershell
# Run as Administrator in PowerShell
netsh interface portproxy add v4tov4 listenport=8444 listenaddress=0.0.0.0 connectport=8444 connectaddress=172.x.x.x
```

Replace 172.x.x.x with WSL2 IP from step 1.

3. **Allow through Windows Firewall:**
- Windows Firewall → Advanced → Inbound Rules
- New Rule → Port 8444 TCP → Allow

#### PATH Issues

**Error:** "dilithion-node is not recognized"

**Solutions:**

1. **Run from directory:**
```cmd
cd C:\dilithion
.\dilithion-node.exe
```

2. **Add to PATH:**
- System Properties → Advanced → Environment Variables
- Edit PATH → Add `C:\dilithion\`

### macOS Issues

#### Gatekeeper Blocking

**Error:** "dilithion-node cannot be opened because the developer cannot be verified"

**Solutions:**

1. **Remove quarantine attribute:**
```bash
xattr -d com.apple.quarantine dilithion-node
```

2. **Or allow in System Preferences:**
- System Preferences → Security & Privacy
- Click "Allow Anyway" for dilithion-node

#### Code Signing Issues

**For self-compiled binaries:**

```bash
# Sign locally (developer account not required for personal use)
codesign -s - dilithion-node
```

#### Permission Issues

**Fix permissions:**
```bash
chmod +x dilithion-node
chmod 700 ~/.dilithion
```

---

## Performance Issues

### High CPU Usage (When Not Mining)

**Normal CPU usage when NOT mining:** 5-15%

**Diagnose:**

```bash
top
# Find dilithion-node process
```

**Causes:**

1. **Mining accidentally enabled:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}'
```

If mining=true, stop it:
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"stopmining","params":[],"id":1}'
```

2. **Initial sync:** High CPU during signature verification is normal

3. **Many transactions:** Processing large blocks

### High Memory Usage

**Normal:** 500 MB - 2 GB (depending on cache settings)

**Reduce memory:**

Edit `~/.dilithion/dilithion.conf`:
```ini
dbcache=512  # Reduce cache (default 4096)
maxmempool=50  # Reduce mempool size
```

### Slow Disk I/O

**Check disk performance:**
```bash
iostat -x 1
# High await times = bottleneck
```

**Solutions:**

1. **Use SSD instead of HDD**
2. **Check disk health:**
```bash
sudo smartctl -a /dev/sda
```

3. **Defragment (Windows)** or **TRIM (Linux/SSD)**

---

## Diagnostic Tools

### Log Files

**Main log:**
```bash
tail -f ~/.dilithion/debug.log
```

**Filter for errors:**
```bash
grep -i error ~/.dilithion/debug.log
```

**Filter for mining:**
```bash
grep -i mining ~/.dilithion/debug.log | tail -50
```

### RPC Diagnostics

**Node information:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getnetworkinfo","params":[],"id":1}' | jq
```

**Blockchain status:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' | jq
```

**Peer information:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getpeerinfo","params":[],"id":1}' | jq
```

### System Diagnostics

**CPU:**
```bash
lscpu
cat /proc/cpuinfo | grep "model name" | head -1
```

**Memory:**
```bash
free -h
```

**Disk:**
```bash
df -h
du -sh ~/.dilithion
```

**Network:**
```bash
netstat -tulpn | grep dilithion
ss -tulpn | grep 8444
```

---

## Recovery Procedures

### Wallet Recovery

**From backup:**
```bash
# Stop node
systemctl stop dilithion

# Restore wallet
cp ~/wallet-backup.dat ~/.dilithion/wallet.dat
chmod 600 ~/.dilithion/wallet.dat

# Restart and rescan
./dilithion-node -rescan
```

### Database Corruption Recovery

**Reindex blockchain:**
```bash
./dilithion-node -reindex
```

**Complete resync:**
```bash
# BACKUP WALLET FIRST!
cp ~/.dilithion/wallet.dat ~/wallet-backup.dat

# Remove blockchain data
rm -rf ~/.dilithion/chainstate ~/.dilithion/blocks

# Restart (will download from scratch)
./dilithion-node
```

### Clean Reinstall

**Full clean slate:**

```bash
# 1. Backup wallet
cp ~/.dilithion/wallet.dat ~/wallet-backup-SAFE.dat

# 2. Remove all data
rm -rf ~/.dilithion

# 3. Reinstall dilithion-node

# 4. Restore wallet
mkdir -p ~/.dilithion
cp ~/wallet-backup-SAFE.dat ~/.dilithion/wallet.dat

# 5. Start fresh
./dilithion-node
```

---

## Getting Help

### Before Asking for Help

1. **Check logs:**
```bash
tail -100 ~/.dilithion/debug.log
```

2. **Collect system info:**
```bash
uname -a
cat /etc/os-release
dilithion-node --version
```

3. **Try diagnostic commands above**

### Where to Get Help

**Official Channels:**
- **Discord:** https://discord.gg/c25WwRNg (#support channel)
- **GitHub Issues:** https://github.com/WillBarton888/dilithion/issues
- **Reddit:** r/dilithion (coming soon)

**When Reporting Issues:**

Include:
1. Operating system and version
2. Dilithion version (`dilithion-node --version`)
3. Error messages (exact text)
4. Relevant log excerpts
5. Steps to reproduce

**DO NOT share:**
- ❌ Private keys
- ❌ Wallet file
- ❌ Passphrases
- ❌ Seed phrases

### Emergency Contacts

**Critical network issues:**
- Discord: @moderator
- Email: support@dilithion.org

**Security vulnerabilities:**
- Email: security@dilithion.org
- GPG key: [provided on website]

---

## Additional Resources

- **[Node Setup Guide](MAINNET-NODE-SETUP-2025-11-07.md)** - Complete installation
- **[Mining Guide](MAINNET-MINING-GUIDE-2025-11-07.md)** - Mining optimization
- **[Wallet Guide](MAINNET-WALLET-GUIDE-2025-11-07.md)** - Wallet management

**Community Resources:**
- Website: https://dilithion.org
- Documentation: https://docs.dilithion.org
- Block Explorer: https://explorer.dilithion.org (coming soon)

---

**Document Version:** 1.0.0
**Mainnet Launch:** January 1, 2026 00:00:00 UTC
**Last Updated:** November 7, 2025

---

*Dilithion - Post-Quantum Cryptocurrency - We're Here to Help!* 🛡️
