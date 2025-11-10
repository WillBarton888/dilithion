# Testnet Phase 1 - Quick Start Guide
**Get Your Testnet Seed Nodes Running in 1-2 Hours**

---

## Overview

This quick start guide gets you from zero to 3 operational testnet seed nodes.

**Time Required:** 1-2 hours
**Cost:** ~$36/month (3 droplets @ $12 each)
**Difficulty:** Easy (copy/paste commands)

---

## Prerequisites Checklist

Before you begin, ensure you have:

- [ ] Digital Ocean account (sign up at https://cloud.digitalocean.com)
- [ ] Payment method added to DO account
- [ ] SSH key generated on your local machine
- [ ] Domain name for DNS (optional but recommended)
- [ ] This repository cloned locally

---

## Step-by-Step Process

### Step 1: Generate SSH Key (5 minutes)

**On your local machine:**

```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "dilithion-testnet-admin"

# Press Enter for default location: ~/.ssh/dilithion_testnet_ed25519
# Set a strong passphrase when prompted

# Display public key (copy this)
cat ~/.ssh/dilithion_testnet_ed25519.pub
```

**Copy the output** - you'll paste this into Digital Ocean.

---

### Step 2: Add SSH Key to Digital Ocean (2 minutes)

1. Log into Digital Ocean: https://cloud.digitalocean.com
2. Click profile icon (top right) → **Settings** → **Security**
3. Click **Add SSH Key**
4. Paste your public key
5. Name it: `dilithion-testnet-admin`
6. Click **Add SSH Key**

---

### Step 3: Create 3 Droplets (15-20 minutes)

Create these 3 droplets with identical settings (except region/hostname):

#### Droplet 1: NYC
- **Region:** New York 3 (NYC3)
- **Image:** Ubuntu 22.04 LTS x64
- **Plan:** Basic / Regular / $12/mo (2GB RAM, 1 CPU, 50GB SSD)
- **Authentication:** Select your SSH key (`dilithion-testnet-admin`)
- **Hostname:** `dilithion-testnet-nyc`
- **Advanced:** ✅ Enable IPv6, ✅ Enable Monitoring
- **Tags:** `dilithion`, `testnet`, `seed-node`

#### Droplet 2: London
- **Region:** London 1 (LON1)
- **Hostname:** `dilithion-testnet-lon`
- *(All other settings same as Droplet 1)*

#### Droplet 3: Singapore
- **Region:** Singapore 1 (SGP1)
- **Hostname:** `dilithion-testnet-sgp`
- *(All other settings same as Droplet 1)*

**Wait 2-3 minutes** for all droplets to finish provisioning.

---

### Step 4: Document IP Addresses (2 minutes)

On your local machine, create a file with your droplet IPs:

```bash
# Create tracking file
cat > ~/dilithion-testnet-ips.txt <<EOF
# NYC Droplet
NYC_IP=[PASTE_IP_FROM_DO_DASHBOARD]

# London Droplet
LON_IP=[PASTE_IP_FROM_DO_DASHBOARD]

# Singapore Droplet
SGP_IP=[PASTE_IP_FROM_DO_DASHBOARD]
EOF
```

Replace the bracketed values with actual IPs from Digital Ocean dashboard.

---

### Step 5: Initial Security Setup (15 minutes per droplet = 45 minutes)

**For each droplet, SSH in and run these commands:**

#### Connect to Droplet

```bash
# Replace with your droplet's IP
ssh -i ~/.ssh/dilithion_testnet_ed25519 root@YOUR_DROPLET_IP
```

#### Update System & Install Essentials

```bash
# Update everything
apt update && apt upgrade -y

# Install required tools
apt install -y curl wget git build-essential ufw fail2ban htop unattended-upgrades

# Enable automatic security updates
dpkg-reconfigure -plow unattended-upgrades
# Select "Yes"
```

#### Configure Firewall

```bash
# Allow SSH
ufw allow 22/tcp

# Allow Dilithion testnet P2P
ufw allow 18444/tcp

# Enable firewall
ufw --force enable

# Verify
ufw status
```

Expected output:
```
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
18444/tcp                  ALLOW       Anywhere
```

#### Enable Fail2Ban

```bash
systemctl enable fail2ban
systemctl start fail2ban
systemctl status fail2ban
```

---

### Step 6: Install Dilithion Testnet Node (10 minutes per droplet = 30 minutes)

**Still on each droplet:**

```bash
# Clone repository
cd /root
git clone https://github.com/YOUR_ORG/dilithion.git
cd dilithion

# Make installation script executable
chmod +x scripts/install-testnet-2025-11-07.sh

# Run installation (automatic mode)
./scripts/install-testnet-2025-11-07.sh --auto

# This will:
# - Install dependencies
# - Build from source
# - Configure testnet
# - Create systemd service
# - Start node
```

**Installation takes 5-10 minutes.** You'll see:
- Dependencies installing
- Dilithium library building
- Main node building
- Configuration being created
- Service starting

---

### Step 7: Verify Installation (5 minutes per droplet)

**On each droplet:**

```bash
# Check service status
systemctl status dilithion-testnet

# Should show: Active: active (running)

# Check blockchain info
dilithion-cli -testnet getblockchaininfo

# Check peer connections
dilithion-cli -testnet getconnectioncount

# Should show: 1-8 peers (will grow over time)

# Watch logs (Ctrl+C to exit)
journalctl -u dilithion-testnet -f
```

**Success indicators:**
- ✅ Service status: "Active: active (running)"
- ✅ Blockchain syncing (blocks > 0)
- ✅ Peers connecting (count > 0)
- ✅ No errors in logs

---

### Step 8: Configure DNS (10 minutes) - OPTIONAL

If you have a domain, configure DNS:

**Add these A records:**
```
testnet-seed.dilithion.org   → NYC_DROPLET_IP
testnet-seed1.dilithion.org  → NYC_DROPLET_IP
testnet-seed2.dilithion.org  → LON_DROPLET_IP
testnet-seed3.dilithion.org  → SGP_DROPLET_IP
```

**Test DNS (wait 5-10 minutes for propagation):**
```bash
dig testnet-seed.dilithion.org
dig testnet-seed1.dilithion.org
dig testnet-seed2.dilithion.org
dig testnet-seed3.dilithion.org
```

---

## Verification Checklist

After completing all steps, verify:

**Infrastructure:**
- [ ] 3 Digital Ocean droplets created
- [ ] All droplets accessible via SSH
- [ ] Firewall enabled on all droplets
- [ ] Fail2ban running on all droplets

**Dilithion Nodes:**
- [ ] Testnet node installed on all 3 droplets
- [ ] Systemd service running on all 3 droplets
- [ ] Blockchain syncing on all 3 nodes
- [ ] Peer connections on all 3 nodes (1-8+ peers)

**Monitoring:**
- [ ] Can check status with systemctl
- [ ] Can view logs with journalctl
- [ ] No errors in logs

**Optional:**
- [ ] DNS configured and resolving
- [ ] All DNS records pointing correctly

---

## Quick Reference Commands

### From Your Local Machine

```bash
# SSH into droplet
ssh -i ~/.ssh/dilithion_testnet_ed25519 root@DROPLET_IP

# Check all droplets at once (if you have 3 terminal windows)
# Terminal 1:
ssh -i ~/.ssh/dilithion_testnet_ed25519 root@NYC_IP

# Terminal 2:
ssh -i ~/.ssh/dilithion_testnet_ed25519 root@LON_IP

# Terminal 3:
ssh -i ~/.ssh/dilithion_testnet_ed25519 root@SGP_IP
```

### On Each Droplet

```bash
# Service management
systemctl status dilithion-testnet
systemctl restart dilithion-testnet
systemctl stop dilithion-testnet
systemctl start dilithion-testnet

# Node interaction
dilithion-cli -testnet getblockchaininfo
dilithion-cli -testnet getpeerinfo
dilithion-cli -testnet getconnectioncount
dilithion-cli -testnet getnetworkinfo

# Logs
journalctl -u dilithion-testnet -f              # Follow live logs
journalctl -u dilithion-testnet -n 100          # Last 100 lines
journalctl -u dilithion-testnet --since "1 hour ago"

# System monitoring
htop                    # CPU/RAM usage
df -h                   # Disk usage
free -h                 # Memory usage
ufw status              # Firewall status
```

---

## Troubleshooting

### Can't SSH into droplet
```bash
# Check you're using correct key
ssh -i ~/.ssh/dilithion_testnet_ed25519 root@DROPLET_IP -v

# If connection refused, check firewall allows port 22
# If permission denied, verify SSH key is added to DO
```

### Service won't start
```bash
# Check logs for errors
journalctl -u dilithion-testnet -n 50

# Check if binary exists
which dilithiond
ls -la /usr/local/bin/dilithiond

# Try starting manually
/usr/local/bin/dilithiond -testnet -daemon

# Check if already running
ps aux | grep dilithiond
```

### No peer connections
```bash
# Check firewall allows P2P port
ufw status | grep 18444

# Check node is listening
netstat -an | grep 18444

# Check logs for connection attempts
tail -f ~/.dilithion/testnet/debug.log | grep "connection"

# May take 5-10 minutes to find peers initially
```

### Blockchain not syncing
```bash
# Check block count
dilithion-cli -testnet getblockcount

# Check sync status
dilithion-cli -testnet getblockchaininfo | grep -E "(blocks|headers|verificationprogress)"

# If blocks = 0 after 10 minutes, check logs
journalctl -u dilithion-testnet -n 100
```

---

## Next Steps

Once all 3 droplets are running successfully:

**Phase 1 Complete! Now proceed to:**

1. ✅ **Update chainparams.cpp** with seed node IPs
2. ✅ **Deploy monitoring** (Prometheus/Grafana)
3. ✅ **Run security scans**
4. ✅ **Test all automation scripts**
5. ✅ **Begin 7-day stability test**

**See:** `TESTNET-VALIDATION-PLAN-2025-11-07.md` for complete testing plan

---

## Cost Breakdown

**Monthly costs:**
- 3 droplets @ $12/month = **$36/month**
- Bandwidth included (3-4TB per droplet)
- Total: **$36/month** for testnet validation

**One-time costs:**
- Domain registration (if needed): ~$10-15/year
- None other

**Can destroy after testing** - total cost for 3-week testnet validation: ~$27-36

---

## Support & Documentation

**Full Documentation:**
- `docs/DIGITAL-OCEAN-SETUP-GUIDE-2025-11-07.md` - Detailed DO setup
- `TESTNET-VALIDATION-PLAN-2025-11-07.md` - Complete testing plan
- `scripts/install-testnet-2025-11-07.sh` - Installation script

**Get Help:**
- Check logs: `journalctl -u dilithion-testnet -f`
- Review debug log: `tail -f ~/.dilithion/testnet/debug.log`
- Verify configuration: `cat ~/.dilithion/dilithion.conf`

---

## Success!

If you've completed all steps and verification passes, you now have:

✅ 3 geographically distributed testnet seed nodes
✅ All nodes running and syncing
✅ Firewall configured and secured
✅ Automatic security updates enabled
✅ Ready for Phase 2 testing

**Congratulations! Phase 1 complete.** 🎉

---

**Time to Complete:** 1-2 hours
**Next Phase:** Monitoring & Validation (Week 1-2)
**Final Goal:** Rigorous testnet validation before mainnet launch

---

*Dilithion - Test Rigorously, Launch Confidently* 🔐✅
