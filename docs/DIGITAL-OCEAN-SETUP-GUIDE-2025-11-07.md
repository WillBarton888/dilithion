# Digital Ocean Droplet Setup Guide - Testnet
**Dilithion Testnet Seed Node Deployment**

---

## Overview

This guide walks through setting up 3-5 testnet seed nodes on Digital Ocean droplets.

**Cost:** ~$36-60/month for 3-5 droplets
**Time:** ~30-60 minutes for initial setup
**Difficulty:** Easy

---

## Prerequisites

- [ ] Digital Ocean account (sign up at digitalocean.com)
- [ ] Payment method added to account
- [ ] SSH key generated on your local machine
- [ ] Domain name for DNS configuration (or use DO's nameservers)

---

## Step 1: Generate SSH Key (if not already done)

**On your local machine:**

```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -C "dilithion-testnet-admin"

# Save to: ~/.ssh/dilithion_testnet_ed25519
# Set a strong passphrase

# Display public key (you'll add this to Digital Ocean)
cat ~/.ssh/dilithion_testnet_ed25519.pub
```

**Copy the public key output** - you'll need it in Step 3.

---

## Step 2: Log into Digital Ocean

1. Go to https://cloud.digitalocean.com/
2. Log in to your account
3. If new account, complete verification and add payment method

---

## Step 3: Add SSH Key to Digital Ocean

1. Click on your profile (top right)
2. Go to **Settings** → **Security**
3. Click **Add SSH Key**
4. Paste your public key from Step 1
5. Name it: `dilithion-testnet-admin`
6. Click **Add SSH Key**

---

## Step 4: Create Droplets for Testnet Seed Nodes

We'll create **3 droplets** for testnet (can expand to 5 later).

### Droplet 1: NYC (North America)

1. Click **Create** → **Droplets**
2. **Choose Region:** New York 3 (NYC3)
3. **Choose Image:** Ubuntu 22.04 LTS x64
4. **Choose Size:**
   - Droplet Type: **Basic**
   - CPU Options: **Regular**
   - Select: **$12/mo** (2 GB RAM / 1 vCPU / 50 GB SSD)
5. **Choose Authentication:**
   - Select **SSH Keys**
   - Check your `dilithion-testnet-admin` key
6. **Finalize Details:**
   - Hostname: `dilithion-testnet-nyc`
   - Tags: `dilithion`, `testnet`, `seed-node`
   - Project: Create new or select existing
7. **Advanced Options:**
   - [x] Enable IPv6
   - [x] Enable Monitoring
   - [ ] Don't enable backups yet (can add later)
8. Click **Create Droplet**

**Wait 1-2 minutes for droplet creation**

### Droplet 2: London (Europe)

Repeat the same process:
- **Region:** London 1 (LON1)
- **Hostname:** `dilithion-testnet-lon`
- **All other settings same as Droplet 1**

### Droplet 3: Singapore (Asia)

Repeat the same process:
- **Region:** Singapore 1 (SGP1)
- **Hostname:** `dilithion-testnet-sgp`
- **All other settings same as Droplet 1**

### Optional: Droplet 4 & 5

If you want 5 seed nodes:
- **Droplet 4:** San Francisco 3 (SFO3) - `dilithion-testnet-sfo`
- **Droplet 5:** Frankfurt 1 (FRA1) - `dilithion-testnet-fra`

---

## Step 5: Document Droplet Information

Once all droplets are created, document their details:

```bash
# Create a file to track your droplets
cat > ~/dilithion-testnet-droplets.txt <<EOF
# Dilithion Testnet Seed Nodes
# Created: $(date)

# Droplet 1: NYC
Hostname: dilithion-testnet-nyc
IPv4: [COPY FROM DIGITAL OCEAN]
IPv6: [COPY FROM DIGITAL OCEAN]
Region: NYC3

# Droplet 2: London
Hostname: dilithion-testnet-lon
IPv4: [COPY FROM DIGITAL OCEAN]
IPv6: [COPY FROM DIGITAL OCEAN]
Region: LON1

# Droplet 3: Singapore
Hostname: dilithion-testnet-sgp
IPv4: [COPY FROM DIGITAL OCEAN]
IPv6: [COPY FROM DIGITAL OCEAN]
Region: SGP1
EOF
```

**Fill in the IP addresses** from the Digital Ocean dashboard.

---

## Step 6: Initial Security Setup (For Each Droplet)

**Connect to each droplet and perform initial hardening:**

### Connect to Droplet

```bash
# Replace with your droplet's IP address
ssh -i ~/.ssh/dilithion_testnet_ed25519 root@DROPLET_IP
```

### Update System

```bash
# Update package lists
apt update

# Upgrade all packages
apt upgrade -y

# Install essential tools
apt install -y curl wget git build-essential ufw fail2ban htop
```

### Configure Firewall (UFW)

```bash
# Allow SSH (default port 22)
ufw allow 22/tcp

# Allow Dilithion testnet P2P port
ufw allow 18444/tcp

# Enable firewall
ufw --force enable

# Verify status
ufw status
```

Expected output:
```
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
18444/tcp                  ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
18444/tcp (v6)             ALLOW       Anywhere (v6)
```

### Enable Automatic Security Updates

```bash
# Install unattended-upgrades
apt install -y unattended-upgrades

# Enable automatic updates
dpkg-reconfigure -plow unattended-upgrades
# Select "Yes" when prompted
```

### Configure Fail2Ban (Brute Force Protection)

```bash
# Fail2ban is already installed, just enable it
systemctl enable fail2ban
systemctl start fail2ban

# Verify it's running
systemctl status fail2ban
```

### Create Non-Root User (Optional but Recommended)

```bash
# Create dilithion user
adduser dilithion
# Set a strong password

# Add to sudo group
usermod -aG sudo dilithion

# Copy SSH key to dilithion user
mkdir -p /home/dilithion/.ssh
cp /root/.ssh/authorized_keys /home/dilithion/.ssh/
chown -R dilithion:dilithion /home/dilithion/.ssh
chmod 700 /home/dilithion/.ssh
chmod 600 /home/dilithion/.ssh/authorized_keys

# Test SSH access as dilithion user (from your local machine)
# ssh -i ~/.ssh/dilithion_testnet_ed25519 dilithion@DROPLET_IP
```

### Disable Root SSH Login (After Confirming User Access)

```bash
# Edit SSH config
nano /etc/ssh/sshd_config

# Find and change:
PermitRootLogin yes
# to:
PermitRootLogin no

# Also ensure:
PasswordAuthentication no
PubkeyAuthentication yes

# Save and exit (Ctrl+X, Y, Enter)

# Restart SSH
systemctl restart sshd
```

**IMPORTANT:** Test SSH access with dilithion user BEFORE disabling root login!

---

## Step 7: Install Dilithion Node (Testnet)

Now we'll install the Dilithion node using our installation script.

**On each droplet:**

```bash
# Change to dilithion user (if using non-root)
su - dilithion

# Or if still root, that's fine for now

# Download the testnet installation script
# (We'll create this script in the next step)
wget https://raw.githubusercontent.com/YOUR_REPO/dilithion/main/scripts/install-testnet-2025-11-07.sh

# Make executable
chmod +x install-testnet-2025-11-07.sh

# Run installation
sudo ./install-testnet-2025-11-07.sh
```

**Note:** We need to create the testnet-specific installation script (coming next).

---

## Step 8: Configure DNS (After All Droplets Are Running)

Once all droplets are operational, configure DNS:

### Option A: Using Digital Ocean DNS

1. Go to **Networking** → **Domains**
2. Add your domain (e.g., dilithion.org)
3. Add A records:
   ```
   testnet-seed   → Points to NYC droplet IP
   testnet-seed1  → Points to NYC droplet IP
   testnet-seed2  → Points to London droplet IP
   testnet-seed3  → Points to Singapore droplet IP
   ```
4. Add AAAA records (IPv6):
   ```
   testnet-seed   → Points to NYC droplet IPv6
   testnet-seed1  → Points to NYC droplet IPv6
   testnet-seed2  → Points to London droplet IPv6
   testnet-seed3  → Points to Singapore droplet IPv6
   ```

### Option B: Using External DNS Provider

If using Cloudflare, Route53, etc.:
- Add A/AAAA records as shown above
- Use your DNS provider's interface

### Verify DNS Configuration

```bash
# Wait 5-10 minutes for DNS propagation, then test:
dig testnet-seed.dilithion.org
dig testnet-seed1.dilithion.org
dig testnet-seed2.dilithion.org
dig testnet-seed3.dilithion.org

# All should return the correct IP addresses
```

---

## Step 9: Verification Checklist

After all droplets are set up, verify:

**For Each Droplet:**
- [ ] Can SSH into droplet
- [ ] System updated (apt update && apt upgrade)
- [ ] Firewall enabled and configured
- [ ] Fail2ban running
- [ ] Non-root user created (if using)
- [ ] Dilithion node installed
- [ ] Dilithion service running
- [ ] Blockchain syncing

**Verification Commands:**
```bash
# Check service status
systemctl status dilithion-testnet

# Check blockchain info
dilithion-cli -testnet getblockchaininfo

# Check peer connections
dilithion-cli -testnet getconnectioncount

# Check logs
journalctl -u dilithion-testnet -f
```

**Overall:**
- [ ] All 3 droplets operational
- [ ] DNS configured and resolving
- [ ] All nodes connecting to testnet
- [ ] All nodes have 8+ peer connections

---

## Step 10: Monitoring Setup

Install monitoring on each droplet or use central monitoring server.

```bash
# We'll use the monitoring scripts from Phase 2
# (Installation instructions coming in next phase)
```

---

## Troubleshooting

### Can't Connect via SSH
```bash
# Check firewall allows SSH
ufw status

# Check SSH service running
systemctl status sshd

# Check SSH logs
tail -f /var/log/auth.log
```

### Dilithion Node Not Starting
```bash
# Check service status
systemctl status dilithion-testnet

# Check logs
journalctl -u dilithion-testnet -n 100

# Check configuration
cat ~/.dilithion/dilithion.conf
```

### No Peer Connections
```bash
# Check firewall allows P2P port
ufw status | grep 18444

# Check node is listening
netstat -an | grep 18444

# Check debug logs
tail -f ~/.dilithion/testnet/debug.log
```

### DNS Not Resolving
```bash
# Check DNS propagation
dig testnet-seed.dilithion.org

# May take 5-60 minutes to propagate globally
# Try different DNS servers:
dig @8.8.8.8 testnet-seed.dilithion.org
dig @1.1.1.1 testnet-seed.dilithion.org
```

---

## Cost Summary

### Monthly Costs (3 Droplets)
- 3 x $12 Basic Droplets = **$36/month**
- Bandwidth (included): 3-4 TB per droplet
- Backups (optional): +$1.20/month per droplet

### Monthly Costs (5 Droplets)
- 5 x $12 Basic Droplets = **$60/month**

### Annual Costs (3 Droplets)
- **$432/year** (testnet only)
- Mainnet will need 5-10 nodes: $720-1,440/year

---

## Security Best Practices

### Implemented ✅
- [x] SSH key authentication only
- [x] Firewall (UFW) enabled
- [x] Fail2ban for brute force protection
- [x] Automatic security updates
- [x] Root login disabled (recommended)
- [x] Minimal open ports (22, 18444)

### Recommended (Advanced)
- [ ] Change SSH port from 22 to high random port
- [ ] Install and configure AppArmor/SELinux
- [ ] Set up log monitoring (Logwatch, OSSEC)
- [ ] Enable 2FA for Digital Ocean account
- [ ] Regular security audits with our security-scan script

---

## Next Steps

After all droplets are provisioned and secured:

1. ✅ Update `src/chainparams.cpp` with testnet seed node IPs
2. ✅ Build and deploy updated testnet binary
3. ✅ Install monitoring stack (Prometheus/Grafana)
4. ✅ Run security scans on all nodes
5. ✅ Begin 7-day stability testing

---

## Quick Reference

### SSH Connection
```bash
ssh -i ~/.ssh/dilithion_testnet_ed25519 dilithion@DROPLET_IP
```

### Common Commands
```bash
# Service management
systemctl status dilithion-testnet
systemctl restart dilithion-testnet
systemctl stop dilithion-testnet

# Node interaction
dilithion-cli -testnet getblockchaininfo
dilithion-cli -testnet getpeerinfo
dilithion-cli -testnet getnetworkinfo

# Logs
journalctl -u dilithion-testnet -f
tail -f ~/.dilithion/testnet/debug.log

# System monitoring
htop
df -h
free -h
ufw status
```

### Droplet IP Addresses

| Hostname | Region | IPv4 | IPv6 |
|----------|--------|------|------|
| dilithion-testnet-nyc | NYC3 | [Your IP] | [Your IPv6] |
| dilithion-testnet-lon | LON1 | [Your IP] | [Your IPv6] |
| dilithion-testnet-sgp | SGP1 | [Your IP] | [Your IPv6] |

---

**Document:** Digital Ocean Setup Guide - Testnet
**Created:** November 7, 2025
**Purpose:** Testnet seed node provisioning
**Next:** Install Dilithion testnet nodes

---

*Dilithion - Building Robust Infrastructure* 🔐
