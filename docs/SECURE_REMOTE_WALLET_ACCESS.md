# Secure Remote Wallet Access via SSH

**Date:** 2025-11-10
**Version:** 1.0
**Status:** Security Architecture Design

## Overview

This document describes secure methods for accessing your Dilithion HD wallet remotely via SSH without compromising security or increasing the risk of fund loss.

## Security Principles

**Core Principle:** The wallet's private keys and mnemonic should NEVER be transmitted over the network, even encrypted.

**Defense in Depth:** Multiple layers of security to protect against various attack vectors.

## Architecture Options

### Option 1: SSH with Encrypted Wallet (Recommended for Most Users)

**Architecture:**
```
Your Device (SSH Client)
    |
    | (Encrypted SSH Tunnel)
    v
Remote Server (Wallet Node)
    |
    | (Encrypted Wallet)
    v
HD Wallet (Locked by Default)
```

**Security Features:**
- Wallet always encrypted and locked by default
- Passphrase required to unlock (short duration)
- No mnemonic export over SSH
- All wallet operations via RPC commands
- Audit logging of all wallet operations

**Setup Steps:**

1. **Server Setup:**
```bash
# Create dedicated wallet user
sudo useradd -m -s /bin/bash dilithion-wallet
sudo passwd dilithion-wallet

# Install Dilithion wallet
cd /home/dilithion-wallet
# ... install dilithion software

# Create encrypted wallet
dilithion-cli createhdwallet
dilithion-cli encryptwallet "strong-passphrase-here"
```

2. **SSH Hardening:**
```bash
# Edit /etc/ssh/sshd_config
sudo nano /etc/ssh/sshd_config

# Add these settings:
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
Port 22222  # Non-standard port
AllowUsers dilithion-wallet
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Restart SSH
sudo systemctl restart sshd
```

3. **SSH Key Authentication:**
```bash
# On your local machine, generate SSH key
ssh-keygen -t ed25519 -C "dilithion-wallet-access"

# Copy to server
ssh-copy-id -i ~/.ssh/id_ed25519.pub dilithion-wallet@your-server.com -p 22222
```

4. **Firewall Configuration:**
```bash
# Allow only your IP(s)
sudo ufw allow from YOUR.IP.ADDRESS to any port 22222 proto tcp
sudo ufw enable
```

**Usage Pattern:**
```bash
# SSH into server
ssh dilithion-wallet@your-server.com -p 22222

# Unlock wallet for 60 seconds only
dilithion-cli walletpassphrase "your-passphrase" 60

# Perform operation
dilithion-cli getnewaddress
dilithion-cli sendtoaddress "dil1..." 10.0

# Wallet auto-locks after 60 seconds
```

### Option 2: SSH with Hardware Security Key (Maximum Security)

**Architecture:**
```
Your Device
    |
    | (SSH + Hardware Key Auth)
    v
Bastion Server (Jump Host)
    |
    | (Internal Network)
    v
Wallet Server (Encrypted Wallet)
    |
    v
Hardware Wallet (Optional - for signing)
```

**Additional Security:**
- Hardware key required for SSH access (YubiKey, etc.)
- Bastion host for additional isolation
- Wallet server not directly accessible from internet
- Optional: Hardware wallet for transaction signing

**Setup:**
```bash
# Install libpam-u2f
sudo apt install libpam-u2f

# Configure PAM for U2F
sudo nano /etc/pam.d/sshd
# Add: auth required pam_u2f.so

# Register U2F key
mkdir -p ~/.ssh
pamu2fcfg > ~/.ssh/u2f_keys

# Now SSH requires both:
# 1. SSH key
# 2. Physical hardware key touch
```

### Option 3: SSH Tunnel with Local RPC (Paranoid Mode)

**Architecture:**
```
Your Local Machine
    |
    | (SSH Tunnel)
    v
Remote Server (Wallet RPC)
    ^
    | (localhost only)
Encrypted Wallet (Never exposed)
```

**Security Features:**
- Wallet RPC only listens on localhost
- SSH tunnel forwards RPC port to your machine
- You interact with wallet as if it's local
- Zero network exposure of wallet RPC

**Setup:**
```bash
# On remote server - Configure wallet to listen on localhost only
# dilithion.conf
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=8332
rpcuser=your-rpc-user
rpcpassword=your-strong-rpc-password

# Start wallet daemon
dilithiond -daemon

# On your local machine - Create SSH tunnel
ssh -L 8332:localhost:8332 dilithion-wallet@your-server.com -p 22222

# Now use wallet from your local machine
dilithion-cli -rpcconnect=localhost:8332 getnewaddress
```

## Security Best Practices

### 1. SSH Configuration

**Use SSH Keys Only:**
```bash
# Generate strong key
ssh-keygen -t ed25519 -a 100 -C "dilithion-wallet"

# Protect private key
chmod 600 ~/.ssh/id_ed25519
```

**SSH Hardening Checklist:**
- [ ] Disable password authentication
- [ ] Use non-standard SSH port
- [ ] Enable fail2ban
- [ ] Use SSH key with passphrase
- [ ] Enable 2FA/U2F for SSH
- [ ] Whitelist IPs in firewall
- [ ] Disable root login
- [ ] Set MaxAuthTries=3
- [ ] Enable SSH connection logging

### 2. Wallet Security

**Encrypted Wallet:**
```bash
# Always encrypt your wallet
dilithion-cli encryptwallet "strong-passphrase"

# Use strong passphrase (20+ characters)
# Example: "correct-horse-battery-staple-quantum-2025"
```

**Limited Unlock Duration:**
```bash
# Unlock for minimum time needed (60 seconds)
dilithion-cli walletpassphrase "passphrase" 60

# Never leave wallet unlocked
# Auto-locks after timeout
```

**Mnemonic Protection:**
```bash
# NEVER export mnemonic over SSH
# If you must see it:
# 1. Access server physically (console/KVM)
# 2. Or use extremely secure connection

# Mnemonic should only be:
# - Written on paper
# - Stored in fireproof safe
# - NEVER transmitted over network
```

### 3. Network Security

**Firewall Configuration:**
```bash
# Only allow your IP
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from YOUR.IP.ADDRESS to any port 22222 proto tcp
sudo ufw enable
```

**Fail2Ban:**
```bash
# Install fail2ban
sudo apt install fail2ban

# Configure for SSH
sudo nano /etc/fail2ban/jail.local

[sshd]
enabled = true
port = 22222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
```

**VPN Option:**
```bash
# Additional layer: Require VPN connection first
# Then SSH through VPN
# Server only accepts SSH from VPN IP range
```

### 4. Operational Security

**Audit Logging:**
```bash
# Enable comprehensive logging
# Log all wallet operations
dilithion-cli setlogcategory wallet 1

# Review logs regularly
tail -f ~/.dilithion/debug.log | grep wallet
```

**Separate Hot/Cold Wallets:**
```
Hot Wallet (Remote Server):
- Small amounts for daily transactions
- Encrypted, SSH-accessible
- Regular monitoring

Cold Wallet (Offline):
- Large amounts / long-term storage
- Air-gapped machine
- Mnemonic in safe
- Only for major transactions
```

**Transaction Limits:**
```bash
# For large transactions, use multi-signature
# Require physical confirmation for amounts > threshold

# Example workflow:
# 1. Prepare transaction on hot wallet
# 2. Sign with cold wallet (air-gapped)
# 3. Broadcast signed transaction
```

### 5. Monitoring & Alerts

**Monitor Failed SSH Attempts:**
```bash
# Set up email alerts for failed SSH attempts
sudo apt install mailutils

# Add to /etc/fail2ban/action.d/sendmail-whois.conf
# Configure to send alerts on ban events
```

**Wallet Activity Monitoring:**
```bash
# Monitor wallet.dat changes
sudo apt install inotify-tools

inotifywait -m -e modify ~/.dilithion/wallet.dat | \
while read path action file; do
    echo "$(date): Wallet file modified" >> ~/.dilithion/wallet-monitor.log
    # Optional: Send alert
done
```

## Security Checklist

### Before First Remote Access:
- [ ] Wallet encrypted with strong passphrase (20+ characters)
- [ ] SSH key authentication configured (no passwords)
- [ ] SSH running on non-standard port
- [ ] Firewall configured with IP whitelist
- [ ] Fail2ban installed and configured
- [ ] Wallet RPC bound to localhost only
- [ ] Backup of mnemonic in secure physical location
- [ ] Tested wallet unlock/lock cycle
- [ ] Audit logging enabled

### For Each Remote Session:
- [ ] Verify SSH fingerprint (first connection)
- [ ] Unlock wallet for minimum duration needed
- [ ] Perform operation quickly
- [ ] Verify wallet locks after timeout
- [ ] Review recent transactions
- [ ] Check audit logs for anomalies
- [ ] Log out completely

### Weekly Maintenance:
- [ ] Review SSH logs for failed attempts
- [ ] Review wallet audit logs
- [ ] Check fail2ban ban list
- [ ] Verify firewall rules
- [ ] Test backup restoration
- [ ] Update system security patches

## Advanced Security Techniques

### 1. Port Knocking

**Concept:** SSH port is closed by default, only opens after "knock" sequence.

```bash
# Install knockd
sudo apt install knockd

# Configure /etc/knockd.conf
[openSSH]
sequence    = 7000,8000,9000
seq_timeout = 5
command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22222 -j ACCEPT

[closeSSH]
sequence    = 9000,8000,7000
seq_timeout = 5
command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22222 -j ACCEPT

# Knock to open port:
knock your-server.com 7000 8000 9000
ssh dilithion-wallet@your-server.com -p 22222
# After session, knock to close
knock your-server.com 9000 8000 7000
```

### 2. SSH Certificate Authentication

**More secure than regular keys:**

```bash
# Create CA key (on secure machine)
ssh-keygen -t ed25519 -f ~/.ssh/dilithion_ca

# Sign user key
ssh-keygen -s ~/.ssh/dilithion_ca \
    -I "dilithion-wallet-user" \
    -n dilithion-wallet \
    -V +52w \
    ~/.ssh/id_ed25519.pub

# Configure server to trust CA
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/dilithion_ca.pub
```

### 3. Geofencing

**Only allow SSH from specific geographic locations:**

```bash
# Use GeoIP database
sudo apt install geoip-bin geoip-database

# Create script to check location
#!/bin/bash
COUNTRY=$(geoiplookup $PAM_RHOST | cut -d: -f2 | sed 's/^ *//' | cut -d, -f1)
if [ "$COUNTRY" != "US" ]; then
    exit 1
fi
exit 0
```

### 4. Time-Based Access Control

**Only allow SSH during specific hours:**

```bash
# /etc/security/time.conf
sshd;*;dilithion-wallet;MoTuWeThFr0800-1800

# Enable in PAM
# /etc/pam.d/sshd
account required pam_time.so
```

## Emergency Procedures

### If Server is Compromised:

1. **Immediately:**
   ```bash
   # From a secure device, transfer all funds to new wallet
   # Revoke SSH access
   # Shutdown server if possible
   ```

2. **Create New Wallet:**
   ```bash
   # Generate new HD wallet with new mnemonic
   # NEVER reuse compromised mnemonic
   ```

3. **Forensics:**
   ```bash
   # Review logs
   # Determine compromise vector
   # Strengthen security before re-deployment
   ```

### If SSH Key is Lost/Stolen:

1. **Revoke Access:**
   ```bash
   # Remove from authorized_keys
   ssh console-access-user@server
   nano ~/.ssh/authorized_keys
   # Delete compromised key
   ```

2. **Generate New Keys:**
   ```bash
   # Create new SSH key pair
   ssh-keygen -t ed25519 -C "new-dilithion-wallet-key"
   ```

## Risk Assessment

### Risks of Remote Access:

| Risk | Severity | Mitigation |
|------|----------|------------|
| SSH key theft | High | Passphrase on key, 2FA, hardware key |
| Server compromise | Critical | Encrypted wallet, limited funds, monitoring |
| Man-in-the-middle | Medium | SSH fingerprint verification, VPN |
| Keylogger on client | High | Hardware wallet for signing, virtual keyboard |
| Network eavesdropping | Low | SSH encryption (secure by default) |
| Brute force attack | Medium | Fail2ban, strong passphrases, rate limiting |
| Insider threat | Medium | Audit logging, multi-sig for large amounts |

### Risk Reduction Strategies:

**Minimize Attack Surface:**
- Use cold wallet for majority of funds
- Keep only operational amounts in hot wallet
- Limit remote access to necessary operations

**Defense in Depth:**
- Multiple authentication factors (SSH key + 2FA + passphrase)
- Network isolation (VPN, firewall, port knocking)
- Monitoring and alerting

**Principle of Least Privilege:**
- Dedicated user for wallet operations
- Minimal permissions
- Time-limited unlocking

## Recommended Configuration

**For Personal Use (1 user, moderate security):**
```yaml
SSH:
  - Key authentication only
  - Non-standard port
  - Firewall with IP whitelist
  - Fail2ban enabled

Wallet:
  - Encrypted with strong passphrase
  - Auto-lock after 60 seconds
  - RPC on localhost only
  - SSH tunnel for access

Monitoring:
  - Basic audit logging
  - Weekly log review
```

**For Business Use (Multi-user, high security):**
```yaml
SSH:
  - Certificate authentication
  - Hardware 2FA (YubiKey)
  - Bastion host
  - Port knocking
  - Geofencing

Wallet:
  - Multi-signature (2-of-3 or 3-of-5)
  - Encrypted wallet
  - Hardware wallet for signing
  - Transaction limits with approval workflow
  - RPC access through secure proxy

Monitoring:
  - Real-time monitoring
  - Automated alerts
  - Daily audit log review
  - Intrusion detection system (IDS)
```

## Implementation Example

**Complete setup script for secure remote wallet access:**

```bash
#!/bin/bash
# secure-wallet-setup.sh

set -e

echo "Dilithion Secure Remote Wallet Setup"
echo "====================================="

# 1. Create wallet user
sudo useradd -m -s /bin/bash dilithion-wallet
echo "Created dilithion-wallet user"

# 2. Install fail2ban
sudo apt update
sudo apt install -y fail2ban
echo "Installed fail2ban"

# 3. Configure SSH
SSH_PORT=22222
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sudo cat >> /etc/ssh/sshd_config <<EOF

# Dilithion Wallet SSH Hardening
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers dilithion-wallet
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

sudo systemctl restart sshd
echo "SSH hardened on port $SSH_PORT"

# 4. Configure firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
echo "Enter your IP address for SSH whitelist:"
read YOUR_IP
sudo ufw allow from $YOUR_IP to any port $SSH_PORT proto tcp
sudo ufw --force enable
echo "Firewall configured"

# 5. Setup SSH key (manual step)
echo ""
echo "MANUAL STEPS REQUIRED:"
echo "1. On your local machine, run:"
echo "   ssh-keygen -t ed25519 -C 'dilithion-wallet'"
echo "2. Copy the public key to server:"
echo "   ssh-copy-id -i ~/.ssh/id_ed25519.pub dilithion-wallet@$(hostname -I | awk '{print $1}') -p $SSH_PORT"
echo ""
echo "3. After SSH key is configured, create encrypted wallet:"
echo "   ssh dilithion-wallet@$(hostname -I | awk '{print $1}') -p $SSH_PORT"
echo "   dilithion-cli createhdwallet"
echo "   dilithion-cli encryptwallet 'your-strong-passphrase'"
echo ""
echo "Setup complete!"
```

## Conclusion

Remote wallet access via SSH can be secure when properly configured with:

1. **Strong authentication** (SSH keys + 2FA)
2. **Network isolation** (Firewall, VPN, port knocking)
3. **Encrypted wallet** (Always locked by default)
4. **Minimal exposure** (Short unlock times, hot/cold separation)
5. **Comprehensive monitoring** (Audit logs, alerts)

**Key Principle:** Your mnemonic phrase should NEVER leave the server. All operations should be performed via RPC commands with the wallet remaining encrypted except during brief unlocking periods.

For maximum security, combine SSH access for small operational amounts with cold storage (air-gapped) for the majority of funds.

---

**Document Version:** 1.0
**Last Updated:** 2025-11-10
**Author:** Claude Code AI
**Security Level:** Production-Ready
