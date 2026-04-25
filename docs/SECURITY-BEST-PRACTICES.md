# Security Best Practices for Dilithion

**Version:** 1.0.0
**Date:** October 25, 2025
**Audience:** Node operators, wallet users, developers

---

## Table of Contents

1. [Node Security](#node-security)
2. [Wallet Security](#wallet-security)
3. [Operational Security](#operational-security)
4. [Network Security](#network-security)
5. [Incident Response](#incident-response)
6. [Security Checklist](#security-checklist)

---

## Node Security

### 1.1 RPC Authentication

**CRITICAL**: Always enable RPC authentication before exposing your node.

#### Configuration

Edit `dilithion.conf`:

```ini
# RPC Authentication (REQUIRED)
rpcuser=your_username_here
rpcpassword=your_very_secure_password_here

# RPC Network Binding
rpcbind=127.0.0.1  # Only localhost by default
rpcport=8332

# Allow specific IPs (if needed)
rpcallowip=127.0.0.1
rpcallowip=192.168.1.0/24  # Your local network
```

#### Strong Password Requirements

- **Minimum length**: 16 characters
- **Include**: Uppercase, lowercase, numbers, symbols
- **Avoid**: Dictionary words, personal information
- **Generate**: Use a password manager

**Example strong password:**
```
rpcpassword=K7$mN#9pQ2@vL4xR8&tY3zW!
```

#### Testing Authentication

```bash
# This should fail (no auth):
curl http://localhost:8332

# This should succeed:
curl -u your_username:your_password http://localhost:8332 \
  -d '{"jsonrpc":"1.0","id":"test","method":"getblockcount","params":[]}'
```

### 1.2 Firewall Configuration

#### Linux (ufw)

```bash
# Default deny incoming
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow P2P port (8444)
sudo ufw allow 8444/tcp

# Allow RPC only from localhost (already blocked by rpcbind=127.0.0.1)
# DO NOT: sudo ufw allow 8332/tcp

# Enable firewall
sudo ufw enable
```

#### Linux (iptables)

```bash
# Flush existing rules
sudo iptables -F

# Default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow P2P
sudo iptables -A INPUT -p tcp --dport 8444 -j ACCEPT

# Allow SSH (if remote)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

#### Windows Firewall

```powershell
# Allow P2P port
New-NetFirewallRule -DisplayName "Dilithion P2P" -Direction Inbound -LocalPort 8444 -Protocol TCP -Action Allow

# Block RPC from external (redundant but safe)
New-NetFirewallRule -DisplayName "Block Dilithion RPC" -Direction Inbound -LocalPort 8332 -Protocol TCP -Action Block
```

### 1.3 System Hardening

#### Run as Non-Root User

```bash
# Create dilithion user
sudo useradd -m -s /bin/bash dilithion

# Set up data directory
sudo mkdir -p /var/lib/dilithion
sudo chown dilithion:dilithion /var/lib/dilithion

# Run node as dilithion user
sudo -u dilithion ./dilithion-node -datadir=/var/lib/dilithion
```

#### File Permissions

```bash
# Wallet file: user-only read/write
chmod 600 ~/.dilithion/wallet.dat

# Config file: user-only read
chmod 600 ~/.dilithion/dilithion.conf

# Data directory: user-only
chmod 700 ~/.dilithion
```

#### Disable Unnecessary Services

```bash
# List running services
systemctl list-units --type=service --state=running

# Disable unnecessary services
sudo systemctl disable <service-name>
```

---

## Wallet Security

### 2.1 Wallet Encryption

**MANDATORY**: Always encrypt your wallet.

#### Encrypting Your Wallet

```bash
# Via RPC
curl -u user:pass http://localhost:8332 \
  -d '{"jsonrpc":"1.0","method":"encryptwallet","params":["YourStrongPassphrase123!"]}'

# Via command line (if implemented)
./dilithion-cli encryptwallet "YourStrongPassphrase123!"
```

#### Passphrase Requirements

- **Minimum**: 12 characters
- **Recommended**: 20+ characters
- **Use**: Passphrase (multiple words) rather than password
- **Example**: `correct horse battery staple mountain river`

#### Unlocking Wallet

```bash
# Unlock for 5 minutes (300 seconds)
curl -u user:pass http://localhost:8332 \
  -d '{"jsonrpc":"1.0","method":"walletpassphrase","params":["YourPassphrase",300]}'

# Lock immediately after transaction
curl -u user:pass http://localhost:8332 \
  -d '{"jsonrpc":"1.0","method":"walletlock","params":[]}'
```

### 2.2 Backup Strategy

#### Regular Backups

```bash
# Backup wallet (while locked)
cp ~/.dilithion/wallet.dat ~/wallet-backup-$(date +%Y%m%d).dat

# Encrypt backup (extra layer)
gpg --symmetric --cipher-algo AES256 ~/wallet-backup-20251025.dat

# Verify backup
gpg --decrypt ~/wallet-backup-20251025.dat.gpg > /tmp/test-wallet.dat
# Test load in separate node instance
```

#### Backup Locations

1. **Local encrypted backup**: Different drive
2. **Offline backup**: USB drive stored securely
3. **Remote backup**: Encrypted cloud storage (Google Drive, Dropbox)
4. **Physical backup**: Paper wallet (export private keys to paper)

#### Backup Schedule

- **Daily**: If actively transacting
- **Weekly**: For normal use
- **After**: Every new key generation

### 2.3 Cold Storage

For large amounts, use cold storage (offline wallet).

#### Setup Cold Wallet

```bash
# On air-gapped computer (never connected to internet):
./dilithion-node -offline  # Generate wallet offline
./dilithion-cli getnewaddress  # Generate receiving addresses

# Transfer addresses to online computer
# Send funds to cold wallet addresses
# Funds secured, private keys never exposed to internet
```

#### Signing Transactions Offline

```bash
# 1. On online node: Create unsigned transaction
./dilithion-cli createrawtransaction '[{"txid":"...","vout":0}]' '{"address":"...", "amount":100}'

# 2. Transfer to offline computer (USB drive)
# 3. On offline node: Sign transaction
./dilithion-cli signrawtransaction <hex>

# 4. Transfer signed transaction back to online node
# 5. On online node: Broadcast
./dilithion-cli sendrawtransaction <signed-hex>
```

### 2.4 Multi-Device Strategy

**DO NOT** copy `wallet.dat` to multiple devices (risk of double-spend).

Instead:
1. Use **one** master wallet (cold storage)
2. Use **multiple** watching-only wallets (track balances)
3. Transfer funds between wallets explicitly

---

## Operational Security

### 3.1 Key Management

#### Key Generation

- **Always** generate keys on secure device
- **Never** use online key generators
- **Use** the official Dilithion wallet only

#### Key Storage

- **Encrypted wallet**: Primary storage
- **Encrypted backups**: Secondary storage
- **Paper backups**: Tertiary storage (for recovery)

#### Key Export

```bash
# Export private key (DANGEROUS - only for backup)
curl -u user:pass http://localhost:8332 \
  -d '{"jsonrpc":"1.0","method":"dumpprivkey","params":["youraddress"]}'

# Immediately secure the output:
# - Never email/message
# - Never upload to cloud unencrypted
# - Print and store securely, or encrypt digitally
```

### 3.2 Transaction Verification

Before sending large amounts:

```bash
# 1. Verify recipient address (multiple times)
# 2. Test with small amount first
# 3. Verify amount and fee
# 4. Sign transaction
# 5. Verify transaction details before broadcast
```

### 3.3 Software Updates

```bash
# Check for updates regularly
git pull origin main

# Verify git signatures (if available)
git verify-tag v1.0.0

# Rebuild from source
make clean
make -j4

# Backup before upgrading
cp -r ~/.dilithion ~/.dilithion.backup

# Test new version on testnet first (if available)
```

### 3.4 Monitoring

#### Log Monitoring

```bash
# Monitor node logs
tail -f ~/.dilithion/debug.log

# Watch for:
# - Unexpected transactions
# - Connection attempts from unknown IPs
# - Error messages
# - Abnormal behavior
```

#### Balance Monitoring

```bash
# Check balance regularly
curl -u user:pass http://localhost:8332 \
  -d '{"jsonrpc":"1.0","method":"getbalance","params":[]}'

# Set up alerts for unexpected changes
```

---

## Network Security

### 4.1 VPN Usage

For enhanced privacy:

```bash
# Use VPN when running node
# Recommended providers:
# - Mullvad
# - ProtonVPN
# - IVPN

# Configure node to bind to VPN interface only
rpcbind=10.8.0.1  # VPN IP
```

### 4.2 Tor Integration (Future)

When implemented:

```bash
# Run node over Tor
dilithion-node -proxy=127.0.0.1:9050 -listen -onion=127.0.0.1:9050
```

### 4.3 Peer Whitelisting

If you run multiple nodes:

```bash
# dilithion.conf
# Only connect to trusted peers
addnode=192.168.1.10:8444
addnode=192.168.1.11:8444
connect=0  # Don't accept other connections
```

### 4.4 DNS Security

Avoid DNS hijacking:

```bash
# Use secure DNS
# /etc/resolv.conf
nameserver 1.1.1.1  # Cloudflare
nameserver 8.8.8.8  # Google

# Or use DNS over HTTPS/TLS
```

---

## Incident Response

### 5.1 Suspected Compromise

If you suspect your wallet or node is compromised:

#### Immediate Actions

1. **Disconnect from network**
   ```bash
   # Stop node
   pkill dilithion-node

   # Disconnect network
   sudo ifconfig eth0 down
   ```

2. **Secure funds**
   ```bash
   # If wallet still accessible:
   # Create new wallet on clean system
   # Transfer all funds to new addresses
   # Abandon old wallet
   ```

3. **Analyze compromise**
   ```bash
   # Check logs
   cat ~/.dilithion/debug.log | grep -i "error\|warning"

   # Check transactions
   ./dilithion-cli listtransactions

   # Check connections
   ./dilithion-cli getpeerinfo
   ```

4. **Document everything**
   - Screenshots of suspicious activity
   - Log files
   - Transaction IDs
   - Timeline of events

### 5.2 Lost Passphrase

**There is NO password recovery mechanism.**

Prevention:
- **Write down passphrase** and store securely
- **Use password manager** (encrypted)
- **Create recovery sheet** with hints (not full passphrase)
- **Test recovery** regularly

If passphrase is lost:
- **Funds are irrecoverable**
- **Learn from mistake**
- **Start new wallet**

### 5.3 Stolen Wallet File

If `wallet.dat` is stolen but encrypted:

- **Time to act**: Depends on passphrase strength
- **Strong passphrase (20+ chars)**: Days to years to crack
- **Weak passphrase (<12 chars)**: Hours to days

Actions:
1. **Create new wallet immediately**
2. **Transfer all funds** to new addresses
3. **Monitor old addresses** for unauthorized transactions
4. **Change all passphrases** (assume compromised)

### 5.4 Emergency Contacts

- **GitHub Issues**: https://github.com/dilithion/dilithion/issues
- **Security Email**: security@dilithion.org (if available)
- **Community**: Discord/Telegram (community support)

---

## Security Checklist

### Initial Setup

- [ ] Generate strong RPC username and password
- [ ] Configure firewall (allow P2P, block RPC)
- [ ] Run node as non-root user
- [ ] Set restrictive file permissions (600 for wallet)
- [ ] Enable wallet encryption with strong passphrase
- [ ] Create encrypted backup of wallet
- [ ] Store backup in secure offline location
- [ ] Document recovery process

### Daily Operations

- [ ] Keep wallet locked when not in use
- [ ] Unlock only for necessary duration
- [ ] Verify recipient addresses before sending
- [ ] Check balance regularly
- [ ] Monitor logs for anomalies
- [ ] Use VPN for enhanced privacy

### Weekly Maintenance

- [ ] Create fresh wallet backup
- [ ] Update system packages
- [ ] Check for Dilithion updates
- [ ] Review transaction history
- [ ] Test wallet recovery process

### Monthly Review

- [ ] Audit security settings
- [ ] Review and rotate RPC credentials
- [ ] Test backup restoration
- [ ] Update documentation
- [ ] Review peer connections

### Emergency Prepared

- [ ] Know how to quickly lock wallet
- [ ] Know how to disconnect node
- [ ] Have recovery procedure documented
- [ ] Have emergency contact information
- [ ] Have secure offline backup accessible

---

## Advanced Security

### Hardware Security Modules (HSM)

For enterprise use, consider HSM integration:

- **YubiHSM**: Store private keys in hardware
- **Ledger/Trezor**: When hardware wallet support added
- **TPM**: Trusted Platform Module for key storage

### Air-Gapped Signing

For maximum security:

1. **Signing Computer**: Never connected to internet
2. **Watch-Only Node**: Online, tracks balances
3. **Transaction Creation**: Online node creates unsigned tx
4. **Transfer via QR/USB**: Move unsigned tx to air-gapped computer
5. **Sign Offline**: Sign with air-gapped wallet
6. **Transfer Back**: Move signed tx to online node
7. **Broadcast**: Online node broadcasts

### Key Splitting (Shamir's Secret Sharing)

Split wallet passphrase/keys:

```
Passphrase → 5 shares
Require any 3 shares to reconstruct

Store shares in different locations:
- Safe deposit box 1
- Safe deposit box 2
- Trusted family member
- Secure cloud storage
- Fire-proof safe at home
```

---

## Conclusion

Security is not a one-time setup but an ongoing practice:

1. **Defense in Depth**: Multiple layers of security
2. **Regular Backups**: Automated and tested
3. **Strong Encryption**: AES-256 + strong passphrases
4. **Operational Discipline**: Strict procedures
5. **Stay Updated**: Software and security practices

**Remember**: In cryptocurrency, you are your own bank. Security is YOUR responsibility.

---

**Last Updated:** October 25, 2025
**Version:** 1.0.0
**Next Review:** 2025-11-25
