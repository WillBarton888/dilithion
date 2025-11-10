# Dilithion Wallet - Quick Start for Miners

**5-Minute Setup for Mining Dilithion**

## Prerequisites

- Dilithion wallet installed
- 5 minutes for setup
- Paper and pen (for recovery phrase)

## Step 1: Create Your Wallet (2 minutes)

**First time running Dilithion:**

```bash
# Launch Dilithion
dilithiond

# The setup wizard will start automatically
# Follow the on-screen prompts:
# 1. Write down your 24-word recovery phrase on paper
# 2. Create a strong passphrase
# 3. Wallet auto-encrypts and creates backups
```

**CRITICAL:** Write down your recovery phrase immediately!
This is the ONLY way to recover your mining rewards if something goes wrong.

## Step 2: Get Your Mining Address (1 minute)

```bash
# Get your first mining address
dilithion-cli getnewaddress

# Example output:
# dil1qxyz123abc456def789ghi012jkl345mno678pqr901stu234vwx567yzabc

# Copy this address - you'll use it for mining
```

## Step 3: Configure Mining (1 minute)

**Edit your dilithion.conf:**

```bash
# Open config file
nano ~/.dilithion/dilithion.conf

# Add these lines:
gen=1                           # Enable mining
genproclimit=4                  # Number of CPU cores (adjust as needed)
miningaddress=dil1qyour...      # Your address from Step 2
```

**Restart Dilithion:**

```bash
dilithion-cli stop
dilithiond
```

## Step 4: Start Mining! (immediate)

Mining starts automatically! Check your status:

```bash
# Check mining status
dilithion-cli getmininginfo

# Check your balance
dilithion-cli getbalance

# View recent transactions
dilithion-cli listtransactions
```

---

## Security Best Practices for Miners

### Essential Security (Do This Now):

1. **✓ Write recovery phrase on paper** - Store in safe
2. **✓ Encrypt wallet** - Done automatically by wizard
3. **✓ Enable auto-backup** - Done automatically (daily)
4. **✓ Use strong passphrase** - Needed to unlock wallet

### Recommended Security (Do This Soon):

1. **Set up hot/cold wallet split**
   - Keep small amount in mining wallet (hot)
   - Transfer bulk to cold wallet weekly
   - Cold wallet = offline computer

2. **Enable SSH security** (if mining remotely)
   - Use SSH keys, not passwords
   - Enable fail2ban
   - Firewall: whitelist your IP only

3. **Monitor regularly**
   - Check balance daily
   - Review transactions weekly
   - Test wallet restoration monthly

---

## Mining Reward Management

### Small-Scale Miner (<100 DIL/month):

**Simple Setup:**
```bash
# Weekly routine:
# 1. Check balance
dilithion-cli getbalance

# 2. If balance > 50 DIL, send to cold storage
dilithion-cli sendtoaddress "cold-wallet-address" 45.0

# Keep ~5-10 DIL for transaction fees
```

### Large-Scale Miner (>100 DIL/month):

**Hot/Cold Wallet Setup:**

**Hot Wallet (Mining Server):**
- Receives mining rewards
- Keeps max 10% of total holdings
- Auto-withdraws to cold weekly

**Cold Wallet (Offline Computer):**
- Stores 90% of funds
- Air-gapped (never online)
- Only for major transactions

**Weekly Transfer:**
```bash
# From hot wallet (mining server)
ssh mining-server
dilithion-cli walletpassphrase "passphrase" 60
dilithion-cli sendtoaddress "cold-wallet-address" weekly-rewards
```

---

## Pool Mining Setup

### For Pool Miners:

**1. Get Your Payout Address:**
```bash
dilithion-cli getnewaddress
# dil1qpool789...
```

**2. Configure Pool:**
- Go to your mining pool's website
- Enter your Dilithion address
- Set minimum payout (recommended: 10 DIL)
- Start mining through pool

**3. Monitor Payouts:**
```bash
# Check for incoming pool payouts
dilithion-cli listtransactions

# Check total balance
dilithion-cli getbalance
```

---

## Common Commands

### Wallet Operations:

```bash
# Get new address
dilithion-cli getnewaddress

# Check balance
dilithion-cli getbalance

# Send coins
dilithion-cli walletpassphrase "passphrase" 60
dilithion-cli sendtoaddress "recipient-address" amount

# List recent transactions
dilithion-cli listtransactions

# Backup wallet
dilithion-cli backupwallet "/path/to/backup.dat"

# Encrypt wallet (if not already)
dilithion-cli encryptwallet "strong-passphrase"

# Lock wallet
dilithion-cli walletlock

# Unlock wallet for 60 seconds
dilithion-cli walletpassphrase "passphrase" 60
```

### Mining Operations:

```bash
# Check mining status
dilithion-cli getmininginfo

# Get network difficulty
dilithion-cli getdifficulty

# Get blockchain info
dilithion-cli getblockchaininfo

# Get connection count
dilithion-cli getconnectioncount

# Get latest block
dilithion-cli getbestblockhash
dilithion-cli getblock "<hash>"
```

### Maintenance:

```bash
# Check wallet info
dilithion-cli getwalletinfo

# Verify wallet backup
dilithion-cli verifybackup "/path/to/backup"

# Export recovery phrase (SECURE LOCATION ONLY!)
dilithion-cli exportmnemonic

# Show wallet status
dilithion-cli walletstatus

# Check security score
dilithion-cli securityscore
```

---

## Troubleshooting

### Wallet Won't Unlock:

```bash
# Try unlocking again
dilithion-cli walletpassphrase "your-passphrase" 60

# If forgotten passphrase:
# You can restore from recovery phrase
dilithion-cli restorehdwallet '{"mnemonic":"your 24 words here"}'
```

### Mining Not Working:

```bash
# Check config
cat ~/.dilithion/dilithion.conf | grep gen

# Verify mining is enabled
dilithion-cli getmininginfo

# Check logs
tail -f ~/.dilithion/debug.log
```

### No Connections:

```bash
# Check connection count
dilithion-cli getconnectioncount

# Add nodes manually (if needed)
dilithion-cli addnode "node-ip:port" "add"

# Check firewall
sudo ufw status
```

### Balance Not Updating:

```bash
# Rescan blockchain
dilithion-cli rescanblockchain

# Check sync status
dilithion-cli getblockchaininfo
```

---

## Security Checklist for Miners

### Before Starting:
- [ ] Recovery phrase written on paper
- [ ] Recovery phrase stored in safe
- [ ] Wallet encrypted
- [ ] Strong passphrase chosen
- [ ] Auto-backup enabled
- [ ] Tested wallet restoration

### Weekly Checks:
- [ ] Check mining rewards balance
- [ ] Transfer excess to cold storage (if balance > 10% of total)
- [ ] Review recent transactions
- [ ] Check for wallet software updates

### Monthly Checks:
- [ ] Verify backup files exist
- [ ] Test wallet restoration
- [ ] Review security logs (if SSH)
- [ ] Update mining software

### Important Numbers:

**Hot Wallet Balance Thresholds:**
- **< 10 DIL**: Keep mining
- **10-50 DIL**: Consider transfer to cold storage
- **> 50 DIL**: Transfer to cold storage immediately

**Recommended Hot/Cold Split:**
- **Solo mining**: 90% cold, 10% hot
- **Pool mining**: 95% cold, 5% hot

---

## Emergency Procedures

### If Server is Compromised:

**Immediate Actions:**
```bash
# From secure device, transfer all funds to new wallet
dilithion-cli sendtoaddress "new-safe-address" all-funds

# Generate new wallet
dilithion-cli restorehdwallet '{"mnemonic":"new mnemonic"}'

# Never reuse compromised wallet
```

### If You Lose Access:

**Recovery:**
```bash
# On new/restored server
dilithiond

# Restore from recovery phrase
dilithion-cli restorehdwallet '{"mnemonic":"your 24 words"}'

# Or restore from backup
dilithion-cli restorewallet "/path/to/backup.dat"

# Verify balance
dilithion-cli getbalance
```

---

## Performance Tuning

### For Better Mining Performance:

**CPU Mining Optimization:**
```bash
# In dilithion.conf
genproclimit=cores-1  # Leave 1 core for system
dbcache=512           # Increase if you have RAM
maxmempool=500        # Increase mempool size
```

**System Optimization:**
```bash
# Monitor CPU usage
htop

# Monitor Dilithion performance
dilithion-cli getmininginfo

# Check hash rate
# (Look for "hashespersec" in getmininginfo output)
```

### For Mining Pools:

**Pool Configuration:**
- Minimum payout: 10 DIL (reduces transaction fees)
- Payout frequency: Daily
- Worker name: Descriptive (e.g., "server1-cpu")

---

## FAQ for Miners

**Q: How often should I withdraw to cold storage?**
A: Weekly for balances > 50 DIL. Daily if > 100 DIL.

**Q: Can I mine on multiple machines?**
A: Yes! Use different mining addresses and consolidate weekly.

**Q: What if I forget my passphrase?**
A: Restore from recovery phrase. This is why it's critical!

**Q: How do I upgrade Dilithion wallet?**
A: Backup first, then upgrade, then verify balance.

**Q: Should I mine solo or in a pool?**
A: Pool mining = steady rewards. Solo mining = large but infrequent.

**Q: How much can I earn mining?**
A: Depends on hashrate, difficulty, and pool vs solo. Check mining calculators.

---

## Support & Resources

**Documentation:**
- Main docs: docs.dilithion.org
- Security guide: /docs/SECURE_REMOTE_WALLET_ACCESS.md
- Default setup: /docs/DEFAULT_WALLET_SETUP_FOR_USERS.md

**Community:**
- Forum: forum.dilithion.org
- Discord: discord.gg/dilithion
- GitHub: github.com/dilithion/dilithion

**Emergency:**
- Security issues: security@dilithion.org
- Lost funds recovery: support@dilithion.org

---

## Summary

**5-Minute Mining Setup:**
1. Run Dilithion → Complete setup wizard (2 min)
2. Get mining address (1 min)
3. Configure mining in dilithion.conf (1 min)
4. Restart and start mining! (1 min)

**Security Essentials:**
- ✓ Recovery phrase on paper in safe
- ✓ Wallet encrypted
- ✓ Auto-backup enabled
- ✓ Weekly transfer to cold storage

**You're Ready to Mine!**

Start mining, stay secure, and welcome to Dilithion!

---

**Version:** 1.0
**Last Updated:** 2025-11-10
**For:** Dilithion Miners
