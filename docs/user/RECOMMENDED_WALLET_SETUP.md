# Professional Recommendation: Simple + Secure Wallet Setup

**Date:** 2025-11-10
**For:** Will's Dilithion Wallet
**Goal:** Maximum security, minimum complexity, zero fund loss

## Overview

This is the setup I professionally recommend. It balances security with usability and protects you even if your remote server is completely compromised.

## The Strategy

```
┌────────────────────────────────────────────────────────────┐
│                  FUND ALLOCATION STRATEGY                  │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  COLD WALLET (90-95%)         HOT WALLET (5-10%)          │
│  ══════════════════            ═══════════════            │
│  • Offline computer            • Remote server            │
│  • Never touches internet      • SSH accessible           │
│  • Mnemonic in safe            • Encrypted, auto-lock     │
│  • For long-term storage       • For daily operations     │
│  • Maximum security            • Convenient access        │
│                                                            │
│  Risk if compromised: 0%       Risk if compromised: 5-10% │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

## Phase 1: Cold Wallet (1 hour)

### What You Need:
- Old laptop or desktop (doesn't need to be powerful)
- USB drive
- Fireproof safe or secure location
- Paper and pen

### Steps:

1. **Prepare Offline Computer**
   ```
   - Install Dilithion wallet on computer
   - Disconnect from internet (physically unplug ethernet/disable WiFi)
   - NEVER connect this computer to internet again
   ```

2. **Create Cold Wallet**
   ```bash
   # On offline computer
   dilithion-cli createhdwallet
   ```

3. **Export and Secure Mnemonic**
   ```bash
   dilithion-cli exportmnemonic

   # Write down all 24 words on paper:
   # - Use pen (not pencil)
   # - Write clearly
   # - Double-check each word
   # - Store in fireproof safe
   # - Consider making 2-3 copies in different locations
   ```

4. **Encrypt Wallet**
   ```bash
   dilithion-cli encryptwallet "your-very-strong-passphrase-20-chars-minimum"

   # Write passphrase in safe (separate paper from mnemonic)
   ```

5. **Generate Receive Addresses**
   ```bash
   # Generate 50 addresses for future use
   for i in {1..50}; do
       dilithion-cli getnewaddress
   done > addresses.txt

   # Copy addresses.txt to USB drive
   # Keep USB drive with you for distributing addresses
   ```

6. **Shut Down Securely**
   ```bash
   dilithion-cli stop
   shutdown -h now

   # Unplug computer
   # Store in secure location
   ```

**Result:**
✅ Cold wallet created and secured
✅ Mnemonic safely stored offline
✅ 50 addresses ready to receive funds
✅ Impossible to hack remotely

## Phase 2: Hot Wallet (30 minutes)

### Server: 188.166.255.63 (or any of your servers)

### Steps:

1. **SSH Hardening**
   ```bash
   ssh root@188.166.255.63

   # Edit SSH config
   nano /etc/ssh/sshd_config

   # Ensure these settings:
   PasswordAuthentication no
   PermitRootLogin prohibit-password
   MaxAuthTries 3
   ClientAliveInterval 300

   # Restart SSH
   systemctl restart sshd
   ```

2. **Install Security Tools**
   ```bash
   apt update
   apt install -y fail2ban ufw

   # Enable fail2ban
   systemctl enable fail2ban
   systemctl start fail2ban
   ```

3. **Configure Firewall**
   ```bash
   # Replace YOUR.IP.ADDRESS with your actual home/office IP
   ufw default deny incoming
   ufw default allow outgoing
   ufw allow from YOUR.IP.ADDRESS to any port 22 proto tcp
   ufw enable

   # Verify
   ufw status
   ```

4. **Create Hot Wallet**
   ```bash
   # Create NEW wallet (different from cold wallet!)
   dilithion-cli createhdwallet

   # IMPORTANT: Write down this mnemonic too (different safe/location)
   dilithion-cli exportmnemonic

   # Encrypt with DIFFERENT passphrase than cold wallet
   dilithion-cli encryptwallet "different-strong-passphrase"
   ```

5. **Configure Wallet for Security**
   ```bash
   # Edit config
   nano ~/.dilithion/dilithion.conf

   # Add these lines:
   rpcbind=127.0.0.1
   rpcallowip=127.0.0.1
   walletlocktimeout=60

   # Restart wallet
   systemctl restart dilithiond
   ```

6. **Fund Hot Wallet**
   ```bash
   # Get hot wallet address
   dilithion-cli getnewaddress

   # Send small amount from exchange/cold wallet
   # Start with 5-10% of your total portfolio
   ```

**Result:**
✅ Hot wallet ready for daily use
✅ Protected by encryption + firewall + fail2ban
✅ Limited funds at risk (5-10% only)
✅ Convenient SSH access

## Phase 3: Operational Procedures

### Daily Operations

**For Small Transactions (<5% of total funds):**
```bash
# SSH into hot wallet server
ssh root@188.166.255.63

# Check balance
dilithion-cli getbalance

# Unlock for 60 seconds
dilithion-cli walletpassphrase "hot-wallet-passphrase" 60

# Send transaction
dilithion-cli sendtoaddress "recipient-address" amount

# Wallet auto-locks after 60 seconds
```

**For Large Transactions (>5% of total funds):**
```bash
# Use cold wallet
# 1. Boot offline computer
# 2. Unlock wallet
dilithion-cli walletpassphrase "cold-wallet-passphrase" 300

# 3. Send transaction
dilithion-cli sendtoaddress "recipient-address" large-amount

# 4. Lock wallet
dilithion-cli walletlock

# 5. Shut down computer
# 6. Unplug and secure
```

**Receiving Funds:**
```bash
# Use cold wallet addresses (from addresses.txt on USB)
# Give these to exchanges, services, etc.
# Funds go directly to most secure storage
```

### Weekly Maintenance (5 minutes)

```bash
# 1. Check hot wallet balance
ssh root@188.166.255.63
dilithion-cli getbalance

# 2. If balance > 10% of total, send excess to cold wallet
# Get cold wallet address from USB addresses.txt
dilithion-cli walletpassphrase "passphrase" 60
dilithion-cli sendtoaddress "cold-wallet-address" excess-amount

# 3. Check security logs
grep "Failed password" /var/log/auth.log | tail -20
fail2ban-client status sshd
```

### Monthly Security Review (15 minutes)

```bash
# 1. Review all failed SSH attempts
grep "Failed" /var/log/auth.log | wc -l

# 2. Verify firewall rules
ufw status verbose

# 3. Update system
apt update && apt upgrade -y

# 4. Test cold wallet (power on, verify it works, power off)

# 5. Verify backups
# - Check safe for mnemonic papers
# - Verify they're still readable
# - Consider making additional copies
```

## Security Checklist

### Initial Setup:
- [ ] Cold wallet created on offline computer
- [ ] Cold wallet mnemonic written on paper
- [ ] Cold wallet mnemonic stored in fireproof safe
- [ ] Cold wallet encrypted with strong passphrase
- [ ] 50 receive addresses generated
- [ ] Offline computer unplugged and secured
- [ ] Hot wallet created on remote server
- [ ] Hot wallet encrypted with different passphrase
- [ ] SSH hardened (key auth only)
- [ ] Firewall configured (IP whitelist)
- [ ] Fail2ban installed and running
- [ ] Hot wallet funded with <10% of total

### Weekly Checks:
- [ ] Hot wallet balance <10% of total
- [ ] No suspicious SSH attempts
- [ ] Fail2ban working
- [ ] Firewall active

### Monthly Checks:
- [ ] Cold wallet test (power on, verify, power off)
- [ ] Mnemonic papers still secure and readable
- [ ] System updates applied
- [ ] Security logs reviewed
- [ ] Backup strategy verified

## Security Rules

### The Golden Rules:

1. **Never mix hot and cold:**
   - Different computers
   - Different mnemonics
   - Different passphrases
   - Different purposes

2. **The 90/10 rule:**
   - 90% in cold wallet (offline)
   - 10% in hot wallet (online)
   - Rebalance weekly

3. **The mnemonic rule:**
   - NEVER type mnemonic on internet-connected device
   - NEVER transmit mnemonic over network
   - NEVER store mnemonic digitally
   - Paper only, in safe

4. **The unlock rule:**
   - Unlock for minimum time needed (60 seconds)
   - Never leave wallet unlocked
   - Auto-lock is your friend

5. **The access rule:**
   - Use hot wallet for daily operations
   - Use cold wallet for major transactions
   - When in doubt, use cold wallet

## What This Protects Against

| Threat | Protection |
|--------|------------|
| Server hacked | ✅ Only 10% of funds at risk |
| SSH brute force | ✅ Firewall + fail2ban + key auth |
| Wallet file stolen | ✅ Encrypted, useless without passphrase |
| Keylogger on server | ✅ Most funds in cold wallet (offline) |
| Mnemonic loss | ✅ Multiple paper copies in safes |
| Server fire/disaster | ✅ Mnemonic backup recovers everything |
| User error | ✅ Small amounts in hot wallet limit damage |
| Insider attack | ✅ Cold wallet physically isolated |
| Network MITM | ✅ SSH encryption + no mnemonic on wire |
| Ransomware | ✅ Cold wallet offline, immune to malware |

## Recovery Procedures

### If Hot Wallet is Compromised:

1. **Immediate:**
   ```bash
   # From different secure device
   # Transfer remaining funds to new address immediately
   ```

2. **Assess:**
   - How much was lost? (max 10%)
   - 90% still safe in cold wallet

3. **Recreate:**
   - Create new hot wallet
   - New mnemonic, new passphrase
   - Fund with fresh 10%

### If You Lose Hot Wallet Access:

1. **Not a problem:**
   - Only 10% of funds affected
   - 90% safe in cold wallet

2. **Recover if needed:**
   - Restore from hot wallet mnemonic
   - Or simply create new hot wallet
   - Transfer 10% from cold wallet

### If You Lose Cold Wallet Mnemonic:

1. **Check backup locations:**
   - Primary safe
   - Secondary safe (if you made multiple copies)

2. **If truly lost:**
   - Funds in cold wallet are LOST
   - This is why we keep multiple copies
   - This is the ONE unrecoverable failure mode

3. **Prevention:**
   - 2-3 copies of mnemonic in different locations
   - Annual verification of backups
   - Consider safety deposit box for one copy

## Cost-Benefit Analysis

### What You're Protecting:

If you have $100,000 in Dilithion:
- Cold wallet: $90,000-$95,000 (impossible to hack remotely)
- Hot wallet: $5,000-$10,000 (maximum loss if server compromised)

### What You're Investing:

**Time:**
- Initial setup: 2 hours (one-time)
- Weekly maintenance: 5 minutes
- Monthly review: 15 minutes

**Money:**
- Old laptop for cold wallet: $0-$200 (one-time)
- Fireproof safe: $50-$200 (one-time)
- USB drive: $10 (one-time)
- Remote server: Already have

**Total annual time investment:** ~4 hours
**Total monetary investment:** $60-$410 (one-time)

**Protection gained:** 90% of funds completely safe from remote attacks

## Why This Is The Best Approach

### Simplicity:
- Easy to understand (hot = daily, cold = storage)
- Easy to use (SSH for small, offline for large)
- Easy to maintain (weekly 5-min check)

### Security:
- Defense in depth (multiple layers)
- Limits damage (10% max loss)
- Protects against most threats
- Simple mental model

### Practicality:
- Works with your existing servers
- No expensive hardware required
- Can access funds quickly when needed
- Scales as your holdings grow

### Recovery:
- Always possible (mnemonic in safe)
- Multiple backup points
- Clear procedures

## Alternative Approaches (Why I Don't Recommend)

### Single Hot Wallet (100% online):
- ❌ All funds at risk if compromised
- ❌ One breach = total loss
- Not recommended

### Multiple Hot Wallets:
- ⚠️ More complex to manage
- ⚠️ Higher operational overhead
- ⚠️ More points of failure
- Only for very high transaction volume

### Hardware Wallet Only:
- ⚠️ Good security
- ⚠️ But requires carrying device
- ⚠️ Single point of failure if lost
- ⚠️ Not ideal for remote server access

### 100% Cold Storage:
- ✅ Maximum security
- ❌ Inconvenient for daily use
- ❌ Need to boot offline computer for every transaction
- Only if you rarely transact

## My Professional Opinion

After considering security, usability, and risk management, the **Hot/Cold split (90/10)** is the optimal approach because:

1. **It protects 90% of your funds completely** - even if everything else fails
2. **It's simple** - easy to understand and follow
3. **It's practical** - convenient for daily use
4. **It's robust** - multiple failure points required for total loss
5. **It's standard** - used by exchanges, institutions, and security professionals

The setup I've outlined above gives you **bank-level security** with **maximum convenience** and **minimal complexity**.

**Bottom line:** Spend 2 hours today setting this up, and you'll have peace of mind knowing that even in the worst-case scenario (server completely compromised), you only lose 10% of your funds, and the other 90% are physically impossible to access remotely.

---

**Recommendation Confidence:** Very High
**Complexity Level:** Low-Medium
**Security Level:** Very High
**Risk of Total Fund Loss:** Near Zero (if procedures followed)
