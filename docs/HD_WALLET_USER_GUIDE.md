# Dilithion HD Wallet User Guide

**Version:** 1.0
**Date:** 2025-11-10
**Status:** Production Ready

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Creating an HD Wallet](#creating-an-hd-wallet)
4. [Restoring from Mnemonic](#restoring-from-mnemonic)
5. [Using Your Wallet](#using-your-wallet)
6. [RPC API Reference](#rpc-api-reference)
7. [Security Best Practices](#security-best-practices)
8. [Backup & Recovery](#backup--recovery)
9. [Troubleshooting](#troubleshooting)
10. [Advanced Topics](#advanced-topics)

## Introduction

### What is an HD Wallet?

HD (Hierarchical Deterministic) wallets allow you to generate an unlimited number of cryptocurrency addresses from a single **recovery phrase** (mnemonic). This means:

✅ **One backup protects everything** - Your 24-word recovery phrase can restore all your addresses
✅ **Privacy** - Generate a new address for every transaction
✅ **Organization** - Separate accounts for different purposes
✅ **Post-quantum secure** - Uses CRYSTALS-Dilithium3 signatures

### Why HD Wallets?

**Traditional wallets** require backing up each private key separately. If you generate 100 addresses, you need 100 backups.

**HD wallets** generate all addresses from one seed. Backup once, restore everything.

### How Does It Work?

```
Recovery Phrase (24 words)
    ↓
Master Seed
    ↓
Master Key → Account 0 → Receive Address 0, 1, 2, ...
           → Account 1 → Receive Address 0, 1, 2, ...
                      → Change Address 0, 1, 2, ...
```

## Getting Started

### Prerequisites

1. Dilithion node installed and running
2. RPC server enabled (default port: 8332)
3. Empty wallet (new installation) OR existing wallet you want to upgrade

### Quick Start (5 minutes)

1. **Create new HD wallet:**
   ```bash
   dilithion-cli createhdwallet
   ```

2. **Write down your recovery phrase** (24 words) - This is CRITICAL!

3. **Get your first address:**
   ```bash
   dilithion-cli getnewaddress
   ```

4. **Send some DIL to your address**

5. **Backup your recovery phrase** in a secure location

Done! Your wallet is now HD-enabled and quantum-secure.

## Creating an HD Wallet

### Method 1: Simple Creation (No Passphrase)

```bash
$ dilithion-cli createhdwallet
```

**Response:**
```json
{
  "mnemonic": "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
  "address": "DL1qwertyuiopasdfghjklzxcvbnm1234567890"
}
```

⚠️ **CRITICAL:** Write down the 24-word mnemonic phrase and store it securely!

### Method 2: Creation with Passphrase (Advanced)

```bash
$ dilithion-cli createhdwallet '{"passphrase":"my-super-secret-passphrase"}'
```

**Response:**
```json
{
  "mnemonic": "abandon abandon abandon ... abandon art",
  "address": "DL1different_address_due_to_passphrase"
}
```

**Passphrase Benefits:**
- ✅ Extra security layer
- ✅ Plausible deniability (different passphrase = different wallet)
- ✅ Protection if mnemonic is compromised

**Passphrase Risks:**
- ⚠️ If you forget passphrase, funds are PERMANENTLY LOST
- ⚠️ Must remember both mnemonic AND passphrase

### What is a Mnemonic?

A mnemonic is a **24-word phrase** from a standardized wordlist (BIP39). Example:

```
legal winner thank year wave sausage worth useful
legal winner thank year wave sausage worth useful
legal winner thank year wave sausage worth title
```

**Properties:**
- 24 words = 256 bits of entropy
- Each word is from a 2048-word dictionary
- Last word includes a checksum
- Words are easy to write down and remember

### Security Checklist

Before creating your wallet:

- [ ] You have a pen and paper ready
- [ ] You're in a private location
- [ ] Your computer is malware-free
- [ ] You understand mnemonics are NOT recoverable if lost

## Restoring from Mnemonic

### Scenario 1: New Computer

You bought a new computer and want to restore your wallet.

```bash
$ dilithion-cli restorehdwallet '{
  "mnemonic":"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
}'
```

**Response:**
```json
{
  "success": true,
  "address": "DL1qwertyuiopasdfghjklzxcvbnm1234567890"
}
```

✅ Your wallet is restored! All addresses will be re-generated automatically.

### Scenario 2: Restore with Passphrase

```bash
$ dilithion-cli restorehdwallet '{
  "mnemonic":"abandon abandon abandon ... art",
  "passphrase":"my-super-secret-passphrase"
}'
```

⚠️ **Important:** Both mnemonic AND passphrase must match exactly!

### Verification

After restoring, verify your addresses match:

```bash
$ dilithion-cli listhdaddresses
```

Compare the addresses with your previous wallet. They should be identical.

## Using Your Wallet

### Get a New Address

```bash
$ dilithion-cli getnewaddress
```

**Response:**
```
DL1new_unique_address_here
```

Each call generates a sequential address:
- 1st call: m/44'/573'/0'/0'/0'
- 2nd call: m/44'/573'/0'/0'/1'
- 3rd call: m/44'/573'/0'/0'/2'
- etc.

### Check Wallet Status

```bash
$ dilithion-cli gethdwalletinfo
```

**Response:**
```json
{
  "hdwallet": true,
  "account": 0,
  "external_index": 5,
  "internal_index": 2
}
```

**Meaning:**
- `hdwallet: true` - This is an HD wallet
- `account: 0` - Using account 0
- `external_index: 5` - Generated 5 receive addresses
- `internal_index: 2` - Generated 2 change addresses

### List All Addresses

```bash
$ dilithion-cli listhdaddresses
```

**Response:**
```json
[
  {
    "address": "DL1address1...",
    "path": "m/44'/573'/0'/0'/0'"
  },
  {
    "address": "DL1address2...",
    "path": "m/44'/573'/0'/0'/1'"
  },
  ...
]
```

### Export Mnemonic (Backup)

⚠️ **Only do this in a secure environment!**

```bash
$ dilithion-cli exportmnemonic
```

**Response:**
```json
{
  "mnemonic": "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
}
```

Use this to backup your wallet to a new paper wallet.

### Check Balance

```bash
$ dilithion-cli getbalance
```

Works the same as non-HD wallets.

### Send Funds

```bash
$ dilithion-cli sendtoaddress "DL1recipient_address" 10.5
```

Works the same as non-HD wallets. Change will automatically go to a change address.

## RPC API Reference

### createhdwallet

Creates a new HD wallet and returns the mnemonic phrase.

**Request:**
```json
{
  "passphrase": "optional-passphrase"
}
```

**Response:**
```json
{
  "mnemonic": "24-word mnemonic phrase",
  "address": "first-derived-address"
}
```

**Errors:**
- "Wallet is already an HD wallet"
- "Can only create HD wallet on an empty wallet"

---

### restorehdwallet

Restores an HD wallet from a mnemonic phrase.

**Request:**
```json
{
  "mnemonic": "24-word mnemonic phrase",
  "passphrase": "optional-passphrase"
}
```

**Response:**
```json
{
  "success": true,
  "address": "first-derived-address"
}
```

**Errors:**
- "Wallet is already an HD wallet"
- "Can only restore HD wallet on an empty wallet"
- "Failed to restore HD wallet (invalid mnemonic or passphrase)"

---

### exportmnemonic

Exports the mnemonic phrase (requires wallet to be unlocked if encrypted).

**Request:**
```json
{}
```

**Response:**
```json
{
  "mnemonic": "24-word mnemonic phrase"
}
```

**Errors:**
- "Wallet is not an HD wallet"
- "Failed to export mnemonic (wallet may be locked)"

---

### gethdwalletinfo

Returns information about the HD wallet state.

**Request:**
```json
{}
```

**Response (HD Wallet):**
```json
{
  "hdwallet": true,
  "account": 0,
  "external_index": 10,
  "internal_index": 3
}
```

**Response (Non-HD Wallet):**
```json
{
  "hdwallet": false
}
```

---

### listhdaddresses

Lists all addresses with their derivation paths.

**Request:**
```json
{}
```

**Response:**
```json
[
  {
    "address": "DL1...",
    "path": "m/44'/573'/0'/0'/0'"
  },
  {
    "address": "DL1...",
    "path": "m/44'/573'/0'/1'/0'"
  }
]
```

**Errors:**
- "Wallet is not an HD wallet"

---

## Security Best Practices

### 1. Mnemonic Storage

**DO:**
- ✅ Write on paper with pen (not pencil - it fades)
- ✅ Store in a fireproof/waterproof safe
- ✅ Make multiple copies in different locations
- ✅ Use a passphrase for extra security
- ✅ Test restoration BEFORE funding wallet

**DON'T:**
- ❌ Store in plain text file on computer
- ❌ Email to yourself
- ❌ Store in cloud (Dropbox, Google Drive)
- ❌ Take a photo (can be hacked)
- ❌ Store in password manager (if compromised, wallet is too)

### 2. Passphrase Guidelines

If using a passphrase:

**Good Passphrases:**
- ✅ 20+ characters
- ✅ Mix of uppercase, lowercase, numbers, symbols
- ✅ Unique (not used elsewhere)
- ✅ Memorable but not guessable
- ✅ Example: `MyD0g'sName&MyB1rthYear!`

**Bad Passphrases:**
- ❌ Short (<12 characters)
- ❌ Dictionary words
- ❌ Personal info (birthday, name)
- ❌ Reused from other accounts

### 3. Operational Security

**Creating Wallet:**
- ✅ Use offline/air-gapped computer if possible
- ✅ Ensure no cameras/people can see screen
- ✅ Verify computer is malware-free
- ✅ Use freshly booted OS from read-only media (extra paranoid)

**Using Wallet:**
- ✅ Encrypt wallet with strong passphrase
- ✅ Lock wallet when not in use
- ✅ Use different address for each transaction
- ✅ Keep software updated

**Exporting Mnemonic:**
- ✅ Only do offline
- ✅ Clear clipboard after
- ✅ Ensure no screen recording software
- ✅ Check for keyloggers

### 4. Backup Strategy

**3-2-1 Rule:**
- 3 copies of your mnemonic
- 2 different storage media (paper + metal)
- 1 off-site location

**Example:**
1. Paper in home safe
2. Metal plate in bank safe deposit box
3. Paper with trusted family member (encrypted)

### 5. Recovery Testing

**Test before funding:**
```bash
# 1. Create wallet and note first address
dilithion-cli createhdwallet
# Note the address: DL1abc...

# 2. Backup mnemonic

# 3. Delete wallet
rm ~/.dilithion/wallet.dat

# 4. Restore wallet
dilithion-cli restorehdwallet '{"mnemonic":"..."}'

# 5. Verify address matches
dilithion-cli getnewaddress
# Should be: DL1abc... (same as step 1)
```

## Backup & Recovery

### Full Backup Checklist

- [ ] Mnemonic phrase (24 words)
- [ ] Passphrase (if used)
- [ ] Derivation path (usually default: m/44'/573'/0'/0/X)
- [ ] Account number (usually 0)
- [ ] List of used addresses (for verification)

### Recovery Scenarios

#### Scenario 1: Lost Wallet File

**Problem:** Hard drive crashed, wallet.dat is gone

**Solution:**
```bash
dilithion-cli restorehdwallet '{"mnemonic":"your 24 words here"}'
```

All addresses and balances will be recovered.

#### Scenario 2: Forgot Passphrase

**Problem:** You have mnemonic but forgot passphrase

**Solution:** None. Funds are permanently inaccessible.

**Prevention:**
- Store passphrase separately from mnemonic
- Test restoration before funding
- Use a memorable but strong passphrase

#### Scenario 3: Partial Mnemonic

**Problem:** Lost a few words of your mnemonic

**Solution:** Brute-force the missing words
- 24-word mnemonic with 1 missing word: ~2048 attempts
- 24-word mnemonic with 2 missing words: ~4M attempts
- 24-word mnemonic with 3+ missing words: Practically impossible

**Tools:** btcrecover, specialized recovery services

#### Scenario 4: Wrong Word Order

**Problem:** You wrote down words but not the order

**Solution:** Brute-force word permutations
- 24 words in wrong order: 24! = 6.2×10^23 combinations (impossible)
- If you know most positions are correct: Feasible

**Prevention:** Number your words (1-24) when writing down

### Inheritance Planning

**Problem:** What happens to your crypto when you die?

**Solutions:**

1. **Dead Man's Switch**
   - Give mnemonic to lawyer/executor
   - Sealed envelope with instructions

2. **Multisig (Future Feature)**
   - Require 2-of-3 signatures
   - You + trusted family member + backup

3. **Passphrase Split**
   - Give mnemonic to person A
   - Give passphrase to person B
   - Both needed to access

## Troubleshooting

### "Failed to restore HD wallet (invalid mnemonic or passphrase)"

**Causes:**
1. Typo in mnemonic (wrong word)
2. Wrong passphrase
3. Words in wrong order
4. Wrong wordlist language

**Solutions:**
- Double-check each word against BIP39 wordlist
- Try without passphrase (if you used one, it won't work)
- Try passphrase variations (capitalization, spaces)
- Use `dilithion-cli` mnemonic validator (if available)

### "Wallet is already an HD wallet"

**Cause:** Attempting to create/restore when wallet is already HD

**Solution:**
- Export mnemonic to verify: `dilithion-cli exportmnemonic`
- If you want a new wallet: Delete wallet.dat and start fresh
- If you want to add to existing: Just use `getnewaddress`

### "Can only create HD wallet on an empty wallet"

**Cause:** Wallet has existing keys/addresses

**Solution:**
- Start with a fresh wallet
- OR restore existing HD wallet if you have the mnemonic

### Addresses Don't Match After Restoration

**Causes:**
1. Wrong passphrase used
2. Different account/path used
3. Restored fewer addresses than original

**Solutions:**
- Try restoring with correct passphrase
- Generate more addresses: `dilithion-cli getnewaddress` (repeat)
- Check path with `dilithion-cli listhdaddresses`

### "Failed to export mnemonic (wallet may be locked)"

**Cause:** Wallet is encrypted and locked

**Solution:**
```bash
dilithion-cli walletpassphrase "your-wallet-password" 60
dilithion-cli exportmnemonic
dilithion-cli walletlock
```

## Advanced Topics

### BIP44 Derivation Paths

Dilithion uses the BIP44 standard:

```
m/44'/573'/account'/change'/index'
```

**Breakdown:**
- `m` - Master key
- `44'` - BIP44 purpose (hardened)
- `573'` - Dilithion coin type (hardened)
- `account'` - Account number (default 0, hardened)
- `change'` - 0 for receive, 1 for change (hardened)
- `index'` - Address index (0, 1, 2, ..., hardened)

**Note:** All levels use hardened derivation (') for post-quantum security

### Multiple Accounts

Future feature: Separate accounts for different purposes

```
Account 0: Personal spending
Account 1: Business
Account 2: Savings
```

### Gap Limit

Dilithion follows BIP44's gap limit of 20:
- Wallet scans up to 20 consecutive unused addresses
- If all 20 are unused, scanning stops
- Prevents infinite scanning on restoration

### Passphrase as 25th Word

Your passphrase acts like a "25th word":
- Same mnemonic + different passphrase = Different wallet
- Plausible deniability: "I only have a small amount" (give passphrase for decoy wallet)

**Example:**
```
Mnemonic: "legal winner ... title"
Passphrase A: "secret123" → Wallet A (main funds)
Passphrase B: "decoy456"  → Wallet B (small decoy amount)
```

If coerced, give Passphrase B to show "your wallet" with minimal funds.

### Encryption Best Practices

1. **Encrypt wallet after creation:**
   ```bash
   dilithion-cli encryptwallet "strong-passphrase"
   ```

2. **Lock wallet when not in use:**
   ```bash
   dilithion-cli walletlock
   ```

3. **Unlock temporarily for transactions:**
   ```bash
   dilithion-cli walletpassphrase "strong-passphrase" 60
   # Do your transaction within 60 seconds
   # Wallet auto-locks after timeout
   ```

### Hardware Wallet Integration (Future)

Future versions will support hardware wallets:
- Trezor/Ledger integration
- Master seed never leaves hardware device
- Sign transactions on hardware device

## FAQ

**Q: Can I use the same mnemonic on multiple computers?**
A: Yes! That's the point of HD wallets. Same mnemonic = same addresses.

**Q: What happens if I lose my mnemonic?**
A: Your funds are permanently lost. There is NO recovery method.

**Q: Can I change my mnemonic?**
A: No. You'd need to create a new wallet and send all funds to it.

**Q: How many addresses can I generate?**
A: 2^31 (about 2 billion) per account. Practically unlimited.

**Q: Are HD wallets slower than regular wallets?**
A: Slightly (~10ms per address), but imperceptible to users.

**Q: Can someone guess my mnemonic?**
A: No. 24-word mnemonic has 2^256 combinations. Even with all computers on Earth, it would take longer than the age of the universe.

**Q: What if my mnemonic is leaked but not my passphrase?**
A: If you used a strong passphrase, your funds are safe. The attacker cannot derive keys without it.

**Q: Can I use a 12-word mnemonic instead of 24?**
A: Dilithion generates 24-word mnemonics for maximum security. 12-word is less secure (128-bit vs 256-bit).

**Q: Is this compatible with Bitcoin/Ethereum wallets?**
A: No. Different signature scheme (Dilithium vs ECDSA). Mnemonic format is compatible (BIP39), but derived keys are different.

---

## Support

For issues or questions:
- GitHub: https://github.com/dilithion/dilithion
- Documentation: https://docs.dilithion.org
- Community: https://forum.dilithion.org

**Remember:** NEVER share your mnemonic or passphrase with anyone, including support staff. No legitimate support will ever ask for it.

---

**Document Version:** 1.0
**Last Updated:** 2025-11-10
**License:** MIT
