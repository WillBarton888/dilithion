# Testnet Reset Guide - Chain ID Implementation

## Overview

This guide covers the testnet reset process required for the Chain ID (EIP-155) implementation. The chain ID feature prevents cross-chain replay attacks between mainnet and testnet, but requires a breaking change to the transaction signature format.

**Reset Date:** TBD (Coordinate with testnet participants)
**Reason:** Signature format change (40 bytes → 44 bytes with chain ID)
**Impact:** All existing testnet wallets and transactions become invalid

---

## Why Reset is Necessary

### The Breaking Change

**Old Signature Format (40 bytes):**
```
tx_hash (32B) + input_index (4B) + tx_version (4B) = 40 bytes
```

**New Signature Format (44 bytes with Chain ID):**
```
tx_hash (32B) + input_index (4B) + tx_version (4B) + chain_id (4B) = 44 bytes
```

### Incompatibility

- Old nodes cannot verify new signatures (expect 40 bytes, get 44 bytes)
- New nodes cannot verify old signatures (expect chain ID, don't find it)
- Result: Network fork if both versions run simultaneously

### Why Not Hard Fork?

While a hard fork activation height is possible, resetting is simpler for testnet because:
- Testnet coins have no real value
- Testnet is for testing breaking changes before mainnet
- Clean slate ensures everyone starts with compatible software
- No legacy code needed to support old format

---

## Pre-Reset Checklist

### For Testnet Node Operators

- [ ] **Announce reset date** at least 7 days in advance
- [ ] **Notify all testnet participants** via:
  - Discord/Telegram/Slack channels
  - GitHub repository announcements
  - Email lists
  - Website banner
- [ ] **Schedule downtime window** (coordinate time zones)
- [ ] **Backup important data** (if needed for analysis):
  ```bash
  # Backup testnet blockchain data
  cp -r ~/.dilithion-testnet ~/.dilithion-testnet-backup-$(date +%Y%m%d)
  ```

### For Testnet Users

- [ ] **Save important information** before reset:
  - Transaction IDs (for analysis/testing documentation)
  - Wallet addresses (for reference)
  - Test data/metrics you want to preserve
- [ ] **Understand**: All testnet DIL will be lost (no real value)
- [ ] **Plan**: Be ready to create new wallets after reset

---

## Reset Process

### Step 1: Stop All Testnet Nodes

**Coordinate a specific time for network shutdown:**

```bash
# Stop running testnet node
# Press Ctrl+C or:
pkill dilithion-node

# Verify process stopped
ps aux | grep dilithion-node
```

### Step 2: Delete Testnet Data Directory

**⚠️ WARNING: This deletes all testnet data including wallets!**

```bash
# Linux/macOS
rm -rf ~/.dilithion-testnet

# Windows (PowerShell)
Remove-Item -Recurse -Force "$env:USERPROFILE\.dilithion-testnet"

# Windows (Command Prompt)
rmdir /s /q "%USERPROFILE%\.dilithion-testnet"
```

**Files deleted:**
- `blocks/` - Blockchain database
- `utxos/` - UTXO set database
- `mempool/` - Unconfirmed transactions
- `wallets/` - All testnet wallets and keys
- `peers.dat` - Known peer list
- `banlist.dat` - Banned peers
- `debug.log` - Node logs

### Step 3: Update Node Software

**Pull latest code with chain ID implementation:**

```bash
# Navigate to dilithion repository
cd /path/to/dilithion

# Pull latest changes
git pull origin main

# Verify chain ID commit is included
git log --oneline | grep -i "chain id"
# Should see: 513937e feat: Add Chain ID (EIP-155) replay protection

# Rebuild with chain ID support
export PATH=/c/msys64/mingw64/bin:/c/msys64/usr/bin:$PATH  # Windows only
make clean
make
```

**Verify build includes chain ID:**

```bash
# Check that chainID field exists
grep -r "chainID" src/core/chainparams.h
# Should output: uint32_t chainID;

# Verify signature message size is 44 bytes
grep "sig_message.size() != 44" src/consensus/tx_validation.cpp
# Should find the check in VerifyScript()
```

### Step 4: Mine New Genesis Block

**The new genesis block will be the first block with chain ID protection.**

```bash
# Run genesis generator for testnet
./genesis_gen --testnet

# This will output:
# Network: TESTNET
# Chain ID: 1001
# Genesis Time: [timestamp]
# Genesis nBits: 0x1f060000
# ...
# Mining genesis block...
# [Progress updates]
# ✓ Genesis block mined!
# Genesis Hash: [new hash]
# Genesis Nonce: [new nonce]
```

**Update chainparams.cpp with new genesis:**

The genesis generator will display the values to update. Edit `src/core/chainparams.cpp`:

```cpp
ChainParams ChainParams::Testnet() {
    ChainParams params;
    params.network = TESTNET;
    params.networkMagic = 0xDAB5BFFA;
    params.chainID = 1001;  // ← Chain ID now included!

    // Update these values from genesis_gen output:
    params.genesisTime = [NEW_TIMESTAMP];
    params.genesisNonce = [NEW_NONCE];
    params.genesisNBits = 0x1f060000;
    params.genesisHash = "[NEW_HASH]";
    params.genesisCoinbaseMsg = "Dilithion Testnet Reset - Chain ID Implementation [DATE]";

    // Rest stays the same...
}
```

**Rebuild with new genesis:**

```bash
make clean
make
```

### Step 5: Start New Testnet

**Coordinate simultaneous start with all participants:**

```bash
# Start testnet node
./dilithion-node --testnet --mine --threads=auto

# Or with specific seed node:
./dilithion-node --testnet --mine --addnode=SEED_NODE_IP:18444
```

**Verify chain ID is active:**

```bash
# Check node startup output for:
# Network: TESTNET (256x easier difficulty)
# Chain ID: 1001  ← Should see this!

# Check genesis block:
# Genesis Hash: [matches your new genesis]
```

### Step 6: Create New Wallets

**All users must create new wallets:**

```bash
# Create new testnet wallet
# (Replace with your actual wallet creation command)
./dilithion-wallet --testnet create

# Generate new receiving addresses
./dilithion-wallet --testnet getnewaddress
```

**⚠️ Old wallet files are incompatible and should not be used!**

---

## Post-Reset Verification

### For Node Operators

**Verify chain ID implementation is working:**

1. **Check signature size:**
   ```bash
   # Mine a few blocks and create transactions
   # Monitor logs for signature verification
   tail -f ~/.dilithion-testnet/debug.log | grep -i signature
   ```

2. **Test cross-chain replay protection:**
   ```bash
   # This test verifies mainnet/testnet isolation
   # (Would require running both networks - for advanced testing)

   # Sign transaction on testnet
   # Attempt to broadcast to mainnet node
   # Expected: Signature verification fails due to chain ID mismatch
   ```

3. **Verify network consensus:**
   ```bash
   # Check all nodes agree on chain tip
   ./dilithion-cli --testnet getblockcount

   # Compare with other operators
   # All should report same block height and hash
   ```

### For Testnet Users

**Confirm wallet functionality:**

1. **Create test transaction:**
   ```bash
   # Send testnet DIL to another address
   ./dilithion-wallet --testnet send ADDRESS AMOUNT
   ```

2. **Verify transaction confirms:**
   ```bash
   # Check transaction status
   ./dilithion-wallet --testnet gettransaction TXID

   # Should show confirmations increasing
   ```

3. **Verify balance updates:**
   ```bash
   ./dilithion-wallet --testnet getbalance
   ```

---

## Troubleshooting

### Issue: "Chain parameters not initialized" Error

**Cause:** Node started before chain params were set
**Solution:** Restart the node

```bash
pkill dilithion-node
./dilithion-node --testnet
```

### Issue: "Invalid signature message size" Error

**Cause:** Mixed old/new node versions on network
**Solution:** Ensure all nodes are updated

```bash
# Check your version
git log -1 --oneline
# Should show: 513937e or later

# If old version:
git pull origin main
make clean && make
```

### Issue: Genesis Hash Mismatch

**Cause:** Nodes using different genesis blocks
**Solution:** Coordinate genesis parameters

```bash
# All operators must use EXACT same genesis values:
# - genesisTime (same for all)
# - genesisNonce (same for all)
# - genesisNBits (same for all)
# - genesisHash (same for all)

# Verify your genesis matches coordinator's genesis
./dilithion-cli --testnet getblockhash 0
```

### Issue: No Peers Connecting

**Cause:** Peer cache from old network
**Solution:** Clear peer data

```bash
rm ~/.dilithion-testnet/peers.dat
rm ~/.dilithion-testnet/banlist.dat

# Restart with seed nodes
./dilithion-node --testnet --addnode=SEED_NODE_IP:18444
```

### Issue: Transaction Rejected with "Invalid Signature"

**Possible causes:**

1. **Old wallet file being used:**
   ```bash
   # Solution: Create new wallet
   rm ~/.dilithion-testnet/wallets/*.dat
   ./dilithion-wallet --testnet create
   ```

2. **Node not fully updated:**
   ```bash
   # Solution: Verify chain ID in code
   grep "chainID" src/core/chainparams.cpp
   # Should see: params.chainID = 1001;
   ```

3. **Mixing mainnet/testnet:**
   ```bash
   # Solution: Always specify --testnet flag
   ./dilithion-node --testnet
   ./dilithion-wallet --testnet [command]
   ```

---

## Announcement Template

Use this template to notify testnet participants:

```
🔴 TESTNET RESET ANNOUNCEMENT 🔴

Dear Dilithion Testnet Participants,

We will be resetting the testnet on [DATE] at [TIME UTC] to implement
Chain ID (EIP-155) replay protection.

WHAT'S CHANGING:
- Transaction signature format (security improvement)
- All wallets must be recreated
- All existing testnet DIL will be lost (no real value)

WHY THIS IS NECESSARY:
Chain ID prevents cross-chain replay attacks between mainnet and testnet.
This is a critical security feature that must be in place before mainnet launch.

WHAT YOU NEED TO DO:

1. BEFORE RESET (Do this now):
   - Backup any important test data or transaction IDs
   - Save wallet addresses for reference (keys won't work after reset)

2. ON RESET DAY:
   - Stop your testnet node
   - Delete ~/.dilithion-testnet directory
   - Pull latest code from GitHub
   - Rebuild: make clean && make
   - Wait for new genesis parameters to be announced

3. AFTER RESET:
   - Start testnet node with --testnet flag
   - Create new wallet
   - Resume testing

TIMELINE:
- [7 DAYS BEFORE]: This announcement
- [3 DAYS BEFORE]: Reminder and final preparations
- [1 DAY BEFORE]: Final reminder
- [RESET DAY]: Network shutdown at [TIME UTC]
- [RESET DAY + 1 hour]: New testnet launches

QUESTIONS:
- GitHub: https://github.com/[your-repo]/issues
- Discord: [your-discord-link]
- Email: [your-email]

Thank you for participating in Dilithion testnet! This change makes
the network more secure for everyone.

- The Dilithion Core Team
```

---

## Post-Reset Documentation Updates

### Files to Update After Reset

1. **chainparams.cpp** - New genesis parameters
2. **TESTNET-GUIDE.md** - New genesis hash
3. **README.md** - Update testnet status
4. **CHANGELOG.md** - Document reset

### Git Commit Message Template

```
docs: Update testnet genesis after chain ID reset

Testnet was reset on [DATE] to implement Chain ID (EIP-155) replay protection.

New Genesis Parameters:
- Genesis Time: [TIMESTAMP]
- Genesis Nonce: [NONCE]
- Genesis Hash: [HASH]
- Genesis nBits: 0x1f060000
- Chain ID: 1001 (now enforced in signatures)

Breaking Changes:
- All old testnet wallets are invalid
- Old transaction signatures will not verify
- Network magic unchanged: 0xDAB5BFFA

Related: Commit 513937e (Chain ID implementation)
```

---

## Security Improvements from Reset

### Before Reset
❌ Testnet transactions could be replayed on mainnet
❌ Mainnet transactions could be replayed on testnet
❌ Vulnerable to future fork replay attacks
❌ No cryptographic network binding in signatures

### After Reset
✅ Testnet signatures include chain_id = 1001
✅ Mainnet signatures include chain_id = 1
✅ Cross-network replay attacks prevented
✅ Future fork protection built-in
✅ Follows Ethereum EIP-155 standard

---

## FAQ

### Q: Will mainnet require a similar reset?
**A:** No. Mainnet hasn't launched yet, so chain ID will be included from genesis block 0. No reset needed.

### Q: Can I keep my old testnet wallet?
**A:** No. The signature format changed, making old wallets incompatible. You must create a new wallet.

### Q: What if I miss the reset window?
**A:** Simply follow Steps 2-6 of this guide whenever you're ready. The new testnet will be running.

### Q: Can old and new nodes run together?
**A:** No. They use incompatible signature formats and will reject each other's transactions.

### Q: Will there be more resets?
**A:** Testnet resets may happen for major protocol changes. Mainnet will avoid resets at all costs.

### Q: How do I know if my node has chain ID support?
**A:** Run `git log --oneline | grep "513937e"`. If you see the chain ID commit, you have it.

### Q: What happens if I don't update?
**A:** Your node will be stuck on the old chain. Update and reset to join the new testnet.

---

## Reference

- **Chain ID Implementation:** `CHAIN-ID-IMPLEMENTATION.md`
- **Phase 5 Audit Report:** `PHASE-5-TRANSACTION-UTXO-AUDIT.md`
- **EIP-155 Standard:** https://eips.ethereum.org/EIPS/eip-155
- **Commit:** 513937e (feat: Add Chain ID replay protection)

---

**Document Version:** 1.0.0
**Last Updated:** 2025-01-11
**Status:** Ready for testnet reset coordination
