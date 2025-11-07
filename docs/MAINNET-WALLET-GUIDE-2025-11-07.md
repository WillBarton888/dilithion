# Dilithion Mainnet Wallet Guide

**Version:** 1.0.0
**Network:** Mainnet
**Signature Scheme:** CRYSTALS-Dilithium3 (Post-Quantum)
**Launch Date:** January 1, 2026 00:00:00 UTC
**Last Updated:** November 7, 2025

Complete guide to managing your quantum-safe Dilithion wallet.

---

## Table of Contents

1. [Wallet Overview](#wallet-overview)
2. [Getting Started](#getting-started)
3. [Receiving Funds](#receiving-funds)
4. [Sending Funds](#sending-funds)
5. [Backup and Recovery](#backup-and-recovery)
6. [Security Best Practices](#security-best-practices)
7. [RPC Command Reference](#rpc-command-reference)
8. [Advanced Topics](#advanced-topics)
9. [Troubleshooting](#troubleshooting)

---

## Wallet Overview

### What is a Dilithion Wallet?

Your Dilithion wallet:
- Stores **private keys** secured with CRYSTALS-Dilithium3 (NIST post-quantum standard)
- Generates **quantum-resistant addresses** for receiving DIL
- Signs transactions with **post-quantum signatures** (3,309 bytes)
- Tracks your **UTXO set** (unspent transaction outputs)
- Maintains transaction history

### Post-Quantum Cryptography

**Why it matters:**
- Traditional ECDSA: Vulnerable to quantum computers (Shor's algorithm)
- Dilithium3: Quantum-resistant lattice-based signatures
- Future-proof: Your funds stay safe even against quantum attacks

**Key sizes:**
- **Public key:** 1,952 bytes
- **Private key:** 4,000 bytes
- **Signature:** 3,309 bytes

**Trade-off:** Larger transactions (~5-10KB vs ~500 bytes for Bitcoin), but quantum-safe security.

### Wallet File Location

**Default paths:**

- **Linux/macOS:** `~/.dilithion/wallet.dat`
- **Windows:** `C:\Users\<YourName>\.dilithion\wallet.dat`
- **Custom:** `<datadir>/wallet.dat`

**CRITICAL:** This file contains your private keys. Lose it = lose your funds.

---

## Getting Started

### Creating Your First Wallet

**Wallet is automatically created on first run:**

```bash
./dilithion-node
```

**Output:**
```
Initializing wallet...
  Generating initial address...
  ✓ Initial address: D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV
```

**Verify wallet exists:**
```bash
ls -l ~/.dilithion/wallet.dat
```

### Encrypt Your Wallet

**CRITICAL SECURITY STEP - Do this immediately:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "encryptwallet",
    "params": ["your-strong-passphrase-here"],
    "id": 1
  }'
```

**Passphrase requirements:**
- ✅ Minimum 20 characters
- ✅ Mix of uppercase, lowercase, numbers, symbols
- ✅ NOT a dictionary word
- ✅ Unique to Dilithion (don't reuse passwords)

**Example strong passphrase:**
```
Quantum-Safe-2026!DIL#Secure$Wallet
```

**WARNING:**
- Once encrypted, you MUST remember passphrase
- No passphrase recovery possible
- Lost passphrase = lost funds forever

**Node will restart after encryption**

### Unlock Wallet for Transactions

**After encryption, unlock to send funds:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "walletpassphrase",
    "params": ["your-passphrase", 300],
    "id": 1
  }'
```

**Parameters:**
- `"your-passphrase"`: Your encryption passphrase
- `300`: Unlock duration in seconds (5 minutes)

**Wallet automatically locks after timeout**

---

## Receiving Funds

### Generate Receiving Address

**Create new address:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getnewaddress",
    "params": [],
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV",
  "id": 1
}
```

### Address Format

**Dilithion addresses:**
- Start with `D` (mainnet) or `d` (testnet)
- Base58Check encoded
- Include checksum for typo detection
- Example: `D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV`

**Address validation:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "validateaddress",
    "params": ["D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV"],
    "id": 1
  }'
```

### Privacy Considerations

**Address reuse:**
- ❌ **Don't reuse addresses** (privacy leak)
- ✅ Generate new address for each receipt
- ✅ Old addresses still work, but use new ones

**Why?**
- Links all transactions to same entity
- Reduces privacy for you and sender
- Best practice: One address per transaction

### Check Balance

**Get total balance:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getbalance",
    "params": [],
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": 150.50000000,
  "id": 1
}
```

**Balance types:**

- **Confirmed balance:** 6+ confirmations (safe to spend)
- **Immature balance:** Mined coins < 100 confirmations
- **Unconfirmed balance:** 0-5 confirmations (waiting)

**Check all balance types:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getbalances",
    "params": [],
    "id": 1
  }'
```

### Monitor Incoming Transactions

**List recent transactions:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "listtransactions",
    "params": ["*", 10],
    "id": 1
  }'
```

**Parameters:**
- `"*"`: All accounts
- `10`: Last 10 transactions

**Watch for incoming transactions in real-time:**
```bash
watch -n 10 'curl -s -X POST http://localhost:8332 -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"getbalance\",\"params\":[],\"id\":1}" | jq .result'
```

---

## Sending Funds

### Basic Send

**Send DIL to address:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sendtoaddress",
    "params": [
      "DRecipientAddressHere123456789",
      10.5,
      "Comment for your records",
      "Recipient name (optional)"
    ],
    "id": 1
  }'
```

**Parameters:**
- Address: Recipient Dilithion address
- Amount: DIL to send (decimal precision: 8 places)
- Comment: Optional note (not on blockchain)
- To: Optional recipient label

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "abc123def456...789",
  "id": 1
}
```

**Transaction ID (txid)** returned for tracking.

### Transaction Fees

**Fee calculation:**

Dilithion uses a **hybrid fee model:**

1. **Minimum relay fee:** 0.0001 DIL per KB
2. **Priority fee:** Higher fees get faster confirmation
3. **Size-based:** Post-quantum signatures are larger

**Typical transaction sizes:**
- Simple send (1 input, 2 outputs): ~6-8 KB
- Typical fee: ~0.001 DIL (auto-calculated)

**Fees are automatically calculated and deducted from sent amount.**

### Advanced Send Options

**Send with specific fee:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sendtoaddress",
    "params": [
      "DRecipientAddress",
      10.5,
      "",
      "",
      false,
      0.002
    ],
    "id": 1
  }'
```

**Last parameter:** Custom fee (0.002 DIL)

### Send to Multiple Recipients

**Create raw transaction (advanced):**

```bash
# 1. List unspent outputs
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"listunspent","params":[],"id":1}'

# 2. Create transaction
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "createrawtransaction",
    "params": [
      [{"txid": "abc123...", "vout": 0}],
      {
        "DRecipient1Address": 5.0,
        "DRecipient2Address": 3.5,
        "DChangeAddress": 1.49
      }
    ],
    "id": 1
  }'

# 3. Sign transaction
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "signrawtransaction",
    "params": ["<hex_from_step_2>"],
    "id": 1
  }'

# 4. Broadcast
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sendrawtransaction",
    "params": ["<signed_hex>"],
    "id": 1
  }'
```

### Verify Transaction Status

**Get transaction details:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "gettransaction",
    "params": ["abc123def456...789"],
    "id": 1
  }'
```

**Check confirmations:**
- 0: Unconfirmed (in mempool)
- 1: In latest block
- 6+: Considered final

**Average confirmation time:** 4 minutes per block

---

## Backup and Recovery

### Backup Wallet

**CRITICAL: Backup your wallet regularly**

**Method 1: Manual File Copy**

```bash
# Stop node first (safest)
systemctl stop dilithion  # or kill dilithion-node

# Copy wallet
cp ~/.dilithion/wallet.dat ~/wallet-backup-$(date +%Y%m%d).dat

# Restart node
systemctl start dilithion
```

**Method 2: Backup While Running (Advanced)**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "backupwallet",
    "params": ["/path/to/backup/wallet-backup.dat"],
    "id": 1
  }'
```

### Encrypt Backup

**Always encrypt wallet backups:**

```bash
# GPG encryption
gpg -c wallet-backup-20260101.dat
# Enter strong passphrase

# Encrypted file: wallet-backup-20260101.dat.gpg
```

**Or use zip encryption:**
```bash
zip --encrypt wallet-backup.zip wallet-backup-20260101.dat
```

### Secure Storage

**Store backups in multiple locations:**

1. ✅ **External USB drive** (keep offline, safe location)
2. ✅ **Encrypted cloud storage** (Google Drive, Dropbox - GPG encrypted first!)
3. ✅ **Bank safe deposit box** (for large holdings)
4. ✅ **Secondary computer** (different location)

**3-2-1 Rule:**
- **3** copies total
- **2** different media types
- **1** off-site

### Restore Wallet

**From backup file:**

```bash
# Stop node
systemctl stop dilithion

# Replace wallet.dat
cp ~/wallet-backup-20260101.dat ~/.dilithion/wallet.dat

# Set permissions
chmod 600 ~/.dilithion/wallet.dat

# Start node
systemctl start dilithion
```

**Decrypt GPG backup first:**
```bash
gpg -d wallet-backup-20260101.dat.gpg > wallet-backup-20260101.dat
```

**Node will rescan blockchain for your transactions on startup**

### Export Private Keys (Advanced)

**Dump single address private key:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "dumpprivkey",
    "params": ["D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV"],
    "id": 1
  }'
```

**WARNING:**
- Anyone with private key can spend funds
- Only export for backup/migration
- Never share private keys

**Import private key:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "importprivkey",
    "params": ["<private_key_here>", "imported_address"],
    "id": 1
  }'
```

---

## Security Best Practices

### Wallet Encryption

**Always encrypt your wallet:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "encryptwallet",
    "params": ["quantum-Safe-Passphrase-2026!"],
    "id": 1
  }'
```

**Change passphrase:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "walletpassphrasechange",
    "params": ["old-passphrase", "new-passphrase"],
    "id": 1
  }'
```

### Cold Storage

**For large holdings, use cold storage:**

**Method 1: Offline Computer**
1. Install Dilithion on air-gapped computer
2. Generate addresses offline
3. Transfer signed transactions via USB

**Method 2: Paper Wallet**
1. Generate address and private key
2. Print on paper (use secure printer!)
3. Store in safe location
4. Send funds to printed address

**To spend from cold storage:**
1. Import private key to online node
2. Send transaction
3. (Optional) Send remaining balance to new cold address

### Multi-Signature (Future Feature)

**Currently not implemented, planned for future:**
- Require M-of-N signatures to spend
- Example: 2-of-3 (any 2 of 3 keys required)
- Corporate treasury security
- Inheritance planning

### Security Checklist

- ✅ Wallet encrypted with strong passphrase
- ✅ Backup created and encrypted
- ✅ Backups stored in 3+ locations
- ✅ RPC only accessible from localhost
- ✅ Firewall blocking unauthorized access
- ✅ Operating system updated
- ✅ Antivirus/anti-malware running
- ✅ No wallet files in cloud (unencrypted)
- ✅ Passphrase memorized or in password manager

---

## RPC Command Reference

### Balance Commands

**getbalance** - Get wallet balance
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}'
```

**getunconfirmedbalance** - Get unconfirmed balance
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getunconfirmedbalance","params":[],"id":1}'
```

**listunspent** - List unspent transaction outputs
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"listunspent","params":[6],"id":1}'
```

### Address Commands

**getnewaddress** - Generate new receiving address
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getnewaddress","params":[],"id":1}'
```

**validateaddress** - Check if address is valid
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"validateaddress","params":["DAddress"],"id":1}'
```

**listreceivedbyaddress** - List amounts received by address
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"listreceivedbyaddress","params":[6],"id":1}'
```

### Transaction Commands

**sendtoaddress** - Send to address
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"sendtoaddress","params":["DAddr",10.5],"id":1}'
```

**listtransactions** - List recent transactions
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"listtransactions","params":["*",10],"id":1}'
```

**gettransaction** - Get transaction details
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"gettransaction","params":["txid"],"id":1}'
```

### Security Commands

**encryptwallet** - Encrypt wallet (one-time)
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"encryptwallet","params":["passphrase"],"id":1}'
```

**walletpassphrase** - Unlock wallet temporarily
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"walletpassphrase","params":["passphrase",300],"id":1}'
```

**walletlock** - Lock wallet immediately
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"walletlock","params":[],"id":1}'
```

### Backup Commands

**backupwallet** - Backup wallet file
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"backupwallet","params":["/path/backup.dat"],"id":1}'
```

**dumpprivkey** - Export private key
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"dumpprivkey","params":["DAddress"],"id":1}'
```

**importprivkey** - Import private key
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"importprivkey","params":["privkey"],"id":1}'
```

---

## Advanced Topics

### Watch-Only Wallets

**Import address without private key (monitoring only):**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "importaddress",
    "params": ["DAddressToWatch", "label", false],
    "id": 1
  }'
```

**Use cases:**
- Monitor cold storage balance
- Track donations
- Audit purposes

### Transaction Analysis

**Get detailed transaction hex:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getrawtransaction",
    "params": ["txid", true],
    "id": 1
  }'
```

**Decode raw transaction:**

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "decoderawtransaction",
    "params": ["<hex>"],
    "id": 1
  }'
```

### Coin Control

**Select specific UTXOs for transaction:**

```bash
# 1. List available UTXOs
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"listunspent","params":[],"id":1}'

# 2. Create transaction with specific inputs
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "createrawtransaction",
    "params": [
      [{"txid": "specific_txid", "vout": 0}],
      {"DRecipient": 10.0}
    ],
    "id": 1
  }'
```

**Benefits:**
- Privacy (avoid linking addresses)
- Fee optimization
- UTXO consolidation

---

## Troubleshooting

### Wallet Not Found

**Error:** `Error: wallet.dat not found`

**Solution:**
```bash
# Create new wallet
./dilithion-node
# Wallet auto-creates on first run
```

### Wrong Password

**Error:** `Error: The wallet passphrase entered was incorrect`

**Solutions:**
1. Try passphrase variations (caps lock, typos)
2. Check passphrase in password manager
3. If lost, **funds are unrecoverable**
4. Restore from unencrypted backup (if exists)

### Balance Not Showing

**Issue:** Sent funds not appearing

**Diagnose:**

1. **Check blockchain sync:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'
```

2. **Verify transaction on explorer:**
- Check txid on block explorer
- Confirm transaction was broadcast

3. **Rescan blockchain:**
```bash
./dilithion-node -rescan
```

### Transaction Stuck

**Issue:** Transaction unconfirmed for hours

**Causes:**
- Fee too low
- Network congestion
- Double-spend attempt

**Solutions:**

1. **Check mempool:**
```bash
curl -X POST http://localhost:8332 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getrawmempool","params":[],"id":1}'
```

2. **Wait for next block** (may confirm then)

3. **Replace-by-fee** (if enabled):
- Create new transaction with higher fee
- Uses same inputs

### Corrupted Wallet

**Error:** `Error loading wallet.dat`

**Recovery:**

1. **Restore from backup:**
```bash
cp ~/wallet-backup.dat ~/.dilithion/wallet.dat
```

2. **Use salvage mode:**
```bash
./dilithion-node -salvagewallet
```

3. **If irreparable, extract private keys:**
- Use wallet recovery tools
- Import to new wallet

**Prevention:** Regular backups!

---

## Next Steps

**Your Dilithion wallet is now fully configured!** 💰

### Continue Learning:

1. **[Node Setup Guide](MAINNET-NODE-SETUP-2025-11-07.md)** - Optimize your node
2. **[Mining Guide](MAINNET-MINING-GUIDE-2025-11-07.md)** - Earn DIL rewards
3. **[Troubleshooting](TROUBLESHOOTING-2025-11-07.md)** - Solve issues

### Best Practices Reminder:

✅ Wallet encrypted with strong passphrase
✅ Backup created and stored securely
✅ New address for each receipt (privacy)
✅ Only unlock wallet when sending
✅ Verify recipient address before sending
✅ Test small amount first for new recipients

### Join Community:

- **Discord:** https://discord.gg/c25WwRNg
- **Website:** https://dilithion.org
- **GitHub:** https://github.com/WillBarton888/dilithion

**Your funds are quantum-safe! Welcome to the future!** 🛡️💎

---

**Document Version:** 1.0.0
**Mainnet Launch:** January 1, 2026 00:00:00 UTC
**Last Updated:** November 7, 2025

---

*Dilithion - Post-Quantum Cryptocurrency - Your Quantum-Safe Wallet* 🛡️
