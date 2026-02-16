# How to Transfer DIL (Dilithion Coins)

**Complete Guide for Beginners**

---

## Quick Answer

**Sending DIL:**
```bash
# Using RPC
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"sendtoaddress","params":{"address":"RECIPIENT_ADDRESS","amount":10.5},"id":1}'

# Using command line (future CLI tool)
./dilithion-cli sendtoaddress RECIPIENT_ADDRESS 10.5
```

**That's it!** The transaction will be broadcast to the network and confirmed in ~4 minutes.

---

## Step-by-Step Transfer Guide

### Prerequisites

1. **Running Dilithion Node**
   ```bash
   ./dilithion-node
   ```

2. **Wallet with Balance**
   - Check balance: `{"method":"getbalance"}`
   - Must have sufficient DIL + fees

3. **Recipient Address**
   - Get from recipient (starts with 'D' for mainnet, 'm' for testnet)
   - Example: `D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV`

### Method 1: Using RPC (Current Method)

#### Step 1: Check Your Balance

```bash
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":{},"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "balance": 150.00000000,
    "unconfirmed_balance": 0.00000000,
    "immature_balance": 50.00000000
  },
  "id": 1
}
```

- **balance**: Spendable coins (confirmed)
- **unconfirmed_balance**: Pending transactions
- **immature_balance**: Mining rewards (need 100 confirmations)

#### Step 2: Get Recipient Address

Ask the recipient for their Dilithion address. They can generate one:

```bash
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getnewaddress","params":{},"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV",
  "id": 1
}
```

#### Step 3: Send DIL

**Basic Transfer:**
```bash
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"sendtoaddress",
    "params":{
      "address":"D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV",
      "amount":10.5
    },
    "id":1
  }'
```

**Response (Success):**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "txid": "abc123def456...789"
  },
  "id": 1
}
```

**Response (Error - Insufficient Funds):**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -6,
    "message": "Insufficient funds"
  },
  "id": 1
}
```

#### Step 4: Verify Transaction

**Check transaction status:**
```bash
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"gettransaction",
    "params":{"txid":"abc123def456...789"},
    "id":1
  }'
```

**Monitor mempool:**
```bash
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getmempoolinfo","params":{},"id":1}'
```

### Method 2: Using Python Script (Example)

Create `send_dil.py`:

```python
#!/usr/bin/env python3
import requests
import json
import sys

def send_dil(recipient, amount):
    url = "http://localhost:8332"

    payload = {
        "jsonrpc": "2.0",
        "method": "sendtoaddress",
        "params": {
            "address": recipient,
            "amount": float(amount)
        },
        "id": 1
    }

    try:
        response = requests.post(url, json=payload)
        result = response.json()

        if "result" in result:
            print(f"✅ Transaction sent!")
            print(f"   Transaction ID: {result['result']['txid']}")
            print(f"   Amount: {amount} DIL")
            print(f"   Recipient: {recipient}")
            print(f"\n⏳ Waiting for confirmation (~4 minutes)...")
        elif "error" in result:
            print(f"❌ Error: {result['error']['message']}")
            return False

    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False

    return True

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 send_dil.py <address> <amount>")
        print("Example: python3 send_dil.py D7JS1u... 10.5")
        sys.exit(1)

    recipient = sys.argv[1]
    amount = sys.argv[2]

    send_dil(recipient, amount)
```

**Usage:**
```bash
chmod +x send_dil.py
python3 send_dil.py D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV 10.5
```

---

## Understanding Fees

### Fee Structure

**Dilithion uses a hybrid fee model:**

```
Total Fee = MIN_TX_FEE + (transaction_size_bytes × FEE_PER_BYTE)
```

**Parameters:**
- `MIN_TX_FEE` = 100,000 ions (0.001 DIL) - base fee
- `FEE_PER_BYTE` = 38 ions/byte - size-based fee
- `MIN_RELAY_TX_FEE` = 50,000 ions (0.0005 DIL) - minimum to relay

### Example Fee Calculation

**Standard transaction (1 input, 1 output):**
- Size: ~3,864 bytes
- Fee: 100,000 + (3,864 × 38) = **246,832 ions**
- Fee in DIL: **0.00246832 DIL** (~$0.01 at $5/DIL)

**Large transaction (2 inputs, 1 output):**
- Size: ~7,646 bytes
- Fee: 100,000 + (7,646 × 38) = **390,548 ions**
- Fee in DIL: **0.00390548 DIL** (~$0.02 at $5/DIL)

### What Happens to Fees?

**Fees go to miners!**

1. **Transaction Created**
   - You send 10 DIL + 0.0025 DIL fee
   - Total deducted from your wallet: **10.0025 DIL**

2. **Transaction in Mempool**
   - Broadcast to network
   - Miners see it in mempool

3. **Miner Includes Transaction**
   - Miner selects your transaction for next block
   - Miner collects: **Block reward (50 DIL) + Your fee (0.0025 DIL)**

4. **Block Confirmed**
   - Recipient receives: **10 DIL**
   - Miner receives: **50.0025 DIL total**
   - Fee: **0.0025 DIL** (goes to miner as incentive)

### Fee Breakdown

| Component | Amount | Who Gets It |
|-----------|--------|-------------|
| **Amount Sent** | 10.0000 DIL | Recipient |
| **Transaction Fee** | 0.0025 DIL | Miner (incentive) |
| **Block Reward** | 50.0000 DIL | Miner (coinbase) |
| **Total to Miner** | 50.0025 DIL | Miner |
| **Total Cost to You** | 10.0025 DIL | Deducted from wallet |

**Why fees exist:**
- ✅ Incentivize miners to include your transaction
- ✅ Prevent spam (costly to flood network)
- ✅ Compensate for bandwidth/storage costs
- ✅ Network security (miners secure the blockchain)

### Fee Optimization Tips

**For Regular Users:**
- Fees are automatic (wallet calculates)
- ~0.0025 DIL per transaction (very cheap)
- No action needed

**For Advanced Users (Future):**
- Higher fee = faster confirmation (priority)
- Lower fee = may wait longer
- Monitor mempool congestion

---

## Transaction Lifecycle

### Timeline

```
You Send → Mempool → Miner Selects → Block Mined → Confirmed
   0s         0-30s        ~4 min         ~4 min       done
```

**Detailed Steps:**

1. **T+0s: You Broadcast Transaction**
   - RPC call: `sendtoaddress`
   - Wallet creates transaction
   - Signs with Dilithium3 signature
   - Broadcasts to connected peers

2. **T+0-30s: Network Propagation**
   - Transaction relayed to all nodes
   - Appears in mempool
   - Validation by all nodes

3. **T+0-4min: Waiting in Mempool**
   - Miners see your transaction
   - Miner selects for next block template
   - Your fee incentivizes inclusion

4. **T+~4min: Block Mined**
   - Miner finds valid nonce (PoW)
   - Block includes your transaction
   - Block broadcast to network

5. **T+~4min: First Confirmation**
   - Recipient sees transaction (1 confirmation)
   - Generally safe for small amounts

6. **T+~8min: Second Confirmation**
   - Another block mined on top
   - Transaction more secure (2 confirmations)

7. **T+~24min: Six Confirmations**
   - Transaction considered final
   - Safe for large amounts

### Confirmation Recommendations

| Amount | Confirmations | Wait Time |
|--------|--------------|-----------|
| < 1 DIL | 1 | ~4 minutes |
| 1-10 DIL | 2 | ~8 minutes |
| 10-100 DIL | 3 | ~12 minutes |
| 100-1000 DIL | 6 | ~24 minutes |
| > 1000 DIL | 12+ | ~48+ minutes |

---

## Common Scenarios

### Scenario 1: Send to Exchange

**Question:** How do I send DIL to an exchange?

**Answer:**
1. Get your **deposit address** from exchange
2. Copy address carefully (starts with 'D')
3. Send using `sendtoaddress` method
4. Wait for **required confirmations** (exchange specifies, usually 6)
5. Check exchange balance

**Example:**
```bash
# Exchange deposit address: D9Kx... (example)
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"sendtoaddress",
    "params":{"address":"D9KxDeposit...","amount":100},
    "id":1
  }'

# Wait ~24 minutes (6 confirmations)
# Check exchange balance
```

### Scenario 2: Send to Friend

**Question:** My friend wants DIL, how do I send it?

**Answer:**
1. Ask friend for their Dilithion address
2. They generate: `getnewaddress` (or you send to their existing address)
3. You send: `sendtoaddress` with their address
4. They wait ~4 minutes (1 confirmation sufficient)
5. They check balance: `getbalance`

### Scenario 3: Send to Multiple Recipients

**Question:** Can I send to multiple people at once?

**Answer (Current):**
- Not supported in single transaction yet
- Must send multiple transactions
- Each pays separate fee

**Answer (Future):**
- `sendmany` RPC method (planned)
- One transaction, multiple outputs
- Single fee (more efficient)

---

## Security Best Practices

### Before Sending

1. **Verify Address**
   - Double-check recipient address
   - Dilithion addresses start with 'D' (mainnet) or 'm' (testnet)
   - Wrong address = **permanent loss** (no recovery)

2. **Check Balance**
   - Ensure sufficient funds + fees
   - Don't send immature balance (mining rewards need 100 confirmations)

3. **Test Small Amount First**
   - For large transfers, test with 0.1 DIL first
   - Verify recipient receives it
   - Then send full amount

### After Sending

1. **Save Transaction ID**
   - Record `txid` from response
   - Use to track transaction

2. **Monitor Confirmation**
   - Check `gettransaction` with txid
   - Wait for recommended confirmations

3. **Verify Recipient**
   - Confirm recipient sees transaction
   - Check correct amount received

### Security Warnings

⚠️ **NEVER:**
- Send to unknown/unverified addresses
- Share your private keys
- Send more than you can afford to lose (new network)
- Trust "too good to be true" offers

✅ **ALWAYS:**
- Double-check addresses (copy-paste carefully)
- Test with small amount first for large transfers
- Wait for confirmations before considering finalized
- Keep wallet encrypted with strong passphrase

---

## Troubleshooting

### Problem: "Insufficient Funds"

**Cause:** Not enough confirmed balance

**Solution:**
1. Check balance: `getbalance`
2. Check if balance is immature (mining rewards)
3. Wait for confirmations
4. Reduce send amount (account for fees)

### Problem: "Invalid Address"

**Cause:** Malformed or wrong network address

**Solution:**
1. Verify address starts with 'D' (mainnet) or 'm' (testnet)
2. Check for typos
3. Ensure using same network (mainnet vs testnet)

### Problem: Transaction Stuck in Mempool

**Cause:** Low fee or network congestion

**Solution:**
1. Wait longer (fees are automatic, should be sufficient)
2. Check mempool: `getmempoolinfo`
3. If truly stuck, contact support (rare with automatic fees)

### Problem: Transaction Not Confirmed

**Cause:** Network issue or low hash rate

**Solution:**
1. Check if block are being mined: `getblockchaininfo`
2. Wait longer (block time is ~4 minutes average)
3. Verify transaction in mempool: `getmempoolinfo`

---

## Future Improvements

### Planned Features

1. **Command-Line Tool (dilithion-cli)**
   ```bash
   dilithion-cli send D7JS1u... 10.5
   dilithion-cli balance
   dilithion-cli history
   ```

2. **GUI Wallet**
   - Click-and-send interface
   - Address book
   - Transaction history
   - QR code scanning

3. **Fee Estimation**
   ```bash
   estimatefee 6  # Estimate fee for 6-block confirmation
   ```

4. **Batch Transactions**
   ```bash
   sendmany '{"addr1": 10, "addr2": 5, "addr3": 2.5}'
   ```

5. **Payment URIs**
   ```
   dilithion:D7JS1u...?amount=10.5&label=Coffee
   ```

---

## Quick Reference Card

### Essential Commands

```bash
# Check balance
curl -X POST http://localhost:8332 -d '{"jsonrpc":"2.0","method":"getbalance","params":{},"id":1}'

# Get new address
curl -X POST http://localhost:8332 -d '{"jsonrpc":"2.0","method":"getnewaddress","params":{},"id":1}'

# Send DIL
curl -X POST http://localhost:8332 -d '{
  "jsonrpc":"2.0",
  "method":"sendtoaddress",
  "params":{"address":"ADDRESS","amount":10.5},
  "id":1
}'

# Check transaction
curl -X POST http://localhost:8332 -d '{
  "jsonrpc":"2.0",
  "method":"gettransaction",
  "params":{"txid":"TXID"},
  "id":1
}'

# List transactions
curl -X POST http://localhost:8332 -d '{"jsonrpc":"2.0","method":"listtransactions","params":{},"id":1}'
```

### Fee Quick Reference

| Transaction Type | Size | Fee (DIL) |
|-----------------|------|-----------|
| 1 input, 1 output | 3,864 bytes | 0.0025 |
| 2 inputs, 1 output | 7,646 bytes | 0.0039 |
| 1 input, 2 outputs | 3,904 bytes | 0.0025 |

---

## Getting Help

**Documentation:**
- Full RPC API: `docs/RPC-API.md`
- User Guide: `docs/USER-GUIDE.md`

**Support:**
- GitHub Issues: https://github.com/dilithion/dilithion/issues
- Website: https://dilithion.org
- Email: support@dilithion.org

**Community:**
- Discord: [Coming Soon]
- Reddit: r/dilithion [Coming Soon]
- Twitter: @DilithionCoin [Coming Soon]

---

**Last Updated:** October 30, 2025
**Version:** 1.0.0
