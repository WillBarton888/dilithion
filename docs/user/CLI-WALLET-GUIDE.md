# Dilithion CLI Wallet Guide

**Simple command-line wallet interface for Dilithion cryptocurrency**

## Overview

The Dilithion CLI wallet is a simple wrapper around the RPC interface, making wallet operations easy from the command line without needing to manually craft JSON-RPC requests.

## Installation

The wallet scripts are included in the Dilithion distribution:
- **Linux/Mac:** `dilithion-wallet` (bash script)
- **Windows:** `dilithion-wallet.bat` (batch script)

### Linux/Mac Setup

```bash
# Make executable
chmod +x dilithion-wallet

# Optional: Add to PATH
sudo cp dilithion-wallet /usr/local/bin/

# Or create symlink
sudo ln -s $(pwd)/dilithion-wallet /usr/local/bin/dilithion-wallet
```

### Windows Setup

The `.bat` file works as-is. Optionally add the dilithion directory to your PATH.

## Prerequisites

1. **Dilithion node must be running** with RPC enabled
2. **curl** must be installed (included in Windows 10/11, pre-installed on most Linux/Mac)
3. **jq** (optional) for pretty output on Linux/Mac

### Install jq (optional, for better formatting)

**Ubuntu/Debian:**
```bash
sudo apt-get install jq
```

**macOS:**
```bash
brew install jq
```

**Windows:**
Download from https://stedolan.github.io/jq/

---

## Usage

### Basic Commands

#### 1. Check Balance

```bash
# Linux/Mac
./dilithion-wallet balance

# Windows
dilithion-wallet.bat balance
```

**Output (with jq):**
```
Fetching wallet balance...

Balance:              50.00000000 DIL
Unconfirmed:          0.00000000 DIL
Immature (mining):    100.00000000 DIL

Total:                150.00000000 DIL
```

---

#### 2. Generate New Address

```bash
# Linux/Mac
./dilithion-wallet newaddress

# Windows
dilithion-wallet.bat newaddress
```

**Output:**
```
Generating new address...

New Address: DLT1abc123def456ghi789jkl012mno345pqr678stu901vwx234yz
```

---

#### 3. List All Addresses

```bash
# Linux/Mac
./dilithion-wallet addresses

# Windows
dilithion-wallet.bat addresses
```

**Output:**
```
Listing wallet addresses...
• DLT1abc123def456ghi789...
• DLT1xyz987wvu654tsr321...
```

---

#### 4. List Unspent Outputs (UTXOs)

```bash
# Linux/Mac
./dilithion-wallet listunspent

# Windows
dilithion-wallet.bat listunspent
```

**Output (with jq):**
```
Listing unspent outputs...

  10 conf  50.00000000 DIL  DLT1abc123...  [a1b2c3d4e5f6g7h8...]
  25 conf  25.50000000 DIL  DLT1xyz987...  [9z8y7x6w5v4u3t2s...]

Total UTXOs: 2
```

---

#### 5. Send Transaction

```bash
# Linux/Mac
./dilithion-wallet send DLT1recipient... 10.5

# Windows
dilithion-wallet.bat send DLT1recipient... 10.5
```

**Interactive confirmation:**
```
Sending transaction...

To:      DLT1recipient123abc456def789ghi...
Amount:  10.50000000 DIL

Confirm transaction? (yes/no): yes

✓ Transaction sent successfully!

Transaction ID:
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6
```

---

#### 6. Help

```bash
# Linux/Mac
./dilithion-wallet help

# Windows
dilithion-wallet.bat help
```

---

## Configuration

### Environment Variables

**RPC Host:**
```bash
export DILITHION_RPC_HOST=192.168.1.100  # Linux/Mac
set DILITHION_RPC_HOST=192.168.1.100     # Windows
```

**RPC Port:**
```bash
# Testnet (default: 18332)
export DILITHION_RPC_PORT=18332

# Mainnet (8332)
export DILITHION_RPC_PORT=8332
```

### Examples

**Connect to remote node:**
```bash
# Linux/Mac
DILITHION_RPC_HOST=192.168.1.100 ./dilithion-wallet balance

# Windows
set DILITHION_RPC_HOST=192.168.1.100
dilithion-wallet.bat balance
```

**Use mainnet instead of testnet:**
```bash
# Linux/Mac
DILITHION_RPC_PORT=8332 ./dilithion-wallet balance

# Windows
set DILITHION_RPC_PORT=8332
dilithion-wallet.bat balance
```

---

## Common Workflows

### Getting Started

1. **Start your node with RPC enabled:**
```bash
./dilithion-node --testnet --mine --threads=4
```

2. **Generate your first address:**
```bash
./dilithion-wallet newaddress
```

3. **Check balance after mining:**
```bash
./dilithion-wallet balance
```

### Sending Coins

1. **Check balance:**
```bash
./dilithion-wallet balance
```

2. **List available UTXOs:**
```bash
./dilithion-wallet listunspent
```

3. **Send transaction:**
```bash
./dilithion-wallet send DLT1recipient... 10.5
```

### Receiving Coins

1. **Generate new receiving address:**
```bash
./dilithion-wallet newaddress
```

2. **Give this address to sender**

3. **Monitor incoming transactions:**
```bash
# Watch for unconfirmed balance
watch -n 5 './dilithion-wallet balance'
```

---

## Troubleshooting

### "Could not connect to Dilithion node"

**Problem:** Node is not running or RPC is not enabled

**Solution:**
1. Make sure node is running: `ps aux | grep dilithion-node`
2. Check node is listening on RPC port: `netstat -an | grep 18332`
3. Verify RPC configuration in node startup

---

### "curl: command not found"

**Problem:** curl is not installed

**Solution:**

**Ubuntu/Debian:**
```bash
sudo apt-get install curl
```

**macOS:**
```bash
brew install curl
```

**Windows:** curl is included in Windows 10/11. If missing, download from https://curl.se/windows/

---

### "Invalid response from node"

**Problem:** Node returned an error

**Solution:**
1. Check node logs for errors
2. Verify wallet is unlocked (if encrypted)
3. Check sufficient balance for send operations
4. Ensure address format is correct

---

### Output is not formatted nicely

**Problem:** jq is not installed (Linux/Mac only)

**Solution (optional):**

**Ubuntu/Debian:**
```bash
sudo apt-get install jq
```

**macOS:**
```bash
brew install jq
```

The wallet works without jq, but output will be raw JSON.

---

## Advanced Usage

### Scripting

You can use the CLI wallet in bash scripts:

```bash
#!/bin/bash

# Check balance and send if above threshold
BALANCE=$(./dilithion-wallet balance | jq -r '.result.balance')

if (( $(echo "$BALANCE > 100" | bc -l) )); then
    echo "Balance above threshold, sending..."
    ./dilithion-wallet send DLT1recipient... 50
fi
```

### Monitoring

Monitor balance continuously:

```bash
# Linux/Mac
watch -n 10 './dilithion-wallet balance'

# Windows (PowerShell)
while($true) { dilithion-wallet.bat balance; Start-Sleep -Seconds 10; Clear-Host }
```

---

## Security Notes

1. **RPC Security:** By default, RPC is only accessible from localhost
2. **Unencrypted Connection:** RPC uses HTTP (not HTTPS) - use only on trusted networks
3. **No Password:** Current version has no RPC authentication - do not expose to internet
4. **Wallet Encryption:** Consider encrypting your wallet with a passphrase

---

## Comparison with Direct RPC

### Before (Direct RPC):
```bash
curl -X POST http://localhost:18332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":{},"id":1}' \
  | jq
```

### After (CLI Wallet):
```bash
./dilithion-wallet balance
```

**Much simpler!** 🎉

---

## Available RPC Methods

The CLI wallet wraps these RPC methods:

| Command | RPC Method | Description |
|---------|------------|-------------|
| `balance` | `getbalance` | Get wallet balance |
| `newaddress` | `getnewaddress` | Generate new address |
| `addresses` | `getaddresses` | List all addresses |
| `listunspent` | `listunspent` | List UTXOs |
| `send` | `sendtoaddress` | Send transaction |

For advanced RPC methods, see [docs/RPC-API.md](docs/RPC-API.md)

---

## Support

- **Documentation:** [docs/RPC-API.md](docs/RPC-API.md)
- **Testnet Guide:** [TESTNET-LAUNCH.md](TESTNET-LAUNCH.md)
- **GitHub Issues:** https://github.com/WillBarton888/dilithion/issues
- **Discord:** https://discord.gg/c25WwRNg

---

## Future Enhancements

Planned features for CLI wallet:

- [ ] Transaction history
- [ ] Address labels
- [ ] Multi-signature support
- [ ] Hardware wallet integration
- [ ] Fee estimation
- [ ] Batch transactions
- [ ] QR code generation

---

**Simple, powerful, and easy to use!** 🚀
