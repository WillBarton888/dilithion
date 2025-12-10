# Dilithion Testnet Guide

**Version**: 1.1.7
**Date**: December 6, 2025
**Status**: Testnet Live

## Overview

Dilithion is a post-quantum cryptocurrency using NIST-standardized CRYSTALS-Dilithium signatures. The testnet allows you to mine, send transactions, and test the wallet before mainnet launch.

**Important**: Testnet coins have NO monetary value. They are for testing only.

## Quick Start

### Windows

1. Download and extract the ZIP file
2. Double-click `START-MINING.bat`
3. Done! You're mining testnet DIL

### First Run - Wallet Setup

On first run, the node will:
1. Create a new HD wallet
2. Display your 24-word recovery phrase
3. **Ask you to type 'Y' to confirm** you've saved the phrase
4. Start syncing the blockchain

**CRITICAL**: Write down your 24-word recovery phrase on paper. This is your ONLY backup. If you lose it, your testnet coins are gone.

## Features

### HD Wallet
- 24-word BIP-39 recovery phrase
- Derive unlimited addresses from one seed
- Post-quantum Dilithium3 signatures

### Mining
- CPU mining with RandomX algorithm
- Auto-detects optimal thread count
- Testnet difficulty: 256x easier than mainnet

### Network
- Automatic peer discovery
- Connects to official seed nodes
- Full node validation

## Command Line Options

```bash
# Basic mining
dilithion-node.exe --testnet --mine

# Specify threads
dilithion-node.exe --testnet --mine --threads=4

# Custom data directory
dilithion-node.exe --testnet --datadir=C:\MyNode

# View all options
dilithion-node.exe --help
```

## RPC Commands

The node exposes an RPC interface on port 18332:

```bash
# Get blockchain info
curl -X POST http://localhost:18332 -d '{"method":"getblockchaininfo"}'

# Get balance
curl -X POST http://localhost:18332 -d '{"method":"getbalance"}'

# Get new address
curl -X POST http://localhost:18332 -d '{"method":"getnewaddress"}'

# Send coins
curl -X POST http://localhost:18332 -d '{"method":"sendtoaddress","params":["ADDRESS", 10.0]}'

# Mining info
curl -X POST http://localhost:18332 -d '{"method":"getmininginfo"}'
```

## Network Configuration

### Testnet Parameters

| Parameter | Value |
|-----------|-------|
| P2P Port | 18444 |
| RPC Port | 18332 |
| Block Time | 4 minutes |
| Difficulty | 256x easier than mainnet |
| Network Magic | 0xDAB5BFFA |

### Official Seed Nodes

| Location | Address |
|----------|---------|
| NYC (Primary) | 134.122.4.164:18444 |
| Singapore | 188.166.255.63:18444 |
| London | 209.97.177.197:18444 |

## Wallet Commands

Use the `dilithion-wallet.bat` menu or RPC:

| Command | Description |
|---------|-------------|
| getbalance | Show current balance |
| getnewaddress | Generate new receiving address |
| getaddresses | List all wallet addresses |
| listunspent | Show unspent outputs |
| listtransactions | Show transaction history |
| sendtoaddress | Send coins to address |
| exportmnemonic | Display recovery phrase (requires unlock) |

## Troubleshooting

### "Wallet file not found"
The node hasn't been run yet. Start the node first to create a wallet.

### "Connection refused"
The node isn't running or RPC is disabled. Start the node with default settings.

### Mining but no blocks found
This is normal. Depending on network hashrate, blocks may take minutes to hours. Keep mining!

### Node won't start
- Check if another instance is running
- Try a different data directory
- Check Windows Firewall settings

## Data Directories

Default testnet data location:
- Windows: `%APPDATA%\Dilithion\testnet\` or `.dilithion-testnet\` in current folder
- Linux: `~/.dilithion-testnet/`
- macOS: `~/Library/Application Support/Dilithion/testnet/`

## Security

- **Recovery phrase**: Your 24-word phrase is the master key. Never share it.
- **Testnet only**: This software is for testnet. Don't use for real value.
- **Open source**: All code is available at github.com/WillBarton888/dilithion

## Getting Help

- Website: https://dilithion.org
- GitHub: https://github.com/WillBarton888/dilithion
- Issues: https://github.com/WillBarton888/dilithion/issues

---

**Happy Mining!**

The Dilithion Team
