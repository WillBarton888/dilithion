# 🚀 Dilithion Testnet Public Launch

**Launch Date**: October 28, 2025
**Status**: ✅ **LIVE AND OPEN FOR TESTING**
**Network**: Testnet v1.0
**Test Pass Rate**: 93% (13/14 tests passing)

---

## 🎯 What is Dilithion?

Dilithion is a **post-quantum cryptocurrency** built from scratch (NOT a Bitcoin fork) featuring:

- 🔐 **Post-Quantum Cryptography**: CRYSTALS-Dilithium3 signatures (NIST-approved PQC)
- ⚡ **Quantum-Resistant Hashing**: SHA3-256 throughout
- ⛏️ **CPU-Friendly Mining**: RandomX proof-of-work (ASIC-resistant)
- 💰 **Full UTXO Model**: Bitcoin-style transaction model
- 🔒 **Security Hardened**: 4 phases of security auditing complete

**WHY POST-QUANTUM?** Quantum computers pose an existential threat to current cryptocurrencies. Dilithion is quantum-safe from day one.

---

## 🆕 What's New in This Release

### Critical Fixes (October 28, 2025)
- ✅ **UTXO Serialization Bug**: Fixed consensus-critical transaction validation
- ✅ **Wallet Unlock Issue**: Unencrypted wallets now work properly
- ✅ **DNS Seed Nodes**: Peer discovery operational
- ✅ **Test Pass Rate**: Improved from 79% to 93%

**Full details**: See [DEFICIENCY-FIXES-SUMMARY.md](DEFICIENCY-FIXES-SUMMARY.md)

---

## 🚀 Quick Start: Join the Testnet

### Prerequisites
- **OS**: Linux (Ubuntu 20.04+) or Windows with WSL
- **RAM**: 2GB minimum
- **Disk**: 20GB free space
- **Network**: Ports 8444 (P2P) and 8445 (RPC) open

### Option 1: Quick Start (Recommended for Testing)

```bash
# Clone the repository
git clone https://github.com/WillBarton888/dilithion.git
cd dilithion

# Build (Linux/WSL)
make

# Start mining node
./dilithion-node --mine --threads=4

# In another terminal, check status
./dilithion-cli getinfo
```

### Option 2: Manual Peer Configuration

For better testnet connectivity, manually connect to other nodes:

```bash
# Start node with manual peer connections
./dilithion-node --addnode=<peer1_ip>:8444 --addnode=<peer2_ip>:8444

# Example (replace with real testnet peer IPs):
./dilithion-node --addnode=192.168.1.100:8444 --addnode=192.168.1.101:8444
```

**Where to find peer IPs**: See [Community Discord](#-community--support) or [GitHub Discussions](https://github.com/WillBarton888/dilithion/discussions)

---

## 📖 Testnet Participation Guide

### 1. Get Testnet Coins

**Faucet** (coming soon): `http://faucet.dilithion.testnet` (placeholder)

For now, **mine your own**:
```bash
./dilithion-node --mine --threads=4
```

Block reward: **50 DIL** per block
Block time: **~4 minutes** target
Maturity: **100 blocks** (coinbase outputs)

### 2. Create a Wallet

```bash
# Generate new address
./dilithion-cli getnewaddress

# Check balance
./dilithion-cli getbalance

# List all addresses
./dilithion-cli getaddresses
```

### 3. Send Transactions

```bash
# Send coins
./dilithion-cli sendtoaddress <recipient_address> <amount>

# Example: Send 10 DIL
./dilithion-cli sendtoaddress D7qNcPHFqkgZWE3asMPaAgCyPrSQuNdJPm 10.0
```

### 4. Encrypt Your Wallet (Recommended)

```bash
# Encrypt wallet
./dilithion-cli encryptwallet "your-strong-passphrase"

# Unlock for 60 seconds to send transactions
./dilithion-cli walletpassphrase "your-strong-passphrase" 60

# Send transaction (wallet must be unlocked)
./dilithion-cli sendtoaddress <address> <amount>
```

### 5. Monitor the Network

```bash
# Get blockchain info
./dilithion-cli getblockchaininfo

# Get network info
./dilithion-cli getnetworkinfo

# Get peer info
./dilithion-cli getpeerinfo

# Get mining info
./dilithion-cli getmininginfo
```

---

## 🎓 RPC API Reference

Full RPC command list:

```bash
# Wallet Commands
getnewaddress                    # Generate new address
getbalance                       # Get wallet balance
getaddresses                     # List all addresses
sendtoaddress <addr> <amount>    # Send transaction
encryptwallet <passphrase>       # Encrypt wallet
walletpassphrase <pass> <time>   # Unlock wallet
walletlock                       # Lock wallet

# Mining Commands
startmining <threads>            # Start mining
stopmining                       # Stop mining
getmininginfo                    # Get mining stats

# Blockchain Commands
getblockcount                    # Get block height
getblockhash <height>            # Get block hash
getblock <hash>                  # Get block data
getblockchaininfo                # Get chain info
gettransaction <txid>            # Get transaction

# Network Commands
getnetworkinfo                   # Get network stats
getpeerinfo                      # Get peer list
addnode <ip:port>                # Add peer manually

# General Commands
help [command]                   # Get help
getinfo                          # Get node info
```

---

## 🐛 Testnet Goals & What to Test

### We Need Your Help Testing:

1. **Mining Stability**
   - Run miners for 24+ hours
   - Test different thread counts (1, 2, 4, 8)
   - Report hash rates and found blocks

2. **Wallet Operations**
   - Create multiple addresses
   - Send transactions between wallets
   - Test encrypted wallets
   - Test wallet backup/restore

3. **Network Connectivity**
   - Test peer discovery
   - Test manual peer connections
   - Monitor network health
   - Report connectivity issues

4. **Transaction Validation**
   - Create various transaction types
   - Test fee calculations
   - Test UTXO spending
   - Test coinbase maturity (100 blocks)

5. **Edge Cases**
   - Restart nodes during mining
   - Test chain reorgs
   - Test mempool under load
   - Test RPC under concurrent requests

### 📊 Report Issues

**GitHub Issues**: https://github.com/WillBarton888/dilithion/issues

When reporting bugs, please include:
- Node version (`./dilithion-cli getinfo`)
- OS and architecture
- Steps to reproduce
- Error messages from logs
- Expected vs actual behavior

---

## 🔧 Advanced Configuration

### Custom RPC Port

```bash
./dilithion-node --rpcport=9999
./dilithion-cli --rpcport=9999 getinfo
```

### Custom Data Directory

```bash
./dilithion-node --datadir=/custom/path
```

### Run as Background Service

```bash
./dilithion-node --daemon
```

### Configuration File

Create `~/.dilithion/dilithion.conf`:

```ini
# Network
testnet=1
port=8444
rpcport=8445

# Mining
gen=1
genproclimit=4

# RPC
rpcuser=testuser
rpcpassword=testpass

# Peers (add testnet peers here)
addnode=192.168.1.100:8444
addnode=192.168.1.101:8444

# Logging
debug=1
```

---

## 🏗️ Become a Seed Node Operator

Help strengthen the testnet by running a public seed node!

### Requirements
- **Uptime**: 95%+ availability
- **Network**: Static IP address
- **Bandwidth**: Sufficient for peer connections
- **Monitoring**: Ability to respond to issues

### Setup

1. **Configure firewall**:
```bash
# Allow P2P port
sudo ufw allow 8444/tcp

# Allow RPC only from localhost (security)
# Don't expose RPC to public internet!
```

2. **Run node 24/7**:
```bash
./dilithion-node --daemon
```

3. **Register as seed node**:
- Post your IP:PORT in [GitHub Discussions](https://github.com/WillBarton888/dilithion/discussions)
- Join Discord and share in #seed-nodes channel

4. **Monitor**:
```bash
# Check peer count
./dilithion-cli getpeerinfo | grep addr

# Check blockchain sync
./dilithion-cli getblockcount
```

### Seed Node Operators Get:
- Recognition in CHANGELOG.md
- Listed in official seed node documentation
- Priority consideration for mainnet seed nodes
- Community appreciation! 🙏

---

## 📈 Testnet Economics

| Parameter | Value |
|-----------|-------|
| **Block Reward** | 50 DIL |
| **Block Time** | 240 seconds (~4 minutes) |
| **Halving Interval** | 210,000 blocks (~1.6 years) |
| **Total Supply** | 21 million DIL (after all halvings) |
| **Coinbase Maturity** | 100 blocks |
| **Max Reorg Depth** | 100 blocks |
| **Difficulty Adjustment** | Every 2016 blocks |

**Note**: Testnet coins have **NO MONETARY VALUE**. They are for testing only.

---

## 🎯 Testnet Roadmap

### Week 1-2 (Current)
- ✅ Launch public testnet
- 🔄 Recruit 10+ seed node operators
- 🔄 Test 3-node, 5-node, 10-node networks
- 🔄 Collect mining statistics

### Week 3-4
- 🔲 24-hour+ stability testing
- 🔲 Transaction throughput testing
- 🔲 Network partition recovery testing
- 🔲 Fix any discovered bugs

### Week 5-8
- 🔲 External security audit
- 🔲 Performance optimization
- 🔲 Documentation finalization
- 🔲 Mainnet preparation

### Mainnet Launch
- 🔲 Target: 3-6 months after testnet
- 🔲 Requires: 100% test pass rate
- 🔲 Requires: External audit completion
- 🔲 Requires: Multi-week testnet stability

---

## 💬 Community & Support

### Official Channels

- **GitHub Repository**: https://github.com/WillBarton888/dilithion
- **Issues/Bugs**: https://github.com/WillBarton888/dilithion/issues
- **Discussions**: https://github.com/WillBarton888/dilithion/discussions

### Discord Server (Placeholder)
```
🔗 discord.gg/dilithion (to be created)

Channels:
#announcements - Official updates
#testnet-general - General testnet discussion
#mining - Mining help and stats
#technical - Development discussion
#seed-nodes - Seed node coordination
#bugs - Bug reports and debugging
```

### Social Media (Placeholder)
- **Twitter**: @DilithionCrypto (to be created)
- **Reddit**: r/Dilithion (to be created)

### Developer Contact
- **Lead Developer**: Will Barton
- **Email**: will@bananatree.com.au
- **Security**: For security issues, email directly (do NOT post publicly)

---

## 📜 License & Disclaimer

### License
MIT License - See LICENSE file

### Disclaimer

**⚠️ TESTNET COINS HAVE NO VALUE**

This is experimental software running on a test network:
- Testnet coins are **NOT** real cryptocurrency
- Testnet can be **RESET AT ANY TIME**
- Software may contain **BUGS**
- **DO NOT** use on mainnet
- **DO NOT** store real value
- **NO WARRANTY** provided

By participating, you acknowledge:
- This is alpha/beta software
- You assume all risk
- Developers not liable for any losses
- This is for **TESTING PURPOSES ONLY**

---

## 🎉 Thank You for Testing!

Your participation helps make Dilithion better and more secure. Every bug found, every transaction tested, and every block mined helps us move closer to a quantum-safe cryptocurrency future.

**Together, we're building the future of post-quantum finance.** 🚀🔐

---

## 📚 Additional Documentation

- [WHITEPAPER.md](WHITEPAPER.md) - Technical specification
- [SECURITY.md](docs/SECURITY.md) - Security documentation
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [MANUAL-PEER-SETUP.md](docs/MANUAL-PEER-SETUP.md) - Peer configuration guide
- [DEFICIENCY-FIXES-SUMMARY.md](DEFICIENCY-FIXES-SUMMARY.md) - Latest bug fixes
- [TEST-EXECUTION-REPORT.md](TEST-EXECUTION-REPORT.md) - Test results

---

**Last Updated**: October 28, 2025
**Testnet Version**: v1.0
**Status**: 🟢 LIVE

🤖 Generated with [Claude Code](https://claude.com/claude-code)
