# Dilithion User Guide

**Version:** 1.0.0
**Last Updated:** October 25, 2025

Welcome to Dilithion - The People's Coin with Post-Quantum Cryptography!

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Running a Node](#running-a-node)
4. [Using the Wallet](#using-the-wallet)
5. [Mining](#mining)
6. [RPC Interface](#rpc-interface)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

### 5-Minute Setup

1. **Download Dilithion**
   ```bash
   git clone https://github.com/dilithion/dilithion.git
   cd dilithion
   ```

2. **Compile** (requires g++, leveldb, dependencies)
   ```bash
   # Build dependencies (one-time)
   cd depends/randomx && mkdir build && cd build
   cmake .. && make
   cd ../../dilithium
   make

   # Compile Dilithion
   cd ../..
   make dilithion-node
   ```

3. **Run Your Node**
   ```bash
   ./dilithion-node
   ```

That's it! Your node is now running with a wallet and RPC server.

---

## Installation

### System Requirements

**Minimum:**
- CPU: 2 cores (4+ recommended for mining)
- RAM: 2GB (4GB+ recommended)
- Disk: 10GB free space
- OS: Linux (Ubuntu 20.04+), Windows (WSL2), macOS

**Recommended for Mining:**
- CPU: 8+ cores (modern x64 processor)
- RAM: 8GB+
- Expected hash rate: ~65 H/s per core with RandomX

### Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential git cmake libleveldb-dev
```

**macOS:**
```bash
brew install cmake leveldb
```

**Windows:**
- Use WSL2 (Ubuntu) and follow Linux instructions

### Building from Source

1. **Clone Repository**
   ```bash
   git clone https://github.com/dilithion/dilithion.git
   cd dilithion
   ```

2. **Build Dependencies**
   ```bash
   # RandomX (mining library)
   cd depends/randomx
   mkdir build && cd build
   cmake ..
   make
   cd ../../..

   # Dilithium (post-quantum signatures)
   cd depends/dilithium/ref
   make
   cd ../../..
   ```

3. **Compile Dilithion**
   ```bash
   # Main node application
   make dilithion-node

   # Optional: Genesis block generator
   make genesis_gen
   ```

4. **Verify Build**
   ```bash
   ./dilithion-node --help
   ```

You should see the help message with all available options.

---

## Running a Node

### Starting Your Node

**Basic Start:**
```bash
./dilithion-node
```

**Custom Data Directory:**
```bash
./dilithion-node --datadir=/path/to/data
```

**Custom RPC Port:**
```bash
./dilithion-node --rpcport=9332
```

**Start with Mining:**
```bash
./dilithion-node --mine --threads=4
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--datadir=<path>` | Data directory for blockchain/wallet | `.dilithion` |
| `--rpcport=<port>` | RPC server port | `8332` |
| `--mine` | Start mining automatically | Off |
| `--threads=<n>` | Number of mining threads | Auto-detect |
| `--help`, `-h` | Show help message | - |

### Node Output

When your node starts, you'll see:

```
======================================
Dilithion Node v1.0.0
Post-Quantum Cryptocurrency
======================================

Initializing blockchain storage...
  ✓ Blockchain database opened
Initializing mempool...
  ✓ Mempool initialized
Initializing P2P components...
  ✓ P2P components ready (not started)
Initializing mining controller...
  ✓ Mining controller initialized (8 threads)
Initializing wallet...
  Generating initial address...
  ✓ Initial address: D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV
Initializing RPC server...
  ✓ RPC server listening on port 8332

======================================
Node Status: RUNNING
======================================

RPC Interface:
  URL: http://localhost:8332
  Methods: getnewaddress, getbalance, getmininginfo, help

Press Ctrl+C to stop
```

### Stopping Your Node

Press **Ctrl+C** to gracefully stop your node. The shutdown process will:
1. Stop mining (if active)
2. Stop RPC server
3. Close blockchain database
4. Exit cleanly

---

## Using the Wallet

Your Dilithion node includes an integrated wallet with post-quantum CRYSTALS-Dilithium3 signatures.

### Getting Your Address

When your node starts, it automatically generates your first address. You can get additional addresses via RPC:

```bash
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getnewaddress","params":[],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV",
  "id": 1
}
```

### Checking Your Balance

```bash
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": 0,
  "id": 1
}
```

### Listing All Addresses

```bash
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getaddresses","params":[],"id":1}'
```

### Address Format

Dilithion addresses:
- Start with **'D'** (version byte 0x1E)
- Are **Base58Check encoded**
- Use **SHA-3-256** for hashing (quantum-resistant)
- Example: `D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV`

---

## Mining

Dilithion uses **RandomX** - a CPU-friendly, ASIC-resistant proof-of-work algorithm.

### Starting Mining

**Via Command Line:**
```bash
./dilithion-node --mine --threads=8
```

**Via RPC (after node is running):**
```bash
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"startmining","params":[],"id":1}'
```

### Mining Output

```
Starting mining...
  ✓ Mining started with 8 threads
  Expected hash rate: ~520 H/s

[Mining] Hash rate: 518 H/s, Total hashes: 5180000
[Mining] Hash rate: 521 H/s, Total hashes: 10210000
```

### Checking Mining Status

```bash
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "mining": true,
    "hashrate": 518,
    "threads": 8
  },
  "id": 1
}
```

### Stopping Mining

```bash
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"stopmining","params":[],"id":1}'
```

### Mining Performance

**Expected Hash Rates (RandomX):**
- Intel Core i7-12700: ~780 H/s (12 cores)
- AMD Ryzen 9 5900X: ~845 H/s (12 cores)
- Intel Core i5-10400: ~390 H/s (6 cores)
- **Average:** ~65 H/s per core

**Tips for Better Performance:**
- Use all available CPU cores
- Ensure adequate cooling
- Close other CPU-intensive applications
- Consider overclocking (advanced users)

---

## RPC Interface

Dilithion provides a **JSON-RPC 2.0** interface over HTTP for programmatic access.

### Connection Details

- **URL:** `http://localhost:8332`
- **Method:** POST
- **Content-Type:** `application/json`
- **Protocol:** JSON-RPC 2.0

### Available Methods

See [RPC-API.md](RPC-API.md) for complete documentation with examples.

**Quick Reference:**
- `getnewaddress` - Generate new address
- `getbalance` - Get wallet balance
- `getaddresses` - List all addresses
- `getmininginfo` - Get mining status
- `stopmining` - Stop mining
- `getnetworkinfo` - Get network info
- `help` - List all methods
- `stop` - Stop the node

---

## Troubleshooting

### Node Won't Start

**Error:** `Failed to open blockchain database`

**Solution:** Ensure data directory exists and has write permissions:
```bash
mkdir -p ~/.dilithion
chmod 755 ~/.dilithion
./dilithion-node --datadir=~/.dilithion
```

### RPC Not Responding

**Error:** Connection refused on port 8332

**Solution:**
1. Check if node is running: `ps aux | grep dilithion-node`
2. Verify RPC port: Check startup output for "RPC server listening on port..."
3. Try different port: `./dilithion-node --rpcport=9332`

### Low Hash Rate

**Issue:** Mining slower than expected

**Solutions:**
1. Increase thread count: `./dilithion-node --mine --threads=16`
2. Check CPU usage: `top` or `htop`
3. Verify RandomX is using all cores
4. Check for thermal throttling

### Wallet Address Not Showing

**Issue:** No address generated on startup

**Solution:**
- RPC is still available
- Get new address manually: `curl http://localhost:8332 -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"getnewaddress","params":[],"id":1}'`

---

## Post-Quantum Security

Dilithion uses **industry-standard NIST post-quantum cryptography**:

### Mining: RandomX
- CPU-friendly, ASIC-resistant
- Memory-hard algorithm
- Resistant to quantum speedup

### Signatures: CRYSTALS-Dilithium3
- **NIST PQC Standard**
- Security Level 3 (≈ AES-192)
- Public key: 1952 bytes
- Signature: ~3309 bytes

### Hashing: SHA-3/Keccak-256
- **NIST FIPS 202 Standard**
- Quantum-resistant
- ~128-bit post-quantum security
- Used for blocks, transactions, addresses

---

## Getting Help

- **Documentation:** See `docs/` directory
- **RPC API:** See [RPC-API.md](RPC-API.md)
- **Mining Guide:** See [MINING-GUIDE.md](MINING-GUIDE.md)
- **GitHub Issues:** https://github.com/dilithion/dilithion/issues
- **Discord:** https://discord.gg/dilithion

---

## License

Dilithion is released under the MIT License.

---

**Welcome to The People's Coin!** 🚀

Quantum-safe cryptocurrency for everyone.
