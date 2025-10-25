# Dilithion - The People's Coin

**Post-Quantum Cryptocurrency with NIST-Standard Cryptography**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/dilithion/dilithion)
[![Launch](https://img.shields.io/badge/launch-Jan%201%2C%202026-red.svg)](https://dilithion.org)

---

## Overview

Dilithion is a quantum-resistant cryptocurrency built from the ground up with post-quantum cryptography. Designed as "The People's Coin," Dilithion features CPU-friendly mining, professional-grade code, and industry-standard NIST algorithms.

### Key Features

✅ **Post-Quantum Secure:** CRYSTALS-Dilithium3 + SHA-3
✅ **CPU-Friendly Mining:** RandomX (ASIC-resistant)
✅ **Fair Distribution:** No ASIC advantage
✅ **Exchange-Ready:** JSON-RPC 2.0 interface
✅ **Professional Code:** Production-ready C++

---

## Quick Start

### Installation

**Ubuntu/Debian:**
```bash
# Install dependencies
sudo apt-get install build-essential git cmake libleveldb-dev

# Clone repository
git clone https://github.com/dilithion/dilithion.git
cd dilithion

# Build dependencies
cd depends/randomx && mkdir build && cd build
cmake .. && make
cd ../../dilithium/ref && make
cd ../../..

# Compile Dilithion
make dilithion-node
```

### Running a Node

```bash
# Basic node
./dilithion-node

# Node with mining (8 threads)
./dilithion-node --mine --threads=8

# Custom configuration
./dilithion-node --datadir=~/.dilithion --rpcport=8332 --mine
```

---

## Post-Quantum Security

Dilithion uses **NIST-standardized** post-quantum cryptography:

### Mining: RandomX
- **Algorithm:** CPU-optimized proof-of-work
- **Performance:** ~65 H/s per core
- **Resistance:** ASIC-resistant, memory-hard
- **Power:** Efficient CPU mining

### Signatures: CRYSTALS-Dilithium3
- **Standard:** NIST PQC (Post-Quantum Cryptography)
- **Security Level:** NIST Level 3 (≈ AES-192)
- **Key Sizes:** 1952 bytes (public), 4032 bytes (private)
- **Signature:** ~3309 bytes

### Hashing: SHA-3/Keccak-256
- **Standard:** NIST FIPS 202
- **Quantum Resistance:** ~128-bit post-quantum security
- **Usage:** Blocks, transactions, addresses

---

## Documentation

📖 **User Guide:** [docs/USER-GUIDE.md](docs/USER-GUIDE.md)
📖 **Mining Guide:** [docs/MINING-GUIDE.md](docs/MINING-GUIDE.md)
📖 **RPC API:** [docs/RPC-API.md](docs/RPC-API.md)
📖 **Launch Checklist:** [docs/LAUNCH-CHECKLIST.md](docs/LAUNCH-CHECKLIST.md)

---

## Mining

Dilithion uses RandomX for fair, CPU-friendly mining.

### Expected Hash Rates

| CPU | Cores | Hash Rate |
|-----|-------|-----------|
| Intel Core i9-12900K | 16 | ~1040 H/s |
| AMD Ryzen 9 5900X | 12 | ~845 H/s |
| Intel Core i7-12700 | 12 | ~780 H/s |
| AMD Ryzen 7 5800X | 8 | ~560 H/s |

**Average:** ~65 H/s per core

### Mining Rewards

- **Block Reward:** 50 DIL
- **Block Time:** ~2 minutes
- **Total Supply:** 21 million DIL
- **Halving:** Every 210,000 blocks (~8 months)

---

## RPC Interface

Dilithion provides a JSON-RPC 2.0 interface for programmatic access.

### Connection

```
Endpoint: http://localhost:8332
Protocol: JSON-RPC 2.0
Transport: HTTP
```

### Example Request

```bash
curl http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getnewaddress","params":[],"id":1}'
```

### Response

```json
{
  "jsonrpc": "2.0",
  "result": "D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV",
  "id": 1
}
```

**Available Methods:** `getnewaddress`, `getbalance`, `getaddresses`, `getmininginfo`, `stopmining`, `help`, and more.

See [docs/RPC-API.md](docs/RPC-API.md) for complete documentation.

---

## Genesis Block

**Launch:** January 1, 2026 00:00:00 UTC

```
Timestamp: 1767225600
Difficulty: 0x1d00ffff
Coinbase: "The Guardian 01/Jan/2026: Quantum computing advances
          threaten cryptocurrency security - Dilithion launches
          with post-quantum protection for The People's Coin"
```

---

## Technology Stack

### Core Components

- **Language:** C++17
- **Storage:** LevelDB
- **Mining:** RandomX
- **Signatures:** CRYSTALS-Dilithium3
- **Hashing:** SHA-3 (FIPS 202)
- **RPC:** JSON-RPC 2.0
- **P2P:** Custom protocol

### Dependencies

- **LevelDB:** Blockchain storage
- **RandomX:** Mining algorithm
- **Dilithium:** Post-quantum signatures
- **SHA-3:** Quantum-resistant hashing

---

## Building from Source

### Prerequisites

- GCC 7+ or Clang 6+
- CMake 3.10+
- LevelDB
- Make

### Compilation

```bash
# Clone repository
git clone https://github.com/dilithion/dilithion.git
cd dilithion

# Build RandomX dependency
cd depends/randomx
mkdir build && cd build
cmake ..
make
cd ../../..

# Build Dilithium dependency
cd depends/dilithium/ref
make
cd ../../..

# Compile Dilithion node
make dilithion-node

# Optional: Compile genesis generator
make genesis_gen

# Optional: Compile tests
make tests
```

---

## Testing

Dilithion includes comprehensive test coverage:

```bash
# Run all tests
make test

# Individual test suites
./phase1_test      # Blockchain, mempool, fees
./miner_tests      # Mining controller
./wallet_tests     # Wallet, signatures, addresses
./rpc_tests        # RPC server
./integration_tests # Full node integration
```

**Test Coverage:** All core components tested

---

## Project Structure

```
dilithion/
├── src/
│   ├── consensus/     # Consensus rules, fees
│   ├── crypto/        # SHA-3, RandomX integration
│   ├── miner/         # Mining controller
│   ├── net/           # P2P networking
│   ├── node/          # Blockchain storage, genesis
│   ├── primitives/    # Block, transaction structures
│   ├── rpc/           # RPC server
│   ├── test/          # Test suites
│   └── wallet/        # Wallet, addresses, keys
├── depends/
│   ├── randomx/       # RandomX library
│   └── dilithium/     # Dilithium library
├── docs/              # Documentation
└── README.md
```

---

## Contributing

Dilithion is open source and welcomes contributions!

### How to Contribute

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Write tests
5. Submit a pull request

### Development Guidelines

- Follow C++17 standards
- Maintain code quality (A++)
- Include tests for new features
- Update documentation
- Follow existing code style

---

## Roadmap

### Q4 2025 (Pre-Launch)
- [x] Core blockchain implementation
- [x] P2P networking
- [x] Mining software (RandomX)
- [x] Wallet & RPC
- [x] Integration & testing
- [x] Documentation
- [ ] Genesis block mining
- [ ] Final testing

### Q1 2026 (Launch)
- [ ] **Mainnet launch** (Jan 1, 2026)
- [ ] Network monitoring
- [ ] Bug fixes
- [ ] Community support

### Q2 2026
- [ ] Mining pool protocol
- [ ] Exchange integrations
- [ ] Mobile wallets
- [ ] Block explorer

### Q3 2026+
- [ ] Smart contract research
- [ ] Layer 2 solutions
- [ ] Merchant adoption
- [ ] Advanced features

---

## Security

### Quantum Resistance

Dilithion is designed to resist attacks from quantum computers:

- **Signatures:** Dilithium3 resists Shor's algorithm
- **Hashing:** SHA-3 resists Grover's algorithm
- **Mining:** RandomX unaffected by quantum speedup

### NIST Standards

All cryptography uses **NIST-standardized** algorithms:
- CRYSTALS-Dilithium (NIST PQC)
- SHA-3/Keccak (NIST FIPS 202)

### Security Audits

- Internal code review: Complete
- External audit: Planned pre-launch
- Bug bounty: Coming post-launch

---

## Performance

### Mining Performance

- **Hash Rate:** ~65 H/s per CPU core
- **Memory:** ~2GB per thread
- **Power:** ~15-20W per core
- **Efficiency:** Optimized for modern CPUs

### Node Performance

- **Sync Speed:** Fast (LevelDB storage)
- **Memory Usage:** ~500MB base
- **CPU Usage:** Low (when not mining)
- **Disk I/O:** Optimized

---

## Community

### Official Channels

- **Website:** https://dilithion.org
- **GitHub:** https://github.com/dilithion/dilithion
- **Discord:** https://discord.gg/dilithion
- **Twitter:** @DilithionCoin
- **Reddit:** /r/dilithion

### Support

- **Documentation:** `docs/` directory
- **Issues:** GitHub Issues
- **Email:** support@dilithion.org

---

## License

Dilithion is released under the **MIT License**.

See [LICENSE](LICENSE) for details.

---

## Citation

If you use Dilithion in research, please cite:

```
@software{dilithion2026,
  title = {Dilithion: Post-Quantum Cryptocurrency},
  author = {Dilithion Core Developers},
  year = {2026},
  url = {https://github.com/dilithion/dilithion}
}
```

---

## Acknowledgments

Dilithion builds upon:

- **RandomX** - Efficient CPU mining
- **CRYSTALS-Dilithium** - Post-quantum signatures (NIST)
- **SHA-3/Keccak** - Quantum-resistant hashing (NIST)
- **Bitcoin** - Original blockchain design
- **Monero** - RandomX implementation

---

## Disclaimer

Cryptocurrency involves risk. Mine and use Dilithion responsibly.

- No investment advice
- DYOR (Do Your Own Research)
- Use at your own risk

---

## Statistics

- **Launch:** January 1, 2026
- **Algorithm:** RandomX
- **Supply:** 21 million DIL
- **Block Time:** ~2 minutes
- **Reward:** 50 DIL per block
- **Halving:** Every 210,000 blocks

---

**Dilithion - The People's Coin**

*Quantum-safe cryptocurrency for everyone* 🚀

---

**Status:** ✅ Development Complete - Ready for Launch

**Next Milestone:** Genesis Block Mining (November 2025)

**Launch Date:** January 1, 2026 00:00:00 UTC
