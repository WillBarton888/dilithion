# Dilithion - Post-Quantum Cryptocurrency

**Post-Quantum Cryptocurrency with NIST-Standard Cryptography**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v3.0.12-brightgreen.svg)](https://github.com/dilithion/dilithion/releases)
[![Mainnet](https://img.shields.io/badge/mainnet-LIVE-success.svg)](https://dilithion.org)
[![CI](https://github.com/dilithion/dilithion/workflows/Dilithion%20CI/badge.svg)](https://github.com/dilithion/dilithion/actions)
[![Fuzzing](https://github.com/dilithion/dilithion/workflows/Fuzzing%20Infrastructure%20Build/badge.svg)](https://github.com/dilithion/dilithion/actions)

---

## Disclaimers

**This is experimental software developed with AI assistance (Claude Code):**
- **Open Source:** MIT License - full transparency
- **AI-Assisted Development:** Built with Claude Code assistance
- **No Professional Audit:** Community review only (professional audit: TBD)
- **Use at Own Risk:** No guarantees of security, value, or success
- **Not Financial Advice:** DYOR (Do Your Own Research)

**Seeking Code Review:** We actively welcome expert review from cryptographers, blockchain developers, and security researchers. See [SECURITY.md](SECURITY.md) for details.

---

## Mainnet is LIVE

**Mainnet launched January 28, 2026.** Download the node software and start mining real DIL coins today.

**Website**: [dilithion.org](https://dilithion.org)

**Quick Start**:
```bash
git clone https://github.com/dilithion/dilithion.git
cd dilithion
make
./dilithion-node --mine --threads=4
```

**Pre-built binaries** for Linux, macOS, and Windows are available on the [Releases](https://github.com/dilithion/dilithion/releases) page.

---

## Overview

Dilithion is a quantum-resistant cryptocurrency built from the ground up with post-quantum cryptography. Designed as "The People's Coin," Dilithion features CPU-friendly mining, an HD wallet with BIP39 mnemonics, and industry-standard NIST algorithms.

### Key Features

- **Post-Quantum Secure:** CRYSTALS-Dilithium3 + SHA-3
- **CPU-Friendly Mining:** RandomX (ASIC-resistant)
- **HD Wallet:** BIP39 mnemonic seed phrases, BIP44 key derivation, encrypted storage
- **Fair Launch:** No premine, no ICO, no ASIC advantage
- **Exchange-Ready:** JSON-RPC 2.0 interface
- **Open Source:** MIT License, full transparency

---

## Future Consensus: VDF + Digital DNA

Dilithion is evolving beyond proof-of-work toward **VDF fair mining** with **Digital DNA** Sybil resistance -- eliminating hashrate advantages and reducing energy consumption by ~95%.

### VDF Fair Mining
- **How it works:** Each miner computes one Verifiable Delay Function per block. Lowest output wins. More hardware doesn't help.
- **Energy savings:** ~95% reduction -- no more hash racing across all CPU cores
- **Fairness:** 1 CPU = 1 ticket per round, regardless of farm size
- **Cooldown:** Winners sit out N blocks, ensuring block distribution

### Digital DNA (Anonymous Sybil Resistance)
- **8 unforgeable dimensions:** Latency, VDF timing, perspective, memory, clock drift, bandwidth, thermal, behavioral
- **Physics-based:** Speed of light, oscillator uniqueness, cache hierarchy -- cannot be faked
- **Anonymous:** No KYC, no trusted hardware, no personal data
- **ML-enhanced:** Isolation Forest anomaly detection (advisory mode, promotes to active after proving reliable)

### Migration Path
```
Phase 1 (Current):  RandomX PoW + DFMP
Phase 2 (Hybrid):   RandomX + VDF (both accepted)
Phase 3 (Future):   VDF-Only + Digital DNA
```

**Status:** VDF implementation complete (46 tests passing). Testnet activation in progress. Mainnet activation pending community vote. See [VDF_LOTTERY_PROPOSAL.md](VDF_LOTTERY_PROPOSAL.md) for full details.

---

## Post-Quantum Security

Dilithion uses **NIST-standardized** post-quantum cryptography:

### Mining: RandomX
- **Algorithm:** CPU-optimized proof-of-work
- **Performance:** ~65 H/s per core
- **Resistance:** ASIC-resistant, memory-hard

### Signatures: CRYSTALS-Dilithium3
- **Standard:** NIST FIPS 204 (Post-Quantum Cryptography)
- **Security Level:** NIST Level 3
- **Key Sizes:** 1952 bytes (public), 4032 bytes (private)
- **Signature:** ~3309 bytes

### Hashing: SHA-3/Keccak-256
- **Standard:** NIST FIPS 202
- **Quantum Resistance:** ~128-bit post-quantum security
- **Usage:** Blocks, transactions, addresses

---

## Building from Source

### Prerequisites

- GCC 7+ or Clang 6+
- CMake 3.10+
- LevelDB
- Make

### Ubuntu/Debian

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

### Windows (MSYS2)

```bash
# Open MSYS2 MinGW64 terminal
cd /c/path/to/dilithion
make -j4
```

### Running a Node

```bash
# Basic node (relay only)
./dilithion-node

# Node with mining (8 threads)
./dilithion-node --mine --threads=8

# Custom configuration
./dilithion-node --datadir=~/.dilithion --rpcport=8332 --mine
```

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
- **Block Time:** ~4 minutes (240 seconds)
- **Total Supply:** 21 million DIL
- **Halving:** Every 210,000 blocks (~1.6 years)

---

## HD Wallet

Dilithion includes a full Hierarchical Deterministic (HD) wallet:

- **BIP39** mnemonic seed phrases (24 words) for backup and recovery
- **BIP44** key derivation for organized address management
- **Encrypted storage** with password protection
- **Multiple address** generation from a single seed

See [docs/HD_WALLET_USER_GUIDE.md](docs/HD_WALLET_USER_GUIDE.md) for the complete wallet guide.

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
  -H "X-Dilithion-RPC: 1" \
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

**Mainnet launched:** January 28, 2026

```
Hash:      0000009eaa5e7781ba6d14525c3f75c35444045b21ddafbbea61090db99b0bc3
Timestamp: 1737158400
nBits:     0x1e01fffe
Coinbase:  "Dilithion Mainnet v2.0.0 - Fair Launch Reset - Quantum-Resistant Digital Gold"
```

---

## Technology Stack

### Core Components

- **Language:** C++17
- **Storage:** LevelDB
- **Mining:** RandomX (current), chiavdf VDF (future)
- **Signatures:** CRYSTALS-Dilithium3
- **Hashing:** SHA-3 (FIPS 202)
- **Identity:** Digital DNA (8-dimension anonymous Sybil resistance)
- **RPC:** JSON-RPC 2.0
- **P2P:** Custom protocol (port 8444)

### Dependencies

- **LevelDB:** Blockchain storage
- **RandomX:** Mining algorithm (current)
- **chiavdf:** VDF fair mining (future)
- **Dilithium:** Post-quantum signatures
- **SHA-3:** Quantum-resistant hashing
- **GMP:** Arbitrary precision arithmetic (for VDF)

---

## Documentation

### User Documentation
- **User Guide:** [docs/USER-GUIDE.md](docs/USER-GUIDE.md)
- **HD Wallet Guide:** [docs/HD_WALLET_USER_GUIDE.md](docs/HD_WALLET_USER_GUIDE.md)
- **Mining Guide:** [docs/MINING-GUIDE.md](docs/MINING-GUIDE.md)
- **RPC API:** [docs/RPC-API.md](docs/RPC-API.md)

### Educational Resources
- **Post-Quantum Crypto Course:** [website/POST-QUANTUM-CRYPTO-COURSE.md](website/POST-QUANTUM-CRYPTO-COURSE.md)
- **Whitepaper:** [Dilithion-Whitepaper-v1.0.pdf](Dilithion-Whitepaper-v1.0.pdf)

### Security
- **Security Policy:** [SECURITY.md](SECURITY.md)

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

---

## Project Structure

```
dilithion/
├── src/
│   ├── consensus/     # Consensus rules, fees, VDF validation
│   ├── crypto/        # SHA-3, RandomX integration
│   ├── digital_dna/   # Digital DNA identity system (8 dimensions)
│   ├── dfmp/          # Fair Mining Protocol (MIK identity)
│   ├── miner/         # Mining controller
│   ├── net/           # P2P networking
│   ├── node/          # Blockchain storage, genesis
│   ├── primitives/    # Block, transaction structures
│   ├── rpc/           # RPC server
│   ├── test/          # Test suites
│   ├── vdf/           # VDF miner, cooldown tracker
│   └── wallet/        # HD wallet, addresses, keys
├── depends/
│   ├── randomx/       # RandomX library
│   ├── chiavdf/       # VDF library (class groups)
│   └── dilithium/     # Dilithium library
├── docs/              # Documentation
└── README.md
```

---

## Contributing

Dilithion is open source and welcomes contributions!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Write tests
5. Submit a pull request

### Development Guidelines

- Follow C++17 standards
- Include tests for new features
- Update documentation
- Follow existing code style

---

## Security

### Quantum Resistance

Dilithion is designed to resist attacks from quantum computers:

- **Signatures:** Dilithium3 resists Shor's algorithm
- **Hashing:** SHA-3 resists Grover's algorithm
- **Mining:** RandomX unaffected by quantum speedup

### NIST Standards

All cryptography uses **NIST-standardized** algorithms:
- CRYSTALS-Dilithium3 (NIST FIPS 204 - Post-Quantum Cryptography)
- SHA-3/Keccak-256 (NIST FIPS 202 - Quantum-Resistant Hashing)

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

---

## Performance

### Mining Performance

- **Hash Rate:** ~65 H/s per CPU core
- **Memory:** ~2GB per thread
- **Power:** ~15-20W per core

### Node Performance

- **Memory Usage:** ~500MB base
- **CPU Usage:** Low (when not mining)
- **Storage:** LevelDB optimized

---

## Community

### Official Channels

- **Website:** [dilithion.org](https://dilithion.org)
- **GitHub:** [github.com/dilithion/dilithion](https://github.com/dilithion/dilithion)
- **Discord:** [Join our Discord](https://discord.gg/DS3gjmsFEJ)

### Support

- **Documentation:** `docs/` directory
- **Issues:** [GitHub Issues](https://github.com/dilithion/dilithion/issues)

---

## Statistics

- **Mainnet Launch:** January 28, 2026
- **Algorithm:** RandomX (CPU)
- **Supply:** 21 million DIL
- **Block Time:** ~4 minutes
- **Reward:** 50 DIL per block
- **Halving:** Every 210,000 blocks (~1.6 years)
- **P2P Port:** 8444
- **RPC Port:** 8332

---

## License

Dilithion is released under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

Dilithion builds upon:

- **RandomX** - Efficient CPU mining
- **chiavdf** - Verifiable Delay Function (Chia Network)
- **CRYSTALS-Dilithium** - Post-quantum signatures (NIST)
- **SHA-3/Keccak** - Quantum-resistant hashing (NIST)
- **Bitcoin** - Original blockchain design
- **Monero** - RandomX implementation
- **Claude Code** - AI-assisted development

---

## Disclaimer

Cryptocurrency involves risk. Mine and use Dilithion responsibly.

- No investment advice
- DYOR (Do Your Own Research)
- Use at your own risk

---

**Dilithion - The People's Coin**

*Quantum-safe cryptocurrency for everyone*

---

**Status:** Mainnet LIVE

**Version:** v3.0.12

**Website:** [dilithion.org](https://dilithion.org)
