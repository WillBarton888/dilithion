# Glossary

Technical terms and abbreviations used in Dilithion documentation.

---

## Cryptography

**CRYSTALS-Dilithium** - Post-quantum digital signature scheme based on module lattices, standardized by NIST as FIPS 204.

**Dilithium-2** - Parameter set providing NIST security level 2 (128-bit quantum security). Chosen for Dilithion.

**ECDSA** - Elliptic Curve Digital Signature Algorithm. Used by Bitcoin, vulnerable to quantum computers.

**Post-Quantum Cryptography (PQC)** - Cryptographic algorithms resistant to attacks by quantum computers.

**Side-Channel Attack** - Attack that exploits information leaked through implementation (timing, power consumption, etc.).

**Constant-Time** - Code execution that takes the same time regardless of secret inputs, preventing timing attacks.

**Module-LWE** - Mathematical problem underlying Dilithium's security (Learning With Errors over module lattices).

---

## Bitcoin/Blockchain

**Consensus Rules** - Rules that all nodes must agree on for validating blocks and transactions.

**Proof of Work (PoW)** - Consensus mechanism requiring computational work to mine blocks.

**UTXO** - Unspent Transaction Output. Bitcoin's accounting model.

**Mempool** - Memory pool of unconfirmed transactions.

**Testnet** - Separate blockchain for testing without real value.

**Genesis Block** - First block in a blockchain.

**Halving** - Event where block reward is cut in half (every 210,000 blocks).

**Ion** - Smallest unit (0.00000001 coins).

---

## Dilithion-Specific

**DILI** - Symbol for Dilithion cryptocurrency.

**qb** - Bech32m address prefix for Dilithion.

**4MB Blocks** - Dilithion's block size limit (vs Bitcoin's 1MB).

---

## Development

**CI/CD** - Continuous Integration / Continuous Deployment.

**PR** - Pull Request.

**TDD** - Test-Driven Development.

**Fuzz Testing** - Testing with random/malformed inputs.

**Coverage** - Percentage of code executed by tests.

**Regression Test** - Test ensuring old bugs don't reappear.

---

## Security

**51% Attack** - Attack where one party controls majority of mining power.

**Sybil Attack** - Attack using many fake network identities.

**Eclipse Attack** - Isolating a node by controlling all its connections.

**DoS** - Denial of Service attack.

---

## Abbreviations

- **NIST** - National Institute of Standards and Technology
- **FIPS** - Federal Information Processing Standard
- **API** - Application Programming Interface
- **RPC** - Remote Procedure Call
- **P2P** - Peer-to-Peer
- **HD Wallet** - Hierarchical Deterministic Wallet
- **BIP** - Bitcoin Improvement Proposal
- **ADR** - Architecture Decision Record
