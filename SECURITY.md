# Security Policy

## Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead, report privately to: **security@dilithion.org**

For critical vulnerabilities, you can also reach us via:
- **GitHub Security Advisory:** https://github.com/dilithion/dilithion/security/advisories/new
- **Discord:** https://discord.gg/c25WwRNg

## Response Timeline

We aim to respond to all security reports as quickly as possible. Target
acknowledgement times below are best-effort and reflect current team capacity;
every report is triaged on receipt and escalated if urgent.

| Severity | Example | Target acknowledgement |
|----------|---------|------------------------|
| **P0 — Critical** | Remote code exec, consensus break, custodial fund loss | Within 4 business hours |
| **P1 — High** | Remote DoS, wallet key exposure, bridge replay | Within 1 business day |
| **P2 — Medium** | Local DoS, privilege escalation, info leak | Within 1 week |
| **P3 — Low** | Minor issues, hardening opportunities | Best effort |

An initial acknowledgement is not a fix timeline. Remediation and disclosure
timing are coordinated with the reporter (see **Responsible Disclosure** below).

---

## Security Architecture

### Post-Quantum Cryptography

**Digital Signatures — CRYSTALS-Dilithium3 (NIST FIPS 204):**
- Module-LWE (Learning With Errors) security basis
- Quantum-resistant against Shor's algorithm
- Security Level 3 (equivalent to AES-192)
- 1,952-byte public keys, 4,000-byte private keys, 3,309-byte signatures
- Reference implementation from [pqcrystals/dilithium](https://github.com/pqcrystals/dilithium)

**Hashing — SHA-3/Keccak-256 (NIST FIPS 202):**
- Resistant to Grover's algorithm (~128-bit post-quantum security)
- All hashing uses SHA-3 exclusively (no SHA-256 or RIPEMD-160)

**Mining — RandomX Proof-of-Work:**
- CPU-friendly, ASIC-resistant
- Unaffected by quantum computing speedups

### Wallet Security

- AES-256-CBC encryption for private keys at rest
- PBKDF2-HMAC-SHA3-256 key derivation (100,000 iterations)
- Random salt and IV generation (32-byte salt, BCryptGenRandom on Windows)
- RAII-based secure memory management for entropy and key material
- `memory_cleanse()` guarantees zeroization (not optimized away by compilers)
- Keys never logged or exposed in memory unnecessarily
- HD wallet with BIP39 mnemonic and BIP32/BIP44 derivation

### Network Security

- Eclipse attack prevention (peer diversity via AddrMan)
- Sybil attack resistance (proof-of-work)
- Peer misbehavior scoring and automatic banning
- Connection limits and rate limiting
- DoS-resistant header synchronization
- Maximum message size: 32MB

### Consensus Security

- **DFMP (Dynamic Fair Mining Protocol):** Anti-concentration mechanism preventing mining centralization
- **VDF (Verifiable Delay Function):** Future-scheduled sequential proof system (chiavdf-based)
- **Digital DNA:** 8-dimensional hardware identity fingerprinting for Sybil resistance (Latency, Timing, Perspective, Memory, ClockDrift, Bandwidth, Thermal, Behavioral)
- **Dual Chain:** DIL (RandomX PoW, ~4 min blocks) and DilV (Pure VDF, ~45s blocks)

### Bridge Security (DIL/DilV to Base L2)

- **Trust Model:** Custodial bridge — operator controls minting on Base. Planned migration to Gnosis Safe 3-of-5 multisig for contract ownership.
- **Contracts:** WrappedDIL (wDIL) and WrappedDilV (wDILV) ERC-20 tokens on Base, built with OpenZeppelin v5.1.0 (Ownable, Pausable, ERC20)
- **Rate Limiting:** Daily mint caps and per-deposit maximum enforced on-chain. Minimum burn amounts prevent dust attacks.
- **Replay Protection:** Each native chain txid tracked via `mapping(bytes32 => bool) minted` — prevents double-minting
- **Crash Safety:** Relayer uses a durable attempt ledger with CAS (Compare-And-Swap) state transitions. All RPC send exceptions are treated as ambiguous (transport failures can occur after server processes the send). Stuck transactions are resolved by periodic reconciliation (every ~5 minutes) using on-chain verification and time-windowed wallet history matching. Manual review escalation for sends unresolved after 30 minutes.
- **Reorg Detection:** Block hash history stored for walkback; auto-pauses bridge on backing invariant breach (minted deposits reorged away) or catastrophic reorgs (>100 blocks)
- **Invariant Monitor:** Every cycle verifies `native_balance >= wrapped_supply`. WARNING-level alerts on breach (reserves may be split across wallets). Configurable policy: warn or pause.
- **Address Validation:** Native addresses validated via full base58check (RPC) before any withdrawal send; on-chain validation checks length, prefix, and character set
- **Known Limitation:** Contract ownership is currently a single EOA. Multisig migration is in progress.

### RPC Security

- **Cookie-based authentication by default**: When no `rpcuser`/`rpcpassword` are configured, the node auto-generates a 256-bit random credential written to `<datadir>/.cookie` (permissions 0600 on Linux). RPC is never unauthenticated.
- PBKDF2-HMAC-SHA3-256 password hashing (100,000 iterations)
- Constant-time password and username comparison (prevents timing attacks)
- Role-based access control (RBAC) with granular permission bits (READ_BLOCKCHAIN, WRITE_WALLET, ADMIN_SERVER, etc.)
- Per-method rate limiting
- Dynamic fee estimation based on mempool congestion
- Public API mode (`--public-api`) requires explicit authentication — refuses to start without credentials
- Request/response audit logging

---

## Threat Model

### Quantum Computing Attacks
- **Risk:** LOW — Dilithium3 is quantum-resistant (NIST standardized)
- Signatures based on Module-LWE, not factoring/discrete log
- SHA-3 provides ~128-bit post-quantum security

### Side-Channel Attacks
- **Risk:** MEDIUM — Reference implementation uses constant-time operations
- No secret-dependent branches in critical paths
- Secure memory handling (wiping sensitive data)

### Key Exposure
- **Risk:** MEDIUM — Keys encrypted at rest, never logged
- PBKDF2-HMAC-SHA3-256 key derivation with 100,000 iterations
- RAII-based secure memory wiping after key operations

### Implementation Bugs
- **Risk:** MEDIUM — Uses well-tested reference implementation
- Comprehensive unit tests (300+ tests across 59 test suites, including fuzz campaigns)
- Preparing for professional security audit by Hacken

### Random Number Generation
- **Risk:** LOW — Uses system CSPRNG (`/dev/urandom`, `BCryptGenRandom` on Windows)
- No custom RNG implementation
- Falls back to `CryptGenRandom` only if `BCryptGenRandom` unavailable (legacy Windows)

---

## Development Approach

This project was developed with AI assistance (Anthropic's Claude Code). We believe in:
- **Full transparency** about our development methods
- **Community-driven security** through open source review
- **Honest disclosure** of limitations and risks
- **Continuous improvement** based on feedback

**We actively seek expert review in:**
- Post-quantum cryptography implementation
- Blockchain consensus logic
- Network protocol security
- RandomX integration
- Wallet security and key management

---

## Responsible Disclosure

We request **90 days** to patch critical issues before public disclosure.

### Our Commitment:
- Acknowledge receipt of your report within 24 hours
- Provide regular updates on remediation progress
- Credit researchers who report responsibly (if desired)
- Coordinate disclosure timing with you
- Credit you publicly in our Hall of Fame (if desired)

### Your Commitment:
- Report vulnerabilities privately before public disclosure
- Avoid exploiting vulnerabilities beyond proof-of-concept
- Don't access, modify, or delete other users' data
- Give us reasonable time to fix issues before disclosure
- Act in good faith toward our users

---

## References

- **NIST FIPS 204:** [CRYSTALS-Dilithium Standard](https://csrc.nist.gov/publications/detail/fips/204/final)
- **NIST FIPS 202:** [SHA-3 Standard](https://csrc.nist.gov/publications/detail/fips/202/final)
- **RandomX:** [Official Repository](https://github.com/tevador/RandomX)
- **pqcrystals/dilithium:** [Reference Implementation](https://github.com/pqcrystals/dilithium)
- **Dilithion Website:** [dilithion.org](https://dilithion.org)
- **Source Code:** [GitHub Repository](https://github.com/dilithion/dilithion)

---

## Vulnerability Disclosure History

| Date | Severity | Description | Status | Credit |
|------|----------|-------------|--------|--------|
| - | - | No vulnerabilities reported yet | - | - |

---

## Security Researcher Hall of Fame

We publicly acknowledge security researchers who report vulnerabilities responsibly.

*(Be the first — report a vulnerability and get credited here!)*

---

## Contact

- **Security Reports:** security@dilithion.org
- **GitHub Advisory:** https://github.com/dilithion/dilithion/security/advisories/new
- **Discord:** https://discord.gg/c25WwRNg
- **Vulnerability Reports:** Via GitHub Security Advisory or security@dilithion.org

---

**Last updated:** April 9, 2026

**Thank you for helping make Dilithion more secure!**
