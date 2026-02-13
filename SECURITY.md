# Security Policy

## Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead, report privately to: **security@dilithion.org**

For critical vulnerabilities, you can also reach us via:
- **GitHub Security Advisory:** https://github.com/WillBarton888/dilithion/security/advisories/new
- **Discord:** https://discord.gg/c25WwRNg

## Response Timeline

- **Critical vulnerabilities (P0):** Response within 1 hour
- **High severity (P1):** Response within 24 hours
- **Medium severity (P2):** Response within 1 week
- **Low severity (P3):** Best effort

---

## Bug Bounty Program

### Bounty Rewards (Paid in DIL):

- **Critical vulnerabilities:** 1,000 DIL
  - Private key exposure
  - Consensus bugs allowing double-spend
  - Remote code execution
  - Fund theft vulnerabilities

- **Major bugs:** 100 DIL
  - DoS vulnerabilities
  - Wallet security issues
  - Network protocol exploits
  - Data corruption bugs

- **Minor issues:** 10 DIL
  - Performance problems
  - Edge case bugs
  - Non-critical security improvements

### Scope

**In scope:**
- Post-quantum cryptography implementation (CRYSTALS-Dilithium3, NIST FIPS 204)
- Quantum-resistant hashing (SHA-3/Keccak-256, NIST FIPS 202)
- Wallet security and key management
- Consensus and validation logic (RandomX PoW, DFMP anti-concentration)
- Network protocol and P2P security
- Mining and RandomX integration
- RPC security and authentication
- VDF (Verifiable Delay Function) implementation
- Digital DNA identity system

**Out of scope:**
- Social engineering attacks
- Physical attacks
- Third-party software or services
- Attacks requiring physical access to hardware
- Denial of service attacks on the network (51% attacks)

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
- PBKDF2-SHA3-512 key derivation (500,000 iterations)
- Random salt and IV generation
- Secure memory wiping for sensitive data
- Keys never logged or exposed in memory unnecessarily

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
- **Digital DNA:** Hardware identity fingerprinting for Sybil resistance

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
- PBKDF2 key derivation with 100,000 iterations
- Secure memory wiping after key operations

### Implementation Bugs
- **Risk:** MEDIUM — Uses well-tested reference implementation
- Comprehensive unit tests (200+ tests)
- Actively seeking professional crypto audit

### Random Number Generation
- **Risk:** LOW — Uses system CSPRNG (`/dev/urandom`, `CryptGenRandom`)
- No custom RNG implementation

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
- Pay bug bounties as promised

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
- **Source Code:** [GitHub Repository](https://github.com/WillBarton888/dilithion)

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
- **GitHub Advisory:** https://github.com/WillBarton888/dilithion/security/advisories/new
- **Discord:** https://discord.gg/c25WwRNg
- **Bug Bounty Submissions:** Via GitHub Security Advisory or security@dilithion.org

---

**Last updated:** February 13, 2026

**Thank you for helping make Dilithion more secure!**
