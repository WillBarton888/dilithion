# Security Policy

## Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead, report privately to: **security@dilithion.org**

For critical vulnerabilities, you can also reach us via:
- **GitHub Security Advisory:** https://github.com/dilithion/dilithion/security/advisories/new
- **Discord:** [Server link - to be added]
- **Email:** security@dilithion.org

## Response Timeline

We take security seriously and commit to the following response times:

- **Critical vulnerabilities (P0):** Response within 1 hour
- **High severity (P1):** Response within 24 hours
- **Medium severity (P2):** Response within 1 week
- **Low severity (P3):** Best effort

See [INCIDENT-RESPONSE-PLAN.md](INCIDENT-RESPONSE-PLAN.md) for detailed severity definitions.

---

## Bug Bounty Program

We will launch a bug bounty program upon mainnet release (January 1, 2026).

### Bounty Rewards (Paid in DIL after launch):

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

See [SECURITY-REVIEW-CHECKLIST.md](SECURITY-REVIEW-CHECKLIST.md) for detailed areas of review.

**In scope:**
- Post-quantum cryptography implementation (Dilithium3, SHA-3)
- Wallet security and key management
- Consensus and validation logic
- Network protocol and P2P security
- Mining and RandomX integration
- RPC security and authentication
- Memory safety and resource management

**Out of scope:**
- Social engineering attacks
- Physical attacks
- Third-party software or services
- Attacks requiring physical access to hardware
- Denial of service attacks on the network (51% attacks)

---

## Responsible Disclosure

We request **90 days** to patch critical issues before public disclosure.

### Our Commitment:

- We'll acknowledge receipt of your report within 24 hours
- We'll provide regular updates on remediation progress
- We'll credit researchers who report responsibly (if desired)
- We'll coordinate disclosure timing with you
- We'll pay bug bounties as promised (after mainnet launch)

### Your Commitment:

- Report vulnerabilities privately before public disclosure
- Avoid exploiting vulnerabilities beyond proof-of-concept
- Don't access, modify, or delete other users' data
- Give us reasonable time to fix issues before disclosure
- Act in good faith toward our users

---

## Current Security Status

⚠️ **Experimental Software - Pre-Launch Phase**

- **Code Status:** 100% complete, seeking review
- **Professional audit:** Not yet completed (TBD based on community/budget)
- **Community review:** Actively seeking expert feedback
- **Testing status:** Unit tests complete, testnet launching November 2025
- **Known issues:** See [GitHub Issues](https://github.com/dilithion/dilithion/issues)

### Development Approach

This project was developed with AI assistance (Anthropic's Claude Code). We believe in:
- **Full transparency** about our development methods
- **Community-driven security** through open source review
- **Honest disclosure** of limitations and risks
- **Continuous improvement** based on feedback

**We're actively seeking expert code review in:**
- Post-quantum cryptography implementation
- Blockchain consensus logic
- Network protocol security
- RandomX integration
- Wallet security and key management

---

## Security Features

### Cryptographic Security

**Post-Quantum Signatures:**
- CRYSTALS-Dilithium3 (NIST FIPS 204)
- Module-LWE security basis
- Quantum-resistant against Shor's algorithm
- 1,952-byte public keys, 4,032-byte private keys, 3,309-byte signatures

**Quantum-Resistant Hashing:**
- SHA-3/Keccak-256 (NIST FIPS 202)
- Resistant to Grover's algorithm (~128-bit post-quantum security)
- All hashing uses SHA-3 exclusively

**Mining:**
- RandomX proof-of-work (CPU-friendly, ASIC-resistant)
- Unaffected by quantum computing speedups

---

## Dilithium Cryptography Threat Model

**Phase 9.3: Comprehensive Threat Analysis**

### Overview

Dilithion uses CRYSTALS-Dilithium3 (NIST FIPS 204) for all digital signatures. This section documents the threat model, security assumptions, and implementation considerations.

### Security Assumptions

1. **Mathematical Security:**
   - Module-LWE (Learning With Errors) problem hardness
   - Assumes quantum computers cannot efficiently solve Module-LWE
   - Security level: Level 3 (equivalent to AES-192 security)
   - Estimated post-quantum security: ~128 bits

2. **Implementation Security:**
   - Uses reference implementation from pqcrystals/dilithium
   - No known implementation vulnerabilities in reference code
   - Constant-time operations where required
   - Secure random number generation for key generation

3. **Key Management:**
   - Private keys encrypted at rest (AES-256-CBC)
   - Keys never logged or exposed in memory unnecessarily
   - Secure key derivation (PBKDF2-SHA3, 100,000 iterations)

### Threat Vectors

#### 1. Quantum Computing Attacks

**Threat:** Future quantum computers could break classical cryptography (ECDSA, RSA)

**Mitigation:**
- ✅ Dilithium3 is quantum-resistant
- ✅ Based on Module-LWE, not factoring/discrete log
- ✅ No known quantum algorithm to break Module-LWE
- ✅ NIST standardized (FIPS 204)

**Risk Level:** LOW (for quantum attacks on Dilithium itself)

**Note:** Quantum computers could still break SHA-3 via Grover's algorithm, but this only halves security (256-bit → 128-bit), which remains secure.

#### 2. Side-Channel Attacks

**Threat:** Timing attacks, power analysis, cache attacks on signature operations

**Mitigation:**
- ✅ Reference implementation uses constant-time operations
- ✅ No secret-dependent branches in critical paths
- ✅ Secure memory handling (wiping sensitive data)
- ⚠️ **Review Needed:** Verify constant-time properties in our integration

**Risk Level:** MEDIUM (requires physical access or local execution)

**Action Items:**
- Review constant-time implementation
- Add property-based tests for timing invariance
- Consider hardware security modules (HSMs) for high-value keys

#### 3. Key Exposure

**Threat:** Private keys leaked through memory dumps, logs, or bugs

**Mitigation:**
- ✅ Keys encrypted at rest
- ✅ Keys never logged
- ✅ Secure memory wiping
- ✅ Wallet encryption with strong passphrase
- ✅ PBKDF2 key derivation (100,000 iterations)

**Risk Level:** MEDIUM (depends on attacker access level)

**Best Practices:**
- Use hardware wallets for high-value keys
- Never share private keys
- Use strong, unique passphrases
- Regularly backup encrypted wallets

#### 4. Implementation Bugs

**Threat:** Bugs in our Dilithium integration or key management

**Mitigation:**
- ✅ Uses well-tested reference implementation
- ✅ Comprehensive unit tests
- ✅ Fuzz testing for signature operations
- ⚠️ **Review Needed:** Professional crypto audit

**Risk Level:** MEDIUM (unknown until audit)

**Action Items:**
- Commission third-party crypto audit
- Add property-based tests
- Review all crypto code paths

#### 5. Random Number Generation

**Threat:** Weak or predictable random numbers compromise key security

**Mitigation:**
- ✅ Uses system CSPRNG (`/dev/urandom`, `CryptGenRandom`)
- ✅ No custom RNG implementation
- ✅ Secure seed generation

**Risk Level:** LOW (uses system RNG)

**Best Practices:**
- Ensure system RNG is properly seeded
- Use hardware RNG when available
- Never reuse random values

#### 6. Signature Replay Attacks

**Threat:** Reusing signatures from old transactions

**Mitigation:**
- ✅ Transaction includes unique inputs (prevout)
- ✅ Transaction includes locktime
- ✅ UTXO set prevents double-spending
- ✅ Network validation prevents replay

**Risk Level:** LOW (consensus rules prevent replay)

#### 7. Key Generation Weakness

**Threat:** Weak keys generated due to RNG failure or bugs

**Mitigation:**
- ✅ Uses system CSPRNG
- ✅ Key generation follows NIST FIPS 204 specification
- ✅ No custom key generation logic

**Risk Level:** LOW (uses standard implementation)

### Security Properties

#### Properties We Rely On

1. **Unforgeability:** Cannot forge signatures without private key
2. **Non-repudiation:** Signer cannot deny signing
3. **Quantum Resistance:** Secure against quantum attacks
4. **Forward Secrecy:** Old keys remain secure even if new keys compromised

#### Properties We Don't Rely On

1. **Perfect Forward Secrecy:** Not applicable (blockchain context)
2. **Anonymity:** Addresses are pseudonymous, not anonymous
3. **Confidentiality:** Transactions are public (use encryption for privacy)

### Implementation Review Checklist

- [x] Uses NIST-standardized algorithm (Dilithium3)
- [x] Uses reference implementation from pqcrystals
- [x] Keys encrypted at rest
- [x] Secure random number generation
- [x] No key logging or exposure
- [ ] Constant-time verification (needs review)
- [ ] Property-based tests for crypto operations
- [ ] Third-party crypto audit
- [ ] Timing attack resistance verification

### Recommendations

1. **Immediate:**
   - Add property-based tests for signature operations
   - Review constant-time implementation
   - Document all crypto assumptions

2. **Short Term:**
   - Commission professional crypto audit
   - Add timing attack tests
   - Review key management code

3. **Long Term:**
   - Consider hardware security modules (HSMs)
   - Monitor NIST updates on post-quantum crypto
   - Stay updated on cryptanalysis of Dilithium

### References

- **NIST FIPS 204:** [CRYSTALS-Dilithium Standard](https://csrc.nist.gov/publications/detail/fips/204/final)
- **pqcrystals/dilithium:** [Reference Implementation](https://github.com/pqcrystals/dilithium)
- **NIST Post-Quantum Cryptography:** [Project Overview](https://csrc.nist.gov/projects/post-quantum-cryptography)
- **Dilithium Security Analysis:** [Academic Papers](https://pq-crystals.org/dilithium/)

### Wallet Security

**Key Protection:**
- AES-256-CBC encryption for private keys
- PBKDF2-SHA3 key derivation (100,000 iterations)
- Random salt and IV generation
- Secure memory wiping for sensitive data

**Best Practices Implemented:**
- Keys never logged or printed
- Private keys encrypted at rest
- User confirmation before transactions
- Change addresses handled securely
- Memory cleared after key operations

### Network Security

**DoS Protection:**
- Connection limits enforced
- Rate limiting on incoming messages
- Memory limits on data structures
- CPU usage bounded
- Maximum message size: 32MB

**Attack Mitigation:**
- Eclipse attack prevention (peer diversity)
- Sybil attack resistance (proof-of-work)
- Peer misbehavior handling (automatic banning)
- Message validation and size limits

---

## Security Resources

### For Researchers

- **Security Review Checklist:** [SECURITY-REVIEW-CHECKLIST.md](SECURITY-REVIEW-CHECKLIST.md)
- **Incident Response Plan:** [INCIDENT-RESPONSE-PLAN.md](INCIDENT-RESPONSE-PLAN.md)
- **Source Code:** [GitHub Repository](https://github.com/dilithion/dilithion)
- **Documentation:** [docs/](docs/)
- **Training Summary:** [DILITHION-TRAINING-SUMMARY.md](DILITHION-TRAINING-SUMMARY.md)
- **Whitepaper:** [Dilithion-Whitepaper-v1.0.pdf](Dilithion-Whitepaper-v1.0.pdf)

### External References

- **NIST FIPS 204:** [CRYSTALS-Dilithium Standard](https://csrc.nist.gov/publications/detail/fips/204/final)
- **NIST FIPS 202:** [SHA-3 Standard](https://csrc.nist.gov/publications/detail/fips/202/final)
- **RandomX:** [Official Repository](https://github.com/tevador/RandomX)
- **pqcrystals/dilithium:** [Reference Implementation](https://github.com/pqcrystals/dilithium)

---

## Vulnerability Disclosure History

No vulnerabilities have been reported yet. This section will be updated as issues are discovered and patched.

| Date | Severity | Description | Status | Credit |
|------|----------|-------------|--------|--------|
| - | - | - | - | - |

---

## Contact Information

**Security Contact:** security@dilithion.org

### GPG Keys for Encrypted Communication

For sensitive security reports, you can encrypt your message using PGP/GPG.

**Security Team GPG Keys:**

```
⚠️ TODO: Generate and publish GPG keys before mainnet launch
```

**To be added before mainnet (Week 1):**
- Primary security contact GPG key
- Secondary security contact GPG key
- Emergency contact GPG key

**Key Import Instructions:**
```bash
# Import a key from keyserver (once published)
gpg --keyserver hkps://keys.openpgp.org --recv-keys "<fingerprint>"

# Verify key fingerprint
gpg --fingerprint "<fingerprint>"
```

**Keyservers where keys will be published:**
- keys.openpgp.org
- pgp.mit.edu
- keyserver.ubuntu.com

**Public Communication:**
- **GitHub:** https://github.com/dilithion/dilithion
- **Discord:** [Server link - to be added]
- **Twitter:** @DilithionCoin [to be created]
- **Reddit:** r/dilithion [to be created]

**Bug Bounty Submissions:** Via GitHub Security Advisory or security@dilithion.org

---

## Legal

### Disclaimer

Dilithion is experimental software provided "AS IS" without warranties of any kind. Users assume all risks.

**Important:**
- No guarantees of security, value, or success
- Cryptocurrency involves significant risk
- This is NOT financial advice
- Do Your Own Research (DYOR)
- Use at your own risk

### Bug Bounty Terms

- Bounties paid in DIL after mainnet launch (January 1, 2026)
- Payment amount determined by severity and impact
- Final decisions on bounty eligibility made by project team
- Duplicate reports: First reporter receives bounty
- Public disclosure before patch deployment voids bounty eligibility
- Researchers must act in good faith toward users
- No exploitation beyond proof-of-concept

### Intellectual Property

By submitting a vulnerability report, you agree:
- Project may use your findings to improve security
- You retain credit for discovery (if desired)
- Report details may be published after fix (with your permission)
- No compensation beyond announced bug bounty program

---

## Acknowledgments

We will publicly acknowledge security researchers who:
- Report vulnerabilities responsibly
- Allow time for fixing before disclosure
- Provide detailed, helpful reports
- Act in good faith toward the community

### Security Researcher Hall of Fame

*(To be updated after launch)*

---

**Last updated:** October 26, 2025

**Next review:** January 26, 2026 (quarterly review schedule)

---

**Thank you for helping make Dilithion more secure!**
