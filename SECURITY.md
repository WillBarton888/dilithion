# Security Policy

## Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead, report privately to: **security@dilithion.org**

For critical vulnerabilities, you can also reach us via:
- **GitHub Security Advisory:** https://github.com/WillBarton888/dilithion/security/advisories/new
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
- **Known issues:** See [GitHub Issues](https://github.com/WillBarton888/dilithion/issues)

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
- **Source Code:** [GitHub Repository](https://github.com/WillBarton888/dilithion)
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
- **GitHub:** https://github.com/WillBarton888/dilithion
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
