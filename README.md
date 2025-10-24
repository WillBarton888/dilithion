# Dilithion

> A quantum-resistant cryptocurrency built on Bitcoin Core with CRYSTALS-Dilithium post-quantum signatures.

**Status:** Early Development (Phase 0)
**Domain:** [dilithion.com](https://dilithion.com)
**License:** MIT (planned)

---

## What is Dilithion?

Dilithion is a fair-launch, quantum-resistant cryptocurrency that replaces Bitcoin's ECDSA signatures with CRYSTALS-Dilithium, a NIST-standardized post-quantum cryptographic signature scheme.

### Why Dilithion?

Quantum computers pose an existential threat to current cryptocurrencies. When large-scale quantum computers become available, they will be able to break the ECDSA signatures that protect Bitcoin and most other cryptocurrencies.

Dilithion prepares for this future by:
- Using **CRYSTALS-Dilithium** signatures (NIST FIPS 204)
- Maintaining Bitcoin's **proven consensus mechanism**
- Keeping the same **economic model** (21M supply, halving schedule)
- Reusing Bitcoin's **SHA-256 mining** (ASIC compatible)

---

## Technical Overview

### Core Technology

| Component | Bitcoin | Dilithion |
|-----------|---------|-----------|
| **Signature Scheme** | ECDSA (secp256k1) | CRYSTALS-Dilithium-2 |
| **Public Key Size** | 33 bytes | 1,312 bytes |
| **Signature Size** | ~72 bytes | 2,420 bytes |
| **Address Hash** | RIPEMD160 (20 bytes) | BLAKE3 (32 bytes) |
| **Block Size** | 1 MB | 4 MB |
| **Block Time** | 10 minutes | 10 minutes |
| **Consensus** | Nakamoto PoW | Nakamoto PoW |
| **Mining** | SHA-256 | SHA-256 |
| **Supply** | 21M BTC | 21M DILI |

### Key Features

- **Quantum-Resistant:** Secure against Shor's algorithm and quantum attacks
- **Fair Launch:** No premine, no ICO, no VC backing
- **Bitcoin Compatible:** Same economic model and consensus rules
- **ASIC Friendly:** Reuses SHA-256 mining infrastructure
- **Open Source:** Fully transparent development

---

## Project Status

### Current Phase: Foundation (Months 0-3)

**Completed:**
- [x] Project naming and domain registration
- [x] Trademark clearance research
- [x] Initial technical planning
- [x] Documentation structure

**In Progress:**
- [ ] Development environment setup
- [ ] Bitcoin Core fork and compilation
- [ ] CRYSTALS-Dilithium specification review
- [ ] Technical specification document

**Next Steps:**
- [ ] Proof-of-concept implementation
- [ ] Core cryptographic integration
- [ ] Test framework setup

See [docs/research/initial-planning-discussion.md](docs/research/initial-planning-discussion.md) for detailed planning notes.

---

## Development Roadmap

### Phase 0: Foundation (Months 0-3)
- Technical decisions and planning
- Development environment setup
- Initial research and documentation

### Phase 1: Implementation (Months 4-12)
- Core cryptographic modifications
- Network protocol updates
- Testing infrastructure

### Phase 2: Security & Review (Months 13-18)
- External cryptographer audit
- Professional security audit
- Academic paper publication

### Phase 3: Pre-launch (Months 19-24)
- Public testnet
- Documentation completion
- Legal review

### Phase 4: Launch (Month 25+)
- Fair launch genesis block
- Community building
- Network stabilization

See [docs/implementation-roadmap.md](docs/implementation-roadmap.md) for detailed technical roadmap.

---

## Repository Structure

```
dilithion/
├── docs/                    # Documentation
│   ├── research/           # Research notes and discussions
│   ├── implementation-roadmap.md
│   └── technical-spec.md
├── src/                    # Source code (future)
├── tests/                  # Test suite (future)
├── scripts/                # Build and utility scripts (future)
└── README.md              # This file
```

---

## Getting Started

### For Developers

**Prerequisites:**
- Strong C++ systems programming experience
- Bitcoin Core development knowledge (highly recommended)
- Cryptography background (for core contributors)

**First Steps:**
1. Read [docs/research/initial-planning-discussion.md](docs/research/initial-planning-discussion.md)
2. Review [docs/implementation-roadmap.md](docs/implementation-roadmap.md)
3. Set up Bitcoin Core development environment
4. Study CRYSTALS-Dilithium specification (NIST FIPS 204)

### For Researchers

**Areas of Interest:**
- Post-quantum cryptography
- Blockchain consensus mechanisms
- Quantum computing threat analysis
- Cryptocurrency economics

**Resources:**
- Technical documentation in `docs/`
- Research notes in `docs/research/`
- Implementation details (coming soon)

---

## Contributing

**Current Status:** Not accepting external contributions yet.

We're in the early planning and foundation phase. Once we have a working proof-of-concept, we'll open up for community contributions.

**Future Contribution Areas:**
- Core protocol development
- Testing and QA
- Documentation
- Security research
- Code review

---

## Security

### Responsible Disclosure

**NOT YET APPLICABLE** - No code to audit yet.

Once we have working code, we'll establish a security disclosure policy and bug bounty program.

### Audit Status

- **Cryptographer Review:** Planned for Month 13-15
- **Security Audit:** Planned for Month 16-18
- **Academic Paper:** In preparation

---

## Principles

### Technical Principles

1. **Security First:** Quantum resistance is non-negotiable
2. **Proven Consensus:** Reuse Bitcoin's battle-tested mechanisms
3. **Minimal Changes:** Only modify what's necessary for quantum resistance
4. **Transparency:** Open development from day one

### Community Principles

1. **Fair Launch:** No premine, no insider advantage
2. **No Hype:** Let the technology speak
3. **Long-term Focus:** This is a 5+ year project
4. **Technical Merit:** Build for cryptographers and engineers first

---

## FAQ

### Why fork Bitcoin instead of starting fresh?

Bitcoin Core has 15+ years of security hardening, proven consensus, and known bugs already fixed. Starting fresh would introduce unnecessary risk.

### Why Dilithium instead of other post-quantum schemes?

CRYSTALS-Dilithium is a NIST standard (FIPS 204), has well-understood security properties, and offers a good balance of signature size and performance.

### Why 4MB blocks?

Dilithium signatures are ~33x larger than ECDSA signatures. To maintain similar transaction throughput to Bitcoin, we need proportionally larger blocks.

### When will this launch?

Planned for Month 25 (approximately 2+ years from start). We won't rush. Security and correctness come first.

### Is this a get-rich-quick scheme?

No. This is a serious technical project to prepare cryptocurrency for the quantum era. It may fail. It will take years. Do not invest what you can't afford to lose.

### What if Bitcoin implements quantum resistance first?

That's fine. We'd consider it a success if this project pushes Bitcoin to upgrade. We're building a testbed and fallback option.

---

## Resources

### Documentation

- [Initial Planning Discussion](docs/research/initial-planning-discussion.md)
- [Implementation Roadmap](docs/implementation-roadmap.md)
- Technical Specification (coming soon)

### External Resources

**CRYSTALS-Dilithium:**
- [NIST FIPS 204 Standard](https://csrc.nist.gov/publications/detail/fips/204/final)
- [Dilithium Reference Implementation](https://github.com/pq-crystals/dilithium)
- [Dilithium Paper](https://pq-crystals.org/dilithium/)

**Bitcoin Core:**
- [Bitcoin Core Repository](https://github.com/bitcoin/bitcoin)
- [Bitcoin Core Development](https://bitcoincore.org/en/contribute/)
- [Bitcoin Developer Documentation](https://developer.bitcoin.org/)

**Post-Quantum Cryptography:**
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Open Quantum Safe](https://openquantumsafe.org/)

---

## Contact

**Project Lead:** (To be added)

**Communication Channels:**
- GitHub Issues (for technical discussion only)
- Email: (To be added)
- IRC/Matrix: (To be determined)

**Note:** We are NOT on Discord, Telegram, or other platforms commonly used for crypto marketing. Beware of impersonators.

---

## License

MIT License (planned)

Full license to be added upon first code release.

---

## Disclaimer

This project is experimental software under active development. Do not use it for anything important. It may fail. It may have bugs. Quantum computers may arrive sooner or later than expected. Bitcoin may implement quantum resistance first.

**There is no guarantee of:**
- Project completion
- Network adoption
- Token value
- Security guarantees
- Timeline adherence

**This is not financial advice. This is not investment advice. This is a technical experiment.**

---

## Acknowledgments

- **Satoshi Nakamoto** - For Bitcoin
- **Bitcoin Core Developers** - For maintaining Bitcoin Core
- **CRYSTALS Team** - For Dilithium
- **NIST** - For post-quantum cryptography standardization

---

**Last Updated:** October 2025
**Version:** 0.0.1-alpha (pre-release)
