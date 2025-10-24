# Dilithion Project Overview

## For AI Agents

This document provides context for AI agents working on the Dilithion project.

## Project Summary

**Dilithion** is a quantum-resistant cryptocurrency forked from Bitcoin Core, replacing ECDSA signatures with CRYSTALS-Dilithium post-quantum cryptographic signatures while maintaining Bitcoin's proven consensus mechanism and economic model.

## Current Status

**Phase:** Foundation (Month 0-3)
**Stage:** Planning and Documentation
**Next Milestone:** Development Environment Setup

## Key Objectives

1. **Security First:** Implement quantum resistance without compromising security
2. **Minimal Changes:** Only modify what's necessary for post-quantum signatures
3. **Bitcoin Compatible:** Maintain consensus rules and economic model
4. **Fair Launch:** No premine, no ICO, complete transparency

## Technical Stack

- **Base:** Bitcoin Core v25.0 (or latest stable)
- **Language:** C++ (Bitcoin Core codebase)
- **Signatures:** CRYSTALS-Dilithium-2 (NIST FIPS 204)
- **Build System:** Autotools / CMake
- **Testing:** Boost Test (unit) + Python (functional)

## Architecture

### Core Modifications

1. **Cryptography** (🔴 Critical)
   - Replace ECDSA with Dilithium
   - Files: `src/key.cpp`, `src/pubkey.cpp`, `src/crypto/dilithium/*`

2. **Consensus** (🔴 Critical)
   - Update block size limits (4MB)
   - Files: `src/consensus/*`, `src/validation.cpp`

3. **Data Structures** (🟡 Important)
   - Larger signatures in transactions
   - Files: `src/primitives/transaction.h`

4. **Address Format** (🟡 Important)
   - 32-byte address hash
   - Bech32m encoding
   - Files: `src/key_io.cpp`, `src/chainparams.cpp`

5. **Network** (🟢 Minor)
   - Handle larger transaction sizes
   - Files: `src/net_processing.cpp`

## Agent Roles

### Available Agents

1. **crypto-specialist** - Dilithium integration and cryptographic code
2. **bitcoin-core-expert** - Bitcoin Core modifications and integration
3. **consensus-validator** - Consensus rule verification
4. **test-engineer** - Testing and QA
5. **security-auditor** - Security review
6. **documentation-writer** - Technical documentation

### How to Use Agents

Agents are specialized for specific tasks. Use the appropriate agent for each area:

```bash
# Example: For cryptographic implementation
Use crypto-specialist agent

# Example: For consensus changes
Use consensus-validator agent
```

## Workflows

### Available Workflows

1. **crypto-implementation** - Implement Dilithium cryptography
2. **address-format-update** - Update address format
3. **consensus-integration** - Integrate consensus changes
4. **testing-validation** - Test and validate changes

### Workflow Usage

Follow workflows sequentially:
1. Start with crypto-implementation
2. Then address-format-update
3. Then consensus-integration
4. Finally testing-validation

## Commands

### Available Commands

- `/setup-dev-env` - Set up development environment
- `/run-tests` - Run test suite
- `/build` - Build the project
- `/lint` - Run code linters

## Standards

### Security Standards

- **security-critical-code.md** - Guidelines for security-critical code
- **constant-time-crypto.md** - Constant-time operation requirements
- **consensus-safety.md** - Consensus rule safety

### Coding Standards

- Follow Bitcoin Core coding style
- Use Bitcoin Core patterns and idioms
- Document all changes thoroughly
- Test exhaustively

## Danger Zones

### 🔴 Extreme Caution Required

These files are consensus-critical. One bug = network fork:

- `src/validation.cpp`
- `src/consensus/*`
- `src/script/interpreter.cpp`
- `src/pow.cpp`

### 🚨 Cryptographic Code

These files must be constant-time and side-channel resistant:

- `src/key.cpp`
- `src/pubkey.cpp`
- `src/crypto/dilithium/*`
- `src/random.cpp`

## Development Principles

### Technical Principles

1. **Security > Performance** - Always prioritize security
2. **Test Everything** - Comprehensive testing is mandatory
3. **Document Decisions** - Record why, not just what
4. **Review Critically** - All code must be reviewed

### Collaboration Principles

1. **Ask for Help** - Escalate when uncertain
2. **No Shortcuts** - Don't rush security-critical code
3. **Transparency** - Document all work publicly
4. **Respect** - Treat all contributors professionally

## File Structure

```
dilithion/
├── .claude/                    # Agent OS configuration
│   ├── agents/                # Agent definitions
│   ├── workflows/             # Development workflows
│   ├── commands/              # CLI commands
│   ├── standards/             # Coding standards
│   └── config.yml             # Main configuration
├── docs/                      # Documentation
│   ├── research/              # Research notes
│   ├── implementation-roadmap.md
│   └── technical-spec.md
├── src/                       # Source code (future)
├── tests/                     # Tests (future)
└── README.md
```

## Resources

### Documentation

- [Initial Planning Discussion](../docs/research/initial-planning-discussion.md)
- [Implementation Roadmap](../docs/implementation-roadmap.md)
- [README](../README.md)

### External Resources

- [NIST FIPS 204 - Dilithium](https://csrc.nist.gov/publications/detail/fips/204/final)
- [Bitcoin Core](https://github.com/bitcoin/bitcoin)
- [Dilithium Reference](https://github.com/pq-crystals/dilithium)

## Common Tasks for Agents

### When Asked to Implement Crypto

1. Use crypto-specialist agent
2. Follow crypto-implementation workflow
3. Apply security-critical-code standard
4. Test against NIST vectors
5. Get cryptographer review

### When Asked to Modify Consensus

1. Use consensus-validator agent
2. Document change rationale
3. Write comprehensive tests
4. Review with multiple experts
5. Test on testnet first

### When Asked to Update Documentation

1. Use documentation-writer agent
2. Be clear and technical
3. Include code examples
4. Link to relevant resources
5. Keep it current

## Decision Making

### When to Proceed

✅ Proceed when:
- Requirements are clear
- Design is documented
- Tests are written
- Reviews are complete

### When to Escalate

🚨 Escalate when:
- Security concern discovered
- Consensus rule unclear
- Cryptographic question
- Major architectural decision needed

### Who to Escalate To

- **Crypto questions:** crypto-specialist or external cryptographer
- **Consensus questions:** consensus-validator or Bitcoin Core developers
- **Architecture questions:** Project lead
- **Security issues:** security-auditor and project lead

## Success Metrics

### Phase 0 Success (Current)
- [x] Project named and domain registered
- [x] Documentation structure created
- [ ] Development environment set up
- [ ] Technical specification complete

### Phase 1 Success (Months 4-12)
- [ ] Dilithium integrated and tested
- [ ] Testnet operational
- [ ] Basic wallet functional
- [ ] 10+ nodes running

### Long-term Success (Years 2-5)
- [ ] Security audits complete
- [ ] Fair launch achieved
- [ ] 500+ nodes operational
- [ ] Technical community respect earned

## Remember

1. **This is a multi-year project** - Don't rush
2. **Security is paramount** - No shortcuts
3. **Document everything** - Future you will thank present you
4. **Ask for help** - Better slow and correct than fast and broken
5. **Stay focused** - Quantum resistance is the goal

## Getting Started

New agent joining the project?

1. Read [README.md](../README.md)
2. Review [initial-planning-discussion.md](../docs/research/initial-planning-discussion.md)
3. Study [implementation-roadmap.md](../docs/implementation-roadmap.md)
4. Check your assigned role in `.claude/agents/`
5. Follow relevant workflow in `.claude/workflows/`
6. Apply standards from `.claude/standards/`

## Contact

**Project Lead:** (TBD)
**Repository:** https://github.com/dilithion/dilithion
**Documentation:** https://dilithion.com/docs (future)

---

**Last Updated:** October 2025
**Version:** 0.0.1-alpha
**Status:** Foundation Phase
