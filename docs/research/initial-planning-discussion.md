# Initial Planning Discussion - Dilithion Project

**Date:** October 2025
**Topic:** Quantum-Resistant Bitcoin Fork Implementation Strategy

---

## Project Overview

Dilithion is a quantum-resistant cryptocurrency forked from Bitcoin Core, replacing ECDSA signatures with CRYSTALS-Dilithium post-quantum cryptographic signatures.

### Key Decisions

**Name & Identity:**
- **Project Name:** Dilithion
- **Domain:** dilithion.com (registered)
- **Rationale:** References CRYSTALS-Dilithium algorithm, unique spelling differentiates from Star Trek's "Dilithium"

**Core Technology Stack:**
- **Base:** Bitcoin Core codebase (fork)
- **Signature Scheme:** CRYSTALS-Dilithium-2 (NIST FIPS 204)
- **Key Encapsulation:** CRYSTALS-Kyber
- **Mining:** SHA-256 PoW (reuse Bitcoin ASICs)
- **Consensus:** Nakamoto consensus (identical to Bitcoin)

---

## Phase 0: Foundation (Months 0-3)

### Technical Decisions

**1. Cryptographic Parameters**
- **Dilithium Parameter Set:** Dilithium-2 (128-bit security)
- **Public Key Size:** 1,312 bytes (vs ECDSA's 33 bytes)
- **Signature Size:** 2,420 bytes (vs ECDSA's ~72 bytes)
- **Address Hash:** BLAKE3 → 32 bytes (vs Bitcoin's 20 bytes)

**2. Block Size Implications**
- **Bitcoin:** ~2,000 transactions per 1MB block
- **Dilithion:** ~250 transactions per block at 1MB
- **Solution:** 4MB block size to maintain throughput
- **Transaction Size:** ~400 bytes → ~10 KB (25x increase)

**3. Address Format**
- **Encoding:** Bech32m (like Bitcoin SegWit)
- **Prefix:** "qb" (quantum-bitcoin)
- **Format:** qb1qxyz...abc (prefix + 32 bytes)
- **Alternative:** Base58Check with 'Q' prefix

### Month 1: Setup

**Week 1-2: Infrastructure**
- [x] Domain registered: dilithion.com
- [ ] GitHub organization (public from day 1)
- [ ] Documentation site (Hugo or MkDocs)
- [ ] Development environment setup
- [ ] Fork Bitcoin Core repository

**Week 3-4: Initial Research**
- [ ] Read CRYSTALS-Dilithium spec (NIST FIPS 204)
- [ ] Study existing post-quantum crypto implementations
- [ ] Review Bitcoin Core architecture
- [ ] Map out exactly what needs changing

**Deliverable:** Project plan document outlining every modification needed

### Month 2-3: Proof of Concept

**Build the absolute minimum:**
- [ ] Modified Bitcoin Core that compiles
- [ ] Dilithium signature generation/verification
- [ ] Single node that can mine blocks
- [ ] Basic wallet functionality

**Don't build yet:**
- Network protocol
- Multi-node consensus
- GUI wallet
- Documentation

**Deliverable:** Working single-node prototype

---

## Phase 1: Implementation (Months 4-12)

### Core Development Priorities

#### Month 4-6: Signature System

**Critical Implementation Decisions:**

1. **Dilithium Parameter Set:** Dilithium-2 (recommended)
   - Smaller, faster than Dilithium-3/5
   - 128-bit security is sufficient

2. **Address Format:**
   - Can't use Bitcoin's 20-byte hash (public keys are 1.3KB)
   - Use BLAKE3 hash → 32 bytes
   - New address prefix (avoid BTC confusion)
   - Bech32m encoding

3. **Block Size:**
   - Need 4MB blocks to match Bitcoin throughput
   - This is acceptable (nodes can handle it)

#### Month 7-9: Network Protocol
- [ ] P2P message format
- [ ] Block propagation
- [ ] Mempool management
- [ ] Peer discovery (reuse Bitcoin's DNS seeds model)

#### Month 10-12: Testing Infrastructure
- [ ] Testnet deployment
- [ ] Block explorer
- [ ] Mining pool software
- [ ] Basic wallet (command-line only)

**Deliverable:** Functional testnet with 10+ nodes

---

## Phase 2: Security & Review (Months 13-18)

### Month 13-15: External Review

**Cryptographer Audit (Critical):**
- Reach out to academic cryptographers
- Post-quantum crypto researchers
- Offer co-authorship on paper
- Need their stamp of approval

**Where to Find Them:**
- IACR conferences (attend virtually)
- Post-quantum crypto mailing lists
- University CS departments
- Twitter/X crypto researcher community

**What You're Asking:**
- Review implementation of Dilithium
- Verify parameter choices
- Check for side-channel vulnerabilities
- Identify any cryptographic mistakes

**Cost:** $0 if collaborative, $20K-50K if hired

### Month 16-18: Security Audit

**Professional Audit Firms:**
- Trail of Bits (gold standard, expensive)
- NCC Group
- Kudelski Security
- OpenZeppelin (if they do protocol work)

**What They Check:**
- Memory safety bugs
- Consensus vulnerabilities
- P2P network attacks
- Implementation bugs

**Cost:** $50K-150K (essential, no shortcuts)

**How to Fund:**
- Personal savings (ideal)
- Anonymous donation (risky)
- Crowdfund from technical community
- Defer until post-launch (not recommended)

**Alternative:** Bug bounty program
- Offer rewards for vulnerabilities
- Cheaper than full audit upfront
- But riskier

### Academic Paper

**Write Formal Paper:**
- "Quantum-Resistant Bitcoin: Design and Implementation"
- Submit to IEEE Symposium on Security and Privacy
- Or IACR conferences (Financial Cryptography)
- Or arXiv preprint (faster)

**Purpose:**
- Establish technical credibility
- Get peer review
- Create citation trail
- Differentiate from scams

**Timeline:** 3-6 months (research, write, submit, revise)

---

## Phase 3: Pre-launch (Months 19-24)

### Month 19-20: Final Testnet

**Requirements:**
- 100+ external nodes running
- 1,000+ hours of runtime without crashes
- Simulated attack scenarios
- Performance benchmarks published

**How to Get Participants:**
- Bitcoin Talk announcement
- Cryptography mailing lists
- Reddit r/Bitcoin, r/cryptocurrency (carefully)
- Twitter/X technical community
- No marketing, just "help us test"

### Month 21-22: Documentation Blitz

**Everything Needs Crystal-Clear Docs:**
- Whitepaper (technical specification)
- Installation guide (all major OS)
- Mining guide
- Wallet setup
- Node operation
- Security best practices
- Code documentation

**Style:** Boring, technical, comprehensive
**Model:** Bitcoin's original documentation

### Month 23: Launch Preparation

**Legal Review:**
- Consult lawyer (crypto-specialized)
- Ensure fair launch ≠ security
- Trademark clearance
- Open source license (MIT recommended)

**Infrastructure:**
- DNS seeds for node discovery
- Block explorer hosted
- Download servers (GitHub + mirrors)
- Communication channels (no Discord, maybe Matrix)

### Month 24: The Announcement

**30 Days Before Genesis:**

```
Subject: [Announcement] Dilithion - Post-Quantum Bitcoin Fork

A fair-launch, post-quantum resistant cryptocurrency using
CRYSTALS-Dilithium signatures and Bitcoin's proven consensus mechanism.

Genesis block: [Exact timestamp]
Initial difficulty: [Set low enough for anyone]
Code: github.com/dilithion/dilithion
Whitepaper: [URL]
Security audits: [URLs]

No premine. No ICO. No VC backing.

All are invited to mine from genesis.
```

**Where to Post:**
- Bitcoin Talk (Announcements)
- Cryptography mailing list
- GitHub repository
- Your documentation site
- That's it. No paid marketing.

---

## Phase 4: Launch (Month 25)

### Genesis Block

**Timing:**
- Choose specific timestamp (e.g., Jan 1, 2027 00:00:00 UTC)
- Announce 30+ days in advance
- No surprises, no games

**Genesis Block Contents:**
- Recent news headline (like Satoshi did)
- Initial coinbase reward: 50 coins (same as Bitcoin)
- Hardcoded in client

**What Happens:**
- Release binaries (Windows, Mac, Linux)
- Release source code
- Anyone can download and start mining
- Initial difficulty is very low

**Your Role:**
- Run several nodes
- Mine blocks like anyone else
- Answer technical questions
- Fix bugs immediately

### First 48 Hours

**Critical Period:**
- Monitor for bugs
- Watch for attacks
- Community on high alert
- Be ready for crashes

**What You're Looking For:**
- Consensus failures
- Network splits
- Security vulnerabilities
- Unexpected behavior

**Communication:**
- Frequent status updates
- Transparent about issues
- Quick fixes if needed
- No hype, just facts

### First 6 Months

**Focus On:**
- Network stability
- Bug fixes only
- Building trust through reliability
- Growing miner count organically

**Don't:**
- Announce exchange listings
- Discuss price
- Market to retail
- Change protocol parameters
- Add features

**Success Metrics:**
- 500+ full nodes
- 10+ mining pools
- Zero critical bugs
- Technical community respect

---

## Funding Reality

### Total Estimated Costs

- **Security audits:** $50K-150K
- **Your time:** $0 (labor of love)
- **Infrastructure:** $5K/year (servers, domains)
- **Legal review:** $5K-10K
- **Total:** $60K-165K

### Funding Options

1. **Self-fund (ideal)**
   - Maintains independence
   - No strings attached
   - You take all risk

2. **Anonymous donation campaign**
   - Target: Technical community only
   - Risk: Looks like ICO to regulators
   - Must be very careful

3. **Delay audit until post-launch**
   - Save $100K upfront
   - Risk: Bugs in production
   - Use bug bounties instead

4. **Get sponsored by concerned entity**
   - Quantum computing company
   - Security research lab
   - Must maintain independence

**Recommendation:** Self-fund if possible. The independence is worth it.

---

## Risk Mitigation

### Technical Risks

**Risk:** Critical bug in Dilithium implementation
- **Mitigation:** Multiple independent reviews, extensive testing
- **Contingency:** Emergency fix protocol (pre-announced procedure)

**Risk:** Quantum computers arrive faster than expected
- **Mitigation:** You're already quantum-resistant (this is your advantage)
- **Contingency:** N/A (this validates your project)

**Risk:** Bitcoin upgrades to quantum resistance first
- **Mitigation:** Accept this outcome gracefully
- **Contingency:** Pivot to "we're the testbed for Bitcoin's upgrade"

### Legal Risks

**Risk:** SEC considers it a security
- **Mitigation:** Fair launch, no promises, pure decentralization
- **Contingency:** Legal defense fund from community

**Risk:** Exchange listing rejections
- **Mitigation:** Don't pursue listings early
- **Contingency:** Decentralized exchanges only initially

### Social Risks

**Risk:** Crypto community calls you a scammer
- **Mitigation:** Transparent development, no hype
- **Contingency:** Ignore critics, let work speak

**Risk:** No one cares / zero adoption
- **Mitigation:** Long-term view, quantum threat will materialize
- **Contingency:** Accept failure, publish research anyway

---

## Decision Checkpoints

### Month 6: Do you have working Dilithium signatures?
- **No** → Pivot or get help
- **Yes** → Continue

### Month 12: Does testnet work reliably?
- **No** → Fix or abandon
- **Yes** → Continue

### Month 18: Can you afford security audit?
- **No** → Reconsider timeline
- **Yes** → Proceed to audit

### Month 23: Has anyone shown interest?
- **No** → Seriously reconsider launch
- **Yes** → Proceed

### Month 30 (5 months post-launch): Are there 100+ nodes?
- **No** → Probably failed
- **Yes** → Keep going

---

## What Success Looks Like

### Year 1 Post-Launch
- 500+ full nodes
- 20+ mining pools
- 10,000+ addresses with balance
- Zero critical security issues
- Mentioned in quantum computing discussions

### Year 3 Post-Launch
- 5,000+ full nodes
- Active developer community (5-10 contributors)
- Listed on 2-3 exchanges (small ones)
- Price discovery happening
- Academic papers referencing your work

### Year 5 Post-Launch
- Quantum computers are real threat
- Bitcoin upgrade debate intensifies
- Your chain has security track record
- Seen as legitimate alternative
- Maybe one of the top 50 cryptocurrencies

### Year 10 Post-Launch

**Either:**
- Bitcoin upgraded, your chain is obsolete but you succeeded technically
- Bitcoin didn't upgrade, your chain gains real adoption
- Both coexist as quantum-resistant options

**Either way:** You've contributed to preparing crypto for quantum era.

---

## Start Immediately On

1. **Learning CRYSTALS-Dilithium specification** inside and out
2. **Setting up Bitcoin Core development environment**
3. **Building the proof-of-concept** (Months 1-3)

## Don't Get Distracted By

- Token economics design (just copy Bitcoin)
- Marketing strategy (none needed yet)
- Community building (too early)
- Exchange relationships (way too early)

## Find One Co-founder Who

- Knows C++ systems programming cold
- Has Bitcoin Core contribution history
- Shares your patient, principled approach
- Doesn't need money for 2+ years

## Document Everything

- Every decision
- Every commit
- Every conversation
- This builds trust

## Mental Preparation

- This will take 5+ years
- Most people will ignore you
- You might fail
- Do it anyway

---

## The Real Test

### In the next 30 days, can you:

- [ ] Set up Bitcoin Core development environment
- [ ] Compile Bitcoin Core from source
- [ ] Make a trivial modification and see it work
- [ ] Read and understand CRYSTALS-Dilithium spec
- [ ] Write 10 pages of technical design doc

**If yes:** You might actually pull this off.
**If no:** You need to learn more first or find technical co-founder.

---

## Final Words

The difference between you and 1,000 other people who've had this idea: you said "let's do this" after hearing all the reasons not to.

That's the right attitude.

Now go compile Bitcoin Core from source and report back when you've got a modified genesis block with "QUANTUM RESISTANT" in it.

No guts, no glory indeed.

---

**Next Steps:** See `implementation-roadmap.md` for detailed technical implementation plan.
