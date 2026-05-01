# Dilithion Scaling Analysis — 2026-04-30

**Status**: Strategic discussion document. No decisions ratified — input for future planning conversation with Cockatoo.
**Authors**: Will + Claude (analysis), prompted by Cockatoo's TPS estimates and scaling concerns.
**Trigger**: Cockatoo raised concerns about TPS limits and scaling under global adoption (DIL ~3 TPS, DilV ~16 TPS in his estimates) and proposed BLS signature aggregation + batch transaction processing.

---

## 1. Context and starting question

Cockatoo posted two tables in chat estimating TPS limits:
- DIL: ~3.0 TPS sustained, ~720 tx/block, ~6 KB avg tx, 240s blocks
- DilV: ~16.0 TPS sustained, ~720 tx/block, ~6 KB avg tx, 45s blocks
- Plus a "Critical Limits" table showing congestion thresholds, breakdown points, OOM points

Cockatoo's framing: "We won't be able to scale if the network will come under a lot of stress."

The conversation evolved through three benchmark goals:
1. Initial: 10,000 TPS DilV / 1,000 TPS DIL (global adoption scale)
2. Revised: match Bitcoin's TPS (~7 sustained, ~27 peak)
3. Final constraint: must avoid catastrophic chain bloat

---

## 2. Verified facts about current consensus

Verified directly against the codebase (initial Explore agents made errors I had to correct):

### Signature scheme: Dilithium-3
- `-DDILITHIUM_MODE=3` everywhere ([build.sh:10](../build.sh#L10), [Dockerfile:28](../Dockerfile#L28), all CI workflows)
- Signature size: **3,309 bytes**
- Pubkey size: 1,952 bytes
- (NOT Dilithium-2 / 2,420 B as one Explore agent fabricated)

### Block size limits — there's a real code smell to clean up
- `MAX_BLOCK_SIZE = 1,000,000` in [src/consensus/params.h:77](../src/consensus/params.h#L77) — labeled as byte limit
- BUT [src/consensus/validation.cpp:503](../src/consensus/validation.cpp#L503) checks it against `block.vtx.size()` which is the **transaction count**, not bytes. So the consensus check is effectively "no more than 1M txs per block" — basically unbounded.
- Actual byte enforcement: **4 MB** in mining ([src/node/dilithion-node.cpp:1321](../src/node/dilithion-node.cpp#L1321), [src/node/dilv-node.cpp:1314](../src/node/dilv-node.cpp#L1314)) and storage ([src/node/blockchain_storage.cpp:394](../src/node/blockchain_storage.cpp#L394))
- Chainparams sets `params.maxBlockSize = 4 * 1024 * 1024` for both DIL and DilV ([src/core/chainparams.cpp:47, 435](../src/core/chainparams.cpp))
- **Action item**: separate cleanup PR to fix the misleading `MAX_BLOCK_SIZE` constant — either delete it or rename to `MAX_BLOCK_TX_COUNT`

### Block times (confirmed)
- DIL: 240s ([src/core/chainparams.cpp:40](../src/core/chainparams.cpp#L40))
- DilV: 45s ([src/core/chainparams.cpp:428](../src/core/chainparams.cpp#L428))

### VDF on DilV
- Wesolowski VDF, 500K iterations (~4–8s wall clock) ([src/core/chainparams.cpp:488](../src/core/chainparams.cpp#L488))
- VDF compute time DOES NOT bottleneck the 45s block time
- The 45s is enforced by `vdfLotteryGracePeriod = 45` and `minBlockTimestampGap = 45` consensus rules
- DilV could theoretically have shorter block time without weakening VDF security — the constraint is consensus pacing, not VDF compute

### Mempool
- 300 MB cap ([src/node/mempool.cpp:11](../src/node/mempool.cpp#L11))
- 100,000 tx count cap ([src/node/mempool.h:74](../src/node/mempool.h#L74))
- 14-day expiry
- Fee-rate ordered eviction with descendant protection

### Witness/SegWit handling
- **Not present.** Flat byte counting. `block.GetSerializedSize()` = consensus block size.
- No `MAX_BLOCK_WEIGHT`, no `WITNESS_SCALE_FACTOR`, no `nWeight`
- `NODE_WITNESS` service flag exists but is unused
- `CTransaction` has no witness field

### Already-implemented infrastructure (good news)
- **Compact Blocks (BIP 152): fully implemented** in [src/net/blockencodings.h/cpp](../src/net/blockencodings.h). Foundation for safely raising block size if ever needed.
- **HTLCs: fully implemented** in [src/script/htlc.cpp](../src/script/htlc.cpp) — supports SHA3-256 hashing, Dilithium-3 sig/pubkey, both claim and refund paths
- **Atomic swaps: implemented** with cross-chain orchestration ([src/script/atomic_swap.h/cpp](../src/script/atomic_swap.h))
- **OP_CHECKLOCKTIMEVERIFY (CLTV)** and **OP_CHECKSEQUENCEVERIFY (CSV)**: both supported ([src/script/interpreter.cpp:481, 509](../src/script/interpreter.cpp))
- **Parallel signature verification: implemented** ([src/consensus/signature_batch_verifier.h/cpp](../src/consensus/signature_batch_verifier.h)) — 4–16 worker threads doing parallel single-verifies (NOT true Dilithium batch verification, which is a separate optimization)

### Not implemented (gaps)
- **Erlay (BIP 330)**: not present. Would save ~75% of tx relay bandwidth.
- **OP_CHECKMULTISIG**: stubbed at [src/script/interpreter.cpp:545](../src/script/interpreter.cpp#L545) — returns "not yet implemented" error. Needed for non-trivial L2 (Lightning channel funding txs require multisig).
- **MuSig / signature aggregation**: not present (and not feasible for Dilithium directly anyway)
- **Witness segregation**: not present
- **Payment channels / Lightning code**: zero references (HTLC scaffolding exists but no channel state machines)
- **Sidechain/peg infrastructure**: not present

---

## 3. TPS math — current parameters

Block size 4 MB, Dilithium-3 sigs at 3,309 B, typical tx ~3.76 KB (1-input/2-output: ~450 B base + 1 sig).

- 4 MB ÷ 3.76 KB ≈ **1,063 typical tx per block**
- DIL: 1,063 ÷ 240s ≈ **~4.4 TPS sustained**
- DilV: 1,063 ÷ 45s ≈ **~23.6 TPS sustained**

For 2-input txs (~7.2 KB): DIL ~2.4 TPS, DilV ~13 TPS — which matches Cockatoo's 3 / 16 estimate. His numbers are an honest worst-case for busier transactions.

Comparison: Bitcoin sustained throughput ~7 TPS post-SegWit, ~3–4 TPS pre-SegWit (2009–2017 era).

**Conclusion: DilV already exceeds Bitcoin throughput; DIL is at ~63% of modern Bitcoin / ~100% of pre-SegWit Bitcoin.** No L1 changes needed to "match Bitcoin." Capability is already there.

---

## 4. Chain bloat math — the actual constraint

This was the conversation's pivot point. TPS isn't really the problem; chain bloat is.

### Annual chain growth at full block utilization

- DIL at 4 MB / 240s: **~526 GB/year** worst case
- DilV at 4 MB / 45s: **~2.8 TB/year** worst case
- DIL at 8 MB: ~1 TB/year
- DilV at 8 MB: **~5.6 TB/year** — exceeds Bitcoin's 16-year history in ~6 weeks

### At Bitcoin-like 30–50% block fill (more realistic average)

- DIL: ~150–260 GB/year (comparable to Bitcoin's current ~150 GB/year)
- DilV: ~840 GB – 1.4 TB/year (still problematic)

### The DilV-specific issue

DilV is designed for fast payments / micropayments. But Dilithium-3 signatures are 3,309 bytes — **they don't shrink for small payments**. A 1-cent micropayment carries the same signature as a 1,000 DIL transfer.

**DilV's primary use case is the worst possible workload for L1 chain bloat.** Per-tx storage is ~15× higher than Bitcoin's typical ECDSA tx, and that's the unavoidable price of post-quantum security.

### Storage centralization risk

DilV growing at 1+ TB/year means archive nodes (full history) become rare and expensive. Maybe 5–10 entities can afford archives instead of Bitcoin's hundreds. Real long-term decentralization concern.

---

## 5. Options evaluated — pros and cons

### Option A: Raise block size to 8 MB
- **Pros**: doubles TPS to ~50 DilV / ~9 DIL; comfortably beats modern Bitcoin
- **Cons**: chain growth becomes catastrophic (DilV ~5.6 TB/year worst case); home-node operation becomes infeasible within 1–2 years; archive concentration accelerates
- **Verdict**: REJECT. Bitcoin parity TPS is already met without this.

### Option B: Lower block size to 1 MB on both chains (counterintuitive)
- **Pros**:
  - DilV chain growth drops to ~700 GB/year worst case (~210–350 GB at typical fill)
  - With witness segregation: pruning nodes grow at ~84 GB/year — below Bitcoin's current rate
  - Forces L2 architecture (no cheap L1 alternative drives channel adoption — same forcing function that made Lightning viable on Bitcoin post-2017)
  - Faster block propagation, lower orphan rate, mining decentralization wins
  - Faster IBD, more home nodes
  - Permanent commitment to home-node sustainability
  - Philosophically consistent: DIL = settlement, DilV = fast settlement, channels = payments rail
- **Cons**:
  - DilV at ~5.9 TPS sustained — below modern Bitcoin's ~7 TPS, just above pre-SegWit
  - DIL at ~1.1 TPS — well below Bitcoin's modern rate (but 86,400 tx/day is plenty for "digital gold" settlement use case)
  - Capacity wall during the L2-readiness window if user growth outpaces PQ-Lightning delivery (Bitcoin lived through this 2016–2018; survivable but painful)
  - Politically hard to ever raise later (Bitcoin's blocksize wars precedent)
  - "Unambitious" marketing optics — competitors will pitch 65k TPS Solana claims
- **Verdict**: STRONG CANDIDATE. Disciplined choice. Will and Claude both leaning this direction.

### Option C: Middle ground — 2 MB DilV / 1 MB DIL
- **Pros**: DilV ~12 TPS (exceeds Bitcoin sustained), more headroom during L2 build, ~170 GB/year pruned with witness segregation
- **Cons**: less disciplined commitment, more capacity tempts off-ramp from L2 priority
- **Verdict**: defensible compromise; less clean than Option B

### Option D: Switch from Dilithium-3 to FALCON-512
- **Pros**: ~5× signature compression (666 B vs 3,309 B); fits more txs per block
- **Cons**: weaker NIST security level (L1 vs L3); invalidates Hacken pre-audit work; FALCON has historic implementation pitfalls (floating-point in original); undercuts the entire post-quantum security thesis we've built the project on
- **Verdict**: REJECT. User explicitly hesitant to move away from Dilithium-3, and rightly so — it's our security benchmark.

### Option E: BLS signature aggregation (Cockatoo's suggestion #1)
- **Pros**: 75–85% signature compression; aggregating N sigs into one is the highest-impact base-layer lever in principle
- **Cons**: **BLS is NOT post-quantum secure.** Pairing-based, broken by Shor's algorithm same as ECDSA. Adopting BLS unwinds the Dilithium-3 thesis entirely. Would invalidate Hacken pre-audit and put us in the same long-term threat position as Bitcoin.
- **Verdict**: REJECT. Whitepaper roadmap section mentioning BLS needs to be reworded to "PQ-secure aggregation" specifically.

### Option F: PQ-secure signature aggregation
- **Status of research** (as of Apr 2026):
  - **Lattice half-aggregation** (Boneh-Kim 2020 generalized; Fleischhacker-Simkin-Zhang "Squirrel" 2022): ~30–50% compression, research-grade reference implementations only
  - **Boudgoust-Sakzad-Steinfeld (2023–2024) lineage**: ~50–70% compression, provable security under Module-LWE/SIS; most mature line of work
  - **LaBRADOR (Beullens-Seiler 2023) + Greyhound (2024)**: lattice-based ZK proofs that could prove "I have N valid Dilithium signatures" — research-stage
  - **STARK-based aggregation**: prove validity of N Dilithium sigs in one STARK proof; ~50–150 KB regardless of N; STARKs are PQ-secure (hash-based); building blocks (Cairo, Plonky3, RISC Zero) increasingly available; Dilithium verification circuits in STARKs are early-engineering-stage
  - **BLS-grade compression for PQ schemes**: not currently achievable by anyone
- **Pros**: real "world first" opportunity; significant chain bloat reduction when mature
- **Cons**: NO production-grade audited implementation exists; inventing our own would be project-killing risk (cryptographic schemes typically need 10–15 years of academic vetting before adoption — BLS 2001→2020, Dilithium 2017→2024); SIKE precedent (NIST finalist for 6 years, broken in an afternoon by Castryck-Decru 2022)
- **Verdict**: TRACK AND DEPLOY WHEN MATURE. Do NOT attempt to invent ourselves. If we're serious, the path is:
  1. Track research closely (designate someone to monitor IACR ePrint, CRYPTO/EUROCRYPT/ASIACRYPT)
  2. Engage academia (Boudgoust at Aarhus, Aranha at Aarhus, Lyubashevsky at IBM Zurich, StarkWare research, LaBRADOR authors). Frame: "deployment partner for mature schemes"
  3. Build infrastructure aggregation will plug into (witness segregation, versioned tx serialization, modular sig verification)
  4. If genuinely committing: hire a published lattice cryptographer (~$300K+/year) — Yannick Seurin, Damien Stehlé, or similar profile

### Option G: Multi-output transaction batching (Cockatoo's suggestion #2)
- **Mechanic**: one tx with many outputs paying many recipients. Existing script primitive.
- **Compression**: 100 separate payments = ~376 KB; 100 batched = ~7.2 KB. **~52× compression**
- **Pros**: no consensus changes needed; ships today via wallet UX; massive impact for exchanges, payment processors, mining pool payouts
- **Cons**: only helps when one entity signs for many recipients (one-to-many); doesn't help peer-to-peer payments
- **Verdict**: SHIP NOW. Add batched-send to wallet. Verify `sendmany`-style RPC exists. Document for exchanges/payment processors.

### Option H: Witness segregation (SegWit-equivalent)
- **Mechanic**: separate signature data from base transaction data; pruning nodes can drop signatures of buried blocks
- **Pros**: signatures are ~88% of every Dilithion tx (3,309 B sig / 3,760 B total), so witness pruning gives ~6.5× storage reduction for pruning nodes — far higher leverage than Bitcoin's SegWit gave (~30–40%)
- **Cons**: hard fork (Bitcoin pulled it off as a soft fork via clever script versioning, but that's a delicate maneuver); design complexity; sequencing risk
- **Verdict**: HIGHEST-PRIORITY CONSENSUS CHANGE. Single biggest lever for sustainable PQ chain.

### Option I: Pruning by default + assumeutxo bootstrap
- **Pros**: home nodes stay viable indefinitely; IBD goes from weeks to hours; Bitcoin Core has reference implementations
- **Cons**: archive nodes become opt-in community service rather than default
- **Verdict**: YES. Low controversy.

### Option J: PQ-Lightning (payment channels)
- **Pros**: moves micropayment volume off-chain (DilV's primary use case is the worst possible workload for L1 bloat); unbounded effective TPS; HTLC consensus foundations already exist
- **Cons**: 1–2 year build minimum; channel state machines, watchtowers, routing layer all need design; needs multisig (currently stubbed)
- **Verdict**: LOAD-BEARING ROADMAP ITEM. Not "if we ever need it" — DilV's design intent requires it for bloat sustainability.

### Option K: Erlay (BIP 330) tx relay
- **Pros**: ~75% reduction in tx relay bandwidth; supports the small-block plan
- **Cons**: not yet ported; minisketch dependency
- **Verdict**: YES. Post-Phase-6 Bitcoin Core port work.

### Option L: Shorten DilV block time below 45s
- VDF doesn't bottleneck (computes in 4–8s vs 45s block target)
- **Cons**: reducing block time worsens per-block bloat ratio; more headers to track during IBD; orphan rate concerns
- **Verdict**: NO. 45s is a reasonable balance.

---

## 6. Recommended course of action

In sequence, lowest risk to highest:

**Phase 1 — Ship now (wallet/UX):**
1. **Multi-output batched send** in wallet. Free 50× compression for exchanges and high-volume users. No consensus work.
2. **Verify `sendmany`-style RPC** exists; document for ecosystem.
3. **Cleanup PR**: fix the misleading `MAX_BLOCK_SIZE` constant in [src/consensus/params.h:77](../src/consensus/params.h#L77) and [src/consensus/validation.cpp:503](../src/consensus/validation.cpp#L503) — comment says bytes, code checks tx count.

**Phase 2 — Block size decision (consensus, hard fork):**
4. **Set DilV at 1 MB, DIL at 1 MB.** Permanent caps. (Or, if more conservative, DilV 2 MB / DIL 1 MB as middle option.) Coordinate hard-fork activation height with seed nodes.

**Phase 3 — Ongoing Bitcoin Core port work:**
5. **Port assumeutxo** for fast new-node bootstrap.
6. **Port Erlay (BIP 330)** for tx relay efficiency.
7. **Implement OP_CHECKMULTISIG** (currently stubbed) — prerequisite for L2.
8. **Port pruning defaults** so new installs prune by default.

**Phase 4 — Major consensus change:**
9. **Design and ship witness segregation.** Highest-leverage chain-bloat fix. DilV first, port to DIL after. Major release window.

**Phase 5 — L2 development:**
10. **Begin PQ-Lightning design.** Multi-year project. Design phase can start in parallel with Phase 4.

**Phase 6 — Research engagement:**
11. **Track PQ aggregation research.** Designate someone to monitor papers quarterly.
12. **Engage academic researchers.** Reach out to Boudgoust, Aranha, Lyubashevsky, StarkWare research team. Frame as deployment partner.
13. **If serious about leading PQ aggregation**: hire a published lattice cryptographer ($300K+/year), do NOT attempt to invent crypto in-house.

**Achievable "world firsts" without crypto invention:**
- First production PQ-Lightning deployment
- First witness-segregated PQ chain
- First chain to deploy mature lattice signature half-aggregation when audited
- First PQ chain with deployed multi-output batched payment standard

---

## 7. Open decisions / questions for Cockatoo

1. **Block size cap**: 1 MB or 2 MB on DilV? The 1 MB option is the disciplined choice, the 2 MB option is the safety hedge.
2. **DIL block size**: 1 MB (matches DilV philosophy) or stay at 4 MB (more flexibility)?
3. **Whitepaper rewording**: the BLS signature aggregation reference needs to be replaced with "PQ-secure aggregation, evaluated as schemes mature." Who edits and reviews?
4. **Cryptographer hire**: are we serious enough about leading PQ aggregation to commit $300K+/year for a published cryptographer? If not, Phase 6 is "track and engage" only.
5. **L2 timeline commitment**: PQ-Lightning is multi-year. Does the project commit to it now, or stay at "design phase" until block size constraints force it?

---

## 8. Hard-not-to-cross principles that emerged from this conversation

1. **Don't compromise Dilithium-3.** Switching to FALCON or BLS unwinds the entire project thesis.
2. **Don't invent new cryptography in-house.** Cryptographic schemes need decades of academic vetting before they're trustable. Engineering risk we accept; cryptographic risk we don't.
3. **Don't chase TPS at the cost of chain bloat.** DilV's micropayment use case + PQ signature size makes L1 throughput inherently bounded. The answer is L2, not bigger blocks.
4. **Plan for pruning, not archive, as the default node experience.** Archive nodes are a community service.
5. **L2 is not optional.** It's load-bearing for DilV's design intent to be sustainable at any meaningful adoption.

---

## 9. Reference: source files and constants cited

- [src/consensus/params.h:77](../src/consensus/params.h#L77) — misleading `MAX_BLOCK_SIZE = 1,000,000`
- [src/consensus/validation.cpp:498-504](../src/consensus/validation.cpp#L498) — checks tx count not bytes
- [src/core/chainparams.cpp:47](../src/core/chainparams.cpp#L47) — DIL `params.maxBlockSize = 4 MB`
- [src/core/chainparams.cpp:435](../src/core/chainparams.cpp#L435) — DilV `params.maxBlockSize = 4 MB`
- [src/core/chainparams.cpp:488](../src/core/chainparams.cpp#L488) — DilV VDF iterations 500K
- [src/core/chainparams.cpp:492](../src/core/chainparams.cpp#L492) — `vdfLotteryGracePeriod = 45`
- [src/core/chainparams.cpp:524](../src/core/chainparams.cpp#L524) — `minBlockTimestampGap = 45`
- [src/node/dilithion-node.cpp:1321](../src/node/dilithion-node.cpp#L1321) — actual mining 4 MB enforcement
- [src/node/dilv-node.cpp:1314](../src/node/dilv-node.cpp#L1314) — DilV mining 4 MB enforcement
- [src/node/blockchain_storage.cpp:394](../src/node/blockchain_storage.cpp#L394) — storage 4 MB enforcement
- [src/node/mempool.cpp:11](../src/node/mempool.cpp#L11) — 300 MB mempool cap
- [src/node/mempool.h:74](../src/node/mempool.h#L74) — 100K tx mempool cap
- [src/script/htlc.cpp](../src/script/htlc.cpp) — HTLC implementation (305 lines)
- [src/script/atomic_swap.h](../src/script/atomic_swap.h) — atomic swap state machine
- [src/script/interpreter.cpp:481](../src/script/interpreter.cpp#L481) — OP_CHECKLOCKTIMEVERIFY
- [src/script/interpreter.cpp:509](../src/script/interpreter.cpp#L509) — OP_CHECKSEQUENCEVERIFY
- [src/script/interpreter.cpp:545](../src/script/interpreter.cpp#L545) — OP_CHECKMULTISIG stubbed
- [src/net/blockencodings.h](../src/net/blockencodings.h) — BIP 152 Compact Blocks (full implementation)
- [src/consensus/signature_batch_verifier.h](../src/consensus/signature_batch_verifier.h) — parallel sig verify (4–16 workers)
- `build.sh:10`, `Dockerfile:28`, all CI workflows — `-DDILITHIUM_MODE=3`

---

## 10. Signature compression: what's possible, what isn't

Two distinct questions get conflated under "compress Dilithium signatures":

1. Can a *single* Dilithium-3 signature be made smaller? **No, not meaningfully.**
2. Can *multiple* Dilithium-3 signatures together be made smaller? **Yes, via PQ-secure aggregation, with bounded gains and significant maturity caveats.**

### A single signature, in isolation: no

A Dilithium-3 signature is `(c̃, z, h)`:
- `c̃` — 32-byte challenge hash; effectively a random SHAKE-256 output. **Incompressible.**
- `z` — vector of residues in `[-(γ₁-β), γ₁-β]`. Already bit-packed near-optimally per FIPS 204.
- `h` — sparse hint vector, encoded as positions of nonzeros (already a sparse encoding).

Generic compression (gzip, zstd) nets <2% — Dilithium signatures are high-entropy by design. Low entropy would leak information about the secret key.

Dangerous proposals to reject:
- **Truncate `z`** → verification equation fails. Breaks the scheme.
- **Reduce internal parameters** (smaller γ₁, smaller k/ℓ) → that's a new, unaudited variant. SIKE precedent applies — don't.
- **Drop hints, recompute on verify** → technically possible at 5–10× verification cost; not compression, just trading bandwidth for CPU.
- **"Switch to Dilithium-2" (2,420 B)** → that's a security *reduction* from NIST L3 to L1, not maintaining PQ resistance. Out of scope.

### Multiple signatures, aggregated: yes — with caveats

This is where real gains exist, and PQ-security is preserved if the right primitive is chosen:

| Approach | Per-sig amortized | PQ-secure? | Maturity (Apr 2026) |
|---|---|---|---|
| Lattice half-aggregation (Boneh-Kim 2020 generalized; Squirrel) | ~50–70% of original | Yes (Module-LWE/SIS) | Reference impls; not production-audited |
| Boudgoust-Sakzad-Steinfeld lineage (2023–24) | ~30–50% of original | Yes (lattice) | Most mature lattice line; not audited |
| LaBRADOR / Greyhound (lattice ZK proofs) | Approaches constant in N for large batches | Yes (lattice) | Research-stage |
| STARK proof of "N valid Dilithium sigs" | ~50–150 KB total, regardless of N | Yes (hash-based) | Engineering possible today; ~$500K–$2M effort |
| **BLS aggregation (Cockatoo's original suggestion)** | ~85% reduction per sig | **NO — pairings broken by Shor** | Production-grade for non-PQ chains |

The BLS row is why Cockatoo's BLS suggestion has to be rejected outright: the compression is real, but it unwinds the entire Dilithium-3 thesis. A PQ chain that aggregates with BLS is no longer a PQ chain.

### What this means for DilV specifically

1. **There is no encoding trick that delivers 50% off a single sig.** Anyone claiming one has either reduced security or invented unaudited crypto.
2. **Aggregation is the only legitimate path to per-sig compression**, and the production-grade options are:
   - Wait for lattice aggregation to mature + be audited (timeline uncertain; 3–7 years realistic)
   - Commit to STARK-proof-of-Dilithium-verification engineering ($500K–$2M, partnership with StarkWare / Risc Zero / Polygon Labs ZK)
3. **Non-cryptographic levers already identified in this doc** — witness segregation (88% of tx bytes are sigs, prunable from buried blocks), L2 channels (move volume off L1), STARK rollups (replace L1 sigs with one proof per N user txs) — give 5–100× chain-size wins **without touching the signature primitive**. Cheaper, lower risk, faster to deploy.

### Verdict

**Don't compress the signature. Either don't store it (witness pruning) or don't put it on L1 at all (channels, rollups).**

Aggregation research stays on the "track and engage" plan from Section 6, Phase 6. If/when a lattice aggregation scheme reaches the maturity bar (peer-reviewed + reference impl + audited library), it slots in as a soft-fork tx version upgrade. Until then, the question is answered.

---

## 11. Conversation provenance

- Initial Cockatoo Telegram messages: 30/04/2026 10:27 AM, 10:28 AM, 10:31 AM, 10:34 AM (TPS tables, scaling concern)
- Cockatoo follow-up: 30/04/2026 4:16 PM (BLS signature aggregation + batch tx processing)
- Will + Claude analysis session: 30/04/2026 (this document)
- Analysis included 3 parallel Explore agents to verify codebase facts; first explore made errors on Dilithium mode and file paths that were corrected

**Note on Explore agent errors**: in this session, the first Explore agent fabricated file paths (`src/dilithion/pqc/dilithium/api.h`) and got the Dilithium mode wrong (claimed mode 2, actually mode 3). Lesson reinforced: verify Explore agent claims before quoting, especially file:line references. This document's source references have all been verified by direct grep/read.
