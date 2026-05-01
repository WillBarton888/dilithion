# Competitor Analysis — Soqucoin (SOQ)

**Status**: Investigation snapshot. Companion document to [SCALING-ANALYSIS-2026-04-30.md](SCALING-ANALYSIS-2026-04-30.md).
**Authors**: Will + Claude (4 parallel investigation agents covering PAT cryptography, LatticeFold+/Lattice-BP++ trust model, system/audit posture, and academic/peer-review backing).
**Trigger**: Will surfaced soqucoin.org during scaling discussion; project advertises PAT as a 100-byte constant-size proof for Dilithium aggregation, which would directly affect our Section 6 / Phase 6 plan if accurate.
**Investigation method**: 4 parallel general-purpose agents, each reading the public Soqucoin repo via `gh api` / raw GitHub URLs and reporting source-cited findings. Cross-validated against academic literature search (IACR ePrint, CRYPTO/EUROCRYPT/CCS).

---

## 0. One-line verdict

A solo-developed Dogecoin Core fork that ships marketing-driven cryptographic naming (PAT, LatticeFold+, Lattice-BP++) over an in-house Merkle commitment scheme, an off-chain "trusted pools" prover for a published folding scheme that doesn't aggregate signatures in its paper, and a never-activated patent-pending range-proof construction. The Dilithium signatures themselves are real and reference-implementation-clean. Almost nothing else is what it appears to be.

---

## 1. Repository facts

- **Repo**: https://github.com/soqucoin/soqucoin
- **License**: MIT
- **Created**: 2025-11-18 (Nov 2025)
- **Recent push**: 2026-04-28 (active)
- **Size**: ~184 MB; primary language C++ (Bitcoin/Dogecoin Core lineage, libbitcoinconsensus present)
- **Engagement**: 5 stars, 2 forks, 5 watchers, 0 issues, 0 PRs, discussions disabled
- **Mainnet**: Q2 2026 (announced; pre-genesis at time of this writing)
- **Sites**: https://soqu.org (main), https://soqucoin.org (Foundation), https://soqucoin.com (Soqucoin Labs Inc) — all Cloudflare-blocked from automated fetchers but reachable in browser

---

## 2. PAT (Practical Aggregation Technique) — what it actually is

**PAT is not a signature aggregation scheme. It is a SHA3-256 Merkle commitment over `(sig_hash, pk_hash, msg)` tuples.**

### Direct quotes from the source

`src/crypto/pat/logarithmic.h:95-99`:
> "This implementation uses 32-byte commitments (hashes) rather than full signatures. Actual Dilithium signature verification happens off-chain before proof creation. **The proof only commits to signatures; it doesn't verify them cryptographically.**"

`doc/specifications/pat-specification.md:248`:
> "**No Actual Signature Verification**: PAT only commits to signatures, doesn't verify them."

### The 100-byte "proof" decomposed (logarithmic.cpp:175-186)

| Bytes | Field |
|------:|---|
| 32 | Merkle root (SHA3-256 over leaves) |
| 32 | `pk_agg` = SHA3-256 of concatenated 32-byte pubkey *hashes* (not the 1.3 KB pubkeys themselves) |
| 32 | `msg_root` = SHA3-256 over concatenated 32-byte message digests |
| 4 | count (LE) |

There is no inclusion path inside the 100 bytes. There can't be — for n=1024 a Merkle path alone is 320 B.

### The "25,600× compression" headline is a presentation artifact

On-chain consensus (`src/script/interpreter.cpp:166`, `OP_CHECKPATAGG`) requires `4 + 3·n` stack items. The entire 96·n-byte witness must be supplied to the script for full-mode verification. Soqucoin's own spec performance table (lines 222-228) admits **~26× compression at n=1024** once witness is included, vs the marketed 25,600× "proof-only" comparison. And the 32-byte "sig" in the witness is itself a *hash* of the actual Dilithium signature, which lives off-chain entirely — nothing on-chain ever sees a real Dilithium signature.

### Halborn fixed two consensus-critical breaks shipped in the original design

- **FIND-002**: original `ReconstructMerkleRoot` "verified only leaf 0 via a sibling path, allowing an attacker to forge leaves 1..n-1." Patched by removing the sibling path and forcing full-tree rebuild on-chain.
- **FIND-007**: original pubkey aggregation was XOR — Wagner's-algorithm vulnerable to rogue-key substitution. Replaced with SHA3 hash.
- **FIND-006**: simple-mode verification (the path benchmarked at <4 µs) was removed from consensus; only full mode now runs. The README's "<4 µs verify" benchmark still measures simple mode, which is now a memcmp wrapper that doesn't run in production.

That an in-house "novel aggregation" scheme shipped with both a forgery bypass and a rogue-key vulnerability is itself a strong signal about design rigor.

### Academic basis: none

No IACR ePrint paper. No CRYPTO/EUROCRYPT/CCS presentation. No citation to Boneh-Kim half-aggregation, Squirrel (Fleischhacker-Simkin-Zhang 2022), Boudgoust-Takahashi (ePrint 2023/159), or Chipmunk. The only reference is "Soqucoin Whitepaper §4.2." It is in-house.

---

## 3. LatticeFold+ — real paper, wrong application, no prover

**The paper is real**: Boneh-Chen, IACR ePrint 2025/247, CRYPTO 2025. Soqucoin's verifier (`src/crypto/latticefold/verifier.cpp:1`) cites it correctly.

**But LatticeFold+ is a folding scheme for IVC/SNARKs over lattice commitments — not a Dilithium signature aggregation scheme.** The paper does not propose Dilithium aggregation. There is no public statement from Boneh or Chen endorsing or being involved with Soqucoin. Using the name to describe Dilithium batch verification is a marketing extension, not a published result.

### No prover exists in the repo

- `src/crypto/latticefold/` contains exactly two files: `verifier.cpp` and `verifier.h`. No `prover.*`. No `prove()` function.
- `src/rpc/batch.cpp` `createbatchtransaction`: literally `batch_proof.resize(1380); // 1.38 kB` — a zero-filled placeholder with comment `"Off-chain prover assumed (e.g. via latticefold-prover CLI tool we ship)"`. **No such CLI exists in the repo.**
- README "Prover Implementation Status" table line 117-124: **"LatticeFold+ Prover | Off-chain (trusted pools) | ✅ Operational"** — versus PAT/Lattice-BP++ which give file paths. The "trusted pools" wording is theirs.

### Activation status

`src/chainparams.cpp:148-152` — `DEPLOYMENT_LATTICEFOLD = ALWAYS_ACTIVE, NO_TIMEOUT` from genesis. They activated a verifier in consensus from genesis with no working trustless prover. **Operationally that's a federation**: only "trusted pools" can produce proofs the chain accepts.

---

## 4. Lattice-BP++ — in-house, never-activated, patent-pending

- `range_proof.cpp:5-7`: **"LNP22-inspired polynomial product range proof / Patent: Soqucoin Labs Inc. — Provisional Application (Lattice-BP Hybrid)"**. "LNP22" is uncited; presumably Lyubashevsky-Nguyen-Plançon 2022 but unverified. No reference to Eagen-Kanjalkar-Ruffing's actual Bulletproofs++ paper (ePrint 2022/510).
- The naming is misleading: real BP++ is elliptic-curve based and not quantum-safe, so "Lattice-BP++" reuses an audience-friendly name without porting the construction.
- **The legacy `LatticeRangeProof` class is a stub** that memcpys the cleartext value into the proof (`commitment.cpp:540-541` TODO comment, `range_proof.cpp:~180`).
- The V2 implementation uses an `r_0`-correction trick (`range_proof.cpp:~180-195`) that makes reconstruction trivially correct *by construction*. The "binary constraint" `b_i ∈ {0,1}` is enforced via comment-level Schwartz-Zippel hand-waving, not an explicit polynomial product check. Soundness is unclear without an academic paper.
- Test HKDF is explicitly marked `"NOT cryptographically secure - replace with real HKDF"` (`test_latticebp.cpp:24-38`).
- **Activation**: `src/chainparams.cpp:157-159` — `nStartTime = 0, nTimeout = 0` (never activates) on mainnet. Even Soqucoin doesn't trust it yet.
- **Halborn audit**: explicitly out of scope.
- **Patent**: provisional only — a 12-month placeholder with no published claims to assess. "Patent pending" can't be verified in USPTO/Google Patents searches.

---

## 5. The chain itself is barely customized Dogecoin

- `src/chainparams.cpp` mainnet genesis still has Dogecoin's literal `pszTimestamp = "Nintondo"` and `nTime = 1386325540` (December 2013). Comment: `// TODO: Re-mine mainnet genesis with new nonce after CTxOut format change`. **The mainnet chain as configured cannot be mined today.**
- `BIP34Height = 1,034,383`, `BIP65Height = 3,464,751` (Dogecoin's millions, not adjusted for SOQ's chain).
- `vSeeds` still pointing to `seed.multidoge.org`.
- 23-entry Dogecoin checkpoint table (height 0…5,050,000) still present.
- Mainnet P2P port: `chainparams.cpp` says 33388, `RELEASE_NOTES_v1.0.0-rc1.md` says 44556 (testnet's port).
- Genesis output script: same hardcoded P2PKH key reused across mainnet, testnet, and stagenet.
- **Address scheme contradicts itself across three documents**: README says SHA-256, `ADDRESS_FORMAT_SPEC.md` says BLAKE2b-160 (80-bit collision — surprisingly weak for a "production" PQ chain), RC1 release notes say "SHA3-256 + Bech32m". Three sources, three answers.

The crypto changes (PAT/LatticeFold+/Lattice-BP++ opcodes, witness versions v2/v3/v4) are real edits to the script interpreter. Almost everything else — chainparams, P2P, tx format, mempool — is unmodified Dogecoin Core.

---

## 6. Halborn audit — real, but narrower than it looks

- **Real and public**: https://www.halborn.com/audits/soqucoin/soqucoin-blockchain-node-a4f1f7
- **22 days, single security engineer**, Feb 17 – Mar 24, 2026
- **30 findings**: 3 Critical / 1 High / 3 Medium / 3 Low / 20 Informational, all reported remediated
- **All three Criticals were in PAT**, including the forgery bypass and a Merkle padding bug enabling chain split
- **The audit was implementation-centric** — memory safety, key lifecycle, RPC validation. **Halborn did not formally verify PAT's soundness.**
- **LatticeFold+ and Lattice-BP++ were both out of scope.**
- **Network/P2P explicitly out of scope** per `doc/AUDIT_PREPARATION_SUMMARY.md` ("inherited Dogecoin Core"). Their own threat model document covers wallet only — no eclipse, Sybil, IBD DoS analysis.

A second-pass "Extension Audit" (SOQ-A001…A006) found **four critical-severity field-arithmetic bugs in their own `src/crypto/binius64/field.cpp` — including a reducible trinomial allowing zero divisors** (file completely rewritten). That class of finding in a self-implemented field-arithmetic library is alarming, even when remediated.

The README claim "audit complete, 30 findings remediated" is technically true but lets the reader infer more coverage than was actually performed. The novel cryptographic constructions were not design-reviewed.

---

## 7. Engineering and team signals

- **Single human committer**: `Odenrider` (54157783+odenrider, ~371 SOQ-era commits over 5.5 months). Self-identifies as "Founder Soqucoin Labs, Principal Architect." `@odenridercasey` on X. No real name publicly disclosed; SECURITY.md names "Casey Wilson, Soqucoin Founder" but no public crypto/academic profile and no published cryptographer is named anywhere on the project.
- The remaining "contributors" (laanwj, sipa, gavinandresen, patricklodder) are inherited Bitcoin Core / Dogecoin Core authors from the fork lineage with no involvement in Soqucoin.
- **CODEOWNERS**: `@odenrider` owns *everything* including consensus and crypto. No second-reviewer enforced.
- `.gemini/` and `.agent/` directories present — heavy LLM-assisted development.
- **5 stars / 2 forks / 5 watchers / 0 issues / 0 PRs / discussions advertised but disabled** for a "production cryptocurrency" 5 months from announced mainnet.
- **CI is weak**: 4 build matrices (Linux x64/ARM64, macOS ARM64, Windows mingw cross). No ASan/UBSan/MSan, no fuzz CI run, no `-Werror`, "Lint" job literally echoes `Lint passed`. CodeQL weekly. No reproducible-build (gitian/guix) workflow despite docs referencing gitian.
- A 569 KB compiled fuzz binary (`pqwallet_fuzz`) is checked into `src/test/fuzz/`.
- **rc1 → rc2 in 2 days** fixed a SEGFAULT under ASIC load and re-enabled `IsInitialBlockDownload()` in `getblocktemplate` after it had been disabled "for testing." rc1 also shipped with `SOQ-P001`: "PAT opcodes not yet wired into VerifyScript()" — i.e., the audited consensus code wasn't called by the consensus path at release.
- **SECURITY.md is unprofessional** for a production chain: disclosure via Twitter DM to `@memecoin_doctor`, bounty paid from "block 100,001 reward."
- 0 issues/PRs and discussions disabled = essentially no public peer review or community engagement.

### Cryptographic talent signal — mixed

**Strong**: NIST reference Dilithium used unmodified, fuzz harnesses for crypto primitives, real-shaped Halborn findings (rogue-key XOR→SHA3, deterministic nonce, constant-time HMAC).

**Weak/concerning**: own field-arithmetic implementation had four critical bugs; address-hash function disagreed across three docs; no named cryptographer on the project; sole anonymous committer; SECURITY.md disclosure via memecoin Twitter DM. Reads like a competent solo developer with audit-driven LLM assistance, not a team with in-house cryptographic research.

---

## 8. What Dilithion can learn

### Worth borrowing

1. **`Halborn FIND-XXX` inline comment style** anchoring remediations to traceable IDs in security-critical code paths. Useful for our own audit prep.
2. **Per-primitive fuzz harnesses** (`dilithium_verify.cpp`, etc.) — small, focused, easy to maintain.
3. **Three-network model** (mainnet / testnet / stagenet) with `ALWAYS_ACTIVE` differentials for staged feature integration testing pre-audit.
4. **Witness-version opcode upgrades** (v2 PAT, v3 LatticeFold+, v4 Lattice-BP++) is a clean upgrade path pattern.

### Anti-patterns to explicitly avoid (their flags = our discipline)

1. **Single CODEOWNER on consensus.** Enforce a second reviewer on consensus before mainnet, durably.
2. **Marketing-driven cryptographic naming.** If we adopt aggregation, name it after the published primitive, not a coined term.
3. **Activating crypto in consensus before the paper is published.** Don't ship a verifier in `ALWAYS_ACTIVE` consensus when the prover lives off-chain in trusted pools — that's a federation.
4. **Inheriting fork chainparams without scrubbing.** Soqucoin still has Dogecoin's BIP heights, DNS seeds, checkpoints, and `"Nintondo"` genesis message. Our chainparams pass must be clean.
5. **Out-of-scope networking in audits.** Bitcoin Core port specifically addresses this — we're already differentiated. Keep P2P in scope when we get our consensus audit.
6. **Audit-finding-shaped feature gates** (`SOQ-P001` shipping rc1 with audited opcodes unwired). If a finding shows a feature isn't fully integrated, don't ship the release.
7. **Self-implemented field arithmetic.** If we ever need binius/lattice primitives, port from a reviewed library; don't write our own.
8. **Address scheme inconsistency** across README/spec/release notes. Document the canonical scheme once, link from all others.
9. **Trusted off-chain provers in consensus.** We made this point in our own scaling analysis (Section 10); Soqucoin is a live example of why.
10. **Activation immediately at genesis for unvetted novel cryptography.** Activate via versioned soft fork after the construction is published and audited.

---

## 9. Strategic positioning vs Soqucoin

- We chose **Dilithium-3 (NIST L3, 3,309 B sig)**; they chose Dilithium-2 (L2, 2,420 B). Their existence as a "smaller-sig PQ chain" validates our conservative choice in the whitepaper.
- Our **Bitcoin Core port** (Phase 6 PeerManager work on `port/bitcoin-core-peer-ibd`) explicitly modernizes P2P/networking; their Dogecoin fork inherits unmaintained P2P. This is a real, defensible technical differentiator for whitepaper messaging.
- We have **multiple reviewers, named contributors, plus Cursor as second-opinion partner**. Their CODEOWNERS lists one anonymous person.
- Our scaling-analysis Section 10 verdict ("don't compress the signature; either don't store it or don't put it on L1") is now empirically supported: the closest live attempt at PQ aggregation is a Merkle commitment that doesn't actually aggregate, with a forgery bypass in its first audited version.

### What does NOT change in our roadmap

- **PAT does not move our Phase 6 plan.** It is not the "track and engage" lattice aggregation we said we'd watch for. Real candidates remain Boneh-Kim half-aggregation, Squirrel (Fleischhacker-Simkin-Zhang 2022), Boudgoust-Takahashi (ePrint 2023/159), and Chipmunk. None are referenced by Soqucoin.
- **LatticeFold+ (the paper) remains worth tracking** as a folding-scheme primitive for our potential rollup track (the layered-architecture sketch from the 2,500-TPS conversation). The Soqucoin implementation is not a useful reference; the underlying paper is.
- **Lattice-BP++ is dismissable** — provisional patent + unpublished construction + Soqucoin's own non-activation = nothing actionable.

---

## 10. Open follow-ups

1. **Q3 2026 follow-up check** (after Soqucoin's announced Q2 mainnet): did genesis ship? Did the trusted-pools LatticeFold+ launch? Did any peer-reviewed paper appear for PAT? Did Lattice-BP++ activate? Real outcomes will validate or update this analysis. Suggest scheduling via `/schedule`.
2. **Whitepaper rewording** in our Section 7 open question: when we replace the BLS reference with "PQ-secure aggregation, evaluated as schemes mature," include a footnote that explicitly distinguishes our approach from PAT-style Merkle commitments labeled as aggregation.
3. **If we ever find a real lattice aggregation candidate ready to deploy**, use Soqucoin's deployment as a cautionary template: don't activate before the paper is published, don't activate before a cryptographic-design audit (not just implementation audit), and never let the prover live off-chain.

---

## 11. Sources

- [Soqucoin GitHub repository](https://github.com/soqucoin/soqucoin)
- [Halborn — Soqucoin Blockchain Node Audit](https://www.halborn.com/audits/soqucoin/soqucoin-blockchain-node-a4f1f7)
- [LatticeFold+ paper (Boneh-Chen, ePrint 2025/247)](https://eprint.iacr.org/2025/247)
- [LatticeFold paper (Boneh-Chen, ePrint 2024/257)](https://eprint.iacr.org/2024/257)
- [Bulletproofs++ paper (Eagen-Kanjalkar-Ruffing, ePrint 2022/510)](https://eprint.iacr.org/2022/510)
- [LNP22 (Lyubashevsky-Nguyen-Plançon, ePrint 2022/284)](https://eprint.iacr.org/2022/284)
- [Squirrel: Synchronized Multi-Signatures from Lattices (ePrint 2022/694)](https://eprint.iacr.org/2022/694)
- [Sequential Half-Aggregation of Lattice-Based Signatures (Boudgoust-Takahashi, ePrint 2023/159)](https://eprint.iacr.org/2023/159)
- [Soqucoin website](https://soqu.org/) (Cloudflare-blocked from automated fetchers)
- [Soqucoin Foundation](https://soqucoin.org/)
- [Soqucoin Labs](https://soqucoin.com/)
- [Soqucoin whitepaper PDF](https://soqu.org/whitepaper/soqucoin_whitepaper.pdf) (Cloudflare-blocked)
- [Soqucoin Labs Inc — federal vendor record](https://govtribe.com/vendors/soqucoin-labs-inc-dot-19wh7)

---

## 12. Source-citation provenance

Every numeric or quoted claim in this document traces to one of:
- Direct quote from a file in `github.com/soqucoin/soqucoin@main` (line numbers cited)
- A linked academic paper (IACR ePrint reference)
- The Halborn public audit report (linked above)
- The Soqucoin README, RELEASE_NOTES, CHANGELOG, or `doc/specifications/*.md` (cited by name)

No claim in this document derives from speculation or from a Soqucoin marketing statement that was not corroborated against source code or audit deliverable. Where the four investigation agents found an unverifiable claim, we flagged it explicitly (e.g., the patent, the "trusted pools" wording, the inaccessible whitepaper PDF).
