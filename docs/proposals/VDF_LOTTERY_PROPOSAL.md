# Dilithion Improvement Proposal: VDF Fair Mining

**Status:** Implemented & Tested — Awaiting Community Activation Vote
**Author:** Will
**Date:** February 2026
**Version:** 3 (Updated to reflect current implementation)

---

## Summary

Replace Dilithion's current RandomX proof-of-work mining with a **VDF-based fair mining system**. This change would:

- Eliminate hashrate advantages (no more "biggest farm wins")
- Reduce energy consumption by ~95%
- Create truly fair block distribution
- Replace DFMP complexity with a single, elegant mechanism

**Implementation status:** Fully coded, 46 unit tests passing, testnet activation heights set. Ready for mainnet activation vote.

---

## The Problem

Current mining has fundamental issues:

1. **Hashrate = Power**: A miner with 10x more CPUs gets ~10x more blocks
2. **Energy Waste**: Miners race 24/7, burning electricity. Most hashes are thrown away.
3. **Concentration**: Mining rewards concentrate toward larger operations
4. **Complexity**: DFMP has evolved through v3.0 and v3.1 with multiple penalty systems trying to enforce fairness — free tiers, growth caps, payout heat, dormancy decay, maturity multipliers

No amount of penalty tuning fixes the core issue: **proof-of-work rewards those who burn the most electricity**.

---

## The Solution: VDF Fair Mining

### What is a VDF?

A **Verifiable Delay Function** is a computation that:
- Takes a fixed amount of time (~200 seconds on mainnet)
- Cannot be parallelized — 1 CPU or 1000 CPUs, same time
- Produces a provable result anyone can verify quickly (~milliseconds)

### How It Works

```
Every ~4 minutes (mainnet) / ~1 minute (testnet):
1. All miners compute ONE VDF tied to their address
2. The lowest VDF output wins the block
3. Winner sits out for N blocks (cooldown)
4. Repeat
```

### Why This is Fair

| Scenario | Current PoW | VDF Fair Mining |
|----------|-------------|-----------------|
| 1 miner, 1 CPU | 1 ticket | 1 ticket |
| 1 miner, 100 CPUs | 100 tickets | 1 ticket |
| 10 miners, 1 CPU each | 10 tickets total | 10 tickets total |

**Hashrate becomes irrelevant.** Each address gets exactly one ticket per round. More hardware doesn't help.

### The Cooldown

After winning a block, you're excluded from the next N blocks:

| Network Size | Cooldown | Max Share |
|--------------|----------|-----------|
| 10 miners | 10 blocks | 10% |
| 50 miners | 50 blocks | 2% |
| 100+ miners | 100 blocks | 1% |

Parameters: `MIN_COOLDOWN = 10`, `MAX_COOLDOWN = 100`, `ACTIVE_WINDOW = 360 blocks`

The cooldown scales automatically with the number of active miners observed in the last 360 blocks. This **single mechanism** replaces all of DFMP's penalty systems.

---

## Sybil Resistance: Digital DNA

The main attack vector is address multiplication — creating many addresses to get many tickets. Dilithion addresses this with **Digital DNA**, an anonymous, physics-based identity system that makes Sybil attacks detectable without requiring KYC or trusted hardware.

### What is Digital DNA?

Every miner builds an unforgeable identity fingerprint from **8 independent dimensions**:

| Dimension | What It Measures | Why It's Unique |
|-----------|-----------------|-----------------|
| **L** - Latency Fingerprint | Round-trip time to seed nodes | Speed of light — location determines latency |
| **V** - VDF Timing Signature | Computation speed profile | CPU/silicon differences are measurable |
| **P** - Perspective Proof | Which peers you see and when | Network position is unique |
| **M** - Memory Fingerprint | Cache hierarchy timing | L1/L2/L3 cache sizes vary by hardware |
| **D** - Clock Drift | Crystal oscillator frequency | Every clock drifts differently |
| **B** - Bandwidth Proof | Upload/download throughput | Connection capacity varies |
| **T** - Thermal Profile | Cooling curve from VDF checkpoints | Thermal behavior is hardware-specific |
| **BP** - Behavioral Profile | Protocol participation patterns | Activity timing is unique |

### How Sybil Detection Works

When a new identity registers, it's compared against all existing identities across all available dimensions:

- **Combined score ≥ 0.92** → Auto-reject (same identity)
- **Combined score ≥ 0.55** → Trigger challenge verification
- **Memory + Clock Drift both ≥ 0.95** → Physics hard rule auto-reject (probability of two distinct machines matching both is vanishingly small)

Scoring uses equal-weight averaging across all available dimensions, with correlation-aware damping for the V/M/T hardware cluster (these dimensions tend to correlate on the same machine, so their combined signal is dampened to prevent triple-counting).

### ML Anomaly Detection (Future Enhancement)

An Isolation Forest ML model is implemented and runs in **ADVISORY** mode — it logs anomalies but doesn't auto-reject. It uses 13 features per identity pair and will be promoted to **SUPPLEMENTARY** mode (actively flagging alongside threshold detection) once these prerequisites are met:

- 5,000+ scored pairs
- 1,000+ full-dimension pairs
- 300+ challenge-resolved outcomes
- False positive rate < 1%
- 3+ hardware clusters and 3+ geographic regions observed

This data-driven approach ensures ML only influences decisions after proving itself reliable on real network data.

### The Economics of a Sybil Attack

With Digital DNA + cooldown, an attacker trying to capture 50% of blocks would need:

| Requirement | Why |
|------------|-----|
| 60+ addresses | 100-block cooldown limits each to ~3 blocks per 360-block window |
| 60+ distinct machines | Digital DNA detects same-hardware identities |
| 60+ distinct locations | Latency fingerprint detects co-located machines |
| Sustained commitment | Not burst-rentable — identities build over time |

Compare to current PoW: rent hashrate for an hour, dominate, leave. VDF + Digital DNA requires **ongoing, geographically distributed, unique hardware** — a fundamentally different cost structure.

---

## VDF Security

### Why chiavdf?

We use [chiavdf](https://github.com/Chia-Network/chiavdf), the same VDF library powering Chia Network since 2021.

**Class groups of unknown order** were chosen because:
- No known ASIC/FPGA acceleration exists
- Harder to optimize than RSA or elliptic curves
- Believed to be post-quantum resistant
- Battle-tested in production for 4+ years

### Hardware Acceleration Risk

**Worst case:** Someone builds a 2-5x faster VDF implementation.

This doesn't break the system — faster computation doesn't guarantee a lower output (it's deterministic, not a race). It just lets that entity run more addresses, which brings us back to Sybil costs (and Digital DNA catches same-hardware identities).

**Mitigation:** VDF iteration count is a consensus parameter. If acceleration emerges, we increase iterations to maintain target duration.

### Long-term Resilience

- Monitor academic VDF research (active area with Ethereum Foundation, Chia funding)
- Class group security is well-studied
- Upgrade path exists if new constructions prove stronger

---

## Benefits

### For Small Miners
- Your single CPU has the same chance as someone with 100 CPUs
- No need to race or optimize — just compute your VDF and wait
- Predictable: if you're not in cooldown, you have a fair shot

### For the Network
- **95% less energy** — no more hash racing
- **Simpler fairness** — cooldown replaces DFMP's 6+ penalty systems
- **Truly decentralized** — no hashrate advantage to accumulate

### For the Environment
- Current: 50 miners × 100% CPU × 24/7 = constant burning
- VDF: 50 miners × 1 thread × 200 seconds per round = minimal usage

---

## Technical Details

### Block Changes

VDF blocks use **block version 4** with a 144-byte header (vs 80-byte legacy):

| Field | Size | Description |
|-------|------|-------------|
| Legacy header | 80 bytes | version, prevHash, merkleRoot, timestamp, nBits, nonce |
| `vdfOutput` | 32 bytes | The VDF computation result |
| `vdfProofHash` | 32 bytes | SHA3-256 commitment to the full proof |

Full Wesolowski VDF proof is stored in the coinbase transaction's OP_RETURN output (~100 bytes). This keeps the header compact while allowing full proof verification.

VDF block hashing uses **SHA3-256 of the full 144-byte header** (no RandomX computation needed).

### Challenge Derivation

Each round's challenge is deterministic and unpredictable:
```
challenge = SHA3-256(previous_block_hash || height_le32 || miner_address)
```

This prevents grinding — you can't influence your VDF output without changing the previous block. The miner address is included to ensure each miner gets a unique challenge.

### Identity

Your mining identity is your **coinbase address**. No separate identity registration needed — Digital DNA fingerprints are built passively from your node's network behavior.

### Parameters

| Parameter | Mainnet | Testnet |
|-----------|---------|---------|
| VDF iterations | 200,000,000 (~200s) | 10,000,000 (~10s) |
| Block time target | 240 seconds | 60 seconds |
| Cooldown min | 10 blocks | 10 blocks |
| Cooldown max | 100 blocks | 100 blocks |
| Active window | 360 blocks | 360 blocks |
| Block version | 4 | 4 |
| Header size | 144 bytes | 144 bytes |

---

## Migration Plan

### Phase 1: Hybrid Period (VDF + RandomX)

At a designated activation height, **both VDF and RandomX blocks are accepted**. Miners can upgrade at their own pace. If VDF has issues, RandomX still works as a safety net.

- Testnet hybrid activation: **block 86,850**
- Mainnet hybrid activation: **TBD (pending community vote)**

### Phase 2: VDF-Only

At a second activation height, **only VDF blocks are accepted**. RandomX mining is disabled. DFMP code becomes inactive.

- Testnet VDF-only: **block 87,500** (650 blocks after hybrid = ~11 hours at 60s blocks)
- Mainnet VDF-only: **TBD (pending community vote)**

### Migration Safety

- Long hybrid period gives miners time to upgrade
- RandomX acts as fallback during hybrid period
- Clear upgrade instructions will be published before each activation
- Testnet activation proves the full migration path before mainnet

---

## Implementation Status

| Component | Status | Tests |
|-----------|--------|-------|
| chiavdf integration | Complete | Submodule in `depends/chiavdf/` |
| VDF compute & verify | Complete | Validated at 200M iterations |
| Cooldown tracker | Complete | 11 unit tests |
| Block header extension (144-byte) | Complete | 18 unit tests |
| Consensus validation | Complete | 8 unit tests |
| VDF miner | Complete | 9 unit tests |
| Node integration | Complete | VDF/RandomX switching wired up |
| Digital DNA (8 dimensions) | Complete | Scoring, thresholds, physics rule |
| ML anomaly detector | Complete | Advisory mode, readiness tracking |
| **Total** | **Ready** | **46 VDF tests passing** |

### chiavdf Windows Compatibility

Fixed three critical bugs in chiavdf for Windows/MinGW64 + GMP 6.3.0:
- 64-bit signed overflow in Lehmer inner loop (`mpz_xgcd_partial`)
- Heap corruption in `bqfc_compr` (bounds checks)
- Hot-path callers replaced with reference implementations

These fixes ensure VDF computation is correct across all platforms.

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Address multiplication (Sybil) | Digital DNA 8-dimension fingerprinting + ML anomaly detection |
| VDF hardware acceleration | Class groups resist optimization; iteration count adjustable |
| Clock synchronization | Epoch-based challenges with tolerance window |
| Low initial participation | Adaptive cooldown scales with miner count (min 10 blocks) |
| Migration confusion | Long hybrid period, testnet proves path first |
| Digital DNA false positives | Conservative thresholds (0.92/0.55), ML starts advisory-only |

---

## What This Means for Current Miners

- **Your hardware still works** — VDF runs on standard CPUs
- **No advantage from more CPUs** — one thread per identity is all you need
- **Simpler setup** — just set your address and mine
- **Fair participation** — equal opportunity, not hashrate wars
- **Lower costs** — no need to run CPUs at 100% constantly
- **Privacy preserved** — Digital DNA is anonymous, no KYC required

---

## Questions for Discussion

1. **Is this direction right?** Should Dilithion move from PoW to VDF fair mining?

2. **Mainnet activation timing?** When should we schedule the hybrid activation height?

3. **Hybrid period length?** How long should VDF + RandomX coexist before VDF-only?

4. **Cooldown parameters?** Is 10-100 blocks the right range?

5. **VDF duration?** 200 seconds per round on mainnet. Too long? Too short?

6. **Concerns?** What attack vectors or issues are we missing?

---

## Next Steps

1. **Gather feedback** from community on this proposal
2. **Activate on testnet** for live validation (heights already set: 86,850 / 87,500)
3. **Set mainnet activation heights** based on community consensus
4. **Deploy mainnet** with hybrid period

---

## References

- [chiavdf GitHub](https://github.com/Chia-Network/chiavdf)
- [Chia VDF Documentation](https://docs.chia.net/chia-blockchain/consensus/proof-of-time/)
- [VDF Research](https://vdfresearch.org/)
- [Stanford VDF Survey](https://crypto.stanford.edu/~dabo/pubs/papers/VDFsurvey.pdf)

---

**Feedback welcome!** This is a foundational change and we want to get it right. The code is ready — we're waiting on community consensus to set mainnet activation heights.
