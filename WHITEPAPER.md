# Dilithion: A Post-Quantum Cryptocurrency

**Version 3.0**
**February 2026**

**Launch Date:** January 28, 2026

---

## Abstract

Dilithion is a decentralized cryptocurrency designed from the ground up for the post-quantum era. As quantum computers advance toward breaking classical cryptographic systems like ECDSA and RSA, the need for quantum-resistant blockchain technology becomes critical. Dilithion addresses this threat by implementing CRYSTALS-Dilithium, a NIST-standardized post-quantum digital signature scheme, combined with RandomX proof-of-work for ASIC-resistant CPU mining.

This whitepaper presents Dilithion's technical architecture, consensus parameters optimized for large post-quantum signatures, economic model, and roadmap for sustainable decentralized currency in the quantum age.

**Key Features:**
- **Post-quantum security:** CRYSTALS-Dilithium3 (NIST FIPS 204, Level 3)
- **ASIC-resistant mining:** RandomX proof-of-work (transitioning to VDF fair mining)
- **Optimized consensus:** 4-minute blocks for large signature propagation
- **Fair mining:** DFMP v2.0 with Mining Identity Keys (current), VDF fair mining (future)
- **Sybil resistance:** Digital DNA anonymous identity system (8 dimensions)
- **Fair distribution:** No premine, pure proof-of-work launch
- **Fixed supply:** 21 million coins
- **Launch:** January 18, 2026, 00:00:00 UTC

---

## Important Disclosure

**Experimental Nature:** Dilithion is an experimental cryptocurrency project. This software has NOT been professionally audited and may contain bugs or vulnerabilities. Use at your own risk.

**AI-Assisted Development:** This project was developed with AI assistance (Anthropic's Claude Code). While AI tools enable rapid development and comprehensive documentation, all code requires careful human review and community scrutiny. We believe in full transparency about our development methods.

**No Guarantees:** This project comes with no guarantee of success, security, or value. Users assume all risks. This is not financial advice. Do your own research (DYOR) before participating.

---

## Table of Contents

1. [Introduction: The Quantum Threat](#1-introduction-the-quantum-threat)
2. [Post-Quantum Cryptography](#2-post-quantum-cryptography)
3. [Technical Architecture](#3-technical-architecture)
4. [Consensus Mechanism](#4-consensus-mechanism)
   - 4.5 [Dilithion Fair Mining Protocol (DFMP)](#45-dilithion-fair-mining-protocol-dfmp)
   - 4.6 [VDF Fair Mining (Future Consensus)](#46-vdf-fair-mining-future-consensus)
   - 4.7 [Digital DNA: Anonymous Sybil Resistance](#47-digital-dna-anonymous-sybil-resistance)
   - 4.8 [Consensus Evolution Roadmap](#48-consensus-evolution-roadmap)
5. [Economic Model](#5-economic-model)
6. [Network Security](#6-network-security)
7. [Roadmap](#7-roadmap)
8. [Conclusion](#8-conclusion)

---

## 1. Introduction: The Quantum Threat

### 1.1 The Problem

Modern cryptocurrency security relies on classical cryptography:
- **ECDSA (Bitcoin, Ethereum):** Elliptic Curve Digital Signature Algorithm
- **RSA:** Rivest-Shamir-Adleman encryption
- **SHA-256:** Secure Hash Algorithm (for mining)

**Shor's Algorithm** (1994) demonstrated that quantum computers can break ECDSA and RSA in polynomial time. While SHA-256 mining receives only a modest speedup (Grover's algorithm), **digital signatures are critically vulnerable**.

### 1.2 Timeline to Quantum Threat

**Current State (2025):**
- IBM: 1,121-qubit quantum computer (Condor)
- Google: Quantum supremacy claimed
- China: Pan-Jianwei's quantum network

**Expert Estimates:**
- **2030-2035:** Cryptographically relevant quantum computers (CRQC)
- **Breaking Bitcoin:** Estimated 1,500-3,000 logical qubits required
- **Current trajectory:** Doubling qubits every ~2 years

**Conclusion:** Cryptocurrencies must transition to post-quantum cryptography **now** to remain secure over their multi-decade lifespan.

### 1.3 Existing Cryptocurrency Vulnerability

| Cryptocurrency | Signature Scheme | Quantum Vulnerable? | Migration Plan? |
|----------------|------------------|---------------------|-----------------|
| Bitcoin | ECDSA | ✅ Yes | None announced |
| Ethereum | ECDSA | ✅ Yes | Research phase only |
| Litecoin | ECDSA | ✅ Yes | None announced |
| Monero | EdDSA | ✅ Yes | None announced |
| **Dilithion** | **Dilithium3** | **❌ No** | **Built-in from genesis** |

**Critical Issue:** Retrofitting existing blockchains with post-quantum cryptography requires:
- Hard fork (community consensus required)
- Wallet migrations (user action required)
- Backward compatibility challenges
- Risk of botched transition

**Dilithion's Solution:** Start with post-quantum cryptography from genesis block.

---

## 2. Post-Quantum Cryptography

### 2.1 CRYSTALS-Dilithium

**Selection Process:**
- NIST Post-Quantum Cryptography Standardization (2016-2024)
- 82 initial submissions
- Multiple rounds of evaluation
- **Winner:** CRYSTALS-Dilithium (2022)
- **Standardized:** FIPS 204 (August 2024)

**Why Dilithium?**

1. **Security:** Based on hard lattice problems (Module-LWE, Module-SIS)
2. **Performance:** Fast signing and verification
3. **Standardization:** Official NIST standard
4. **Analysis:** Years of public cryptanalysis, no serious breaks
5. **Versatility:** Three security levels (Dilithium2, 3, 5)

**Dilithion uses Dilithium3:**
- **Security level:** NIST Level 3 (equivalent to AES-192)
- **Public key size:** 1,952 bytes
- **Signature size:** 3,309 bytes
- **Signing speed:** ~1-2 milliseconds
- **Verification speed:** ~1 millisecond

### 2.2 Comparison to Classical Cryptography

| Metric | ECDSA (secp256k1) | Dilithium3 | Ratio |
|--------|-------------------|------------|-------|
| **Public key** | 33 bytes | 1,952 bytes | 59x larger |
| **Signature** | 72 bytes | 3,309 bytes | 46x larger |
| **Security** | ~128-bit | 192-bit (quantum-safe) | More secure |
| **Signing time** | <1 ms | 1-2 ms | Comparable |
| **Verify time** | ~1 ms | ~1 ms | Identical |
| **Quantum safe?** | ❌ No | ✅ Yes | Critical advantage |

**Trade-off:** Dilithion transactions are ~15x larger than Bitcoin transactions, but provide quantum resistance.

### 2.3 SHA-3 Hashing

Dilithion uses **SHA-3 (Keccak)** throughout:
- **Address generation:** SHA3-256
- **Transaction IDs:** SHA3-256
- **Merkle trees:** SHA3-256
- **Wallet encryption:** SHA3-512 with PBKDF2

**Why SHA-3?**
- Quantum-resistant (Grover's algorithm provides only quadratic speedup)
- NIST standard (FIPS 202)
- Different construction than SHA-2 (defense in depth)
- Well-analyzed and trusted

---

## 3. Technical Architecture

### 3.1 System Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Dilithion Network                     │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐          │
│  │  Wallet  │◄──►│   Node   │◄──►│  Miner   │          │
│  └──────────┘    └──────────┘    └──────────┘          │
│       │               │                │                 │
│       │         ┌─────┴──────┐        │                 │
│       │         │            │         │                 │
│  ┌────▼────┐  ┌▼─────┐  ┌──▼────┐  ┌▼────────┐        │
│  │Dilithium│  │SHA-3 │  │LevelDB│  │RandomX  │        │
│  │  Sigs   │  │ Hash │  │  DB   │  │   PoW   │        │
│  └─────────┘  └──────┘  └───────┘  └─────────┘        │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Transaction Structure

```cpp
class CTransaction {
    int32_t nVersion;               // Transaction version
    std::vector<CTxIn> vin;         // Inputs
    std::vector<CTxOut> vout;       // Outputs
    uint32_t nLockTime;             // Lock time
};

class CTxIn {
    COutPoint prevout;              // Previous output reference
    std::vector<uint8_t> scriptSig; // Dilithium signature (3,309 bytes)
    uint32_t nSequence;             // Sequence number
};

class CTxOut {
    CAmount nValue;                 // Amount in ions (smallest unit)
    std::vector<uint8_t> scriptPubKey; // Dilithium public key (1,952 bytes)
};
```

**Typical Transaction Sizes:**
- 1-input, 1-output: ~3,864 bytes
- 2-input, 2-output: ~9,598 bytes
- Average: ~5,000-7,000 bytes

**Comparison to Bitcoin:**
- Bitcoin typical: ~250 bytes
- **Dilithion is ~15x larger** (trade-off for quantum security)

### 3.3 Currency Units and Denominations

**Base Unit: DIL**
- Symbol: **DIL**
- Total Supply: 21,000,000 DIL
- Decimal Places: 8

**Smallest Unit: ions**
- 1 DIL = 100,000,000 ions
- Named after "Dilith-**ion**" - fitting the post-quantum theme
- Similar to how Bitcoin uses "satoshis" (named after Satoshi Nakamoto)

**Denomination Table:**

| Unit Name | Value in ions | Value in DIL | Description |
|-----------|---------------|--------------|-------------|
| **ion** | 1 | 0.00000001 DIL | Smallest unit (indivisible) |
| **kiloion** | 1,000 | 0.00001 DIL | Thousand ions |
| **megaion** | 1,000,000 | 0.01 DIL | Million ions (1 cent) |
| **DIL** | 100,000,000 | 1 DIL | Base currency unit |

**Why "ions"?**
- Consistent with Dilithion branding
- Quantum/scientific theme (from "Dilithium")
- Short, memorable, easy to type
- Avoids confusion with other cryptocurrencies
- Represents the smallest "quantum" of value

**Examples:**
- Minimum transaction fee: 50,000 ions (0.0005 DIL)
- Typical transaction: 100,000-300,000 ions (0.001-0.003 DIL)
- Block reward (initial): 5,000,000,000 ions (50 DIL)

---

### 3.4 Block Structure

```cpp
class CBlockHeader {
    int32_t nVersion;               // Block version
    uint256 hashPrevBlock;          // Previous block hash (SHA-3)
    uint256 hashMerkleRoot;         // Merkle root of transactions
    uint32_t nTime;                 // Block timestamp
    uint32_t nBits;                 // Difficulty target (compact)
    uint32_t nNonce;                // RandomX nonce
};

class CBlock {
    CBlockHeader header;            // Block header
    std::vector<CTransaction> vtx;  // Transactions
};
```

**Block Properties:**
- **Target time:** 4 minutes (240 seconds)
- **Max size:** 4 MB (soft limit, adjustable)
- **Typical size:** ~500 KB - 2 MB
- **Hash algorithm:** RandomX (for mining)
- **Header hash:** SHA-3-256

---

## 4. Consensus Mechanism

### 4.1 RandomX Proof-of-Work

**Design Goals:**
- ASIC-resistant (keep mining decentralized)
- CPU-optimized (accessible to everyone)
- Memory-hard (prevent brute force)

**RandomX Characteristics:**
- **Memory requirement:** 2 GB (dataset)
- **Algorithm:** Random code execution
- **Hash rate:** ~60-80 H/s per CPU core (consumer hardware)
- **ASIC resistance:** High (designed to utilize general-purpose CPU features)

**Why RandomX?**
1. **Proven:** Used by Monero since 2019
2. **Fair:** Anyone with a CPU can mine
3. **Decentralized:** Prevents mining centralization
4. **Secure:** Well-analyzed, no shortcuts found

### 4.2 Block Time: 4 Minutes

**Decision Rationale:**

Original proposal: 2 minutes (5x faster than Bitcoin)
**Final decision: 4 minutes** (2.5x faster than Bitcoin)

**Why 4 minutes is optimal:**

1. **Large Signature Propagation**
   - Dilithium signatures: 3,309 bytes each
   - Typical block: 10-50 transactions = 33-165 KB of signatures
   - Global network needs time to propagate
   - **4 minutes reduces orphan rate by ~50%** vs 2-minute blocks

2. **Blockchain Growth**
   ```
   2-minute blocks: 720 blocks/day = ~767 GB/year
   4-minute blocks: 360 blocks/day = ~365 GB/year (50% reduction)
   ```

3. **Balanced Confirmation Time**
   ```
   Bitcoin:    10 min/block × 6 confirmations = 60 minutes
   Dilithion:   4 min/block × 3 confirmations = 12 minutes (5x faster)
   Litecoin:  2.5 min/block × 6 confirmations = 15 minutes
   ```

4. **Better Emission Schedule**
   ```
   2-min: 62.6% mined in Year 1 (too aggressive)
   4-min: 31.3% mined in Year 1 (balanced distribution)
   ```

5. **Global Mining Fairness**
   - Network latency (200-400ms globally) becomes smaller % of block time
   - Miners worldwide have equal opportunity

### 4.3 Difficulty Adjustment

**Algorithm:** Similar to Bitcoin's difficulty adjustment

```cpp
// Adjust difficulty every 2016 blocks
const int64_t DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;
const int64_t BLOCK_TARGET_SPACING = 240; // 4 minutes

// Target timespan: 2016 blocks × 4 minutes = 5.6 days
const int64_t TARGET_TIMESPAN = DIFFICULTY_ADJUSTMENT_INTERVAL * BLOCK_TARGET_SPACING;

// Difficulty adjustment formula:
new_difficulty = old_difficulty * (actual_time / target_time)

// With bounds:
new_difficulty = clamp(new_difficulty, old_difficulty / 4, old_difficulty * 4)
```

**Properties:**
- Adjusts every ~5.6 days
- Maximum change: 4x per adjustment
- Prevents difficulty manipulation attacks
- Responsive to hash rate changes

### 4.4 Timestamp Validation

**Rules:**
1. Block time must not be more than **2 hours in the future**
2. Block time must be greater than **median-time-past** (last 11 blocks)

**Prevents:**
- Time manipulation attacks
- Difficulty adjustment gaming
- Chain reorganization exploits

### 4.5 Dilithion Fair Mining Protocol (DFMP)

**Version:** 2.0
**Purpose:** Prevent mining centralization through identity-based difficulty adjustments

#### 4.5.1 Overview

DFMP creates economic incentives for distributed block production by tracking miner identities and applying difficulty multipliers to concentrated mining activity. This discourages any single entity from dominating block production.

#### 4.5.2 Mining Identity Key (MIK)

In DFMP v2.0, each miner is identified by a dedicated **Mining Identity Key (MIK)** - a Dilithium3 keypair separate from payout addresses. This closes the address rotation loophole where miners could bypass DFMP penalties by using a new payout address for each block.

```
MIK Identity = SHA3-256(MIK_public_key)[:20 bytes]
```

**MIK Specifications:**
- **Public key:** 1,952 bytes (Dilithium3)
- **Private key:** 4,032 bytes (Dilithium3)
- **Signature:** 3,309 bytes (included in every block)
- **Identity:** 20 bytes (hash of public key)

**Coinbase Integration:**
- First block with new MIK: Includes full public key (registration)
- Subsequent blocks: Includes identity hash only (reference) + signature

#### 4.5.3 Maturity Penalty (No First-Block Grace)

New MIKs face elevated difficulty that decays step-wise over 400 blocks:

```
penalty = 3.0x → 2.5x → 2.0x → 1.5x → 1.0x (every 100 blocks)
```

| Blocks Since Registration | Maturity Penalty |
|---------------------------|------------------|
| 0-99 | 3.0x |
| 100-199 | 2.5x |
| 200-299 | 2.0x |
| 300-399 | 1.5x |
| 400+ | 1.0x (mature) |

**Purpose:** New identities must "mature" over 400 blocks before achieving full mining efficiency. Unlike v1.x, there is **no first-block grace** - the penalty applies immediately.

#### 4.5.4 Heat Penalty (Tiered System)

Miners who produce many blocks within the observation window face tiered difficulty scaling:

**Parameters:**
- Observation window: 360 blocks (~24 hours at 4-minute blocks)
- Free tier: 20 blocks (~5.5% of window)

**Tiered Formula:**
```
0-20 blocks:   Free tier (1.0x penalty)
21-25 blocks:  Linear zone (1.0x → 1.5x, +0.1x per block)
26+ blocks:    Exponential zone (1.5x × 1.08^(blocks-25))
```

| Blocks in Last 360 | Heat Penalty |
|--------------------|--------------|
| 0-20 | 1.0x |
| 21 | 1.1x |
| 22 | 1.2x |
| 23 | 1.3x |
| 24 | 1.4x |
| 25 | 1.5x |
| 30 | 2.2x |
| 40 | 4.8x |
| 50 | 10.3x |
| 60 | 22.2x |

**Purpose:** The free tier allows reasonable solo mining (~5.5% of blocks). The linear zone provides a gradual transition. Beyond that, exponential scaling makes dominance progressively more expensive.

#### 4.5.5 Total Difficulty Multiplier

The final difficulty multiplier combines both penalties:

```
total_multiplier = maturity_penalty × heat_penalty
effective_difficulty = base_difficulty × total_multiplier
```

Blocks must meet the DFMP-adjusted difficulty target to be valid.

#### 4.5.6 Consensus Integration

DFMP multipliers are enforced at the consensus level:

1. Parse MIK data from coinbase scriptSig
2. Verify MIK signature against block commitment
3. Calculate maturity penalty based on MIK registration height
4. Calculate heat penalty based on blocks in observation window
5. Apply combined multiplier to difficulty target
6. Reject blocks that don't meet adjusted target

**Note:** Blocks that meet base difficulty but fail DFMP-adjusted difficulty are invalid.

### 4.6 VDF Fair Mining (Future Consensus)

**Status:** Implemented, tested (46 unit tests), testnet activation scheduled. Mainnet activation pending community vote.

DFMP successfully prevents mining centralization, but it addresses a symptom rather than the root cause: **proof-of-work inherently rewards those who burn the most electricity.** Dilithion's next-generation consensus replaces hashrate competition with a Verifiable Delay Function (VDF).

#### 4.6.1 What is a VDF?

A Verifiable Delay Function is a computation that:
- Takes a **fixed amount of time** (~200 seconds on mainnet) regardless of hardware
- **Cannot be parallelized** -- 1 CPU or 1,000 CPUs produce the same result in the same time
- Produces a **provable output** that anyone can verify in milliseconds
- Is **deterministic** -- the same input always produces the same output

Dilithion uses [chiavdf](https://github.com/Chia-Network/chiavdf), the same VDF library powering Chia Network since 2021, based on class groups of unknown order.

#### 4.6.2 How VDF Mining Works

```
Every block period:
1. Each miner computes ONE VDF seeded with their address
2. The miner with the lowest VDF output wins the block
3. The winner enters a cooldown period (sits out N blocks)
4. Repeat
```

**Challenge derivation:**
```
challenge = SHA3-256(previous_block_hash || height || miner_address)
```

Each miner gets a unique, unpredictable challenge. The miner address component ensures every miner computes a different VDF, and the previous block hash prevents grinding.

#### 4.6.3 Why This Eliminates Hashrate Advantage

| Scenario | Current PoW | VDF Fair Mining |
|----------|-------------|-----------------|
| 1 miner, 1 CPU | 1 ticket | 1 ticket |
| 1 miner, 100 CPUs | 100 tickets | 1 ticket |
| 10 miners, 1 CPU each | 10 tickets total | 10 tickets total |

**Hashrate becomes irrelevant.** Each address gets exactly one VDF computation per round. Additional hardware provides zero advantage.

#### 4.6.4 Cooldown Mechanism

After winning a block, a miner is excluded from the next N blocks. The cooldown scales with network participation:

| Active Miners | Cooldown | Max Block Share |
|---------------|----------|-----------------|
| 10 | 10 blocks | 10% |
| 50 | 50 blocks | 2% |
| 100+ | 100 blocks | 1% |

Parameters: `MIN_COOLDOWN = 10`, `MAX_COOLDOWN = 100`, `ACTIVE_WINDOW = 360 blocks`

This single mechanism replaces all of DFMP's penalty systems (heat, maturity, payout tracking) with one elegant rule.

#### 4.6.5 VDF Block Format

VDF blocks use **block version 4** with a 144-byte header:

| Field | Size | Description |
|-------|------|-------------|
| Legacy header | 80 bytes | version, prevHash, merkleRoot, timestamp, nBits, nonce |
| `vdfOutput` | 32 bytes | VDF computation result |
| `vdfProofHash` | 32 bytes | SHA3-256 commitment to full proof |

The full Wesolowski VDF proof (~100 bytes) is stored in the coinbase transaction's OP_RETURN output. Block hash uses SHA3-256 of the full 144-byte header (no RandomX computation).

#### 4.6.6 Energy Reduction

| Metric | RandomX PoW | VDF Mining |
|--------|-------------|------------|
| CPU usage per miner | 100% all cores, 24/7 | 1 thread, ~200s per round |
| Network total (50 miners) | 50 x 8 cores x 100% = 400 cores | 50 x 1 thread x ~30% duty = 15 cores |
| Estimated energy reduction | Baseline | **~95% reduction** |

#### 4.6.7 Parameters

| Parameter | Mainnet | Testnet |
|-----------|---------|---------|
| VDF iterations | 200,000,000 (~200s) | 10,000,000 (~10s) |
| Block time target | 240 seconds | 60 seconds |
| Cooldown min/max | 10 / 100 blocks | 10 / 100 blocks |
| Active window | 360 blocks | 360 blocks |
| Block version | 4 | 4 |

### 4.7 Digital DNA: Anonymous Sybil Resistance

The primary attack against VDF fair mining is **address multiplication** (Sybil attack) -- creating many identities to get many lottery tickets. Dilithion addresses this with Digital DNA, an anonymous, physics-based identity system.

#### 4.7.1 Design Principles

- **Anonymous:** No KYC, no trusted hardware, no personal data
- **Unforgeable:** Based on physics (speed of light, computation time, oscillator drift)
- **Verifiable:** Third parties can validate claims
- **Privacy-preserving:** Identity fingerprints reveal nothing about the person
- **Data-driven:** Equal-weight bootstrap, ML calibration, then ML-primary detection

#### 4.7.2 Eight Identity Dimensions

Every miner builds an unforgeable identity fingerprint from 8 independent dimensions:

| Dimension | Measures | Why It's Unique |
|-----------|----------|-----------------|
| **L** - Latency Fingerprint | Round-trip time to seed nodes | Speed of light -- geographic location determines latency |
| **V** - VDF Timing Signature | VDF computation speed profile | CPU/silicon manufacturing differences are measurable |
| **P** - Perspective Proof | Which peers you see and when | Network position is unique per node |
| **M** - Memory Fingerprint | Cache hierarchy timing | L1/L2/L3 cache sizes and latencies vary by hardware |
| **D** - Clock Drift | Crystal oscillator frequency | Every clock crystal drifts at a unique rate |
| **B** - Bandwidth Proof | Upload/download throughput | Connection capacity varies per location and ISP |
| **T** - Thermal Profile | Cooling curve from VDF checkpoints | Thermal behavior is hardware and environment-specific |
| **BP** - Behavioral Profile | Protocol participation patterns | Activity timing and patterns are unique |

#### 4.7.3 Sybil Detection

When a new identity registers, it is compared against all existing identities across all available dimensions:

- **Combined score >= 0.92** -- Auto-reject (same identity, different address)
- **Combined score >= 0.55** -- Trigger challenge verification
- **Memory + Clock Drift both >= 0.95** -- Physics hard rule: auto-reject (probability of two distinct machines matching both is vanishingly small)

Scoring uses equal-weight averaging across all available dimensions, with correlation-aware damping for hardware-correlated dimensions (V, M, T).

#### 4.7.4 ML Anomaly Detection

An Isolation Forest ML model runs in **advisory mode** -- logging anomalies without auto-rejecting. It uses 13 features per identity pair and will be promoted to active mode after meeting these prerequisites:

- 5,000+ scored identity pairs
- 1,000+ full-dimension pairs
- 300+ challenge-resolved outcomes
- False positive rate below 1%
- Diversity threshold: 3+ hardware clusters, 3+ geographic regions

This ensures ML only influences decisions after proving reliable on real network data.

#### 4.7.5 Cost of a Sybil Attack

With Digital DNA + cooldown, an attacker trying to capture 50% of blocks would need:

| Requirement | Reason |
|------------|--------|
| 60+ mining addresses | 100-block cooldown limits each to ~3 blocks per 360-block window |
| 60+ distinct physical machines | DNA detects same-hardware identities |
| 60+ distinct geographic locations | Latency fingerprint detects co-location |
| Sustained long-term commitment | Identities build over time, not burst-rentable |

Compare to current PoW: rent hashrate for an hour, dominate, leave. VDF + DNA requires **ongoing, geographically distributed, unique hardware** -- a fundamentally different cost model.

### 4.8 Consensus Evolution Roadmap

Dilithion's consensus evolves through three phases:

```
Phase 1 (Current):  RandomX PoW + DFMP
                    ├── ASIC-resistant CPU mining
                    ├── MIK-based identity tracking
                    └── Heat/maturity penalty system

Phase 2 (Hybrid):   RandomX PoW + VDF (both accepted)
                    ├── Miners upgrade at their own pace
                    ├── RandomX acts as safety net
                    └── Digital DNA collection begins

Phase 3 (Future):   VDF-Only + Digital DNA
                    ├── Hashrate irrelevant
                    ├── ~95% energy reduction
                    ├── Anonymous Sybil resistance
                    └── DFMP retired
```

**Migration safety:**
- Long hybrid period gives miners time to upgrade
- RandomX continues during hybrid as a fallback
- Testnet activation proves the full migration path before mainnet
- Activation heights set by community vote

---

## 5. Economic Model

### 5.1 Supply Schedule

```
Total Supply:    21,000,000 DIL (fixed cap)
Initial Reward:  50 DIL per block
Block Time:      4 minutes (240 seconds)
Halving:         Every 210,000 blocks (~1.6 years)
```

### 5.2 Emission Schedule

| Halving | Block Range | Reward | Duration | DIL Mined | % of Supply | Cumulative % |
|---------|-------------|--------|----------|-----------|-------------|--------------|
| 0 | 0 - 209,999 | 50 DIL | 1.60 years | 10,500,000 | 50.0% | 50.0% |
| 1 | 210k - 419,999 | 25 DIL | 1.60 years | 5,250,000 | 25.0% | 75.0% |
| 2 | 420k - 629,999 | 12.5 DIL | 1.60 years | 2,625,000 | 12.5% | 87.5% |
| 3 | 630k - 839,999 | 6.25 DIL | 1.60 years | 1,312,500 | 6.25% | 93.75% |
| 4+ | 840k+ | <6.25 DIL | ~8 years | ~1,312,500 | ~6.25% | ~100% |

**Year-by-Year Emission:**
- **Year 1:** 6,570,000 DIL (31.3% of total supply)
- **Year 2:** 5,250,000 DIL (25.0%)
- **Year 3:** 3,285,000 DIL (15.6%)
- **Year 5:** 89.1% mined
- **Year 13:** 99%+ mined

### 5.3 Comparison to Bitcoin

| Metric | Bitcoin | Dilithion | Ratio |
|--------|---------|-----------|-------|
| **Total Supply** | 21M BTC | 21M DIL | 1:1 |
| **Initial Reward** | 50 BTC | 50 DIL | 1:1 |
| **Block Time** | 10 min | 4 min | 2.5x faster |
| **Halving Period** | 210,000 blocks | 210,000 blocks | 1:1 |
| **First Halving** | ~4 years | ~1.6 years | 2.5x faster |
| **99% Mined** | ~32 years | ~12.8 years | 2.5x faster |
| **Year 1 Emission** | 12.5% | 31.3% | 2.5x faster |

**Conclusion:** Dilithion's emission is **exactly 2.5x faster** than Bitcoin (matching the block time ratio).

### 5.4 Transaction Fees

**Fee Model (Option A):**

```cpp
// Consensus parameters
MIN_TX_FEE = 50,000 ions          // 0.0005 DIL (base fee)
FEE_PER_BYTE = 25 ions            // 25 ions per byte
MIN_RELAY_TX_FEE = 100,000 ions   // 0.001 DIL (relay minimum)

// Fee calculation
fee = MIN_TX_FEE + (transaction_size_bytes × FEE_PER_BYTE)
```

**Typical Transaction Fees:**
| Transaction Type | Size | Fee (DIL) | Fee (USD at $1/DIL) |
|------------------|------|-----------|---------------------|
| 1-in, 1-out | 3,864 bytes | 0.00147 | $0.00147 |
| 1-in, 2-out | 5,816 bytes | 0.00195 | $0.00195 |
| 2-in, 2-out | 9,598 bytes | 0.00290 | $0.00290 |

**Design Goals:**
1. **Affordable:** Fees remain negligible (<$0.003 per transaction)
2. **Spam protection:** 3x higher than minimal baseline (prevents cheap attacks)
3. **Miner incentives:** Provides meaningful revenue (3x improvement over original)
4. **Sustainable:** Scales with transaction complexity

**Long-term Fee Market:**
- **Short-term:** Fixed fee model (simple, predictable)
- **Year 1-2:** Monitor usage patterns and fee adequacy
- **Year 2+:** Implement dynamic fee market (EIP-1559 style consideration)

### 5.5 Inflation Rate

| Year | Supply Start | Annual Emission | Supply End | Inflation Rate |
|------|--------------|-----------------|------------|----------------|
| 1 | 0 | 6,570,000 | 6,570,000 | N/A |
| 2 | 6,570,000 | 5,250,000 | 11,820,000 | 79.9% |
| 3 | 11,820,000 | 3,285,000 | 15,105,000 | 27.8% |
| 4 | 15,105,000 | 1,965,000 | 17,070,000 | 13.0% |
| 5 | 17,070,000 | 1,642,500 | 18,712,500 | 9.6% |
| 10 | ~20,200,000 | ~205,000 | ~20,405,000 | ~1.0% |
| 20 | ~20,900,000 | ~12,800 | ~20,912,800 | ~0.06% |

**Observation:** Inflation drops to single digits by Year 5, below 1% by Year 10.

---

## 6. Network Security

### 6.1 Attack Vector Analysis

#### 6.1.1 51% Attack

**Definition:** Attacker controls >50% of network hash rate

**Dilithion Defenses:**
1. **RandomX CPU Mining**
   - No ASICs available (ASIC-resistant design)
   - Attacker must acquire thousands of consumer CPUs
   - Very expensive and detectable

2. **Confirmation Requirements**
   ```
   Small tx (<$100):    3 confirmations = 12 minutes
   Medium tx ($1K):     6 confirmations = 24 minutes
   Large tx ($10K+):    10 confirmations = 40 minutes
   Exchange deposits:   20+ confirmations = 80+ minutes
   ```

3. **Economic Disincentive**
   ```
   Attack cost: $20,000-$50,000 (hardware)
   Attack profit: $1,000-$5,000 (one-time, if successful)
   Consequence: Coin price crashes, attacker's holdings worthless
   Result: Attacker loses money
   ```

**Risk Level:** LOW to MEDIUM (economically impractical)

#### 6.1.2 Double-Spend Attack

**Mitigation:**
- Requires 51% attack to succeed
- Exchanges wait for multiple confirmations
- Cost exceeds potential gain

**Risk Level:** LOW (same as 51% attack)

#### 6.1.3 Sybil Attack

**Definition:** Attacker creates many fake identities to gain disproportionate influence

**Dilithion Defenses:**
1. **Current (PoW):** Mining power matters, not node count
2. **Future (VDF):** Digital DNA 8-dimension fingerprinting detects same-machine identities
3. **Physics-based:** Latency (speed of light), clock drift (crystal uniqueness), memory hierarchy (hardware-specific) are unforgeable
4. **ML anomaly detection:** Isolation Forest model flags suspicious identity pairs

**Risk Level:** LOW (ineffective under PoW, actively countered under VDF via Digital DNA)

#### 6.1.4 Eclipse Attack

**Definition:** Isolate a node from the honest network

**Mitigation:**
- Multiple seed nodes (DNS + hardcoded)
- Peer diversity requirements
- Automatic peer discovery

**Risk Level:** LOW (standard Bitcoin-style defenses)

#### 6.1.5 Quantum Computer Attack

**Definition:** Use quantum computer to break cryptography

**Dilithion Defense:**
- **Signatures:** Quantum-resistant (Dilithium3)
- **Hashing:** Quantum-resistant (SHA-3, only Grover speedup)
- **Mining:** Quantum computers provide minimal advantage (Grover = 2x speedup at best)

**Verdict:** ✅ **Dilithion is quantum-safe** (primary design goal)

### 6.2 Wallet Security

**Features:**
1. **AES-256-CBC Encryption**
   - Industry-standard wallet encryption
   - PBKDF2-SHA3 key derivation (100,000 rounds)
   - Two-tier architecture (master key + encrypted private keys)

2. **Lock/Unlock Mechanism**
   - Automatic lock after timeout
   - Secure memory wiping
   - Password strength requirements

3. **Backup & Recovery**
   - Binary wallet file format (DILWLT01)
   - Encrypted backups
   - **Future:** HD wallet with 24-word seed phrase (Month 1-2 post-launch)

**Best Practices:**
- Always encrypt wallet with strong passphrase
- Regular backups to multiple locations
- Store backups encrypted
- Use cold storage for large amounts

### 6.3 Network Monitoring

**Planned Infrastructure:**
1. **Seed Nodes:** 3-5 globally distributed nodes
2. **DNS Seeds:** Automatic peer discovery
3. **Block Explorer:** Public blockchain viewer
4. **Hash Rate Monitor:** Real-time network statistics

---

## 7. Roadmap

### 7.1 Genesis Launch (January 18, 2026)

**Launch Specifications:**
- **Genesis timestamp:** January 18, 2026, 00:00:00 UTC
- **Initial difficulty:** 0x1e01fffe
- **First halving:** Block 210,000 (~July 2027)
- **Network:** Mainnet with seed nodes

**Launch Readiness:**
- ✅ Core node implementation complete
- ✅ Wallet functionality complete
- ✅ Mining integration complete
- ✅ Consensus parameters finalized
- ✅ Security features implemented
- ✅ Testing complete

### 7.2 Month 1-2 (Launch Infrastructure)

**Priority Features:**
1. **Desktop GUI Wallet**
   - User-friendly interface
   - One-click mining
   - Visual transaction history
   - Windows, macOS, Linux support

2. **Website Launch**
   - Countdown timer
   - Live network dashboard
   - Getting started guide
   - Documentation

3. **Block Explorer**
   - View blocks and transactions
   - Search functionality
   - Network statistics
   - API for developers

4. **Mining Pool Software**
   - Stratum protocol implementation
   - Pool operator toolkit
   - Fair reward distribution

### 7.3 Month 2-3 (Ecosystem Growth)

**Key Milestones:**
1. **HD Wallet Implementation** (HIGH PRIORITY)
   - 24-word seed phrase recovery
   - BIP32/BIP39 adapted for Dilithium
   - Infinite address generation from single seed
   - **Impact:** Prevents coin loss, major UX improvement

2. **Mobile Wallets**
   - iOS app
   - Android app
   - QR code scanning
   - Push notifications
   - SPV-style lightweight verification

3. **Exchange Listings**
   - Engage major exchanges (Binance, Coinbase, Kraken)
   - Provide integration documentation
   - Listing applications submitted

4. **Dynamic Fee Market**
   - Fee estimation API
   - Market-driven pricing
   - Mempool analytics

### 7.4 Month 6+ (VDF + Digital DNA)

**Consensus Evolution:**
1. **VDF Fair Mining Activation**
   - Testnet validation of VDF mining (in progress)
   - Community vote on mainnet activation heights
   - Hybrid period: both RandomX and VDF blocks accepted
   - VDF-only transition after successful hybrid period

2. **Digital DNA Deployment**
   - Passive identity collection from network behavior
   - Sybil detection scoring across 8 dimensions
   - ML anomaly detection in advisory mode
   - Progressive enforcement as dataset grows

3. **DFMP Retirement**
   - Heat/maturity penalties replaced by cooldown mechanism
   - MIK identity system replaced by Digital DNA
   - Simpler, more elegant fairness model

**Other Enhancements:**
4. **Payment Integration** - Merchant tools, POS systems, e-commerce plugins
5. **Hardware Wallet Support** - Custom PQC hardware wallet research
6. **Layer 2 Scaling** - Lightning Network research adapted for PQC
7. **Signature Aggregation** - 75-85% transaction size reduction potential

### 7.5 Year 2+ (Ecosystem Maturity)

**Vision:**
1. **DeFi Integration**
   - Decentralized exchanges
   - Lending protocols
   - Liquidity pools

2. **Smart Contracts** (Research)
   - Post-quantum compatible VM
   - Turing-complete capabilities
   - Security-first design

3. **Privacy Features** (Optional)
   - Ring signatures or similar
   - Optional privacy transactions
   - Balance transparency vs. privacy

4. **Cross-chain Bridges**
   - Connect to other blockchains
   - Atomic swaps
   - Interoperability protocols

---

## 8. Conclusion

### 8.1 Why Dilithion Matters

**The Quantum Threat is Real:**
- Timeline: 5-10 years to cryptographically relevant quantum computers
- Existing cryptocurrencies are vulnerable
- Transition will be difficult and contentious
- **Action needed now**

**Dilithion's Solution:**
- Built quantum-safe from genesis
- No migration required
- Users protected from day one
- Proven cryptography (NIST standard)

### 8.2 Technical Excellence

**Optimized for Post-Quantum Era:**
- 4-minute blocks accommodate large signatures
- Balanced emission schedule (31.3% Year 1)
- Affordable transaction fees
- ASIC-resistant CPU mining
- Professional-grade security

**Comparison to Competition:**

| Feature | Bitcoin | Ethereum | Other PQC Projects | Dilithion |
|---------|---------|----------|-------------------|-----------|
| Quantum-safe signatures | ❌ No | ❌ No | ⚠️ Experimental | ✅ NIST standard |
| ASIC-resistant mining | ❌ No | N/A (PoS) | Varies | ✅ RandomX |
| Optimized for PQC | ❌ No | ❌ No | ⚠️ Partial | ✅ Yes (4-min blocks) |
| Fixed supply | ✅ Yes | ❌ No | Varies | ✅ Yes (21M) |
| Launch readiness | ✅ Mature | ✅ Mature | ⚠️ Alpha/Beta | ✅ Production-ready |

### 8.3 Fair Launch Principles

**Dilithion adheres to fair launch principles:**
- ✅ No premine
- ✅ No ICO / token sale
- ✅ No founder allocation
- ✅ No venture capital pre-allocation
- ✅ Pure proof-of-work from genesis
- ✅ Open-source (MIT license)
- ✅ Community-driven development

**Everyone starts equal on January 18, 2026.**

### 8.4 Long-term Vision

Dilithion aims to be:
1. **The standard** for quantum-safe cryptocurrency
2. **A store of value** in the post-quantum era
3. **A medium of exchange** with reasonable fees
4. **The fairest mining system** in crypto -- VDF eliminates hashrate advantage, Digital DNA prevents Sybil attacks, all without KYC or trusted hardware
5. **Energy-efficient** -- ~95% reduction in mining energy via VDF
6. **A community** of quantum-aware developers and users

**Mission Statement:**
> "Secure digital currency for the quantum age, built by the community, for the community."

### 8.5 Call to Action

**For Miners:**
- CPU mining opens January 18, 2026
- Fair distribution, no ASIC advantage
- Early adoption opportunity

**For Developers:**
- Open-source codebase (GitHub)
- Documentation available
- Contribute to post-quantum crypto future

**For Users:**
- Download wallet before launch
- Participate in first quantum-safe cryptocurrency
- Be part of the solution

**For Investors:**
- Study the technology
- Understand the quantum threat
- Position for the post-quantum era

---

## Technical Specifications Summary

| Parameter | Value |
|-----------|-------|
| **Launch Date** | January 1, 2026, 00:00:00 UTC |
| **Total Supply** | 21,000,000 DIL |
| **Block Time** | 4 minutes (240 seconds) |
| **Block Reward** | 50 DIL (halves every 210,000 blocks) |
| **Halving Interval** | Every 210,000 blocks (~1.6 years) |
| **Signature Algorithm** | CRYSTALS-Dilithium3 (NIST FIPS 204) |
| **Hash Algorithm** | SHA-3-256 (NIST FIPS 202) |
| **Mining Algorithm** | RandomX (current), VDF fair mining (future) |
| **Difficulty Adjustment** | Every 2,016 blocks (~5.6 days) |
| **Fair Mining Protocol** | DFMP v2.0 (current), VDF cooldown (future) |
| **Sybil Resistance** | Digital DNA (8-dimension anonymous identity) |
| **VDF Library** | chiavdf (class groups of unknown order) |
| **Address Format** | Dilithium3 public key hash (SHA-3) |
| **Transaction Fee** | 0.0005 DIL base + 25 ions/byte |
| **Confirmations (typical)** | 3-10 blocks (12-40 minutes) |
| **Genesis Block** | Hardcoded, January 18, 2026 |

---

## References

1. NIST. (2024). *FIPS 204: Module-Lattice-Based Digital Signature Standard*. National Institute of Standards and Technology.

2. Ducas, L., et al. (2018). *CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme*. IACR Transactions on Cryptographic Hardware and Embedded Systems.

3. Shor, P. (1994). *Algorithms for quantum computation: Discrete logarithms and factoring*. Proceedings 35th Annual Symposium on Foundations of Computer Science.

4. National Academies of Sciences, Engineering, and Medicine. (2019). *Quantum Computing: Progress and Prospects*. The National Academies Press.

5. Monero Research Lab. (2019). *RandomX: CPU-optimized Proof-of-Work*. https://github.com/tevador/RandomX

6. Nakamoto, S. (2008). *Bitcoin: A Peer-to-Peer Electronic Cash System*.

7. Bernstein, D. J., et al. (2015). *Post-quantum cryptography*. Nature, 549(7671), 188-194.

---

## Appendix A: Glossary

**ASIC (Application-Specific Integrated Circuit):** Specialized hardware designed for a specific task (e.g., Bitcoin mining). Dilithion uses RandomX to resist ASICs.

**CRYSTALS-Dilithium:** NIST-standardized post-quantum digital signature scheme based on lattice cryptography.

**DFMP (Dilithion Fair Mining Protocol):** MIK-based difficulty adjustment system that prevents mining centralization by applying maturity and heat penalties to concentrated mining activity. Version 2.0 uses Mining Identity Keys (MIK) for persistent identity tracking. To be replaced by VDF fair mining.

**Digital DNA:** Anonymous, physics-based identity system using 8 unforgeable dimensions (latency, VDF timing, perspective, memory, clock drift, bandwidth, thermal, behavioral) to detect Sybil attacks without KYC or trusted hardware.

**Halving:** Reduction of block reward by 50%, occurs every 210,000 blocks (~1.6 years for Dilithion).

**Hash Rate:** Measure of mining computational power, typically measured in hashes per second (H/s).

**Lattice Cryptography:** Post-quantum cryptographic approach based on hard mathematical problems in lattice structures.

**MIK (Mining Identity Key):** A dedicated Dilithium3 keypair used in DFMP v2.0 to uniquely identify miners. Closes the address rotation loophole from DFMP v1.x.

**Module-LWE:** Learning With Errors over Module Lattices, the hard problem underlying Dilithium's security.

**Orphan Block:** Valid block that's not included in the longest chain, typically due to network propagation delays.

**Post-Quantum Cryptography (PQC):** Cryptographic algorithms designed to be secure against quantum computer attacks.

**RandomX:** ASIC-resistant proof-of-work algorithm optimized for general-purpose CPUs.

**SHA-3:** Secure Hash Algorithm 3, NIST-standardized hash function (Keccak).

**Shor's Algorithm:** Quantum algorithm that can break RSA and ECDSA in polynomial time.

**VDF (Verifiable Delay Function):** A computation that takes a fixed amount of time and cannot be parallelized, producing a provable result that can be verified quickly. Dilithion uses chiavdf (class groups of unknown order) for its VDF fair mining system.

---

## Appendix B: Contact & Community

**Website:** https://dilithion.org (launching soon)

**GitHub:** https://github.com/WillBarton888/dilithion

**Discord:** [Community server - launching Week 2]

**Twitter/X:** @DilithionCoin

**Reddit:** r/dilithion

**Contact:**
- **General Inquiries:** team@dilithion.org
- **Security Reports:** security@dilithion.org
- **Media Inquiries:** media@dilithion.org
- **User Support:** support@dilithion.org

---

**Dilithion Whitepaper v3.0**
**February 2026**
**"Quantum-Safe. Energy-Efficient. Truly Fair."**

---

**Disclaimer:** This whitepaper is for informational and educational purposes only and does not constitute investment, financial, or legal advice. Dilithion is EXPERIMENTAL software developed with AI assistance and has NOT been professionally audited. The software may contain bugs, vulnerabilities, or design flaws. Cryptocurrency investments carry significant risk, including total loss of funds. No guarantees are made regarding security, functionality, future value, adoption, or success. Use this software entirely at your own risk. Users are responsible for securing their own keys and funds. Always do your own research (DYOR) and consult with qualified professionals before participating in any cryptocurrency project.
