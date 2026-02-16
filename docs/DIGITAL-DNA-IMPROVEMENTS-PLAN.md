# Digital DNA v3.0: Comprehensive Improvement Plan

**Version:** 1.0
**Date:** 2026-02-12
**Authors:** Will Barton, Claude (Anthropic)
**Status:** Implementation Plan — Pending Approval

---

## Executive Summary

This document specifies 13 improvements to the Digital DNA anonymous Sybil-resistant identity system, ordered by return on investment (ROI). The improvements add 3 new fingerprint dimensions, decentralize trust, introduce economic incentives, and enable zero-knowledge privacy guarantees.

**Total estimated effort:** 30-50 developer-weeks
**Parallelizable to:** ~25 calendar weeks with 2-3 developers
**Expected outcome:** Digital DNA goes from prototype-grade to production-grade, with the world's most comprehensive anonymous Sybil resistance system.

---

## Pre-Requisites: Current Codebase Issues to Fix First

Before implementing any improvement, these divergences between code and spec must be resolved:

| Issue | Current Code | v2.0 Spec | Fix |
|-------|-------------|-----------|-----|
| Similarity weights | L=0.40, V=0.30, P=0.30 (`digital_dna.cpp:354`) | L=0.20, V=0.35, P=0.45 | Update weights to match spec |
| Hash function | SipHash-like mixing (`digital_dna.cpp:17`) | SHA3-256 | Replace with SHA3-256 from existing crypto |
| Timing delay function | Fake hash iteration (`timing_signature.cpp:16`) | Real VDF (chiavdf) | Wire up `src/vdf/vdf.h::compute()` |
| Witness signatures | Non-zero check only (`perspective_proof.cpp:36`) | Dilithium/Ed25519 signatures | Implement real sig verification |
| Registry storage | In-memory vector (`digital_dna.h:192`) | On-chain + LevelDB persistence | Port to LevelDB with consensus rules |
| Latency array | Fixed `array<LatencyStats, 4>` | Should support variable-size | Convert to `vector<LatencyStats>` |

**Estimated fix time:** 1-2 weeks. MUST be completed before starting any improvement below.

---

## Dependency Graph

```
                    ┌──────────────────────────────────────────────────┐
                    │              PRE-REQUISITES                       │
                    │  Fix weights, hash, VDF, sigs, registry, array   │
                    └──────────────┬───────────────────────────────────┘
                                   │
            ┌──────────────────────┼──────────────────────┐
            │                      │                      │
            v                      v                      v
   ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
   │ PHASE A (No P2P)│  │ PHASE B (P2P)    │  │ PHASE C (Economic)   │
   │                 │  │                  │  │                      │
   │ 3. Trust Score  │  │ 1. Decentral.    │  │ 5. Stake Bond        │
   │ 4. Memory Fprint│  │    Latency       │  │ 9. False Positive    │
   │ 8. Behavioral   │  │ 2. Clock Drift   │  │    Protection        │
   │ 11. Thermal     │  │ 7. Bandwidth     │  └──────────┬───────────┘
   │    Throttle     │  │ 10. Witness      │             │
   └────────┬────────┘  │    Diversity     │             │
            │           └────────┬─────────┘             │
            │                    │                        │
            v                    v                        v
   ┌────────────────────────────────────────────────────────────────┐
   │                      PHASE D (Advanced)                        │
   │                                                                │
   │  6. Zero-Knowledge Proofs  ←── requires all dimensions final   │
   │  12. Cross-Chain Portability ←── requires ZK proofs            │
   │  13. ML Anomaly Detection   ←── requires network data          │
   └────────────────────────────────────────────────────────────────┘
```

**Key dependencies:**
- Improvement 1 (Decentralized Latency) requires converting `array<LatencyStats, 4>` to `vector` (pre-req)
- Improvement 6 (ZK Proofs) requires all dimensions finalized (Phases A+B complete)
- Improvement 12 (Cross-Chain) requires ZK Proofs (Improvement 6)
- Improvement 13 (ML Detection) requires network data from live deployment
- Improvements 3, 4, 8, 11 are independent of each other (fully parallelizable)
- Improvement 9 (False Positive) requires Improvement 5 (Stake Bond) for the slashing mechanism

---

## Phased Rollout Plan

| Phase | Improvements | Duration | Why This Order |
|-------|-------------|----------|----------------|
| **Pre-req** | Fix 6 codebase issues | 1-2 weeks | Foundation must be solid |
| **A** | 3 (Trust), 4 (Memory), 8 (Behavioral), 11 (Thermal) | 2-3 weeks | No P2P changes, pure software upgrades, highest ROI per effort |
| **B** | 1 (Decentral. Latency), 2 (Clock Drift), 7 (Bandwidth), 10 (Witness Diversity) | 4-6 weeks | P2P protocol extensions, new measurement infrastructure |
| **C** | 5 (Stake Bond), 9 (False Positive Protection) | 2-3 weeks | Economic layer, requires consensus changes |
| **D** | 6 (ZK Proofs), 12 (Cross-Chain), 13 (ML Detection) | 8-12 weeks | Advanced features, requires stable base |

---

## Improvement 1: Decentralized Latency Measurement

**ROI Rank: #1** | **Effort: L (2-3 weeks)** | **Phase: B**

### Summary

The current latency fingerprint depends on 4 hardcoded seed nodes — a centralization risk and single point of trust. This improvement enables latency measurement against randomly-selected established identities, making the system more secure as it grows and eliminating the seed node trust assumption.

### Technical Design

#### Data Structures

```cpp
// New: src/digital_dna/decentralized_latency.h

struct LatencyMeasurementRequest {
    std::array<uint8_t, 32> challenge_hash;  // Hash of block used for verifier selection
    uint32_t block_height;                    // Block whose hash seeds selection
    std::array<uint8_t, 20> registrant;       // Who is being measured
    std::vector<std::array<uint8_t, 20>> selected_verifiers;  // Deterministically chosen
};

struct LatencyMeasurementResponse {
    std::array<uint8_t, 20> verifier_id;
    double rtt_ms;                            // Round-trip time measured by verifier
    uint64_t timestamp;
    std::array<uint8_t, 64> verifier_signature;  // Verifier signs the measurement
};

struct DecentralizedLatencyFingerprint {
    std::vector<LatencyMeasurementResponse> measurements;  // N measurements (N=10-20)
    std::array<uint8_t, 32> selection_block_hash;          // Proves verifier selection was fair
    uint32_t selection_block_height;

    // Backward compat: also include seed node measurements during bootstrap
    std::vector<LatencyStats> seed_measurements;  // Legacy 4 seed nodes (optional)
};
```

#### New Files
- `src/digital_dna/decentralized_latency.h` — Data structures and verifier selection
- `src/digital_dna/decentralized_latency.cpp` — Implementation

#### Changes to Existing Files
- `src/digital_dna/latency_fingerprint.h` — Convert `array<LatencyStats, 4>` to `vector<LatencyStats>`
- `src/digital_dna/digital_dna.h` — `LatencyFingerprint` becomes `DecentralizedLatencyFingerprint` (or wraps it)
- `src/digital_dna/digital_dna.cpp` — Update `calculate_latency_similarity()` for variable-length vectors
- `src/net/protocol.h` — Add P2P messages: `MSG_DNA_LATENCY_PING`, `MSG_DNA_LATENCY_PONG`
- `src/net/net_processing.cpp` — Handle new P2P messages

#### Protocol Changes

**Verifier Selection Algorithm:**
```
function select_verifiers(block_hash, registrant_id, registry, N=15):
    candidates = registry.get_active_identities()
    candidates.remove(registrant_id)
    candidates = candidates.filter(trust_score > MIN_VERIFIER_TRUST)

    # Deterministic shuffle seeded by block_hash + registrant_id
    seed = SHA3-256(block_hash || registrant_id)
    shuffle(candidates, seed)

    return candidates[:N]
```

**Measurement Protocol:**
1. Registrant broadcasts `MSG_DNA_LATENCY_PING` to selected verifiers
2. Each verifier responds with `MSG_DNA_LATENCY_PONG` containing signed RTT measurement
3. Registrant collects responses (minimum 10 of 15 required)
4. Validators verify: selection was deterministic from block hash, signatures valid, RTT physically plausible

**Backward Compatibility:**
- During bootstrap (network < 50 active identities), fall back to seed node measurements
- Hybrid mode: use both seed + decentralized measurements when network is growing
- Full decentralized mode: network > 200 active identities

### Implementation Steps

1. Convert `array<LatencyStats, 4>` to `vector<LatencyStats>` across all files
2. Implement verifier selection algorithm (deterministic from block hash)
3. Define P2P message types for latency ping/pong
4. Implement `MSG_DNA_LATENCY_PING` / `PONG` handlers in net_processing
5. Create `DecentralizedLatencyFingerprint` struct with backward compat
6. Update similarity calculation for variable-length measurement vectors
7. Add bootstrap/hybrid/full mode switching based on network size
8. Add RPC command `getlatencyverifiers` to inspect selection
9. Write unit tests for verifier selection determinism
10. Write integration tests with simulated network

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Verifiers refuse to respond | Medium | Measurement fails | Over-select (15 for 10 needed), timeout + retry |
| Verifiers collude to lie | Low | Wrong fingerprint | Require geographic diversity (see Improvement 10) |
| Network too small for diversity | High (early) | Poor fingerprint | Hybrid mode with seed fallback |
| Block hash manipulation | Very Low | Biased selection | Use hash of block N-100 (deep enough to prevent reorgs) |

### Success Metrics

- Verifier selection produces geographically diverse set (>3 regions in >80% of cases)
- Measurement completion rate >90% (10+ of 15 verifiers respond)
- Latency fingerprints from decentralized measurement match seed node measurements within 15% for same node
- No single entity can predict their verifier set before the selection block is mined

### Test Plan

- **Unit test**: Verifier selection is deterministic (same block hash + registrant = same verifiers)
- **Unit test**: Verifier selection excludes registrant from candidate pool
- **Unit test**: Variable-length latency similarity calculation produces correct scores
- **Unit test**: Backward compatibility — old 4-seed fingerprints still compare correctly
- **Integration test**: 3+ node network performs decentralized latency measurement
- **Fuzz test**: Random block hashes produce uniform verifier distribution

---

## Improvement 2: Clock Drift Fingerprinting (5th Dimension)

**ROI Rank: #2** | **Effort: M (1-2 weeks)** | **Phase: B**

### Summary

Every computer's quartz crystal oscillator drifts uniquely due to manufacturing imprecision. By measuring clock drift relative to peers over the observation window, we add a 5th dimension that is orthogonal to all existing dimensions, stable over weeks, and trivially detects co-located VMs (which share the same physical oscillator).

### Technical Design

#### Data Structures

```cpp
// New: src/digital_dna/clock_drift.h

struct ClockDriftSample {
    std::array<uint8_t, 20> reference_peer;  // Who we compared against
    int64_t offset_us;                        // Our clock offset from peer (microseconds)
    uint64_t timestamp;                       // When sampled
};

struct ClockDriftFingerprint {
    // Raw samples collected over observation window
    std::vector<ClockDriftSample> samples;

    // Derived metrics
    double drift_rate_ppm;          // Parts per million drift relative to consensus
    double drift_stability;         // Std dev of drift rate over time (lower = more stable)
    double jitter_signature;        // Characteristic jitter pattern

    // Measurement metadata
    uint64_t observation_start;
    uint64_t observation_end;
    uint32_t num_reference_peers;

    // Comparison
    static double similarity(const ClockDriftFingerprint& a, const ClockDriftFingerprint& b);
};
```

#### New Files
- `src/digital_dna/clock_drift.h` — Clock drift fingerprint structures
- `src/digital_dna/clock_drift.cpp` — Collection and comparison logic

#### Changes to Existing Files
- `src/digital_dna/digital_dna.h` — Add `ClockDriftFingerprint drift;` to `DigitalDNA` struct
- `src/digital_dna/digital_dna.cpp` — Update combined similarity calculation (new weight for drift)
- `src/net/protocol.h` — Add `MSG_DNA_TIME_SYNC` message for clock comparison
- `src/net/net_processing.cpp` — Handle time sync messages

#### Measurement Protocol

**How Clock Drift is Measured:**
1. During the observation window (100 blocks, ~7 hours), periodically exchange timestamps with connected peers
2. Each exchange: send local timestamp → receive peer's local timestamp → compute round-trip and one-way offset
3. Over many samples, compute the linear regression of offset vs. time = drift rate
4. The drift rate itself (ppm) plus its stability (std dev) forms the fingerprint

**Why VMs on Same Host are Detectable:**
- VMs on the same physical host share the same quartz oscillator
- Their drift rates will be nearly identical (within measurement noise)
- Different physical machines have drift rates that differ by 1-100 ppm
- Similarity threshold: drift rates within 0.1 ppm = likely same oscillator

**Updated Similarity Weights (with 5th dimension):**
```
Combined = 0.15×L + 0.25×V + 0.30×P + 0.15×D + 0.15×M
```
(D = clock drift, M = memory fingerprint from Improvement 4)

Note: Exact weights should be empirically calibrated on live network data.

### Implementation Steps

1. Define `ClockDriftFingerprint` data structure
2. Implement timestamp exchange protocol (piggyback on existing P2P ping/pong or new message)
3. Implement drift rate computation via linear regression on offset samples
4. Implement jitter signature extraction (FFT or statistical moments of offset residuals)
5. Implement similarity function (compare drift rate, stability, jitter)
6. Add `ClockDriftFingerprint` field to `DigitalDNA` struct
7. Update `DigitalDNACollector` to collect clock drift during observation window
8. Update combined similarity weights
9. Add `getclockdrift` RPC command
10. Write unit and integration tests

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| NTP correction masks drift | Medium | Drift appears uniform | Measure between peers, not against NTP; use raw monotonic clock |
| Network jitter obscures signal | Medium | Noisy measurements | Collect many samples (100+), use median/regression |
| VM hypervisor virtualizes TSC | Low | Different VMs appear different | Also measure wall-clock drift, not just TSC |
| Short observation window | Medium | Insufficient samples | Minimum 4 hours observation, 50+ samples |

### Success Metrics

- Two runs on the same machine produce drift rates within 0.5 ppm of each other
- Two different physical machines produce drift rates differing by >1 ppm in >90% of cases
- Two VMs on same host produce drift rates within 0.2 ppm (correctly flagged as similar)
- Clock drift dimension adds >5% improvement to Sybil detection accuracy in testing

### Test Plan

- **Unit test**: Linear regression correctly computes drift from synthetic samples
- **Unit test**: Similarity function returns >0.9 for identical drift profiles, <0.3 for different
- **Unit test**: Jitter signature extraction produces stable results across runs
- **Integration test**: Two nodes exchange timestamps and produce valid drift fingerprints
- **Real hardware test**: Run on 3+ distinct machines, verify different drift rates
- **VM test**: Run 2 VMs on same host, verify drift rates are correlated

---

## Improvement 3: Progressive Trust Scoring

**ROI Rank: #3** | **Effort: M (1-2 weeks)** | **Phase: A**

### Summary

Currently identity is binary (active/inactive). Progressive trust creates a time-weighted reputation score that makes Sybil attacks fundamentally more expensive — an attacker creating 100 new identities gets 100 low-trust identities, while a legitimate miner with months of honest participation has a high-trust identity with protocol privileges.

### Technical Design

#### Data Structures

```cpp
// New: src/digital_dna/trust_score.h

struct TrustEvent {
    enum Type {
        HEARTBEAT_SUCCESS,      // +1.0
        HEARTBEAT_MISSED,       // -5.0
        BLOCK_RELAYED_HONEST,   // +0.1
        SYBIL_CHALLENGE_RECEIVED, // -10.0 (temporary hold)
        SYBIL_CHALLENGE_CLEARED,  // +2.0 (vindicated)
        REGISTRATION_COMPLETE,    // +0.0 (start at zero)
    };

    Type type;
    uint32_t block_height;
    uint64_t timestamp;
    double score_delta;
};

struct TrustScore {
    double current_score;        // Current trust score (0.0 to 100.0)
    double lifetime_score;       // Sum of all positive contributions
    uint32_t registration_height;
    uint32_t last_heartbeat_height;
    uint32_t consecutive_heartbeats;
    uint32_t missed_heartbeats;
    std::vector<TrustEvent> recent_events;  // Last 100 events

    // Trust tier thresholds
    static constexpr double TIER_UNTRUSTED = 0.0;
    static constexpr double TIER_NEW = 10.0;
    static constexpr double TIER_ESTABLISHED = 30.0;
    static constexpr double TIER_TRUSTED = 60.0;
    static constexpr double TIER_VETERAN = 90.0;

    // Decay: trust decays by 0.1% per 2000 blocks (~5.5 days) of inactivity
    static constexpr double DECAY_RATE = 0.001;
    static constexpr uint32_t DECAY_INTERVAL = 2000;

    enum Tier { UNTRUSTED, NEW, ESTABLISHED, TRUSTED, VETERAN };
    Tier get_tier() const;

    // Time-weighted score: score * log2(age_in_blocks / 1000 + 1)
    double time_weighted_score(uint32_t current_height) const;
};

class TrustScoreManager {
public:
    // Record events
    void on_heartbeat_success(const std::array<uint8_t, 20>& address, uint32_t height);
    void on_heartbeat_missed(const std::array<uint8_t, 20>& address, uint32_t height);
    void on_block_relayed(const std::array<uint8_t, 20>& address, uint32_t height);
    void on_sybil_challenge(const std::array<uint8_t, 20>& address, uint32_t height, bool cleared);

    // Query
    TrustScore get_score(const std::array<uint8_t, 20>& address) const;
    TrustScore::Tier get_tier(const std::array<uint8_t, 20>& address) const;

    // Persistence (LevelDB)
    bool save(const std::string& db_path) const;
    bool load(const std::string& db_path);

private:
    std::map<std::array<uint8_t, 20>, TrustScore> scores_;

    void apply_decay(TrustScore& score, uint32_t current_height);
    void clamp_score(TrustScore& score);
};
```

#### New Files
- `src/digital_dna/trust_score.h` — Trust score structures and manager
- `src/digital_dna/trust_score.cpp` — Implementation

#### Changes to Existing Files
- `src/digital_dna/digital_dna.h` — Add `TrustScore trust;` to `DigitalDNA` or reference via registry
- `src/digital_dna/digital_dna_rpc.h/cpp` — Add `gettrustscore`, `gettrusttier` RPC commands
- `src/consensus/params.h` — Add trust-related consensus parameters

#### Protocol Impact

Trust tiers affect protocol behavior:

| Tier | Score | Privileges |
|------|-------|------------|
| UNTRUSTED | 0-10 | Basic participation only |
| NEW | 10-30 | Can participate in witness committees (low weight) |
| ESTABLISHED | 30-60 | Full witness committee participation |
| TRUSTED | 60-90 | Priority in block relay tie-breaking, higher witness weight |
| VETERAN | 90-100 | Can serve as latency measurement reference node |

### Implementation Steps

1. Define `TrustScore` and `TrustEvent` data structures
2. Implement `TrustScoreManager` with event handlers
3. Implement decay logic (0.1% per 2000 blocks of inactivity)
4. Implement time-weighted scoring formula
5. Implement tier classification
6. Wire heartbeat events to trust manager (from temporal presence system)
7. Wire block relay events to trust manager (from net_processing)
8. Wire Sybil challenge events to trust manager (from registration system)
9. Add LevelDB persistence for trust scores
10. Add `gettrustscore` and `gettrusttier` RPC commands
11. Write comprehensive tests

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Gaming via fake relays | Medium | Inflated trust | Only count relays verified by recipients |
| Established Sybils hard to remove | Low | Trust protects attacker | Sybil challenge zeroes trust instantly |
| New legitimate users disadvantaged | Medium | Adoption friction | New tier still allows basic participation |
| Trust score consensus disagreement | Medium | Fork risk | Trust is local advisory, not consensus-critical |

### Success Metrics

- Trust scores increase monotonically for honest nodes (absent challenges)
- 6-month-old identity has score >60 (TRUSTED tier)
- Newly created identity starts at 0 (UNTRUSTED tier)
- Trust decay correctly reduces score after missed heartbeats
- Trust zeroing on Sybil challenge works correctly

### Test Plan

- **Unit test**: Score starts at 0 after registration
- **Unit test**: Heartbeat success increments score correctly
- **Unit test**: Missed heartbeat decrements score correctly
- **Unit test**: Decay reduces score after inactivity period
- **Unit test**: Time-weighted score increases with age
- **Unit test**: Tier classification at boundary values
- **Unit test**: Score clamping (never below 0, never above 100)
- **Integration test**: Full lifecycle — register, heartbeat, challenge, clear, verify trust progression
- **Regression test**: Trust scores survive save/load cycle

---

## Improvement 4: Memory Subsystem Fingerprinting

**ROI Rank: #4** | **Effort: S (1 week)** | **Phase: A**

### Summary

The current timing signature only measures VDF computation speed (CPU-bound). Memory hierarchy characteristics (L1/L2/L3 cache sizes, DRAM latency, memory bandwidth) vary dramatically between hardware. By probing the memory subsystem during registration, we create a much richer hardware fingerprint that makes it trivially detectable when "different" identities run on identical hardware.

### Technical Design

#### Data Structures

```cpp
// New: src/digital_dna/memory_fingerprint.h

struct MemoryProbeResult {
    uint32_t working_set_kb;        // Size of working set for this probe
    double access_time_ns;          // Average access time at this working set size
    double bandwidth_mbps;          // Throughput at this working set size
};

struct MemoryFingerprint {
    // Access time curve at different working set sizes
    // Sharp jumps indicate cache boundaries (L1→L2→L3→DRAM)
    std::vector<MemoryProbeResult> access_curve;

    // Derived features
    double estimated_l1_kb;         // Detected L1 cache size (jump point)
    double estimated_l2_kb;         // Detected L2 cache size
    double estimated_l3_kb;         // Detected L3 cache size
    double dram_latency_ns;         // Main memory latency
    double peak_bandwidth_mbps;     // Peak memory bandwidth

    // Comparison
    static double similarity(const MemoryFingerprint& a, const MemoryFingerprint& b);
};

class MemoryFingerprintCollector {
public:
    // Collect memory fingerprint (~5-10 seconds)
    MemoryFingerprint collect();

private:
    // Probe at specific working set size
    MemoryProbeResult probe(uint32_t working_set_kb, uint32_t iterations);

    // Detect cache boundaries from access curve
    void detect_cache_boundaries(MemoryFingerprint& fp);

    // Working set sizes to probe (KB): 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048,
    // 4096, 8192, 16384, 32768, 65536
    static const std::vector<uint32_t> PROBE_SIZES;
};
```

#### New Files
- `src/digital_dna/memory_fingerprint.h` — Data structures
- `src/digital_dna/memory_fingerprint.cpp` — Memory probing and comparison

#### Changes to Existing Files
- `src/digital_dna/digital_dna.h` — Add `MemoryFingerprint memory;` to `DigitalDNA`
- `src/digital_dna/digital_dna.cpp` — Add memory similarity to combined score
- `src/digital_dna/digital_dna.cpp` — Update `DigitalDNACollector` to run memory probe

#### How Memory Probing Works

```
For each working_set_size in [4KB, 8KB, 16KB, ..., 64MB]:
    1. Allocate buffer of working_set_size
    2. Initialize with random pointer-chase pattern
    3. Time 1 million random accesses
    4. Record average access time

Result: Access time curve shows sharp jumps at cache boundaries:
    4KB-32KB:  ~1ns   (L1 cache)
    32KB-256KB: ~4ns  (L2 cache)
    256KB-8MB:  ~12ns (L3 cache)
    >8MB:      ~80ns  (DRAM)

Each machine has a unique curve shape.
```

#### Similarity Function

```
similarity(A, B) = 1.0 - normalized_dtw_distance(A.access_curve, B.access_curve)
```

Uses Dynamic Time Warping (DTW) to compare curves, handling slight offsets in cache boundary positions. Normalize by curve length so result is in [0, 1].

### Implementation Steps

1. Implement pointer-chase memory probe (random access pattern to defeat prefetcher)
2. Implement sequential bandwidth probe (streaming access pattern)
3. Define probe sizes (15 sizes from 4KB to 64MB)
4. Implement cache boundary detection (find inflection points in access curve)
5. Implement DTW-based similarity function
6. Add `MemoryFingerprint` to `DigitalDNA` struct
7. Add memory probing to `DigitalDNACollector::start_collection()`
8. Update combined similarity weights
9. Add `getmemoryfingerprint` RPC command
10. Write unit tests with synthetic and real-hardware data

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| OS background processes affect timing | Medium | Noisy results | Run multiple iterations, use median; pin to CPU core if possible |
| Cloud VMs have variable memory perf | Medium | Unstable fingerprint | Include variance as part of fingerprint (cloud VMs have higher variance) |
| Same CPU model = similar fingerprint | Medium | False positives | Memory fingerprint is one of 6 dimensions, others differentiate |
| NUMA effects on multi-socket | Low | Inconsistent results | Pin to single NUMA node during collection |

### Success Metrics

- Cache boundaries detected correctly for L1, L2, L3 on >90% of tested hardware
- Two runs on same machine produce similarity >0.95
- Different hardware classes (laptop/desktop/server) produce similarity <0.5
- Probe completes in <10 seconds
- Combined with timing signature, hardware fingerprint false positive rate drops by >30%

### Test Plan

- **Unit test**: Pointer-chase probe returns consistent results across runs (<5% variance)
- **Unit test**: Cache boundary detection identifies correct sizes for known hardware
- **Unit test**: DTW similarity returns >0.9 for identical curves, <0.4 for different
- **Unit test**: Probe handles allocation failure gracefully (large working sets)
- **Real hardware test**: Run on 3+ machines, verify distinct fingerprints
- **Cross-platform test**: Verify probe works on Windows (MSYS2), Linux, macOS

---

## Improvement 5: Economic Stake Bond

**ROI Rank: #5** | **Effort: L (2-3 weeks)** | **Phase: C**

### Summary

Layer an economic dimension on top of physics-based proofs. Identities must lock DILI tokens when registering (slashed if proven Sybil). This creates a direct monetary cost for Sybil attacks beyond infrastructure costs, and incentivizes the community to police the network by rewarding successful challengers.

### Technical Design

#### Data Structures

```cpp
// New: src/digital_dna/stake_bond.h

struct StakeBond {
    std::array<uint8_t, 20> identity_address;
    uint64_t amount_satoshis;       // Amount locked (in smallest unit)
    uint32_t lock_height;           // Block where bond was created
    uint32_t unlock_height;         // Earliest block where bond can be reclaimed (0 = locked)
    std::array<uint8_t, 32> bond_txid;  // Transaction that created the bond

    static constexpr uint64_t MIN_BOND = 10'000'000;   // 0.1 DILI minimum
    static constexpr uint64_t MAX_BOND = 1'000'000'000; // 10 DILI maximum
    static constexpr uint32_t LOCK_PERIOD = 10'000;     // ~27.5 days minimum lock
};

struct SybilChallenge {
    std::array<uint8_t, 20> challenger_address;
    std::array<uint8_t, 20> target_address;
    std::array<uint8_t, 20> suspected_sybil_address; // The identity target is allegedly same as
    SimilarityScore evidence;                          // Similarity score as evidence
    uint64_t challenger_stake;                        // Challenger must also stake
    uint32_t challenge_height;
    uint32_t resolution_height;                       // 0 = pending

    enum Resolution { PENDING, UPHELD, REJECTED };
    Resolution resolution = PENDING;

    static constexpr uint64_t MIN_CHALLENGE_STAKE = 5'000'000;  // 0.05 DILI
    static constexpr uint32_t CHALLENGE_PERIOD = 200;           // ~9 hours for resolution
};

struct SlashResult {
    uint64_t slashed_amount;        // Amount taken from target
    uint64_t challenger_reward;     // 50% to challenger
    uint64_t burn_amount;           // 50% burned (prevents self-challenge gaming)
};
```

#### New Files
- `src/digital_dna/stake_bond.h` — Bond and challenge structures
- `src/digital_dna/stake_bond.cpp` — Bond management, challenge resolution
- `src/consensus/dna_consensus.h` — Consensus rules for DNA bonds

#### Changes to Existing Files
- `src/digital_dna/digital_dna.h` — Add `StakeBond bond;` to `DigitalDNA`
- `src/digital_dna/digital_dna_rpc.h/cpp` — Add `stakebond`, `challengeidentity`, `resolvechallenge` RPCs
- `src/consensus/params.h` — Bond amount parameters
- `src/core/transaction.h` — New transaction type or OP_CODE for bond operations
- `src/validation/tx_verify.cpp` — Validate bond transactions

#### Consensus Rules

1. **Bond Creation**: Special transaction output type, locked for LOCK_PERIOD blocks
2. **Bond Reclaim**: Only after LOCK_PERIOD and if identity is active (no pending challenges)
3. **Challenge**: Challenger posts stake + evidence (similarity score). Challenge period = 200 blocks.
4. **Resolution**: After challenge period, community validators vote (or automatic threshold: if similarity > 0.85, auto-upheld)
5. **Slash**: 50% to challenger, 50% burned. Target identity deactivated.
6. **Rejected Challenge**: Challenger loses stake (50% to target, 50% burned)

### Implementation Steps

1. Design bond transaction format (new OP_RETURN format or script type)
2. Implement bond creation and locking in transaction validation
3. Implement bond reclaim after lock period
4. Implement challenge submission (special transaction)
5. Implement challenge resolution (auto-resolution at threshold + manual appeals)
6. Implement slashing logic (50/50 split)
7. Add bond amount to trust score calculation (higher bond = higher trust ceiling)
8. Add `stakebond`, `challengeidentity`, `resolvechallenge` RPC commands
9. Update block validation to process DNA bond transactions
10. Write comprehensive tests including edge cases

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Self-challenge to grief competitors | Medium | False slashing | Challenger must also stake; rejected challenge = lose stake |
| Minimum bond too low for deterrence | Medium | Weak protection | Adjust parameters via soft fork; trust score weights bond amount |
| Bond locks capital, deters participation | Medium | Lower adoption | Keep minimum low (0.1 DILI), voluntary higher bonds for trust boost |
| Transaction complexity increases | Low | Validation bugs | Extensive testing, conservative deployment |

### Success Metrics

- Bond creation and reclaim transactions validate correctly
- Challenge → resolution → slash flow works end-to-end
- Self-challenge is unprofitable (50% burn makes it net negative)
- Average Sybil attack cost increases by >10x with bonding
- Bond reclaim succeeds after lock period for honest identities

### Test Plan

- **Unit test**: Bond creation locks funds correctly
- **Unit test**: Bond reclaim fails before lock period, succeeds after
- **Unit test**: Challenge with similarity >0.85 auto-upholds
- **Unit test**: Challenge with similarity <0.60 auto-rejects
- **Unit test**: Slash correctly splits 50/50 (challenger + burn)
- **Unit test**: Rejected challenge slashes challenger
- **Unit test**: Pending challenge prevents bond reclaim
- **Integration test**: Full lifecycle — bond → challenge → resolution → slash
- **Economic test**: Self-challenge is provably unprofitable

---

## Improvement 6: Zero-Knowledge Sybil Proofs

**ROI Rank: #6** | **Effort: XL (6-8 weeks)** | **Phase: D**

### Summary

Transform Digital DNA's privacy story by enabling zero-knowledge proofs of uniqueness. A registrant can prove "my fingerprint is sufficiently different from all registered identities" without revealing any component of their fingerprint. This makes Digital DNA the only Sybil resistance system in existence that proves uniqueness while revealing zero personal information.

### Technical Design

#### Approach: ZK-SNARKs (Groth16 via libsnark or PLONK via PLONKY2)

The ZK circuit proves:
```
Public inputs:
    - Merkle root of identity registry
    - Threshold value T (e.g., 0.85)
    - Registration commitment C = Hash(fingerprint || blinding_factor)

Private inputs (witness):
    - Full fingerprint F = (L, V, P, D, M, ...)
    - Blinding factor r
    - Merkle proofs for each existing identity

Circuit logic:
    1. Verify C = Hash(F || r)
    2. For each identity I_i in registry:
       a. Retrieve I_i via Merkle proof
       b. Compute similarity(F, I_i) using circuit arithmetic
       c. Assert similarity < T
    3. Assert each component of F is within valid range
```

#### Practical Simplification

Full ZK-SNARK over the entire registry is expensive. Practical approach:

**Commit-then-Reveal with ZK Distance Proofs:**
1. Registrant commits `C = Hash(fingerprint || blinding)` on-chain
2. N randomly selected verifiers each receive the fingerprint privately
3. Each verifier produces a ZK proof: "fingerprint differs from my set of identities by >T"
4. With 5/7 verifier proofs, registration accepted
5. Full fingerprint never published on-chain

This avoids proving over the entire registry in a single circuit.

#### New Files
- `src/digital_dna/zk_identity.h` — ZK proof structures, commitment scheme
- `src/digital_dna/zk_identity.cpp` — Proof generation and verification
- `src/digital_dna/zk_circuit.h` — Circuit definition for similarity checking
- `depends/` — ZK library dependency (libsnark, bellman, or plonky2)

#### Changes to Existing Files
- `src/digital_dna/digital_dna.h` — Add commitment field, optional full fingerprint
- `src/digital_dna/digital_dna.cpp` — Support commitment-based registration
- `src/consensus/dna_consensus.h` — ZK proof verification in consensus
- `src/net/protocol.h` — Private fingerprint transmission messages

### Implementation Steps

1. Research and select ZK library (libsnark vs bellman vs plonky2)
2. Define commitment scheme: `C = Poseidon(L || V || P || D || M || r)`
3. Define ZK circuit for pairwise similarity check
4. Implement circuit in chosen framework
5. Implement proof generation (prover side)
6. Implement proof verification (verifier side, fast)
7. Implement private fingerprint transmission (encrypted, to verifiers only)
8. Implement verifier-side proof generation workflow
9. Implement commitment-based registration flow
10. Add ZK proof to block validation pipeline
11. Benchmark proof generation time (target: <60 seconds)
12. Write comprehensive tests

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Proof generation too slow | High | Bad UX | Use PLONK (faster proving) or split into smaller proofs |
| ZK library adds large dependency | Medium | Build complexity | Evaluate lightweight alternatives; consider WASM-based provers |
| Circuit bugs allow invalid proofs | Medium | Security broken | Formal verification of circuit; extensive test vectors |
| Trusted setup requirement (Groth16) | Medium | Trust assumption | Use PLONK (no trusted setup) or contribute to ceremony |

### Success Metrics

- ZK proof generation completes in <60 seconds on commodity hardware
- Proof verification completes in <10 milliseconds
- Proof size < 1KB
- No false positives (valid uniqueness proofs for genuinely different identities)
- No false negatives (cannot prove uniqueness when identity is duplicate)
- Zero information leakage about fingerprint components

### Test Plan

- **Unit test**: Commitment scheme is binding and hiding
- **Unit test**: Valid proof verifies correctly
- **Unit test**: Invalid proof (same identity) fails verification
- **Unit test**: Proof over boundary similarity values (just above/below threshold)
- **Benchmark test**: Proof generation time on target hardware
- **Benchmark test**: Proof verification time
- **Security test**: Attempt to generate proof with forged fingerprint (must fail)

---

## Improvement 7: Proof of Bandwidth (6th Dimension)

**ROI Rank: #7** | **Effort: S (1 week)** | **Phase: B**

### Summary

Network bandwidth is a physical constraint that varies dramatically between connection types (home broadband, datacenter, mobile). Measuring relay throughput adds an orthogonal dimension and helps detect co-located VMs that share bandwidth (contention detection).

### Technical Design

#### Data Structures

```cpp
// New: src/digital_dna/bandwidth_proof.h

struct BandwidthMeasurement {
    std::array<uint8_t, 20> peer_id;       // Who we measured against
    double upload_mbps;                     // Upload throughput
    double download_mbps;                   // Download throughput
    double asymmetry_ratio;                 // upload/download (home ~0.1, datacenter ~1.0)
    uint64_t timestamp;
    std::array<uint8_t, 64> peer_signature; // Peer attests to measurement
};

struct BandwidthFingerprint {
    std::vector<BandwidthMeasurement> measurements;

    // Derived metrics
    double median_upload_mbps;
    double median_download_mbps;
    double median_asymmetry;
    double bandwidth_stability;    // Std dev of measurements (cloud = stable, home = variable)

    // Comparison
    static double similarity(const BandwidthFingerprint& a, const BandwidthFingerprint& b);
};
```

#### New Files
- `src/digital_dna/bandwidth_proof.h` — Bandwidth fingerprint structures
- `src/digital_dna/bandwidth_proof.cpp` — Measurement and comparison

#### Measurement Protocol

1. During observation window, perform bandwidth tests with 5+ connected peers
2. Send controlled-size payload (1MB), measure transfer time in both directions
3. Compute upload/download throughput and asymmetry ratio
4. Peers sign the measurement results (mutual attestation)

### Implementation Steps

1. Define bandwidth measurement protocol (controlled payload exchange)
2. Implement upload/download throughput measurement
3. Implement bandwidth fingerprint collection during observation window
4. Implement similarity function (compare throughput, asymmetry, stability)
5. Add `BandwidthFingerprint` to `DigitalDNA` struct
6. Update combined similarity weights
7. Add `getbandwidthproof` RPC command
8. Write tests

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| ISP throttling during test | Medium | Distorted results | Spread measurements over hours, use median |
| Bandwidth sharing with co-tenants | Medium | Variable results | Include variability as a feature (shared = variable) |
| Network congestion affects results | Medium | Noisy data | Multiple measurements at different times |

### Success Metrics

- Home connections show asymmetry ratio <0.3
- Datacenter connections show asymmetry ratio >0.8
- Same connection measured twice produces similarity >0.85
- Co-located VMs show bandwidth contention when measured simultaneously

### Test Plan

- **Unit test**: Throughput calculation from payload size and transfer time
- **Unit test**: Asymmetry ratio computation
- **Unit test**: Similarity function returns expected values for known profiles
- **Integration test**: Two nodes perform mutual bandwidth measurement
- **Network simulation test**: Verify contention detection with simulated shared bandwidth

---

## Improvement 8: Behavioral Consistency Layer

**ROI Rank: #8** | **Effort: S (1 week)** | **Phase: A**

### Summary

Track protocol participation patterns that emerge naturally from honest node operation. Over time, each identity develops a consistent behavioral profile — when they relay blocks (timezone proxy), how quickly they relay (position signal), their peer churn rate (stability signal). Batch-created Sybils show suspiciously uniform or artificially varied patterns.

### Technical Design

#### Data Structures

```cpp
// New: src/digital_dna/behavioral_profile.h

struct BehavioralProfile {
    // Activity distribution (24 hourly buckets)
    std::array<double, 24> hourly_activity;    // Block relay frequency by hour

    // Relay performance
    double mean_relay_delay_ms;                // How fast we relay new blocks
    double relay_consistency;                  // Std dev of relay delay

    // Peer behavior
    double avg_peer_session_duration;          // How long our peers stay connected
    double peer_diversity_score;               // ASN diversity of connected peers

    // Transaction patterns (no personal data, just timing)
    double tx_relay_rate;                      // Transactions relayed per hour
    double tx_timing_entropy;                  // Shannon entropy of tx creation times

    // Observation period
    uint32_t observation_blocks;               // How many blocks of data
    uint64_t start_time;
    uint64_t end_time;

    // Comparison
    static double similarity(const BehavioralProfile& a, const BehavioralProfile& b);
};
```

#### New Files
- `src/digital_dna/behavioral_profile.h` — Profile structures
- `src/digital_dna/behavioral_profile.cpp` — Collection and comparison

#### Changes to Existing Files
- `src/digital_dna/digital_dna.h` — Add `BehavioralProfile behavior;` to `DigitalDNA`
- `src/digital_dna/digital_dna.cpp` — Update combined similarity with behavioral component

### Implementation Steps

1. Define behavioral profile data structure
2. Implement hourly activity bucketing (relay times → 24-hour histogram)
3. Implement relay delay tracking (time between receiving block and relaying)
4. Implement peer session duration tracking
5. Implement similarity function (cosine similarity of hourly vectors + metric comparison)
6. Add `BehavioralProfile` to `DigitalDNA`
7. Wire collection into existing net_processing hooks
8. Update combined similarity weights
9. Add `getbehavioralprofile` RPC command
10. Write tests

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Privacy concern (timezone leak) | Medium | User objection | Profile is stored locally, only similarity compared |
| Behaviors change over time | High | Profile drift | Rolling window (last 30 days), profile update mechanism |
| Insufficient observation period | Medium | Weak signal | Minimum 7 days of data before profile is used |
| Sophisticated attacker randomizes behavior | Low | Evades detection | Hard to maintain convincingly random behavior across 6+ dimensions |

### Success Metrics

- Same node's profile over two consecutive weeks has similarity >0.80
- Two nodes in different timezones have hourly activity similarity <0.40
- Batch-created Sybils show detectable behavioral uniformity
- Behavioral dimension adds measurable improvement to Sybil detection accuracy

### Test Plan

- **Unit test**: Hourly bucketing correctly classifies block relay times
- **Unit test**: Cosine similarity of activity vectors returns expected values
- **Unit test**: Shannon entropy computation for timing data
- **Unit test**: Profile comparison with synthetic profiles
- **Integration test**: Node accumulates behavioral profile over simulated blocks

---

## Improvement 9: Inverse Sybil Protection (False Positive Handling)

**ROI Rank: #9** | **Effort: M (1-2 weeks)** | **Phase: C**

### Summary

Two legitimate miners at the same datacenter WILL get flagged as Sybils. Without a differentiation mechanism, the system risks punishing honest users. This improvement adds a challenge-response protocol where flagged pairs prove they are on distinct hardware, plus a community arbitration process for edge cases.

### Technical Design

#### Data Structures

```cpp
// New: src/digital_dna/differentiation.h

struct DifferentiationChallenge {
    std::array<uint8_t, 20> identity_a;
    std::array<uint8_t, 20> identity_b;
    std::array<uint8_t, 32> challenge_seed;   // Random seed for VDF challenges
    uint32_t challenge_height;
    uint32_t deadline_height;                 // Must respond within 100 blocks

    static constexpr uint32_t RESPONSE_WINDOW = 100;
};

struct DifferentiationResponse {
    std::array<uint8_t, 20> responder;
    std::array<uint8_t, 32> vdf_output;       // VDF computed on unique challenge
    std::vector<uint8_t> vdf_proof;           // Wesolowski proof
    MemoryFingerprint memory_snapshot;         // Fresh memory fingerprint
    ClockDriftFingerprint drift_snapshot;      // Fresh clock drift measurement

    // If both responses have different VDF timing profiles + different memory curves
    // + different drift rates → different hardware confirmed
};

struct DifferentiationResult {
    bool hardware_different;         // VDF timing + memory fingerprint differ sufficiently
    bool clock_different;            // Clock drift rates differ
    double confidence;               // Overall confidence (0-1)
    std::string reasoning;           // Human-readable explanation
};
```

#### Protocol

1. When two identities flag as suspicious (similarity 0.60-0.85), system issues `DifferentiationChallenge`
2. Both parties receive unique VDF challenges: `challenge_a = SHA3(seed || "A")`, `challenge_b = SHA3(seed || "B")`
3. Both must run VDF simultaneously and submit results within 100 blocks
4. Verifiers compare:
   - VDF timing profiles (if on different hardware, computation speeds differ)
   - Memory fingerprints (if on different machines, cache hierarchies differ)
   - Clock drift (if on different motherboards, drift rates differ)
5. If at least 2 of 3 differ significantly → **different hardware confirmed**, both identities cleared
6. If all 3 match → **same hardware**, one identity must be deactivated

### Implementation Steps

1. Define challenge/response data structures
2. Implement challenge issuance (automatic when similarity is suspicious)
3. Implement simultaneous VDF computation with unique challenges
4. Implement response collection and comparison
5. Implement differentiation decision logic (2-of-3 threshold)
6. Add community arbitration for ambiguous cases
7. Wire into registration and similarity detection pipeline
8. Add `differentiate`, `getdifferentiationstatus` RPC commands
9. Write tests

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| One party refuses to respond | Medium | Can't differentiate | Non-response = treated as same identity (incentive to respond) |
| Both respond but hardware very similar | Low | Ambiguous result | Community arbitration; additional manual proof accepted |
| Resource cost of running extra VDFs | Low | UX friction | Only triggered for suspicious pairs, not routine |

### Success Metrics

- Two nodes on different hardware at same datacenter pass differentiation >95% of the time
- Two VMs on same physical host fail differentiation >95% of the time
- Differentiation completes within 100 blocks
- False positive rate (honest users flagged and unable to prove difference) <1%

### Test Plan

- **Unit test**: Challenge generation produces unique VDF challenges per party
- **Unit test**: Response comparison correctly identifies different hardware
- **Unit test**: Response comparison correctly identifies same hardware
- **Unit test**: 2-of-3 threshold logic works at boundary cases
- **Integration test**: Full challenge → response → resolution flow with 2 nodes
- **Edge case test**: One party times out, verify correct handling

---

## Improvement 10: Witness Geographic Diversity Requirement

**ROI Rank: #10** | **Effort: S (1 week)** | **Phase: B**

### Summary

Currently the witness protocol requires 3/5 attestations, but all 5 witnesses could be in the same geographic region, making collusion easier. This improvement requires witnesses from at least 3 different geographic regions, using the latency fingerprint to classify regions.

### Technical Design

#### Region Classification

```cpp
// In: src/digital_dna/decentralized_latency.h (or witness_selection.h)

enum class GeoRegion {
    AMERICAS_EAST,    // <30ms to NYC
    AMERICAS_WEST,    // <60ms to NYC, <30ms to hypothetical LA node
    EUROPE,           // <30ms to London
    ASIA_EAST,        // <30ms to Singapore
    OCEANIA,          // <30ms to Sydney
    UNKNOWN           // Doesn't clearly fit any region
};

struct WitnessSelectionPolicy {
    uint32_t total_witnesses = 7;         // Select 7
    uint32_t required_attestations = 5;   // Need 5
    uint32_t min_regions = 3;             // From at least 3 regions
    uint32_t max_per_region = 2;          // No more than 2 from same region
};

// Classify a node's region from its latency fingerprint
GeoRegion classify_region(const LatencyFingerprint& fingerprint);

// Select witnesses with geographic diversity
std::vector<std::array<uint8_t, 20>> select_diverse_witnesses(
    const std::array<uint8_t, 32>& block_hash,
    const std::array<uint8_t, 20>& registrant,
    const DigitalDNARegistry& registry,
    const WitnessSelectionPolicy& policy
);
```

### Implementation Steps

1. Implement region classification from latency fingerprints
2. Modify witness selection to enforce geographic diversity constraints
3. Add fallback for small networks (relax constraints if insufficient diversity)
4. Update registration validation to verify witness diversity
5. Add `getwitnessdiversity` RPC command for diagnostics
6. Write tests

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Not enough witnesses in some regions | High (early) | Can't meet diversity | Fallback to relaxed constraints; bootstrap mode |
| Region classification wrong | Medium | Incorrect diversity | Use conservative classification with UNKNOWN fallback |
| Latency-based region gaming | Low | Witness selection manipulation | Region is advisory, not exact; overlap with other dimensions |

### Success Metrics

- Witness set contains nodes from 3+ regions in >80% of registrations (mature network)
- No single region contributes >40% of witnesses in any registration
- Geographic diversity correlates with lower collusion rate in simulations

### Test Plan

- **Unit test**: Region classification returns correct region for known latency profiles
- **Unit test**: Witness selection produces diverse sets from synthetic registry
- **Unit test**: Fallback mode activates when diversity constraints can't be met
- **Integration test**: Registration with diverse witness committee completes successfully

---

## Improvement 11: Thermal Throttling Curve

**ROI Rank: #11** | **Effort: S (1 week)** | **Phase: A**

### Summary

During the 15-minute VDF registration computation, CPUs heat up and throttle at different rates depending on cooling solution, TDP, and form factor. By measuring VDF speed at intervals throughout the computation, we capture a "cooling curve" that distinguishes laptops from desktops from servers — at zero extra computation cost (we're already running the VDF).

### Technical Design

#### Data Structures

```cpp
// Extension to: src/digital_dna/timing_signature.h

struct ThermalProfile {
    // VDF speed at different points during the 15-minute computation
    std::vector<double> speed_curve;   // iterations/sec at each minute
    uint32_t measurement_interval_sec; // How often we sample (e.g., 60s)

    // Derived metrics
    double initial_speed;              // Speed in first minute (before thermal)
    double sustained_speed;            // Speed in last 5 minutes (steady state)
    double throttle_ratio;             // sustained/initial (1.0 = no throttle, 0.7 = 30% throttle)
    double time_to_steady_state_sec;   // How long until speed stabilizes
    double thermal_jitter;             // Std dev of speed in steady state

    // Comparison
    static double similarity(const ThermalProfile& a, const ThermalProfile& b);
};
```

#### Integration with Existing VDF

The VDF computation in `timing_signature.cpp` already collects checkpoints. We simply group checkpoints by minute and compute per-minute iteration rates:

```cpp
// In TimingSignatureCollector::collect():
// After VDF completes, derive thermal profile from existing checkpoint data

ThermalProfile derive_thermal_profile(const TimingSignature& sig) {
    ThermalProfile profile;
    // Group checkpoints into 1-minute buckets
    // Compute iterations/sec per bucket
    // Fit throttling curve
    return profile;
}
```

No additional computation required — we extract this from data we already collect.

### Implementation Steps

1. Add `ThermalProfile` struct to `timing_signature.h`
2. Implement `derive_thermal_profile()` from existing checkpoint data
3. Implement thermal similarity function
4. Add thermal profile to `TimingSignature` (derived, not stored separately)
5. Update timing similarity to incorporate thermal curve comparison
6. Add thermal data to `gettimingsignature` RPC output
7. Write tests

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| AC/ambient temp affects throttling | Medium | Variable results | Include variability as feature; measure over long enough window |
| Cloud VMs don't throttle (shared cooling) | Medium | Less distinctive | Cloud VMs already detectable via other dimensions |
| 10-second testnet VDF too short for thermal effects | High | Testnet only | Only enable thermal for mainnet (200s VDF) |

### Success Metrics

- Laptop throttle ratio typically 0.70-0.90 (significant throttling)
- Desktop throttle ratio typically 0.90-0.98 (minimal throttling)
- Server throttle ratio typically 0.95-1.00 (no throttling, active cooling)
- Same machine's thermal profile is consistent across runs (similarity >0.90)

### Test Plan

- **Unit test**: Thermal profile derivation from synthetic checkpoint data
- **Unit test**: Throttle ratio computation
- **Unit test**: Time-to-steady-state detection
- **Unit test**: Thermal similarity function
- **Integration test**: Full VDF computation produces valid thermal profile (mainnet params only)

---

## Improvement 12: Cross-Chain Identity Portability

**ROI Rank: #12** | **Effort: XL (4-6 weeks)** | **Phase: D**

### Summary

Allow Digital DNA identities to be verified on other blockchains without revealing the underlying fingerprints. This makes Dilithion the universal Sybil oracle — other chains pay to query Digital DNA's registry, creating token demand and establishing Dilithion as critical infrastructure.

### Technical Design

#### Approach: Attestation Bridge

Rather than full ZK cross-chain proofs (very expensive), use an attestation model:

```
1. User requests identity attestation on Dilithion
2. Dilithion validators produce signed attestation:
   "Address X has active Digital DNA, trust tier Y, registered at height Z"
3. Attestation is posted on target chain (Ethereum, Solana, etc.)
4. Target chain smart contract verifies Dilithion validator signatures
5. dApp on target chain queries attestation contract
```

#### Data Structures

```cpp
// New: src/digital_dna/cross_chain.h

struct IdentityAttestation {
    std::array<uint8_t, 20> dilithion_address;
    std::array<uint8_t, 20> target_chain_address;  // Address on target chain
    uint8_t target_chain_id;                         // 1=ETH, 2=SOL, etc.
    TrustScore::Tier trust_tier;
    uint32_t registration_height;
    uint32_t attestation_height;
    uint32_t expiry_height;                          // Attestation expires after N blocks
    std::array<uint8_t, 32> identity_commitment;     // Hash commitment (no raw data)

    // Multi-sig from Dilithion validators
    std::vector<std::array<uint8_t, 64>> validator_signatures;
    uint32_t required_signatures;                    // M-of-N threshold
};
```

#### External Components (not in Dilithion codebase)
- Ethereum smart contract: `DigitalDNAVerifier.sol` — Verifies attestation signatures
- Solana program: `digital_dna_verifier` — Same for Solana
- SDK/API: Client libraries for dApps to query Digital DNA status

### Implementation Steps

1. Define attestation data structure and serialization format
2. Implement attestation request RPC command
3. Implement validator attestation signing (M-of-N from active validators)
4. Implement attestation verification on Dilithion side
5. Create Ethereum smart contract for attestation verification
6. Create client SDK for querying attestation status
7. Define attestation expiry and renewal protocol
8. Test end-to-end flow: Dilithion → attestation → Ethereum → dApp query

### Dependencies

- **Requires:** Improvement 6 (ZK Proofs) for privacy-preserving attestations
- **Requires:** Improvement 3 (Trust Scoring) for trust tier attestation
- **Requires:** Stable identity registry with sufficient network size

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Validator collusion | Medium | False attestations | Require M-of-N from geographically diverse validators |
| Bridge security | High | Funds at risk | Conservative design, no funds in bridge, attestation-only |
| Adoption requires other chains | High | Low usage | Start with EVM chains (largest ecosystem) |
| Attestation staleness | Medium | Stale trust data | Short expiry (1 week), automatic renewal |

### Success Metrics

- Attestation generation completes in <10 seconds
- Ethereum verification gas cost <100K gas
- End-to-end latency (request to on-chain attestation) <5 minutes
- At least one dApp integrates Digital DNA attestation within 3 months of launch

### Test Plan

- **Unit test**: Attestation serialization/deserialization roundtrip
- **Unit test**: M-of-N signature verification
- **Unit test**: Attestation expiry logic
- **Smart contract test**: Ethereum verifier correctly validates/rejects attestations
- **Integration test**: Full flow from Dilithion identity to Ethereum attestation to dApp query

---

## Improvement 13: ML Anomaly Detection

**ROI Rank: #13** | **Effort: L (2-3 weeks)** | **Phase: D**

### Summary

Replace fixed similarity thresholds with a machine learning model trained on real network data. The ML model can detect statistical anomalies that fixed rules miss, adapt to new attack patterns, and calibrate automatically to network conditions.

### Technical Design

#### Approach: Isolation Forest + Feature Engineering

Rather than deep learning (too complex for a blockchain node), use lightweight anomaly detection:

```
Features per identity pair:
    1. Latency Euclidean distance
    2. Latency Wasserstein distance per seed
    3. VDF speed ratio
    4. VDF checkpoint correlation
    5. Memory curve DTW distance
    6. Clock drift rate difference
    7. Peer set Jaccard similarity
    8. Hourly activity cosine similarity
    9. Bandwidth asymmetry ratio difference
    10. Thermal throttle ratio difference
    11. Trust score difference
    12. Registration time gap
    13. Geographic region match (binary)
```

**Model**: Isolation Forest (unsupervised, lightweight, no training labels needed)
- Fits in <1MB of memory
- Inference in microseconds
- Retrains periodically as network grows
- Runs locally on each node (no centralized model server)

#### New Files
- `src/digital_dna/ml_detector.h` — Feature engineering and model interface
- `src/digital_dna/ml_detector.cpp` — Isolation Forest implementation
- `src/digital_dna/isolation_forest.h` — Lightweight IF implementation (no external ML library)

#### Training Pipeline

```
Every 10,000 blocks:
    1. Extract all pairwise features from registry
    2. Train Isolation Forest on feature matrix
    3. Compute anomaly scores for all pairs
    4. Flag pairs with anomaly score > threshold
    5. Compare with fixed-threshold results
    6. Update adaptive threshold based on distribution
```

### Implementation Steps

1. Implement Isolation Forest from scratch (no external dependency, ~300 lines)
2. Define feature engineering pipeline (extract 13 features per pair)
3. Implement periodic retraining trigger (every 10K blocks)
4. Implement anomaly scoring function
5. Add ML-based flagging alongside existing threshold-based flagging
6. Add `getmlstatus`, `getmlanomalies` RPC commands
7. Add logging for ML vs threshold comparison (for validation)
8. Initially run in advisory mode (log anomalies but don't auto-reject)
9. After validation period, optionally enable as primary detector
10. Write tests with synthetic attack datasets

### Dependencies

- **Requires:** Sufficient network data (>100 active identities) for meaningful training
- **Benefits from:** All other improvements (more dimensions = better features)

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Insufficient training data early on | High | Poor model | Advisory mode only until >100 identities |
| Model drift as network evolves | Medium | Stale detection | Periodic retraining every 10K blocks |
| Different nodes train different models | High | Consensus disagreement | ML is advisory only, not consensus-critical |
| Adversarial ML attacks | Low | Evade detection | Ensemble with fixed thresholds; ML supplements, doesn't replace |

### Success Metrics

- ML model detects >90% of synthetically injected Sybils
- False positive rate <5%
- ML catches cases that fixed thresholds miss (validated on test data)
- Model retraining completes in <60 seconds
- Model size <1MB in memory

### Test Plan

- **Unit test**: Isolation Forest implementation produces correct anomaly scores on known data
- **Unit test**: Feature engineering extracts correct values from identity pairs
- **Unit test**: Retraining produces stable model across runs with same data
- **Synthetic attack test**: Inject known Sybil patterns, verify detection
- **False positive test**: Verify legitimate diverse identities are not flagged
- **Performance test**: Inference time <1ms per pair, retraining <60s

---

## Resource Allocation (Recommended)

### With 1 Developer

| Week | Work |
|------|------|
| 1-2 | Pre-requisites (fix 6 codebase issues) |
| 3-4 | Improvements 4 (Memory) + 11 (Thermal) — both quick, no P2P |
| 5-6 | Improvement 3 (Trust Scoring) |
| 7 | Improvement 8 (Behavioral) |
| 8-10 | Improvement 2 (Clock Drift) + 10 (Witness Diversity) |
| 11-14 | Improvement 1 (Decentralized Latency) |
| 15-16 | Improvement 7 (Bandwidth) |
| 17-19 | Improvement 5 (Stake Bond) |
| 20-21 | Improvement 9 (False Positive Protection) |
| 22-24 | Improvement 13 (ML Detection) |
| 25-32 | Improvement 6 (ZK Proofs) |
| 33-38 | Improvement 12 (Cross-Chain) |

**Total: ~38 weeks (9 months)**

### With 2-3 Developers (Recommended)

| Calendar Week | Dev A | Dev B | Dev C |
|---------------|-------|-------|-------|
| 1-2 | Pre-reqs: Fix weights, hash, VDF | Pre-reqs: Fix sigs, registry, array | — |
| 3-4 | Improvement 4 (Memory) | Improvement 11 (Thermal) | Improvement 8 (Behavioral) |
| 5-6 | Improvement 3 (Trust Scoring) | Improvement 10 (Witness Diversity) | Improvement 2 (Clock Drift) |
| 7-10 | Improvement 1 (Decentralized Latency) | Improvement 7 (Bandwidth) | Improvement 5 (Stake Bond) |
| 11-12 | Improvement 9 (False Positive) | Improvement 13 (ML Detection) | Integration testing |
| 13-20 | Improvement 6 (ZK Proofs) | Improvement 12 (Cross-Chain) | Testing + documentation |

**Total: ~20 weeks (5 months)**

---

## Updated Similarity Formula (After All Improvements)

```
Combined Score = w_L × L_sim        // Latency (decentralized)
              + w_V × V_sim        // VDF Timing + Thermal
              + w_P × P_sim        // Perspective
              + w_D × D_sim        // Clock Drift
              + w_M × M_sim        // Memory Fingerprint
              + w_B × B_sim        // Bandwidth
              + w_H × H_sim        // Behavioral

Suggested initial weights (to be empirically calibrated):
    w_L = 0.15    (Latency — lower weight, now decentralized)
    w_V = 0.20    (VDF Timing + Thermal — combined hardware)
    w_P = 0.25    (Perspective — strongest signal)
    w_D = 0.10    (Clock Drift — new, needs calibration)
    w_M = 0.10    (Memory Fingerprint — new, needs calibration)
    w_B = 0.10    (Bandwidth — new, needs calibration)
    w_H = 0.10    (Behavioral — develops over time)
    -----
    Total = 1.00

Note: Trust score is NOT part of similarity. Trust affects protocol
privileges separately. ML anomaly detection uses all dimensions as
features but produces its own independent anomaly score.
```

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-12 | Initial comprehensive improvement plan |
