# Digital DNA v3.0 Scoring Review — Request for Second Opinion

## Context

Dilithion is a cryptocurrency with a Sybil-resistant identity system called "Digital DNA." Each miner builds an identity fingerprint from 8 physical/behavioral dimensions. When a new miner registers, their fingerprint is compared against all existing identities — if too similar to an existing one, it's flagged as a potential Sybil.

This document describes the v3.0 scoring redesign and asks for a critical review.

---

## The Problem

The v2.0 system used only **3 dimensions** with hard-coded weights:

```cpp
// OLD v2.0 scoring
score.combined_score = 0.20 * latency_similarity +
                      0.35 * timing_similarity +
                      0.45 * perspective_similarity;
```

**Issues:**
1. Only 3 of 8 available dimensions were wired into scoring
2. The weights (20/35/45) were fabricated — no empirical basis
3. Threshold of 0.85 was a guess — too low for auto-reject, too high for challenge
4. No ML component was connected despite having a full Isolation Forest implementation

---

## The 8 Dimensions

| # | Dimension | What It Measures | Unique Per |
|---|-----------|-----------------|------------|
| L | Latency | RTT to seed nodes | Geographic location |
| V | VDF Timing | Computation speed | Hardware model |
| P | Perspective | Peer set Jaccard overlap | Network vantage point |
| M | Memory | Cache hierarchy (L1/L2/L3/DRAM curve) | Hardware class |
| D | Clock Drift | Crystal oscillator drift rate (ppm) | **Individual machine** |
| B | Bandwidth | Upload/download throughput + asymmetry | Connection type |
| T | Thermal | VDF speed degradation over time | Cooling solution |
| BP | Behavioral | 24h activity distribution, relay patterns | Timezone/operator |

### Correlation Problem

Some dimensions are **correlated by hardware model**:
- Two people with the same laptop model will produce similar Timing (V), Memory (M), and Thermal (T) fingerprints
- This means high similarity on those 3 dimensions ≠ same machine — it just means same SKU

**Clock Drift (D) is the lynchpin dimension** — it's unique per individual machine, not per model. Two identical laptops from the same production line will have different crystal oscillator drift rates. VMs on the same host share the same oscillator, so co-located VMs are trivially detected.

---

## What Was Implemented (v3.0)

### 1. Equal-Weight Scoring

```cpp
// NEW v3.0 scoring — equal weight average across available dimensions
SimilarityScore DigitalDNARegistry::compute_combined_score(SimilarityScore score) {
    double sum = 0.0;
    uint32_t n = 0;

    // Core dimensions (always counted)
    sum += score.latency_similarity;     n++;
    sum += score.timing_similarity;      n++;
    sum += score.perspective_similarity;  n++;

    // Extended dimensions (counted only if non-zero, meaning both had data)
    if (score.memory_similarity > 0.0)        { sum += score.memory_similarity;        n++; }
    if (score.clock_drift_similarity > 0.0)   { sum += score.clock_drift_similarity;   n++; }
    if (score.bandwidth_similarity > 0.0)     { sum += score.bandwidth_similarity;     n++; }
    if (score.thermal_similarity > 0.0)       { sum += score.thermal_similarity;       n++; }
    if (score.behavioral_similarity > 0.0)    { sum += score.behavioral_similarity;    n++; }

    score.dimensions_scored = n;
    score.combined_score = (n > 0) ? sum / n : 0.0;
    return score;
}
```

**Rationale:** We don't have real-world data to justify any specific weights. Equal weights is the honest starting point — an uninformed prior. As the network grows and the ML model trains on real comparisons, it will learn the optimal feature importance.

### 2. Updated Thresholds

| Threshold | v2.0 | v3.0 | Purpose |
|-----------|------|------|---------|
| Auto-reject | 0.85 | **0.92** | Higher = fewer false positives during bootstrap |
| Challenge | 0.60 | **0.55** | Lower = wider net for potential Sybils, resolved by challenge protocol |

### 3. Physics-Justified Hard Rule

```cpp
// If both Memory AND Clock Drift are > 0.95, auto-reject.
// Probability of two DIFFERENT machines matching both: vanishingly small.
static constexpr double PHYSICS_HARD_THRESHOLD = 0.95;

bool is_same_identity() const {
    if (memory_similarity >= PHYSICS_HARD_THRESHOLD &&
        clock_drift_similarity >= PHYSICS_HARD_THRESHOLD) {
        return true;  // Same physical machine
    }
    return combined_score >= SAME_IDENTITY_THRESHOLD;
}
```

**Rationale:** Memory fingerprint identifies hardware *class* (cache hierarchy is fixed by design). Clock drift identifies individual *machine* (crystal frequency is unique per oscillator). When both match at 0.95+, the only explanation is: same physical machine or VMs sharing the same host. This is the *only* rule with a physics justification — everything else is statistical.

### 4. ML Detector Connected to Registration Gate

The Isolation Forest (`MLSybilDetector`) was already implemented but disconnected. Now wired into `register_identity()`:

- **ADVISORY mode** (default): Scores every suspicious pair (>0.55), logs anomalies, doesn't reject. This collects training data.
- **SUPPLEMENTARY mode**: If a pair is suspicious AND the ML flags it as anomalous, reject. This is a second-stage filter on top of the threshold.
- **Feature extraction**: Builds a 13-feature vector from raw metrics (Euclidean distances, drift rate differences, bandwidth asymmetry diffs, etc.) — richer representation than the 0-1 similarity scores.

### 5. Graceful Degradation

Extended dimensions (M, D, B, T, BP) are `std::optional` on the `DigitalDNA` struct. The scoring function only includes them when both identities being compared have data. During early network life with mostly v2.0 identities, scoring degrades to the 3 core dimensions. As miners upgrade, all 8 contribute.

---

## Scenarios Analyzed

We ran 10 scenarios through the scoring system:

| Scenario | L | V | P | M | D | B | T | BP | Combined | Verdict |
|----------|---|---|---|---|---|---|---|---|----------|---------|
| Same machine, same ISP | 0.98 | 0.95 | 0.80 | 0.97 | 0.99 | 0.95 | 0.96 | 0.90 | 0.94 | SYBIL (correct) |
| Same model laptop, different cities | 0.30 | 0.92 | 0.15 | 0.90 | 0.10 | 0.40 | 0.85 | 0.20 | 0.48 | DIFFERENT (correct) |
| Raspberry Pi cluster (same model) | 0.95 | 0.98 | 0.70 | 0.95 | 0.12 | 0.90 | 0.99 | 0.55 | 0.77 | SUSPICIOUS (challenge) |
| VPN user, different hardware | 0.85 | 0.20 | 0.60 | 0.15 | 0.05 | 0.50 | 0.25 | 0.30 | 0.36 | DIFFERENT (correct) |
| VMs on same host | 0.97 | 0.93 | 0.85 | 0.96 | 0.98 | 0.94 | 0.95 | 0.90 | 0.94 | SYBIL (physics rule) |
| Home miner vs datacenter miner | 0.15 | 0.50 | 0.10 | 0.40 | 0.05 | 0.10 | 0.30 | 0.15 | 0.22 | DIFFERENT (correct) |
| Bot farm (identical configs) | 0.80 | 0.99 | 0.60 | 0.98 | 0.15 | 0.85 | 0.99 | 0.95 | 0.79 | SUSPICIOUS (challenge + ML) |
| Honest miner upgrading hardware | 0.95 | 0.30 | 0.90 | 0.20 | 0.05 | 0.80 | 0.25 | 0.85 | 0.54 | DIFFERENT (correct) |
| Two family members, same house | 0.98 | 0.40 | 0.70 | 0.35 | 0.08 | 0.95 | 0.50 | 0.60 | 0.57 | SUSPICIOUS (challenge) |
| Same person, two ISPs | 0.40 | 0.95 | 0.30 | 0.97 | 0.99 | 0.20 | 0.96 | 0.85 | 0.70 | SUSPICIOUS → physics rule SYBIL |

**Key insight from scenario analysis:** The K-of-N flagging approach (e.g., "flag if 4 of 8 dimensions > 0.80") was initially considered and **rejected** because it false-positives all Raspberry Pi miners and any group using popular hardware. The equal-weight average + physics hard rule avoids this.

---

## Questions for Review

### 1. Is equal weighting the right bootstrap choice?

**Our reasoning:** Without real-world data, any non-equal weight is a fabricated preference. Equal weights mean every dimension contributes proportionally, and no dimension can be gamed by appearing low on it alone. The ML model will learn optimal weights from real data.

**Counter-argument:** Some dimensions are inherently more discriminative (Clock Drift > Timing for uniqueness). Should we at least weight D higher even before ML data?

### 2. Are the thresholds (0.92 auto-reject, 0.55 challenge) appropriate?

**Our reasoning:** Conservative auto-reject (0.92) minimizes false positives — we'd rather challenge than auto-reject. Wide challenge net (0.55) catches more potential Sybils but relies on the challenge/differentiation protocol to resolve false positives.

**Risk:** If the challenge protocol has bugs or is gamed, the 0.55 threshold may harass honest miners. Is 0.55 too aggressive?

### 3. Is the Memory + Clock Drift physics rule sound?

**Our reasoning:** Memory identifies hardware class (fixed by silicon design). Clock Drift identifies individual machine (unique per crystal). Both matching at >0.95 means same physical machine or shared-host VMs. No other explanation is plausible.

**Counter-argument:** Could there be edge cases where both match without being the same machine? (We couldn't find any, but we'd like a second opinion.)

### 4. Should the ML detector start in ADVISORY or SUPPLEMENTARY mode?

**Current choice:** ADVISORY (logs but doesn't reject). The model needs training data before it's trustworthy.

**Question:** How much training data is needed before enabling SUPPLEMENTARY? The Isolation Forest uses `MIN_TRAINING_SAMPLES = 100` — is that sufficient for a 13-feature model?

### 5. Is the `> 0.0` check for optional dimensions correct?

```cpp
// Extended dimensions (counted only if non-zero, meaning both had data)
if (score.memory_similarity > 0.0) { sum += score.memory_similarity; n++; }
```

**Concern:** A similarity of exactly 0.0 is actually a meaningful signal (completely different). By skipping 0.0, we're conflating "no data" with "completely different." Should we use a flag (`bool has_memory_data`) instead?

### 6. Architectural concern: Isolation Forest vs supervised model

The Isolation Forest is unsupervised — it learns what "normal" looks like and flags outliers. But what we actually want is to flag pairs that are *too similar* (not outliers in general). An unsupervised model might flag unusual-but-honest miners (e.g., satellite internet with unusual latency) as anomalous.

**Should we switch to a supervised approach** once we have labeled data from challenge resolutions? Or is unsupervised the right long-term choice?

---

## Files Modified

| File | Changes |
|------|---------|
| `src/digital_dna/digital_dna.h` | Extended `DigitalDNA` with 5 optional v3.0 dimensions. Extended `SimilarityScore` with all 8 per-dimension scores, updated thresholds (0.92/0.55), added physics hard rule, added `compute_combined_score()` |
| `src/digital_dna/digital_dna.cpp` | Updated `compare()` to score all 8 dimensions when available, added `compute_combined_score()` implementation |
| `src/digital_dna/dna_registry_db.h` | Added `MLSybilDetector` member, `set_ml_detector()`, `ml_status()` |
| `src/digital_dna/dna_registry_db.cpp` | Updated `compare()` for 8 dimensions, replaced inline scoring in `register_identity()` with shared `compare()`, added ML gate (ADVISORY/SUPPLEMENTARY), added raw feature extraction for ML |

---

## Three-Phase Deployment Plan

1. **Bootstrap (now):** Equal weights, 0.92 auto-reject, 0.55 challenge, ML in ADVISORY mode. Collect comparison data.
2. **Calibration (~10,000 identities):** Train ML on real pairwise comparisons + challenge resolution outcomes. Validate ML predictions against threshold decisions.
3. **Mature:** Switch ML to SUPPLEMENTARY. Consider letting ML override thresholds for borderline cases. Eventually ML becomes primary detector, thresholds become safety net.

---

## Second-Opinion Fixes Applied

The following issues from the Cursor review have been implemented:

### 1. Fixed `> 0.0` correctness bug (Question 5)
- Added `has_memory`, `has_clock_drift`, `has_bandwidth`, `has_thermal`, `has_behavioral` boolean flags to `SimilarityScore`
- `compute_combined_score()` now gates on data-availability flags, NOT on value
- Zero similarity (0.0 = completely different hardware) is now correctly counted

### 2. Correlation-aware damping for V/M/T cluster
- When Timing (V), Memory (M), and Thermal (T) are all > 0.80 and within 0.15 spread, they're likely correlated by hardware SKU
- In this case, each gets 0.5 weight instead of 1.0 (cluster contributes ~1.5 dimensions instead of 3)
- Prevents hardware-model correlation from inflating combined scores
- Independent dimensions (L, P, D, B, BP) always get full 1.0 weight

### 3. ML readiness tracking and switch-over rubric (Question 4)
Added `MLReadinessStats` struct with automated promotion checks:

**Prerequisites (ALL must pass):**
- `total_scored_pairs >= 5,000`
- `full_dim_pairs >= 1,000` (pairs with all 8 dimensions)
- `labeled_outcomes >= 300` (challenge-resolved with labels)
- `hardware_clusters >= 3`
- `geo_regions >= 3`
- Feature distributions stable for 2 consecutive windows

**Validation thresholds (3 of 4 must pass):**
- False positive rate < 1% on labeled negatives
- False negative rate < 5% on labeled positives
- Suspicious band precision >= 70%
- Score monotonicity with combined similarity

**Implemented tracking methods:**
- `record_scored(bool full_dimensions)` — called automatically during registration
- `record_challenge_outcome(bool ml_flagged, bool confirmed_sybil)` — called when challenge resolves
- `record_challenge_error()` — track protocol failures
- `update_diversity(hw_clusters, regions)` — update network diversity
- `update_stability(bool stable)` — update after each measurement window
- `ready_for_promotion()` — single check for ADVISORY → SUPPLEMENTARY readiness

### Additional files modified

| File | Additional Changes |
|------|-------------------|
| `src/digital_dna/ml_detector.h` | Added `MLReadinessStats` struct, readiness tracking methods, `ready_for_promotion()` |
| `src/digital_dna/ml_detector.cpp` | Implemented all readiness tracking methods, extended `status_json()` with readiness section |

### Not yet implemented (deferred)
- **Supervised model transition** (Question 6): Agreed that gradient-boosted trees should replace IF once labeled data is available. Deferred until calibration phase.
- **Clock Drift measurement stability** guard: Review suggested insisting on minimum measurement window before applying physics hard rule. The `ClockDriftFingerprint` already has `MIN_SAMPLES = 50` and `MIN_OBSERVATION_MS = 4 hours`, which provides this guard.
- **Soft prior on Clock Drift weighting** (Question 1): Deferred — equal weights is the honest starting point. Will revisit after real-world data collection.

---

*Generated for second-opinion review. Updated with fixes from Cursor review.*
