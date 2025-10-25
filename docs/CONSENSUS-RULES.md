# Dilithion Consensus Rules

**Version:** 1.0.0
**Last Updated:** October 25, 2025

---

## Table of Contents

1. [Overview](#overview)
2. [Block Timestamp Validation](#block-timestamp-validation)
3. [Proof-of-Work](#proof-of-work)
4. [Block Validation](#block-validation)
5. [Transaction Validation](#transaction-validation)

---

## Overview

This document describes the consensus rules enforced by the Dilithion network. All nodes must enforce these rules to maintain network consensus.

**Critical:** Consensus rules are immutable after mainnet launch. Changes require a hard fork.

---

## Block Timestamp Validation

### Purpose

Block timestamp validation prevents various attacks:
- **Time-warp attacks:** Miners manipulating difficulty by using false timestamps
- **Future block attacks:** Miners creating blocks far in the future
- **Chain reorganization attacks:** Attackers using old timestamps to build fake chains

### Rules

#### Rule 1: Maximum Future Timestamp

**Requirement:** Block timestamp must not be more than 2 hours in the future

```cpp
int64_t nMaxFutureBlockTime = GetTime() + 2 * 60 * 60;
if (block.nTime > nMaxFutureBlockTime) {
    return false; // Reject block
}
```

**Rationale:**
- Allows for reasonable clock skew between nodes
- Prevents miners from creating blocks far in the future
- 2 hours is standard in Bitcoin and other cryptocurrencies

**Example:**
```
Current time: 2025-10-25 10:00:00 UTC
Valid block time: ≤ 2025-10-25 12:00:00 UTC
Invalid block time: > 2025-10-25 12:00:00 UTC
```

#### Rule 2: Median-Time-Past

**Requirement:** Block timestamp must be greater than the median-time-past (MTP)

The median-time-past is calculated as the median timestamp of the last 11 blocks.

```cpp
int64_t GetMedianTimePast(const CBlockIndex* pindex) {
    std::vector<int64_t> vTimes;
    const CBlockIndex* pindexWalk = pindex;

    // Collect last 11 block timestamps
    for (int i = 0; i < 11 && pindexWalk != nullptr; i++) {
        vTimes.push_back(pindexWalk->nTime);
        pindexWalk = pindexWalk->pprev;
    }

    // Return median
    std::sort(vTimes.begin(), vTimes.end());
    return vTimes[vTimes.size() / 2];
}
```

**Validation:**
```cpp
if (pindexPrev != nullptr) {
    int64_t nMedianTimePast = GetMedianTimePast(pindexPrev);
    if (block.nTime <= nMedianTimePast) {
        return false; // Reject block
    }
}
```

**Rationale:**
- Prevents miners from using old timestamps
- Ensures blockchain time progresses forward
- Makes difficulty manipulation attacks impractical

**Example:**
```
Last 11 blocks: 1000, 1100, 1200, 1300, 1400, [1500], 1600, 1700, 1800, 1900, 2000
Median-time-past: 1500
Valid block time: > 1500
Invalid block time: ≤ 1500
```

#### Genesis Block Exception

The genesis block (first block, no previous block) only checks Rule 1 (future timestamp). Rule 2 (median-time-past) does not apply.

```cpp
if (pindexPrev == nullptr) {
    // Genesis block - only check future timestamp
    return (block.nTime <= GetTime() + 2 * 60 * 60);
}
```

### Implementation

**Files:**
- `src/consensus/pow.h` - Function declarations
- `src/consensus/pow.cpp` - Implementation
- `src/test/timestamp_tests.cpp` - Comprehensive tests

**Functions:**
```cpp
// Calculate median-time-past
int64_t GetMedianTimePast(const CBlockIndex* pindex);

// Validate block timestamp
bool CheckBlockTimestamp(const CBlockHeader& block, const CBlockIndex* pindexPrev);
```

### Testing

**Test Coverage:**
- ✅ Median-time-past calculation (various chain lengths)
- ✅ Future timestamp validation (1h, 2h, 3h, 1 day)
- ✅ Median-time-past comparison (equal, less, greater)
- ✅ Genesis block handling
- ✅ Edge cases (boundary values, zero, max timestamp)
- ✅ Realistic chain scenarios
- ✅ Attack prevention (old timestamps, future timestamps)

**Run Tests:**
```bash
./timestamp_tests
```

**Expected Output:**
```
======================================
✅ All timestamp validation tests passed!
======================================

Consensus Rules Enforced:
  ✓ Block time must not be > 2 hours in future
  ✓ Block time must be > median-time-past
  ✓ Prevents timestamp manipulation attacks
```

### Attack Scenarios

#### Scenario 1: Future Block Attack

**Attack:** Miner creates block 1 day in the future

```
Current time: 2025-10-25 10:00:00 UTC
Malicious block time: 2025-10-26 10:00:00 UTC (24 hours ahead)
Result: REJECTED (exceeds 2-hour limit)
```

**Protection:** Rule 1 (max future timestamp)

#### Scenario 2: Old Timestamp Attack

**Attack:** Miner uses old timestamp to manipulate difficulty

```
Median-time-past: 2025-10-25 09:00:00 UTC
Malicious block time: 2025-10-25 08:00:00 UTC (before MTP)
Result: REJECTED (not greater than MTP)
```

**Protection:** Rule 2 (median-time-past)

#### Scenario 3: Time-Warp Attack

**Attack:** Miners collude to manipulate timestamps and reduce difficulty

**Protection:** Both rules prevent this:
- Rule 1: Prevents using far-future timestamps
- Rule 2: Prevents using old timestamps
- Combined: Makes difficulty manipulation impractical

---

## Proof-of-Work

### Algorithm

**RandomX** - CPU-friendly, ASIC-resistant proof-of-work

**Properties:**
- Memory-hard (2GB RAM required)
- Optimized for general-purpose CPUs
- Resistant to ASIC acceleration
- Resistant to quantum speedup

### Difficulty Target

Blocks must satisfy: `SHA3-256(block_header) < target`

**Compact Difficulty Representation:**
```cpp
uint32_t nBits = compact_difficulty;
uint256 target = CompactToBig(nBits);
bool valid = HashLessThan(block_hash, target);
```

**Difficulty Range:**
```cpp
const uint32_t MIN_DIFFICULTY_BITS = 0x1d00ffff; // Easiest
const uint32_t MAX_DIFFICULTY_BITS = 0x1f00ffff; // Hardest
```

### Validation

```cpp
bool CheckProofOfWork(uint256 hash, uint32_t nBits) {
    // Check difficulty bits in valid range
    if (nBits < MIN_DIFFICULTY_BITS || nBits > MAX_DIFFICULTY_BITS)
        return false;

    // Convert to target
    uint256 target = CompactToBig(nBits);

    // Verify hash < target
    return HashLessThan(hash, target);
}
```

---

## Block Validation

### Block Header Validation

**Required checks:**
1. ✅ **Proof-of-Work:** `CheckProofOfWork(block.GetHash(), block.nBits)`
2. ✅ **Timestamp:** `CheckBlockTimestamp(block, pindexPrev)`
3. **Difficulty:** Verify `nBits` matches expected difficulty (future)
4. **Version:** Check version is supported (future)

**Validation Order:**
```cpp
// 1. Check proof-of-work (cheap, fail fast)
if (!CheckProofOfWork(block.GetHash(), block.nBits))
    return false;

// 2. Check timestamp
if (!CheckBlockTimestamp(block, pindexPrev))
    return false;

// 3. Additional checks...
```

### Block Body Validation

**Not yet fully implemented** - future versions will include:
- Merkle root validation
- Transaction validation
- Block size limits
- Block reward validation

---

## Transaction Validation

### Signature Verification

**Algorithm:** CRYSTALS-Dilithium3 (NIST PQC standard)

**Properties:**
- Post-quantum secure (Level 3)
- Signature size: ~3,309 bytes
- Public key size: 1,952 bytes
- Verification: ~200,000 cycles

**Validation:**
```cpp
// Pseudo-code (actual implementation in wallet)
bool VerifySignature(const CTransaction& tx) {
    uint8_t message[32];
    SHA3_256(tx.SerializeWithoutSignature(), message);

    return pqcrypto_sign_dilithium3_verify(
        tx.signature.data(),
        message,
        32,
        tx.publicKey.data()
    ) == 0;
}
```

### Transaction Validation Rules

**Basic Rules:**
- Valid signatures (CRYSTALS-Dilithium3)
- No double-spending (check UTXO set)
- Input amounts ≥ output amounts + fees
- All inputs exist and are unspent

**Not yet fully implemented** - see wallet module for current state

---

## Consensus Parameter Summary

| Parameter | Value | Purpose |
|-----------|-------|---------|
| **Max Future Timestamp** | 2 hours | Prevents far-future blocks |
| **Median-Time-Past Blocks** | 11 | MTP calculation window |
| **Min Difficulty** | 0x1d00ffff | Easiest allowed difficulty |
| **Max Difficulty** | 0x1f00ffff | Hardest allowed difficulty |
| **PoW Algorithm** | RandomX | CPU-friendly mining |
| **Signature Algorithm** | Dilithium3 | Post-quantum signatures |
| **Hash Algorithm** | SHA-3-256 | Quantum-resistant hashing |

---

## Version History

### v1.0.0 (October 25, 2025)
- ✅ **Timestamp Validation:** Implemented (TASK-002)
  - Max future timestamp: 2 hours
  - Median-time-past comparison
  - Comprehensive tests
- ✅ **Proof-of-Work:** Implemented
  - RandomX algorithm
  - Difficulty validation
- 🟡 **Block Validation:** Partial
  - Header validation complete
  - Body validation pending
- 🟡 **Transaction Validation:** Partial
  - Signature verification working
  - Full validation pending

### Future Versions
- Difficulty adjustment algorithm
- Complete block validation
- Complete transaction validation
- Network protocol consensus rules

---

## References

- **Bitcoin Timestamp Rules:** [BIP-113](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki)
- **RandomX:** https://github.com/tevador/RandomX
- **CRYSTALS-Dilithium:** [NIST PQC Standard](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- **SHA-3:** [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

---

**Document Version:** 1.0.0
**Last Updated:** October 25, 2025
**Status:** Production-Ready

---

*Dilithion - Post-Quantum Cryptocurrency*
