// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_POW_H
#define DILITHION_CONSENSUS_POW_H

#include <primitives/block.h>
#include <cstdint>

// Forward declarations for DFMP
namespace DFMP {
    class CHeatTracker;
    class CIdentityDB;
}

// Forward declarations for chain access
class CBlockIndex;
class CBlockchainDB;

/**
 * Consensus Parameters
 */

/** Target block time in seconds (4 minutes) */
const int64_t BLOCK_TARGET_SPACING = 240;  // 4 minutes = 240 seconds

/** Minimum difficulty target (hardest) */
const uint32_t MIN_DIFFICULTY_BITS = 0x1d00ffff;

/** Maximum difficulty target (easiest - allow testnet 0x1f060000) */
const uint32_t MAX_DIFFICULTY_BITS = 0x1f0fffff;

/** Check whether a block hash satisfies the proof-of-work requirement */
bool CheckProofOfWork(uint256 hash, uint32_t nBits);

/**
 * Check proof-of-work with DFMP difficulty adjustment
 *
 * This is the DFMP-aware version of CheckProofOfWork that applies
 * identity-based difficulty multipliers.
 *
 * @param block Full block (needed to extract coinbase identity)
 * @param hash Block hash (RandomX result)
 * @param nBits Compact difficulty target
 * @param height Block height
 * @param activationHeight DFMP activation height (0 = always active)
 * @param pindexPrev Previous block index (for chain-based validation during IBD)
 * @param pdb Blockchain database (for loading blocks during IBD)
 * @return true if PoW meets DFMP-adjusted difficulty
 *
 * NOTE: When pindexPrev and pdb are provided, DFMP penalty calculations use
 * deterministic chain-scanning instead of in-memory state. This ensures
 * consistent validation during Initial Block Download (IBD).
 */
bool CheckProofOfWorkDFMP(
    const CBlock& block,
    const uint256& hash,
    uint32_t nBits,
    int height,
    int activationHeight,
    const CBlockIndex* pindexPrev,
    CBlockchainDB* pdb
);

/** Get target from compact difficulty representation */
uint256 CompactToBig(uint32_t nCompact);

/** Get compact difficulty from target */
uint32_t BigToCompact(const uint256& target);

/**
 * Calculate difficulty adjustment (testing version)
 *
 * This is a simplified version of GetNextWorkRequired for testing purposes.
 * It performs just the core difficulty arithmetic without blockchain context.
 *
 * Used by: difficulty_determinism_test.cpp for cross-platform validation
 *
 * @param nCompactOld The current difficulty in compact format
 * @param nActualTimespan The actual time taken (seconds)
 * @param nTargetTimespan The target time expected (seconds)
 * @return The new difficulty in compact format
 */
uint32_t CalculateNextWorkRequired(
    uint32_t nCompactOld,
    int64_t nActualTimespan,
    int64_t nTargetTimespan
);

/** Check if hash is less than target (satisfies PoW) */
bool HashLessThan(const uint256& hash, const uint256& target);

/**
 * Compare chain work (cumulative PoW)
 * Returns true if work1 > work2 (using big-endian comparison)
 */
bool ChainWorkGreaterThan(const uint256& work1, const uint256& work2);

// Forward declaration
class CBlockIndex;

/**
 * Calculate the next required proof-of-work difficulty
 * Implements difficulty adjustment algorithm (every 2016 blocks)
 *
 * @param pindexLast The last block in the chain
 * @param params Chain parameters containing adjustment interval and target spacing
 * @return The new difficulty target in compact format (nBits)
 */
uint32_t GetNextWorkRequired(const CBlockIndex* pindexLast);

/**
 * Calculate median-time-past for timestamp validation
 * Returns the median timestamp of the last 11 blocks
 * @param pindex The block index to calculate MTP from
 * @return Median timestamp (Unix time)
 */
int64_t GetMedianTimePast(const CBlockIndex* pindex);

/**
 * Validate block timestamp according to consensus rules
 *
 * Rules:
 * 1. Block time must not be more than 2 hours in the future
 * 2. Block time must be greater than median-time-past
 *
 * @param block The block header to validate
 * @param pindexPrev The previous block index (nullptr for genesis)
 * @return true if timestamp is valid, false otherwise
 */
bool CheckBlockTimestamp(const CBlockHeader& block, const CBlockIndex* pindexPrev);

#endif // DILITHION_CONSENSUS_POW_H
