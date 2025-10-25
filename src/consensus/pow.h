// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_POW_H
#define DILITHION_CONSENSUS_POW_H

#include <primitives/block.h>
#include <cstdint>

/** Minimum difficulty target (easiest) */
const uint32_t MIN_DIFFICULTY_BITS = 0x1d00ffff;

/** Maximum difficulty target (hardest) */
const uint32_t MAX_DIFFICULTY_BITS = 0x1f00ffff;

/** Check whether a block hash satisfies the proof-of-work requirement */
bool CheckProofOfWork(uint256 hash, uint32_t nBits);

/** Get target from compact difficulty representation */
uint256 CompactToBig(uint32_t nCompact);

/** Get compact difficulty from target */
uint32_t BigToCompact(const uint256& target);

/** Check if hash is less than target (satisfies PoW) */
bool HashLessThan(const uint256& hash, const uint256& target);

#endif // DILITHION_CONSENSUS_POW_H
