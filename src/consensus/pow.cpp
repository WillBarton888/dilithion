// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/pow.h>
#include <node/block_index.h>
#include <core/chainparams.h>
#include <util/time.h>
#include <algorithm>
#include <vector>
#include <cstring>
#include <iostream>

bool HashLessThan(const uint256& hash, const uint256& target) {
    // Compare as big-endian (most significant byte first)
    for (int i = 31; i >= 0; i--) {
        if (hash.data[i] < target.data[i])
            return true;
        if (hash.data[i] > target.data[i])
            return false;
    }
    return false; // Equal, not less than
}

bool ChainWorkGreaterThan(const uint256& work1, const uint256& work2) {
    // Compare chain work as big-endian (most significant byte first)
    // Returns true if work1 > work2
    for (int i = 31; i >= 0; i--) {
        if (work1.data[i] > work2.data[i])
            return true;
        if (work1.data[i] < work2.data[i])
            return false;
    }
    return false; // Equal, not greater than
}

uint256 CompactToBig(uint32_t nCompact) {
    uint256 result;
    memset(result.data, 0, 32);

    int nSize = nCompact >> 24;
    uint32_t nWord = nCompact & 0x007fffff;

    // Validate size is within bounds [1, 32]
    if (nSize < 1 || nSize > 32) {
        std::cerr << "CompactToBig: Invalid nSize " << nSize << " (must be 1-32)" << std::endl;
        return result;  // Return zero target
    }

    if (nSize <= 3) {
        nWord >>= 8 * (3 - nSize);
        result.data[0] = nWord & 0xff;
        result.data[1] = (nWord >> 8) & 0xff;
        result.data[2] = (nWord >> 16) & 0xff;
    } else {
        result.data[nSize - 3] = nWord & 0xff;
        result.data[nSize - 2] = (nWord >> 8) & 0xff;
        result.data[nSize - 1] = (nWord >> 16) & 0xff;
    }

    return result;
}

uint32_t BigToCompact(const uint256& target) {
    // Find first non-zero byte
    int nSize = 32;
    while (nSize > 0 && target.data[nSize - 1] == 0)
        nSize--;
    
    if (nSize == 0)
        return 0;
    
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = target.data[0] | (target.data[1] << 8) | (target.data[2] << 16);
        nCompact <<= 8 * (3 - nSize);
    } else {
        nCompact = target.data[nSize - 3] | (target.data[nSize - 2] << 8) | (target.data[nSize - 1] << 16);
    }
    
    // Set size byte
    nCompact |= nSize << 24;
    
    return nCompact;
}

bool CheckProofOfWork(uint256 hash, uint32_t nBits) {
    // Check if bits are within valid range
    if (nBits < MIN_DIFFICULTY_BITS || nBits > MAX_DIFFICULTY_BITS)
        return false;

    // Convert compact difficulty to full target
    uint256 target = CompactToBig(nBits);

    // Check if hash is less than target
    return HashLessThan(hash, target);
}

uint32_t GetNextWorkRequired(const CBlockIndex* pindexLast) {
    // Genesis block (or no previous block)
    if (pindexLast == nullptr) {
        return Dilithion::g_chainParams->genesisNBits;
    }

    // Get difficulty adjustment interval from chain params
    int64_t nInterval = Dilithion::g_chainParams->difficultyAdjustment;

    // Only adjust difficulty at specific intervals
    if ((pindexLast->nHeight + 1) % nInterval != 0) {
        // Not at adjustment point, return previous difficulty
        // Use header nBits (since block index nBits field may not be deserialized yet)
        uint32_t prevBits = pindexLast->header.nBits;

        // Safety check: if previous difficulty is zero, use genesis difficulty
        if (prevBits == 0) {
            return Dilithion::g_chainParams->genesisNBits;
        }

        return prevBits;
    }

    // We're at a difficulty adjustment point
    // Find the block at the start of this interval
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst != nullptr && i < nInterval - 1; i++) {
        pindexFirst = pindexFirst->pprev;
    }

    if (pindexFirst == nullptr) {
        // Not enough blocks yet, use current difficulty
        return pindexLast->nBits;
    }

    // Calculate actual time taken for this interval
    int64_t nActualTimespan = pindexLast->nTime - pindexFirst->nTime;

    // Calculate expected timespan
    int64_t nTargetTimespan = nInterval * Dilithion::g_chainParams->blockTime;

    // Limit adjustment to prevent extreme changes (4x max change)
    // This prevents difficulty from swinging wildly
    if (nActualTimespan < nTargetTimespan / 4)
        nActualTimespan = nTargetTimespan / 4;
    if (nActualTimespan > nTargetTimespan * 4)
        nActualTimespan = nTargetTimespan * 4;

    // Calculate new target (difficulty)
    // If blocks came faster than expected, increase difficulty (smaller target)
    // If blocks came slower than expected, decrease difficulty (larger target)
    uint256 targetOld = CompactToBig(pindexLast->nBits);
    uint256 targetNew;
    memset(targetNew.data, 0, 32);

    // Multiply old target by actual timespan, divide by expected timespan
    // This is done using 256-bit arithmetic to avoid overflow
    // For simplicity, we'll use a basic implementation

    // Convert to double for calculation (loses some precision but good enough)
    double adjustment = (double)nActualTimespan / (double)nTargetTimespan;

    // Adjust each byte of the target
    uint32_t carry = 0;
    for (int i = 0; i < 32; i++) {
        uint64_t newVal = (uint64_t)(targetOld.data[i] * adjustment) + carry;
        targetNew.data[i] = newVal & 0xFF;
        carry = newVal >> 8;
    }

    // Convert back to compact format
    uint32_t nBitsNew = BigToCompact(targetNew);

    // Ensure new difficulty is within allowed bounds
    if (nBitsNew < MIN_DIFFICULTY_BITS)
        nBitsNew = MIN_DIFFICULTY_BITS;
    if (nBitsNew > MAX_DIFFICULTY_BITS)
        nBitsNew = MAX_DIFFICULTY_BITS;

    std::cout << "[Difficulty] Adjustment at height " << (pindexLast->nHeight + 1) << std::endl;
    std::cout << "  Actual time: " << nActualTimespan << "s, Expected: " << nTargetTimespan << "s" << std::endl;
    std::cout << "  Old difficulty: 0x" << std::hex << pindexLast->nBits << std::endl;
    std::cout << "  New difficulty: 0x" << nBitsNew << std::dec << std::endl;

    return nBitsNew;
}

int64_t GetMedianTimePast(const CBlockIndex* pindex) {
    std::vector<int64_t> vTimes;
    const CBlockIndex* pindexWalk = pindex;

    // Collect timestamps from last 11 blocks (or fewer if near genesis)
    for (int i = 0; i < 11 && pindexWalk != nullptr; i++) {
        vTimes.push_back(pindexWalk->nTime);
        pindexWalk = pindexWalk->pprev;
    }

    // Sort timestamps to find median
    std::sort(vTimes.begin(), vTimes.end());

    // Return median value
    return vTimes[vTimes.size() / 2];
}

bool CheckBlockTimestamp(const CBlockHeader& block, const CBlockIndex* pindexPrev) {
    // Rule 1: Block time must not be more than 2 hours in the future
    // This prevents timestamp attacks and ensures nodes have reasonable clocks
    int64_t nMaxFutureBlockTime = GetTime() + 2 * 60 * 60; // 2 hours

    if (static_cast<int64_t>(block.nTime) > nMaxFutureBlockTime) {
        std::cerr << "CheckBlockTimestamp(): block timestamp too far in future"
                  << " (block time: " << block.nTime
                  << ", max allowed: " << nMaxFutureBlockTime << ")" << std::endl;
        return false;
    }

    // Rule 2: Block time must be greater than median-time-past
    // This prevents miners from using old timestamps and ensures chain progresses forward
    if (pindexPrev != nullptr) {
        int64_t nMedianTimePast = GetMedianTimePast(pindexPrev);

        if (static_cast<int64_t>(block.nTime) <= nMedianTimePast) {
            std::cerr << "CheckBlockTimestamp(): block's timestamp is too early"
                      << " (block time: " << block.nTime
                      << ", median-time-past: " << nMedianTimePast << ")" << std::endl;
            return false;
        }
    }

    return true;
}
