// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/pow.h>
#include <node/block_index.h>
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

uint256 CompactToBig(uint32_t nCompact) {
    uint256 result;
    memset(result.data, 0, 32);
    
    int nSize = nCompact >> 24;
    uint32_t nWord = nCompact & 0x007fffff;
    
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
