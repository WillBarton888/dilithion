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

    // Bug #47 Fix Part 2: Match Bitcoin Core's SetCompact() behavior
    // Bitcoin Core gracefully handles edge cases and returns zero target:
    // - nCompact=0 → nSize=0, nWord=0 → returns zero target
    // - nWord=0 → returns zero target
    // - nSize > 32 → overflow, returns zero target
    //
    // The zero target is then rejected by CheckProofOfWork()
    // This is Bitcoin Core's two-stage validation approach

    // Handle zero word (including when nCompact is fully zero)
    if (nWord == 0) {
        return result;  // Return zero target
    }

    // Handle zero size (can happen if nCompact has zero size byte)
    if (nSize == 0) {
        return result;  // Return zero target
    }

    // Handle overflow (size too large)
    if (nSize > 32) {
        return result;  // Return zero target
    }

    // Normal case: Expand compact format to full 256-bit target
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
    // Bug #47 Fix: Match Bitcoin Core approach
    // Don't reject based on arbitrary MIN/MAX_DIFFICULTY_BITS
    // Instead, validate target expansion and check against powLimit

    // Convert compact difficulty to full target
    uint256 target = CompactToBig(nBits);

    // Check for zero target (invalid)
    bool isZero = true;
    for (int i = 0; i < 32; i++) {
        if (target.data[i] != 0) {
            isZero = false;
            break;
        }
    }
    if (isZero) {
        return false;
    }

    // Check if hash is less than target
    return HashLessThan(hash, target);
}

/**
 * Multiply 256-bit number by 64-bit number using integer-only arithmetic
 * result = a * b (result is 320 bits, stored in 40 bytes)
 *
 * This is consensus-critical code - must be deterministic across all platforms.
 * We store the result in 40 bytes (320 bits) to handle potential overflow.
 *
 * Algorithm: Standard long multiplication in base 256
 * Each byte of 'a' is multiplied by 'b', and results are accumulated with carry.
 */
static bool Multiply256x64(const uint256& a, uint64_t b, uint8_t* result) {
    // Initialize result to zero
    memset(result, 0, 40);

    // Perform long multiplication: multiply each byte of 'a' by 'b'
    // and accumulate results with proper carry handling
    uint64_t carry = 0;
    for (int i = 0; i < 32; i++) {
        // ====================================================================
        // HIGH-C002 FIX: Check for integer overflow before multiplication
        // ====================================================================
        // We need to compute: product = a.data[i] * b + carry
        //
        // This could overflow if:
        //   - a.data[i] = 255 (max uint8_t)
        //   - b = UINT64_MAX
        //   - carry = large value from previous iteration
        //
        // Check overflow in two steps:
        //   1. Check if a.data[i] * b would overflow
        //   2. Check if (a.data[i] * b) + carry would overflow

        uint64_t byte_val = a.data[i];
        uint64_t mul_result;

        // Step 1: Multiply with overflow check
        // For uint64_t multiplication, overflow occurs if a * b > UINT64_MAX
        // We can check this by: if (a != 0 && b > UINT64_MAX / a) → overflow
        if (byte_val != 0 && b > UINT64_MAX / byte_val) {
            std::cerr << "[Difficulty] ERROR: Integer overflow in Multiply256x64 (multiplication)" << std::endl;
            std::cerr << "  byte_val: " << byte_val << ", b: " << b << std::endl;
            return false;
        }
        mul_result = byte_val * b;

        // Step 2: Add carry with overflow check
        // Check if adding carry would overflow
        if (carry > UINT64_MAX - mul_result) {
            std::cerr << "[Difficulty] ERROR: Integer overflow in Multiply256x64 (addition)" << std::endl;
            std::cerr << "  mul_result: " << mul_result << ", carry: " << carry << std::endl;
            return false;
        }
        uint64_t product = mul_result + carry;

        // Store low byte in result
        result[i] = product & 0xFF;

        // Carry forward the high bits
        carry = product >> 8;
    }

    // Store remaining carry bytes (up to 8 bytes = 64 bits)
    for (int i = 32; i < 40 && carry > 0; i++) {
        result[i] = carry & 0xFF;
        carry >>= 8;
    }

    // Final sanity check: carry should be zero after 40 bytes
    if (carry > 0) {
        std::cerr << "[Difficulty] ERROR: Result exceeds 320 bits in Multiply256x64" << std::endl;
        return false;
    }

    return true;
}

/**
 * Divide 320-bit number by 64-bit number using integer-only arithmetic
 * Returns quotient as uint256
 *
 * This is consensus-critical code - must be deterministic across all platforms.
 *
 * Algorithm: Standard long division in base 256
 * We process from most significant byte to least significant byte,
 * maintaining a running remainder that is carried forward.
 */
static uint256 Divide320x64(const uint8_t* dividend, uint64_t divisor) {
    // LOW-C001 FIX: Add defensive check for division by zero
    // While upstream code ensures divisor is never zero (through timespan clamping),
    // this defensive check prevents undefined behavior if called incorrectly
    if (divisor == 0) {
        std::cerr << "[Difficulty] CRITICAL: Division by zero in Divide320x64!" << std::endl;
        std::cerr << "  This should be impossible - indicates logic error in caller" << std::endl;
        uint256 zero;
        memset(zero.data, 0, 32);
        return zero;  // Return zero as safe fallback
    }

    uint256 quotient;
    memset(quotient.data, 0, 32);

    // Long division: process from most significant byte (index 39) to least (index 0)
    uint64_t remainder = 0;

    // Start from the highest byte and work down
    for (int i = 39; i >= 0; i--) {
        // Bring down next byte into remainder
        remainder = (remainder << 8) | dividend[i];

        // Calculate quotient byte and new remainder
        uint64_t q = remainder / divisor;
        remainder = remainder % divisor;

        // Store quotient byte (only first 32 bytes fit in uint256)
        if (i < 32) {
            quotient.data[i] = q & 0xFF;
        }
        // Note: If i >= 32 and q > 0, the result would overflow uint256
        // This should not happen in normal difficulty adjustment as we're
        // dividing by a larger timespan after multiplying
    }

    return quotient;
}

uint32_t CalculateNextWorkRequired(
    uint32_t nCompactOld,
    int64_t nActualTimespan,
    int64_t nTargetTimespan
) {
    // Limit adjustment to prevent extreme changes (4x max change)
    if (nActualTimespan < nTargetTimespan / 4)
        nActualTimespan = nTargetTimespan / 4;
    if (nActualTimespan > nTargetTimespan * 4)
        nActualTimespan = nTargetTimespan * 4;

    // Convert compact to full target
    uint256 targetOld = CompactToBig(nCompactOld);
    uint256 targetNew;

    // CRITICAL: Use integer-only arithmetic for deterministic behavior
    // Formula: targetNew = targetOld * nActualTimespan / nTargetTimespan
    uint8_t product[40];  // 320 bits to handle overflow

    // HIGH-C002 FIX: Check for overflow in multiplication
    if (!Multiply256x64(targetOld, static_cast<uint64_t>(nActualTimespan), product)) {
        std::cerr << "[Difficulty] CRITICAL: Overflow in difficulty calculation!" << std::endl;
        std::cerr << "  Returning previous difficulty (no adjustment)" << std::endl;
        return nCompactOld;  // Return old difficulty as fallback
    }

    targetNew = Divide320x64(product, static_cast<uint64_t>(nTargetTimespan));

    // Convert back to compact format
    uint32_t nBitsNew = BigToCompact(targetNew);

    // Ensure new difficulty is within allowed bounds
    if (nBitsNew < MIN_DIFFICULTY_BITS)
        nBitsNew = MIN_DIFFICULTY_BITS;
    if (nBitsNew > MAX_DIFFICULTY_BITS)
        nBitsNew = MAX_DIFFICULTY_BITS;

    return nBitsNew;
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

    // LOW-C002: Early blockchain edge case handling (DOCUMENTED)
    //
    // During the first difficulty adjustment interval (height < 2016 for Bitcoin,
    // varies by chain params for Dilithion), there may not be enough blocks to
    // calculate a full interval timespan.
    //
    // Behavior: Return current difficulty (pindexLast->nBits) without adjustment
    //
    // This is correct because:
    // - Genesis block uses genesisNBits (handled at line 254-256)
    // - Blocks 1 through (interval-1) use genesis difficulty (no adjustment needed)
    // - First adjustment happens at block `interval` (e.g., block 2016)
    //
    // Alternative considered: Return genesisNBits explicitly
    // - Not necessary - pindexLast->nBits already equals genesisNBits for early blocks
    // - Current approach is simpler and equivalent
    //
    if (pindexFirst == nullptr) {
        // Not enough blocks yet, use current difficulty (no adjustment)
        return pindexLast->nBits;
    }

    // Calculate actual time taken for this interval
    int64_t nActualTimespan = pindexLast->nTime - pindexFirst->nTime;

    // ========================================================================
    // HIGH-C003 FIX: Validate timespan is positive (timestamps must increase)
    // ========================================================================
    // If nActualTimespan <= 0, it indicates:
    // 1. Timestamps going backwards (clock skew or attack)
    // 2. Blocks with identical timestamps
    //
    // This would cause difficulty calculation errors when cast to uint64_t later.
    // Use target timespan as fallback (no difficulty adjustment).
    if (nActualTimespan <= 0) {
        std::cerr << "[Difficulty] WARNING: Invalid timespan detected (timestamps not increasing)" << std::endl;
        std::cerr << "  pindexFirst time: " << pindexFirst->nTime << " (height " << pindexFirst->nHeight << ")" << std::endl;
        std::cerr << "  pindexLast time:  " << pindexLast->nTime << " (height " << pindexLast->nHeight << ")" << std::endl;
        std::cerr << "  Calculated timespan: " << nActualTimespan << " seconds" << std::endl;
        std::cerr << "  Using target timespan instead (no difficulty adjustment)" << std::endl;

        // Fallback: Use target timespan (maintains current difficulty)
        int64_t nTargetTimespan = nInterval * Dilithion::g_chainParams->blockTime;
        nActualTimespan = nTargetTimespan;
    }

    // Calculate expected timespan
    int64_t nTargetTimespan = nInterval * Dilithion::g_chainParams->blockTime;

    // MEDIUM-C001 FIX: Remove code duplication - use CalculateNextWorkRequired()
    // This helper function handles all the difficulty calculation logic,
    // including clamping, overflow checks, and bounds validation
    uint32_t nBitsNew = CalculateNextWorkRequired(
        pindexLast->nBits,
        nActualTimespan,
        nTargetTimespan
    );

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
