// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/block_index.h>
#include <consensus/pow.h>
#include <sstream>
#include <cstring>
#include <iostream>

CBlockIndex::CBlockIndex() {
    pprev = nullptr;
    pnext = nullptr;
    pskip = nullptr;
    nHeight = 0;
    nFile = 0;
    nDataPos = 0;
    nUndoPos = 0;
    nChainWork = uint256();
    nTx = 0;
    nStatus = 0;
    nSequenceId = 0;
    nTime = 0;
    nBits = 0;
    nNonce = 0;
    nVersion = 0;
}

CBlockIndex::CBlockIndex(const CBlockHeader& block) {
    pprev = nullptr;
    pnext = nullptr;
    pskip = nullptr;
    nHeight = 0;
    nFile = 0;
    nDataPos = 0;
    nUndoPos = 0;
    nChainWork = uint256();
    nTx = 0;
    nStatus = 0;
    nSequenceId = 0;
    header = block;
    nTime = block.nTime;
    nBits = block.nBits;
    nNonce = block.nNonce;
    nVersion = block.nVersion;
}

// BUG #70 FIX: Explicit copy constructor to ensure ALL fields are copied
// including header.hashMerkleRoot which was being lost during database loading
CBlockIndex::CBlockIndex(const CBlockIndex& other) {
    // Copy the FULL header including merkle root
    header = other.header;

    // Copy pointers (will be re-linked during chain loading)
    pprev = other.pprev;
    pnext = other.pnext;
    pskip = other.pskip;

    // Copy all integer fields
    nHeight = other.nHeight;
    nFile = other.nFile;
    nDataPos = other.nDataPos;
    nUndoPos = other.nUndoPos;
    nChainWork = other.nChainWork;
    nTx = other.nTx;
    nStatus = other.nStatus;
    nSequenceId = other.nSequenceId;
    nTime = other.nTime;
    nBits = other.nBits;
    nNonce = other.nNonce;
    nVersion = other.nVersion;
    phashBlock = other.phashBlock;
}

uint256 CBlockIndex::GetBlockHash() const {
    if (phashBlock.IsNull()) {
        phashBlock = header.GetHash();
    }
    return phashBlock;
}

bool CBlockIndex::IsValid() const {
    return (nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_HEADER;
}

bool CBlockIndex::HaveData() const {
    return (nStatus & BLOCK_HAVE_DATA) != 0;
}

std::string CBlockIndex::ToString() const {
    std::stringstream ss;
    ss << "CBlockIndex(hash=" << GetBlockHash().GetHex().substr(0, 20) << "...";
    ss << ", height=" << nHeight << ", nTx=" << nTx << ")";
    return ss.str();
}

uint256 CBlockIndex::GetBlockProof() const {
    // Calculate proof-of-work from difficulty target
    // Work should be inversely proportional to target: smaller target = more work
    //
    // Formula: work = 2^256 / (target + 1)
    // We approximate this by calculating: work = 2^(256 - 8*size) / mantissa
    // where size is the exponent byte from nBits compact representation
    //
    // This avoids overflow and maintains proper ordering

    uint256 target = CompactToBig(nBits);
    uint256 proof;
    memset(proof.data, 0, 32);

    // If target is zero, return max work (should never happen)
    bool isZero = true;
    for (int i = 0; i < 32; i++) {
        if (target.data[i] != 0) {
            isZero = false;
            break;
        }
    }

    if (isZero) {
        // Max work
        memset(proof.data, 0xFF, 32);
        return proof;
    }

    // Extract size and mantissa from nBits compact form
    // nBits format: 0xSSMMMMM where SS is size, MMMMM is mantissa
    int size = nBits >> 24;
    uint64_t mantissa = nBits & 0x00FFFFFF;

    // Avoid division by zero
    if (mantissa == 0) {
        memset(proof.data, 0xFF, 32);
        return proof;
    }

    // Calculate work = 2^(256 - 8*size) / mantissa
    // We store this as a 256-bit number in little-endian format
    //
    // The key insight: as size increases, target gets larger, so work decreases
    // As mantissa increases, target gets larger, so work decreases
    //
    // We use a simplified calculation that maintains ordering:
    // Store the exponent in the high bytes and the mantissa reciprocal in low bytes

    // Calculate the byte position where work should be stored
    // work = 2^(256 - 8*size) / mantissa
    // The exponent (256 - 8*size) tells us which byte position has the MSB
    int work_exponent = 256 - 8 * size;  // Bit position of MSB
    int work_byte_pos = work_exponent / 8;  // Byte position (0-31)

    // Clamp to valid range
    if (work_byte_pos < 0) work_byte_pos = 0;
    if (work_byte_pos > 31) work_byte_pos = 31;

    // CID 1675209 FIX: Calculate reciprocal of mantissa scaled to 64 bits
    // Note: mantissa > 0 is guaranteed here because we check mantissa == 0 and return early at line 131
    // The ternary operator's else branch is dead code, so we simplify to just the division
    uint64_t work_mantissa = 0xFFFFFFFFFFFFFFFFULL / mantissa;

    // Store the work value at the appropriate byte position
    // This creates a properly scaled work value
    for (int i = 0; i < 8 && (work_byte_pos + i) < 32; i++) {
        proof.data[work_byte_pos + i] = (work_mantissa >> (i * 8)) & 0xFF;
    }

    return proof;
}

void CBlockIndex::BuildChainWork() {
    // Calculate cumulative chain work = parent's chain work + this block's work
    if (pprev == nullptr) {
        // Genesis block: chain work = this block's work
        nChainWork = GetBlockProof();
    } else {
        // Add this block's work to parent's cumulative work
        uint256 blockProof = GetBlockProof();

        // Add parent chain work + this block's proof
        // Simple byte-by-byte addition with carry
        uint32_t carry = 0;
        for (int i = 0; i < 32; i++) {
            uint32_t sum = (uint32_t)pprev->nChainWork.data[i] +
                          (uint32_t)blockProof.data[i] +
                          carry;
            nChainWork.data[i] = sum & 0xFF;
            carry = sum >> 8;
        }

        // Handle overflow - saturate at maximum value
        // This ensures chain work always increases when adding positive proof
        if (carry != 0) {
            memset(nChainWork.data, 0xFF, 32);  // Set to max value
        }
    }
}

// Helper functions for skip pointer calculation
static inline int InvertLowestOne(int n) {
    return n & (n - 1);
}

static inline int GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to
    // Skip back exponentially: every 2^n blocks, skip 2^n back
    // This gives O(log n) lookup time
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

CBlockIndex* CBlockIndex::GetAncestor(int height) {
    // Return nullptr if requested height is higher than this block
    if (height > nHeight || height < 0) {
        return nullptr;
    }

    // Already at requested height
    if (height == nHeight) {
        return this;
    }

    // Use skip pointer for efficient traversal if available
    CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;

    while (heightWalk > height) {
        // Determine how far to skip
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);

        // Use skip pointer if it gets us closer without overshooting
        if (pindexWalk->pskip != nullptr &&
            (pindexWalk->pskip->nHeight >= height || heightSkip < heightSkipPrev)) {
            pindexWalk = pindexWalk->pskip;
            heightWalk = pindexWalk->nHeight;
        } else {
            // Fall back to pprev
            if (pindexWalk->pprev == nullptr) {
                return nullptr;
            }
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }

    return pindexWalk;
}
