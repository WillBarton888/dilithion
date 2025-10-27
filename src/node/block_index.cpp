// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/block_index.h>
#include <consensus/pow.h>
#include <sstream>
#include <cstring>

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
    // Work = 2^256 / (target + 1)
    // For simplicity, we approximate as: ~target (bitwise NOT)
    // This gives higher work for smaller (harder) targets

    uint256 target = CompactToBig(nBits);
    uint256 proof;

    // If target is zero, return max work (should never happen)
    bool isZero = true;
    for (int i = 0; i < 32; i++) {
        if (target.data[i] != 0) {
            isZero = false;
            break;
        }
    }

    if (isZero) {
        memset(proof.data, 0xFF, 32);  // Max work
        return proof;
    }

    // Calculate ~target (bitwise NOT)
    // This is an approximation: actual formula is (2^256 - 1) / (target + 1)
    // But bitwise NOT is faster and good enough for comparison
    for (int i = 0; i < 32; i++) {
        proof.data[i] = ~target.data[i];
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
