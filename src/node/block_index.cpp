// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/block_index.h>
#include <consensus/pow.h>
#include <consensus/chain_work.h>  // Phase 3: shared chain-work helper
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
    // IBD DEADLOCK FIX #10: Don't auto-compute RandomX hash
    // Computing header.GetHash() here acquires g_validation_mutex for ~700ms
    // If called from ActivateBestChain (which holds cs_main), this can cause
    // severe contention with the message handler thread, effectively serializing
    // all block processing and causing apparent freezes.
    //
    // Instead, require all CBlockIndex creation sites to set phashBlock explicitly.
    // If phashBlock is null, log an error and return null hash (don't block).
    if (phashBlock.IsNull()) {
        std::cerr << "[DEADLOCK-FIX] ERROR: GetBlockHash() called with null phashBlock!" << std::endl;
        std::cerr << "  nHeight: " << nHeight << ", nTime: " << nTime << std::endl;
        // Return null hash instead of computing (prevents blocking)
        return uint256();
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
    // Phase 3 (2026-04-26): chain-work formula consolidated into
    // dilithion::consensus::ComputeChainWork(nBits). One source of truth;
    // both this method and HeadersSyncState now route through it.
    return dilithion::consensus::ComputeChainWork(nBits);
}

void CBlockIndex::BuildChainWork() {
    // Phase 3: consolidated through dilithion::consensus::AddChainWork
    if (pprev == nullptr) {
        nChainWork = GetBlockProof();
    } else {
        nChainWork = dilithion::consensus::AddChainWork(pprev->nChainWork,
                                                        GetBlockProof());
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

const CBlockIndex* CBlockIndex::GetAncestor(int height) const {
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}
