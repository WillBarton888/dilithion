// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_BLOCK_INDEX_H
#define DILITHION_NODE_BLOCK_INDEX_H

#include <primitives/block.h>
#include <cstdint>
#include <string>

class CBlockIndex
{
public:
    CBlockHeader header;
    CBlockIndex* pprev;      // Pointer to previous block in chain
    CBlockIndex* pnext;      // Pointer to next block in MAIN chain (nullptr if not on main chain)
    CBlockIndex* pskip;      // Skip pointer for faster chain traversal
    int nHeight;
    int nFile;
    unsigned int nDataPos;
    unsigned int nUndoPos;
    uint256 nChainWork;      // Total cumulative chain work up to and including this block
    unsigned int nTx;
    uint32_t nStatus;
    uint32_t nSequenceId;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;
    int32_t nVersion;
    mutable uint256 phashBlock;

    CBlockIndex();
    explicit CBlockIndex(const CBlockHeader& block);

    /**
     * BUG #70 FIX: Explicit copy constructor to ensure header.hashMerkleRoot is copied
     * The implicit copy constructor should work, but we add explicit for safety and clarity
     */
    CBlockIndex(const CBlockIndex& other);

    uint256 GetBlockHash() const;
    bool IsValid() const;
    bool HaveData() const;
    std::string ToString() const;

    /**
     * Calculate the proof-of-work for this block
     * Work is defined as: ~uint256(0) / (target + 1)
     * Approximated as: 2^256 / (target + 1)
     */
    uint256 GetBlockProof() const;

    /**
     * Check if this block is on the main (active) chain
     * A block is on main chain if pnext is set OR if it's the current tip
     */
    bool IsOnMainChain() const { return pnext != nullptr; }

    /**
     * Build chain work from parent
     * Called during block index initialization
     */
    void BuildChainWork();

    /**
     * Get ancestor at specific height
     * Uses pskip pointers for efficient traversal
     */
    CBlockIndex* GetAncestor(int height);

    enum BlockStatus : uint32_t {
        BLOCK_VALID_UNKNOWN      = 0,
        BLOCK_VALID_HEADER       = 1,
        BLOCK_VALID_TREE         = 2,
        BLOCK_VALID_TRANSACTIONS = 3,
        BLOCK_VALID_CHAIN        = 4,
        BLOCK_VALID_SCRIPTS      = 5,
        BLOCK_VALID_MASK         = 31,
        BLOCK_HAVE_DATA          = 8,
        BLOCK_HAVE_UNDO          = 16,

        // BUG #255: Failed block tracking (Bitcoin-style)
        // These flags prevent infinite retry loops for invalid blocks.
        // IMPORTANT: Only set during authoritative validation (ConnectTip)
        // where parent is on active chain and state is correct.
        // NEVER set during ProcessNewBlock, async queue, or fork staging.
        BLOCK_FAILED_VALID       = 32,   // Block failed validation in ConnectTip
        BLOCK_FAILED_CHILD       = 64,   // Descends from a BLOCK_FAILED_VALID block
        BLOCK_FAILED_MASK        = BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,
    };

    //! Check if this block or an ancestor failed validation
    bool IsInvalid() const { return (nStatus & BLOCK_FAILED_MASK) != 0; }
};

#endif
