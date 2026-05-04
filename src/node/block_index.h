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
    const CBlockIndex* GetAncestor(int height) const;

    // v4.3.3 F1 (audit modality 1 I4 / modality 2 LOW-15): bit-layout fix.
    // Pre-fix: BLOCK_VALID_MASK = 0x1F (5 bits). The mask covered the slot
    // BLOCK_HAVE_DATA = 0x08 was assigned to, so a block with only the
    // BLOCK_HAVE_DATA bit set evaluated to validLevel == 8 ≥ 3 ==
    // BLOCK_VALID_TRANSACTIONS, accidentally satisfying
    // IsBlockACandidateForActivation when the block had only data, no
    // validation. This let header-only-with-stale-HAVE-DATA leaves into
    // the candidate set; combined with the missing per-ancestor data gate
    // (F5), it produced the canary-3 chain-truncation incident.
    //
    // Post-fix: BLOCK_VALID_MASK = 0x07 (3 bits) — disjoint from data /
    // failure flags. validLevel literally is 0..5 again. Mirrors upstream
    // Bitcoin Core's `chain.h` enum (BLOCK_VALID_MASK covers 1|2|3|4|5,
    // i.e. the level field, NOT the higher flag bits).
    enum BlockStatus : uint32_t {
        BLOCK_VALID_UNKNOWN      = 0,
        BLOCK_VALID_HEADER       = 1,
        BLOCK_VALID_TREE         = 2,
        BLOCK_VALID_TRANSACTIONS = 3,
        BLOCK_VALID_CHAIN        = 4,
        BLOCK_VALID_SCRIPTS      = 5,
        // v4.3.3 F1: 0x07 covers values 0..5 only; HAVE/FAILED flags are
        // now strictly outside the level field.
        BLOCK_VALID_MASK         = 0x07,
        BLOCK_HAVE_DATA          = 0x08,
        BLOCK_HAVE_UNDO          = 0x10,

        // BUG #255: Failed block tracking (Bitcoin-style)
        // These flags prevent infinite retry loops for invalid blocks.
        // IMPORTANT: Only set during authoritative validation (ConnectTip)
        // where parent is on active chain and state is correct.
        // NEVER set during ProcessNewBlock, async queue, or fork staging.
        BLOCK_FAILED_VALID       = 0x20,  // Block failed validation in ConnectTip
        BLOCK_FAILED_CHILD       = 0x40,  // Descends from a BLOCK_FAILED_VALID block
        BLOCK_FAILED_MASK        = BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,
    };

    //! Check if this block or an ancestor failed validation
    bool IsInvalid() const { return (nStatus & BLOCK_FAILED_MASK) != 0; }
};

#endif
