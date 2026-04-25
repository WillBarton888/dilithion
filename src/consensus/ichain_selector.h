// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 interface contract. The chain selector is the heart of the port —
// it holds the block index tree, applies max-cumulative-work selection,
// and reorgs when a better leaf appears.
//
// Bitcoin Core's ChainstateManager / Chainstate are the upstream model.
// CONSENSUS BOUNDARY: the underlying validation (CheckBlock,
// ContextualCheckBlock, ConnectBlock) is NOT changed by the port —
// only the storage + selection plumbing is.

#ifndef DILITHION_CONSENSUS_ICHAIN_SELECTOR_H
#define DILITHION_CONSENSUS_ICHAIN_SELECTOR_H

#include <cstdint>
#include <vector>
#include <memory>
#include <uint256.h>

class CBlock;
class CBlockHeader;
class CBlockIndex;

namespace dilithion::consensus {

// View of a chain tip (active or competing).
struct ChainTipInfo {
    uint256 hash;
    int height;
    int branchlen;                   // 0 for active tip; >0 for fork
    enum class Status {
        Active,                      // The current best tip
        ValidFork,                   // Validated alternative chain
        ValidHeaders,                // Headers known, blocks not all here
        InvalidBlock,                // A block on this chain is invalid
        Unknown,                     // Headers point here but no validation yet
    } status;
    uint256 chain_work;
};

class IChainSelector {
public:
    virtual ~IChainSelector() = default;

    // ============================================================
    // Block-receipt entry point — called by IBlockSink impl.
    // ============================================================
    // Process a newly-received block. Returns true on success (block
    // accepted, possibly triggering reorg). False on validation failure.
    virtual bool ProcessNewBlock(std::shared_ptr<const CBlock> block,
                                 bool force_processing,
                                 bool* triggered_reorg = nullptr) = 0;

    // Process a header — used by HeadersSync. Stores in block index tree
    // (every header gets a CBlockIndex entry, including competing siblings).
    // Returns true on success.
    virtual bool ProcessNewHeader(const CBlockHeader& header) = 0;

    // ============================================================
    // Chain tip queries — replaces fork_manager + chain_tips_tracker.
    // ============================================================
    virtual CBlockIndex* GetActiveTip() const = 0;
    virtual int GetActiveHeight() const = 0;
    virtual uint256 GetActiveTipHash() const = 0;

    // All known chain tips (for getchaintips RPC). Walks the block index
    // tree's leaves; never reads a separate "competing tips" cache.
    virtual std::vector<ChainTipInfo> GetChainTips() const = 0;

    // Find the leaf with maximum cumulative work. This is the chain
    // selector's core responsibility. Called automatically on every
    // header receipt; exposed for diagnostics + testing.
    virtual CBlockIndex* FindMostWorkChain() const = 0;

    // Walk the block index tree to find a block by hash. Returns nullptr
    // if not known. (This replaces ForkManager::IsBlockForActiveFork —
    // every block lookup goes through the index tree.)
    virtual CBlockIndex* LookupBlockIndex(const uint256& hash) const = 0;

    // ============================================================
    // Manual operator overrides — RPC-callable.
    // ============================================================
    // Mark a block as invalid; triggers re-selection of best chain.
    virtual bool InvalidateBlock(const uint256& hash) = 0;

    // Reverse InvalidateBlock; triggers re-selection.
    virtual bool ReconsiderBlock(const uint256& hash) = 0;

    // ============================================================
    // Sync state queries (for getblockchaininfo).
    // ============================================================
    virtual bool IsInitialBlockDownload() const = 0;
};

}  // namespace dilithion::consensus

#endif  // DILITHION_CONSENSUS_ICHAIN_SELECTOR_H
