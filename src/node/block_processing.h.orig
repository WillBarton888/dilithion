// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_BLOCK_PROCESSING_H
#define DILITHION_NODE_BLOCK_PROCESSING_H

#include <primitives/block.h>
#include <uint256.h>

// Forward declarations
class CBlockchainDB;
struct NodeContext;

/**
 * @brief Result codes for ProcessNewBlock()
 *
 * More informative than simple bool for debugging and metrics tracking.
 * Each result indicates a specific outcome for the block processing attempt.
 */
enum class BlockProcessResult {
    ACCEPTED,           // Block accepted and activated on chain
    ACCEPTED_ASYNC,     // Block queued for async validation (IBD)
    ALREADY_HAVE,       // Block already in chain (duplicate)
    INVALID_POW,        // Proof of work validation failed
    ORPHAN,             // Missing parent, stored as orphan
    DB_ERROR,           // Database write failed
    CHAINSTATE_ERROR,   // Failed to add to chainstate
    VALIDATION_ERROR    // ActivateBestChain failed
};

/**
 * @brief Process a new block received from the network or reconstructed from compact block
 *
 * Unified block processing function that handles all phases:
 * 1. Hash computation (from headers_manager or RandomX, or use precomputed)
 * 2. PoW validation (with checkpoint optimization)
 * 3. Duplicate detection (BUG #114, #150 fixes)
 * 4. Database persistence
 * 5. Block index creation / orphan handling (BUG #12, #148, #149 fixes)
 * 6. Validation routing (async queue vs sync)
 * 7. Chain activation + mining update + relay (BUG #43 fix)
 *
 * Thread-safe: Uses cs_main lock internally for chainstate access.
 *
 * @param ctx              NodeContext with all required components
 * @param db               Blockchain database for persistence
 * @param peer_id          ID of peer that sent the block (-1 for local/reconstructed)
 * @param block            The block to process
 * @param precomputed_hash Optional precomputed hash (avoids RandomX for compact blocks)
 * @return BlockProcessResult indicating outcome
 */
BlockProcessResult ProcessNewBlock(
    NodeContext& ctx,
    CBlockchainDB& db,
    int peer_id,
    const CBlock& block,
    const uint256* precomputed_hash = nullptr
);

/**
 * @brief Convert result to human-readable string (for logging)
 */
const char* BlockProcessResultToString(BlockProcessResult result);

#endif // DILITHION_NODE_BLOCK_PROCESSING_H
