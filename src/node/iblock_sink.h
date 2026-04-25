// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 4 interface contract. Receives a fully-downloaded block from
// PeerManager and hands it to the chain selector (Phase 5). Decouples
// peer-layer block reception from consensus-layer block validation.

#ifndef DILITHION_NODE_IBLOCK_SINK_H
#define DILITHION_NODE_IBLOCK_SINK_H

#include <memory>
#include <cstdint>

class CBlock;

namespace dilithion::net {
using NodeId = int;
}

namespace dilithion::node {

// Outcome of submitting a block to the chain. PeerManager uses this to
// update peer score (invalid block => Misbehaving) and tracking state
// (block delivered => clear in-flight).
enum class BlockSubmissionResult {
    Accepted,                // Block validated and connected to chain
    AlreadyHave,             // Block was already known; no-op
    InvalidBlock,            // Block failed validation; misbehavior
    InvalidHeader,           // Header check failed; misbehavior
    Orphan,                  // Block valid but parent unknown; queued
    Stored,                  // Block valid but didn't trigger reorg
    InternalError,           // Validation crashed/IO error; not peer's fault
};

class IBlockSink {
public:
    virtual ~IBlockSink() = default;

    // Submit a block received from a peer. Returns the validation outcome.
    // The implementation is expected to call into the chain selector
    // (which goes through CheckBlock -> ContextualCheckBlock -> ConnectBlock
    // -> ActivateBestChain).
    //
    // CONSENSUS BOUNDARY: the implementation MUST call ProcessNewBlock
    // exactly once with the same arguments today's code uses. No new
    // validation logic. No new bypasses.
    virtual BlockSubmissionResult SubmitBlock(
        std::shared_ptr<const CBlock> block,
        dilithion::net::NodeId source_peer) = 0;
};

}  // namespace dilithion::node

#endif  // DILITHION_NODE_IBLOCK_SINK_H
