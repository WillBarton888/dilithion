// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_NODE_STATE_H
#define DILITHION_NET_NODE_STATE_H

#include <primitives/block.h>
#include <chrono>

// Forward declarations
class CBlockIndex;

/**
 * @struct QueuedBlock
 * @brief A block we're downloading from a peer
 *
 * Tracks which blocks are in-flight to which peers, allowing
 * proper cleanup when a peer disconnects and retry logic when
 * a download times out.
 */
struct QueuedBlock {
    uint256 hash;                                   ///< Block hash being downloaded
    const CBlockIndex* pindex = nullptr;            ///< Block index (if known)
    bool fValidatedHeaders = false;                 ///< Headers validated
    std::chrono::steady_clock::time_point time;     ///< When download started

    QueuedBlock() : time(std::chrono::steady_clock::now()) {}
    QueuedBlock(const uint256& h, const CBlockIndex* idx = nullptr)
        : hash(h), pindex(idx), fValidatedHeaders(idx != nullptr),
          time(std::chrono::steady_clock::now()) {}
};

#endif // DILITHION_NET_NODE_STATE_H
