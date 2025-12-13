// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_NODE_STATE_H
#define DILITHION_NET_NODE_STATE_H

#include <primitives/block.h>
#include <chrono>
#include <list>
#include <map>
#include <mutex>
#include <memory>

/**
 * @file node_state.h
 * @brief Bitcoin Core-style per-peer validation state tracking
 *
 * Ported from Bitcoin Core's net_processing.cpp to provide:
 * 1. Per-peer block download tracking (vBlocksInFlight)
 * 2. Best known block tracking for each peer
 * 3. Handshake and sync state management
 * 4. Stalling detection with adaptive timeouts
 * 5. Bidirectional block tracking (global + per-peer)
 *
 * This fixes issues where:
 * - OnPeerDisconnected() wasn't cleaning up in-flight blocks
 * - BlockFetcher had duplicate state tracking that got out of sync
 * - No adaptive stalling detection based on peer behavior
 *
 * Reference: Bitcoin Core src/net_processing.cpp CNodeState
 */

// Forward declarations
class CBlockIndex;
typedef int NodeId;

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

/**
 * @struct CNodeState
 * @brief Per-peer validation state (ported from Bitcoin Core)
 *
 * Tracks everything we need to know about a peer for block synchronization:
 * - What blocks we're downloading from them
 * - What their best block is (from headers)
 * - Whether they've completed handshake
 * - Whether they're stalling (slow downloads)
 *
 * This replaces the scattered state in BlockFetcher and peers.cpp with
 * a single, coherent per-peer state structure.
 */
struct CNodeState {
    NodeId nodeid;

    //! List of blocks we're downloading from this peer
    //! Ordered by request time (oldest first)
    std::list<QueuedBlock> vBlocksInFlight;

    //! Number of blocks in flight (for quick access)
    int nBlocksInFlight = 0;

    //! Best known block this peer has (from headers they sent us)
    //! Used to know if we should request more from this peer
    const CBlockIndex* pindexBestKnownBlock = nullptr;

    //! Last common block between us and this peer
    //! Used for efficient header sync (request from where we diverged)
    const CBlockIndex* pindexLastCommonBlock = nullptr;

    //! Handshake state
    bool fHandshakeComplete = false;

    //! Height peer reported in VERSION message
    //! -1 means not yet received, >= 0 means we know their height
    int nStartingHeight = -1;

    //! Download preferences
    //! Outbound peers are preferred (we initiated connection = more trusted)
    bool fPreferredDownload = false;

    //! Whether we've started syncing from this peer
    bool fSyncStarted = false;

    //! Stalling detection timestamps
    std::chrono::steady_clock::time_point m_stalling_since;
    std::chrono::steady_clock::time_point m_downloading_since;
    std::chrono::steady_clock::time_point m_last_block_announcement;

    //! Stalling statistics
    int nStallingCount = 0;

    //! Adaptive timeout: starts at 10 seconds, grows up to 320 seconds
    //! after repeated stalls from this peer
    //! BUG #89 FIX: Increased base from 2s to 10s - 2s was too aggressive
    //! for cross-datacenter transfers with RandomX PoW verification overhead
    std::chrono::seconds GetBlockTimeout() const {
        // Base timeout: 10 seconds (was 2s - too aggressive)
        // Double for each stall, max 320 seconds
        int timeout_seconds = 10 << std::min(nStallingCount, 5);
        return std::chrono::seconds(timeout_seconds);
    }

    explicit CNodeState(NodeId id)
        : nodeid(id),
          m_stalling_since(std::chrono::steady_clock::now()),
          m_downloading_since(std::chrono::steady_clock::now()),
          m_last_block_announcement(std::chrono::steady_clock::now()) {}
};

/**
 * @class CNodeStateManager
 * @brief Global manager for all peer states (singleton pattern)
 *
 * Provides thread-safe access to per-peer state and bidirectional
 * block tracking (global map + per-peer list).
 *
 * Usage:
 *   CNodeStateManager::Get().CreateState(peer_id);
 *   CNodeStateManager::Get().MarkBlockAsInFlight(peer_id, hash, pindex);
 *   CNodeStateManager::Get().MarkBlockAsReceived(hash);
 *   CNodeStateManager::Get().RemoveState(peer_id);  // On disconnect
 */
class CNodeStateManager {
public:
    static CNodeStateManager& Get() {
        static CNodeStateManager instance;
        return instance;
    }

    //! Create state for a new peer (call on handshake complete)
    CNodeState* CreateState(NodeId nodeid);

    //! BUG #85 FIX: Atomically create state AND set handshake complete fields
    //! This prevents race conditions where state is modified after lock is released
    //! Returns true if state was created and initialized, false if already exists
    bool CreateStateWithHandshake(NodeId nodeid, int nStartingHeight, bool fPreferredDownload);

    //! Get existing state for a peer (returns nullptr if not found)
    CNodeState* GetState(NodeId nodeid);

    //! Remove state for disconnected peer (re-queues in-flight blocks)
    void RemoveState(NodeId nodeid);

    //! Mark a block as being downloaded from a peer
    //! Returns false if block is already in flight from another peer
    bool MarkBlockAsInFlight(NodeId nodeid, const uint256& hash, const CBlockIndex* pindex = nullptr);

    //! Mark a block as received (removes from in-flight tracking)
    //! Returns the peer it was downloaded from, or -1 if not tracked
    NodeId MarkBlockAsReceived(const uint256& hash);

    //! Check if a block is currently being downloaded
    bool IsBlockInFlight(const uint256& hash) const;

    //! Get the peer downloading a specific block (-1 if not in flight)
    NodeId GetBlockPeer(const uint256& hash) const;

    //! Get all blocks currently in flight (for monitoring)
    std::vector<std::pair<uint256, NodeId>> GetBlocksInFlight() const;

    //! Get blocks in flight for a specific peer
    int GetBlocksInFlightForPeer(NodeId nodeid) const;

    //! Re-queue all in-flight blocks from a peer (for disconnect cleanup)
    std::vector<uint256> GetAndClearPeerBlocks(NodeId nodeid);

    //! Check for stalling peers and return those that need disconnection
    std::vector<NodeId> CheckForStallingPeers();

    //! Get peer count with completed handshakes
    size_t GetHandshakeCompleteCount() const;

    //! Get best peer height (for IBD detection)
    int GetBestPeerHeight() const;

    //! Clear all state (for testing)
    void Clear();

private:
    CNodeStateManager() = default;

    mutable std::mutex cs_nodestate;

    //! Per-peer state (protected by cs_nodestate)
    std::map<NodeId, CNodeState> mapNodeState;

    //! Global block-to-peer mapping for quick lookup
    //! hash -> (peer_id, iterator into that peer's vBlocksInFlight)
    std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator>> mapBlocksInFlight;

    //! Maximum blocks in flight per peer
    //! IBD FIX #12: Increased from 64 to 128 for faster single-peer IBD
    static constexpr int MAX_BLOCKS_IN_FLIGHT_PER_PEER = 128;

    //! Maximum total blocks in flight across all peers
    static constexpr int MAX_BLOCKS_IN_FLIGHT_TOTAL = 256;
};

#endif // DILITHION_NET_NODE_STATE_H
