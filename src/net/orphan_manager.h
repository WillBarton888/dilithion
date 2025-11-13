// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_ORPHAN_MANAGER_H
#define DILITHION_NET_ORPHAN_MANAGER_H

#include <primitives/block.h>
#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <vector>

/**
 * @file orphan_manager.h
 * @brief Orphan block management for Initial Block Download (IBD)
 *
 * Implements Bitcoin Core-style orphan block handling:
 * 1. Temporarily store blocks whose parents are unknown
 * 2. Index by parent hash for efficient lookup when parent arrives
 * 3. Memory-bounded storage with LRU eviction (100 blocks / 100MB)
 * 4. Time-based expiration (orphans expire after 20 minutes)
 * 5. DoS protection (peer limits, memory limits)
 * 6. Recursive orphan resolution when parent is connected
 *
 * This is Phase 2 of the IBD implementation (Bug #12).
 */

// Forward declarations
typedef int NodeId;

/**
 * @class COrphanManager
 * @brief Manages temporary storage of orphan blocks during chain sync
 *
 * When a node receives a block whose parent is not yet known, it becomes
 * an "orphan block". This manager stores such blocks temporarily and
 * automatically processes them when their parent arrives.
 *
 * Key features:
 * - Memory-bounded: Max 100 blocks or 100MB total
 * - Time-limited: Orphans expire after 20 minutes
 * - Peer-limited: Max 100 orphans per peer (DoS protection)
 * - Efficient lookup: O(1) by hash, O(n) by parent hash
 * - Recursive resolution: When parent arrives, processes all children
 * - Thread-safe: All operations protected by mutex
 */
class COrphanManager {
public:
    COrphanManager();
    ~COrphanManager() = default;

    // Disable copying
    COrphanManager(const COrphanManager&) = delete;
    COrphanManager& operator=(const COrphanManager&) = delete;

    /**
     * @brief Add an orphan block to storage
     *
     * Stores a block whose parent is not yet known. Enforces memory limits
     * and evicts oldest orphans if necessary.
     *
     * @param peer Peer ID that sent this block
     * @param block The orphan block
     * @return true if added (or already exists), false if rejected (e.g., peer limit exceeded)
     */
    bool AddOrphanBlock(NodeId peer, const CBlock& block);

    /**
     * @brief Check if an orphan block exists
     *
     * @param hash Block hash to check
     * @return true if orphan exists in storage
     */
    bool HaveOrphanBlock(const uint256& hash) const;

    /**
     * @brief Get an orphan block by hash
     *
     * @param hash Block hash to retrieve
     * @param block Output parameter for block data
     * @return true if found, false otherwise
     */
    bool GetOrphanBlock(const uint256& hash, CBlock& block) const;

    /**
     * @brief Remove an orphan block from storage
     *
     * Also removes from all indices (by hash, by parent, by peer)
     *
     * @param hash Block hash to remove
     * @return true if removed, false if didn't exist
     */
    bool EraseOrphanBlock(const uint256& hash);

    /**
     * @brief Get all orphan blocks that have a specific parent
     *
     * Used when a parent block arrives to find all children that
     * can now be processed.
     *
     * @param parentHash Hash of the parent block
     * @return Vector of orphan block hashes that have this parent
     */
    std::vector<uint256> GetOrphanChildren(const uint256& parentHash) const;

    /**
     * @brief Get the root ancestor of an orphan chain
     *
     * Follows pprev pointers to find the oldest orphan in a chain.
     * Used to request the earliest missing block.
     *
     * @param hash Starting orphan hash
     * @return Hash of the root orphan (first block with unknown parent)
     */
    uint256 GetOrphanRoot(const uint256& hash) const;

    /**
     * @brief Remove all orphans from a specific peer
     *
     * Used when peer disconnects or misbehaves
     *
     * @param peer Peer ID to erase orphans from
     * @return Number of orphans erased
     */
    size_t EraseOrphansForPeer(NodeId peer);

    /**
     * @brief Get count of orphans from a specific peer
     *
     * Used for DoS protection (limit orphans per peer)
     *
     * @param peer Peer ID to count
     * @return Number of orphans from this peer
     */
    size_t GetOrphanCountForPeer(NodeId peer) const;

    /**
     * @brief Remove expired orphans
     *
     * Removes orphans older than maxAge. Should be called periodically.
     *
     * @param maxAge Maximum age for orphans (default 20 minutes)
     * @return Number of orphans erased
     */
    size_t EraseExpiredOrphans(std::chrono::seconds maxAge = std::chrono::seconds(1200));

    // Statistics and monitoring

    /**
     * @brief Get total number of orphans in storage
     *
     * @return Count of orphan blocks
     */
    size_t GetOrphanCount() const;

    /**
     * @brief Get total memory used by orphans
     *
     * @return Bytes used by orphan block storage
     */
    size_t GetOrphanBytes() const;

    /**
     * @brief Get all orphan block hashes
     *
     * Used for diagnostics and monitoring
     *
     * @return Vector of all orphan hashes
     */
    std::vector<uint256> GetAllOrphans() const;

    /**
     * @brief Clear all orphans (for testing or reset)
     *
     * Warning: This clears the entire orphan pool!
     */
    void Clear();

private:
    /**
     * @struct COrphanBlock
     * @brief Storage structure for an orphan block with metadata
     */
    struct COrphanBlock {
        CBlock block;                                                    ///< The actual block data
        NodeId fromPeer;                                                 ///< Peer that sent this block
        std::chrono::time_point<std::chrono::steady_clock> timeReceived; ///< When block was received
        size_t nBlockSize;                                               ///< Serialized block size (for memory tracking)

        COrphanBlock(const CBlock& blk, NodeId peer, size_t size)
            : block(blk)
            , fromPeer(peer)
            , timeReceived(std::chrono::steady_clock::now())
            , nBlockSize(size)
        {}
    };

    // Primary storage: hash -> orphan block
    std::map<uint256, COrphanBlock> mapOrphanBlocks;

    // Index by parent hash for quick lookup when parent arrives
    // parent_hash -> set of orphan hashes
    std::multimap<uint256, uint256> mapOrphanBlocksByPrev;

    // Index by peer for DoS protection and cleanup
    // peer_id -> set of orphan hashes
    std::map<NodeId, std::set<uint256>> mapOrphanBlocksByPeer;

    // Memory tracking
    size_t nOrphanBytes;  ///< Total bytes used by orphan blocks

    // Configuration constants (Bitcoin Core standards)
    static constexpr size_t MAX_ORPHAN_BLOCKS = 100;              ///< Maximum number of orphan blocks
    static constexpr size_t MAX_ORPHAN_BYTES = 100 * 1024 * 1024; ///< Maximum bytes (100MB)
    static constexpr size_t MAX_ORPHANS_PER_PEER = 100;           ///< Maximum orphans from single peer
    static constexpr int DEFAULT_ORPHAN_EXPIRATION_SECS = 1200;   ///< 20 minutes

    // Thread safety
    mutable std::mutex cs_orphans;  ///< Protects all data members

    // Internal helpers

    /**
     * @brief Enforce memory and count limits by evicting oldest orphans
     *
     * Called after adding a new orphan. Uses FIFO eviction strategy.
     */
    void LimitOrphans();

    /**
     * @brief Select an orphan for eviction
     *
     * Currently uses FIFO (oldest first) strategy.
     * Could be enhanced with score-based eviction.
     *
     * @return Hash of orphan to evict, or null hash if none
     */
    uint256 SelectOrphanForEviction();

    /**
     * @brief Remove orphan from all internal data structures
     *
     * Must be called with cs_orphans lock held.
     * Does not update nOrphanBytes (caller's responsibility).
     *
     * @param it Iterator to orphan in mapOrphanBlocks
     */
    void EraseOrphanInternal(std::map<uint256, COrphanBlock>::iterator it);

    /**
     * @brief Calculate serialized size of a block
     *
     * Estimates memory usage for a block
     *
     * @param block Block to size
     * @return Estimated serialized size in bytes
     */
    size_t GetBlockSize(const CBlock& block) const;

    /**
     * @brief Check if peer has exceeded orphan limit
     *
     * @param peer Peer ID to check
     * @return true if peer is at or above limit
     */
    bool PeerExceedsOrphanLimit(NodeId peer) const;
};

#endif // DILITHION_NET_ORPHAN_MANAGER_H
