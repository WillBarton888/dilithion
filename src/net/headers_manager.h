// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_HEADERS_MANAGER_H
#define DILITHION_NET_HEADERS_MANAGER_H

#include <primitives/block.h>
#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <vector>

/**
 * @file headers_manager.h
 * @brief Headers-first synchronization manager for Initial Block Download (IBD)
 *
 * Implements Bitcoin Core-style headers-first sync:
 * 1. Download block headers before full blocks (lightweight)
 * 2. Validate header chain (PoW, timestamps, difficulty)
 * 3. Detect and handle forks (most-work chain selection)
 * 4. Generate block locators for efficient sync
 * 5. Track peer synchronization state
 *
 * This is Phase 1 of the IBD implementation (Bug #12).
 */

// Forward declarations
typedef int NodeId;

namespace NetProtocol {
    class CGetHeadersMessage;
}

/**
 * @class CHeadersManager
 * @brief Manages header chain synchronization and validation
 *
 * Thread-safe class for downloading and validating block headers
 * before downloading full blocks. Enables parallel block downloads
 * and efficient fork detection.
 *
 * Memory efficient: Headers are ~80 bytes each, so 1M headers = ~80MB
 */
class CHeadersManager {
public:
    CHeadersManager();
    ~CHeadersManager() = default;

    // Disable copying
    CHeadersManager(const CHeadersManager&) = delete;
    CHeadersManager& operator=(const CHeadersManager&) = delete;

    /**
     * @brief Process received headers from a peer
     *
     * Validates headers chain:
     * - PoW meets target
     * - Timestamps valid (not too far in future, after median of last 11)
     * - Difficulty transitions valid
     * - Parent blocks exist
     *
     * @param peer Peer ID that sent the headers
     * @param headers Vector of headers to process
     * @return true if headers processed successfully, false if invalid
     */
    bool ProcessHeaders(NodeId peer, const std::vector<CBlockHeader>& headers);

    /**
     * @brief Validate a single header against its parent
     *
     * @param header Header to validate
     * @param pprev Parent header (nullptr for genesis)
     * @return true if header is valid
     */
    bool ValidateHeader(const CBlockHeader& header, const CBlockHeader* pprev);

    /**
     * @brief Request headers from a peer
     *
     * Sends GETHEADERS message with block locator.
     * Locator uses exponential backoff to find common ancestor efficiently.
     *
     * @param peer Peer ID to request from
     * @param hashStart Starting hash for locator (usually current tip)
     */
    void RequestHeaders(NodeId peer, const uint256& hashStart);

    /**
     * @brief Add header when block is activated in chain (Bug #40)
     *
     * Called by CChainState when a new block becomes the chain tip.
     * Updates HeadersManager's internal state to track newly activated blocks.
     *
     * @param header Block header that was activated
     * @param hash Hash of the activated block
     */
    void OnBlockActivated(const CBlockHeader& header, const uint256& hash);

    /**
     * @brief Generate block locator for sync
     *
     * Bitcoin Core exponential backoff algorithm:
     * - Start from tip
     * - Go back: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024...
     * - Always include genesis
     *
     * @param hashTip Starting point (usually best header)
     * @return Vector of block hashes for locator
     */
    std::vector<uint256> GetLocator(const uint256& hashTip);

    /**
     * @brief Check if node is currently syncing headers
     *
     * @return true if actively downloading headers from peers
     */
    bool IsSyncing() const;

    /**
     * @brief Get current header sync progress
     *
     * @return Percentage (0.0 to 1.0) of headers downloaded
     */
    double GetSyncProgress() const;

    /**
     * @brief Get best header (tip of header chain)
     *
     * @return Pointer to best header, nullptr if none
     */
    const CBlockHeader* GetBestHeader() const;

    /**
     * @brief Get best header hash
     *
     * @return Hash of best header
     */
    uint256 GetBestHeaderHash() const;

    /**
     * @brief Get best header height
     *
     * @return Height of best header chain
     */
    int GetBestHeight() const;

    /**
     * @brief Get header by hash
     *
     * @param hash Block hash to lookup
     * @param header Output parameter for header
     * @return true if found
     */
    bool GetHeader(const uint256& hash, CBlockHeader& header) const;

    /**
     * @brief Check if we have a specific header
     *
     * @param hash Block hash to check
     * @return true if header exists in storage
     */
    bool HaveHeader(const uint256& hash) const;

    /**
     * @brief Get all headers at a specific height (for fork detection)
     *
     * @param height Block height
     * @return Vector of hashes at that height
     */
    std::vector<uint256> GetHeadersAtHeight(int height) const;

    // Peer management

    /**
     * @brief Notify manager that a peer connected
     *
     * Initializes sync state for this peer
     *
     * @param peer Peer ID
     */
    void OnPeerConnected(NodeId peer);

    /**
     * @brief Notify manager that a peer disconnected
     *
     * Cleans up sync state for this peer
     *
     * @param peer Peer ID
     */
    void OnPeerDisconnected(NodeId peer);

    /**
     * @brief Check if we should fetch headers from this peer
     *
     * Rate limiting: Don't request too frequently from same peer
     *
     * @param peer Peer ID to check
     * @return true if we should request headers
     */
    bool ShouldFetchHeaders(NodeId peer) const;

    /**
     * @brief Mark peer as having sent us a header
     *
     * Updates peer sync state tracking
     *
     * @param peer Peer ID
     * @param hash Last header hash received
     * @param height Height of last header
     */
    void UpdatePeerState(NodeId peer, const uint256& hash, int height);

    // Diagnostic/monitoring

    /**
     * @brief Get number of headers stored
     *
     * @return Count of headers in memory
     */
    size_t GetHeaderCount() const;

    /**
     * @brief Get estimated memory usage
     *
     * @return Bytes used by header storage
     */
    size_t GetMemoryUsage() const;

    /**
     * @brief Clear all headers (for testing or reorg)
     *
     * Warning: This clears the entire header chain!
     */
    void Clear();

private:
    /**
     * @struct HeadersSyncState
     * @brief Tracks synchronization state for each peer
     */
    struct HeadersSyncState {
        uint256 hashLastHeader;             ///< Last header received from this peer
        int nSyncHeight;                    ///< Height peer claims to have
        std::chrono::time_point<std::chrono::steady_clock> lastUpdate;  ///< Last time we heard from peer
        bool syncing;                       ///< Currently syncing from this peer

        HeadersSyncState() : nSyncHeight(0), syncing(false) {
            lastUpdate = std::chrono::steady_clock::now();
        }
    };

    /**
     * @struct HeaderWithChainWork
     * @brief Header with accumulated chain work for fork selection
     */
    struct HeaderWithChainWork {
        CBlockHeader header;
        uint256 chainWork;                  ///< Accumulated PoW from genesis
        int height;                         ///< Height in chain

        HeaderWithChainWork() : height(0) {}
        HeaderWithChainWork(const CBlockHeader& h, int ht)
            : header(h), height(ht) {}
    };

    // Header storage
    std::map<uint256, HeaderWithChainWork> mapHeaders;     ///< Hash -> Header mapping
    std::map<int, std::set<uint256>> mapHeightIndex;       ///< Height -> Hashes (for fork detection)

    // Best header tracking
    uint256 hashBestHeader;                 ///< Hash of best header (most work)
    int nBestHeight;                        ///< Height of best header

    // Peer synchronization state
    std::map<NodeId, HeadersSyncState> mapPeerStates;     ///< Peer -> Sync state

    // Configuration
    static constexpr size_t MAX_HEADERS_BUFFER = 2000;     ///< Max headers per message (Bitcoin Core std)
    static constexpr int MAX_HEADERS_AGE_SECONDS = 7200;   ///< 2 hours max header age
    static constexpr int MEDIAN_TIME_SPAN = 11;            ///< Blocks for median time calculation

    // Thread safety
    mutable std::mutex cs_headers;          ///< Protects all data members

    // Internal helpers

    /**
     * @brief Calculate accumulated chain work for a header
     *
     * @param header Header to calculate work for
     * @param pprev Parent header (for cumulative work)
     * @return Accumulated chain work (sum of all block work from genesis)
     */
    uint256 CalculateChainWork(const CBlockHeader& header, const HeaderWithChainWork* pprev) const;

    /**
     * @brief Calculate work required for a single block
     *
     * Work = 2^256 / (target + 1)
     *
     * @param nBits Compact difficulty target
     * @return Block work value
     */
    uint256 GetBlockWork(uint32_t nBits) const;

    /**
     * @brief Get compact target from difficulty bits
     *
     * @param nBits Compact bits representation
     * @return Full 256-bit target
     */
    uint256 GetTarget(uint32_t nBits) const;

    /**
     * @brief Check if block hash meets target (PoW validation)
     *
     * @param hash Block hash
     * @param nBits Target difficulty
     * @return true if hash < target
     */
    bool CheckProofOfWork(const uint256& hash, uint32_t nBits) const;

    /**
     * @brief Check if header timestamp is valid
     *
     * Rules:
     * - Not more than 2 hours in future
     * - Greater than median of last 11 blocks
     *
     * @param header Header to check
     * @param pprev Parent header
     * @return true if timestamp valid
     */
    bool CheckTimestamp(const CBlockHeader& header, const HeaderWithChainWork* pprev) const;

    /**
     * @brief Get median timestamp of last N blocks
     *
     * @param pprev Starting block
     * @param span Number of blocks to consider (default 11)
     * @return Median timestamp
     */
    uint32_t GetMedianTimePast(const HeaderWithChainWork* pprev, int span = MEDIAN_TIME_SPAN) const;

    /**
     * @brief Update best header if new header has more work
     *
     * @param hash Hash of potential new best header
     * @return true if best header changed
     */
    bool UpdateBestHeader(const uint256& hash);

    /**
     * @brief Add header to height index for fork tracking
     *
     * @param hash Header hash
     * @param height Header height
     */
    void AddToHeightIndex(const uint256& hash, int height);

    /**
     * @brief Remove header from height index
     *
     * @param hash Header hash
     * @param height Header height
     */
    void RemoveFromHeightIndex(const uint256& hash, int height);
};

/**
 * Global IBD manager pointer (Bug #12)
 */
extern CHeadersManager* g_headers_manager;

#endif // DILITHION_NET_HEADERS_MANAGER_H
