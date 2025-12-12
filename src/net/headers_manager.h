// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_HEADERS_MANAGER_H
#define DILITHION_NET_HEADERS_MANAGER_H

#include <primitives/block.h>
#include <net/headerssync.h>
#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <thread>
#include <vector>
#include <atomic>

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
     * @brief Process headers with two-phase DoS protection (Bitcoin Core style)
     *
     * Uses HeadersSyncState for memory-safe IBD. Headers go through:
     * Phase 1 (PRESYNC): Build commitments, track chain work
     * Phase 2 (REDOWNLOAD): Verify headers match commitments
     *
     * @param peer Peer ID that sent the headers
     * @param headers Vector of headers to process
     * @return true if headers processed successfully
     */
    bool ProcessHeadersWithDoSProtection(NodeId peer, const std::vector<CBlockHeader>& headers);

    /**
     * @brief Check if peer should use DoS-protected header sync
     *
     * Returns true if:
     * - Peer has an active HeadersSyncState, OR
     * - We're in IBD and peer claims significantly more headers
     *
     * @param peer Peer ID to check
     * @return true if DoS protection should be used
     */
    bool ShouldUseDoSProtection(NodeId peer) const;

    /**
     * @brief Initialize DoS-protected sync for a peer
     *
     * Creates HeadersSyncState for the peer. Call this when starting
     * IBD from a new peer.
     *
     * @param peer Peer ID
     * @param minimum_work Minimum chain work to require
     * @return true if state created successfully
     */
    bool InitializeDoSProtectedSync(NodeId peer, const uint256& minimum_work);

    /**
     * @brief Validate a single header against its parent
     *
     * @param header Header to validate
     * @param pprev Parent header (nullptr for genesis)
     * @return true if header is valid
     */
    bool ValidateHeader(const CBlockHeader& header, const CBlockHeader* pprev);

    // ========================================================================
    // BUG #125: Async Header Validation (Non-blocking)
    // ========================================================================

    /**
     * @brief Quick validation - structure check only (<1ms per header)
     *
     * Validates WITHOUT expensive RandomX PoW check:
     * - Version > 0
     * - nBits non-zero
     * - Parent exists in header chain
     * - Not a duplicate header
     *
     * Use this for immediate validation during ProcessHeaders().
     *
     * @param header Header to validate
     * @param pprev Parent header (nullptr for genesis)
     * @return true if structure is valid
     */
    bool QuickValidateHeader(const CBlockHeader& header, const CBlockHeader* pprev) const;

    /**
     * @brief Full validation - RandomX PoW check only (50-250ms per header)
     *
     * Performs expensive Proof-of-Work validation using RandomX.
     * Should be called from background validation thread.
     *
     * CHECKPOINT OPTIMIZATION: If height <= highest checkpoint, PoW validation
     * is skipped (returns true) since the block hash is trusted by checkpoint.
     *
     * @param header Header to validate
     * @param height Block height (for checkpoint-aware PoW skip)
     * @return true if PoW is valid (or skipped due to checkpoint)
     */
    bool FullValidateHeader(const CBlockHeader& header, int height);

    /**
     * @brief Queue headers for background PoW validation
     *
     * Headers are quick-validated immediately, then queued for
     * background PoW validation. Returns immediately (non-blocking).
     *
     * @param peer Peer ID that sent the headers
     * @param headers Headers to validate
     * @return true if headers were queued successfully
     */
    bool QueueHeadersForValidation(NodeId peer, const std::vector<CBlockHeader>& headers);

    /**
     * @brief Start the background validation worker thread
     *
     * Call once during node initialization.
     *
     * @return true if started successfully
     */
    bool StartValidationThread();

    /**
     * @brief Stop the background validation worker thread
     *
     * Call during node shutdown. Waits for thread to finish.
     */
    void StopValidationThread();

    /**
     * @brief Check if validation thread is running
     *
     * @return true if validation thread is active
     */
    bool IsValidating() const { return m_validation_running.load(); }

    /**
     * @brief Get validation queue depth
     *
     * @return Number of headers waiting for PoW validation
     */
    size_t GetValidationQueueDepth() const;

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

    /**
     * @brief Store peer's starting height from VERSION message (BUG #62)
     *
     * Called when receiving VERSION message to track peer's announced chain height.
     * Used to determine if we should request headers from this peer.
     *
     * @param peer Peer ID
     * @param height Peer's announced chain height from VERSION message
     */
    void SetPeerStartHeight(NodeId peer, int height);

    /**
     * @brief Get peer's starting height from VERSION message (BUG #62)
     *
     * @param peer Peer ID
     * @return Peer's announced starting height, or 0 if not known
     */
    int GetPeerStartHeight(NodeId peer) const;

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
     * @struct PeerSyncState
     * @brief Tracks basic synchronization state for each peer
     *
     * Note: For DoS-protected header sync, see HeadersSyncState class.
     */
    struct PeerSyncState {
        uint256 hashLastHeader;             ///< Last header received from this peer
        int nSyncHeight;                    ///< Height peer claims to have
        std::chrono::time_point<std::chrono::steady_clock> lastUpdate;  ///< Last time we heard from peer
        bool syncing;                       ///< Currently syncing from this peer

        PeerSyncState() : nSyncHeight(0), syncing(false) {
            lastUpdate = std::chrono::steady_clock::now();
        }
    };

    //! Per-peer DoS-protected header sync state (Bitcoin Core two-phase)
    std::map<NodeId, std::unique_ptr<HeadersSyncState>> mapHeadersSyncStates;

    /**
     * @struct HeaderWithChainWork
     * @brief Header with accumulated chain work for fork selection
     *
     * Bug #46 Fix: Added parent pointer to support multiple competing chains.
     * This enables proper chain reorganization when nodes have diverged chains.
     */
    struct HeaderWithChainWork {
        CBlockHeader header;
        uint256 chainWork;                  ///< Accumulated PoW from genesis
        int height;                         ///< Height in chain
        uint256 hashPrevBlock;              ///< Parent hash (cached from header)

        HeaderWithChainWork() : height(0) {
            hashPrevBlock = uint256();
        }
        HeaderWithChainWork(const CBlockHeader& h, int ht)
            : header(h), height(ht) {
            hashPrevBlock = h.hashPrevBlock;
        }
    };

    // Header storage
    std::map<uint256, HeaderWithChainWork> mapHeaders;     ///< FastHash -> Header mapping
    std::map<int, std::set<uint256>> mapHeightIndex;       ///< Height -> FastHashes (for fork detection)

    // IBD OPTIMIZATION: Map from hashPrevBlock (RandomX from network) to FastHash (our storage key)
    // This allows O(1) parent lookups without computing expensive RandomX hashes
    // Only populated during IBD; cleared after sync complete
    std::map<uint256, uint256> mapRandomXToFastHash;       ///< hashPrevBlock -> FastHash mapping

    // Best header tracking
    uint256 hashBestHeader;                 ///< Hash of best header (most work)
    int nBestHeight;                        ///< Height of best header

    // Bug #46 Fix: Track multiple chain tips for competing chains
    std::set<uint256> setChainTips;         ///< All known chain tips (leaves in tree)

    // Bug #46 Fix: Minimum chain work for DoS protection
    uint256 nMinimumChainWork;              ///< Reject chains below this work threshold

    // Peer synchronization state
    std::map<NodeId, PeerSyncState> mapPeerStates;        ///< Peer -> Basic sync state
    std::map<NodeId, int> mapPeerStartHeight;             ///< BUG #62: Peer -> Starting height from VERSION

    // Configuration
    static constexpr size_t MAX_HEADERS_BUFFER = 2000;     ///< Max headers per message (Bitcoin Core std)
    static constexpr int MAX_HEADERS_AGE_SECONDS = 7200;   ///< 2 hours max header age
    static constexpr int MEDIAN_TIME_SPAN = 11;            ///< Blocks for median time calculation

    // Thread safety
    mutable std::mutex cs_headers;          ///< Protects all data members

    // ========================================================================
    // BUG #125: Async Validation Queue
    // ========================================================================

    /**
     * @struct PendingValidation
     * @brief Header awaiting PoW validation in background thread
     */
    struct PendingValidation {
        NodeId peer;                        ///< Peer that sent this header
        CBlockHeader header;                ///< Header to validate
        int height;                         ///< Height in chain (for logging)
        uint256 chainWork;                  ///< Accumulated chain work

        PendingValidation() : peer(-1), height(0) {}
        PendingValidation(NodeId p, const CBlockHeader& h, int ht, const uint256& work)
            : peer(p), header(h), height(ht), chainWork(work) {}
    };

    //! Queue of headers pending PoW validation
    std::queue<PendingValidation> m_validation_queue;

    //! Mutex protecting validation queue
    mutable std::mutex m_validation_mutex;

    //! Condition variable for validation queue
    std::condition_variable m_validation_cv;

    //! Validation worker thread
    std::thread m_validation_thread;

    //! Flag indicating validation thread should run
    std::atomic<bool> m_validation_running{false};

    //! Count of successfully validated headers (for stats)
    std::atomic<size_t> m_validated_count{0};

    //! Count of failed validations (for stats)
    std::atomic<size_t> m_validation_failures{0};

    /**
     * @brief Background validation worker thread main loop
     *
     * Waits for headers in queue and validates PoW.
     * Uses per-thread RandomX VM via randomx_hash_thread().
     */
    void ValidationWorkerThread();

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

    // Bug #47 Fix: Removed GetTarget() - now using consensus CompactToBig() instead
    // The custom GetTarget() had incorrect byte ordering due to memcpy usage

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

    /**
     * @brief Update chain tips after adding a new header (Bug #46)
     *
     * When a new header is added:
     * - Remove its parent from chain tips (no longer a leaf)
     * - Add the new header as a chain tip (now a leaf)
     *
     * @param hashNew Hash of newly added header
     */
    void UpdateChainTips(const uint256& hashNew);

    /**
     * @brief Calculate cumulative work with proper uint256 addition (Bug #46)
     *
     * Implements same logic as CBlockIndex::BuildChainWork()
     *
     * @param blockProof Work for this block
     * @param parentChainWork Cumulative work of parent
     * @return Total cumulative work
     */
    uint256 AddChainWork(const uint256& blockProof, const uint256& parentChainWork) const;
};

/**
 * Global IBD manager pointer (Bug #12)
 */
extern CHeadersManager* g_headers_manager;

#endif // DILITHION_NET_HEADERS_MANAGER_H
