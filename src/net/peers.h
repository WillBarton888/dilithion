// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_PEERS_H
#define DILITHION_NET_PEERS_H

#include <net/protocol.h>
#include <net/iaddress_manager.h>  // Phase 1 port: IAddressManager interface
#include <net/ipeer_scorer.h>      // Phase 2 port: IPeerScorer interface
#include <net/port/maybe_punish_node.h>  // Phase 3: HeaderRejectReason enum
#include <net/banman.h>   // Bitcoin Core-style ban manager with persistence
#include <net/peer_discovery.h>  // Network: Enhanced peer discovery
#include <net/bandwidth_throttle.h>   // F21: per-peer throttle cleanup on disconnect
#include <net/connection_quality.h>  // Network: Connection quality metrics
#include <net/socket.h>   // Phase 2: Socket in CPeer
#include <net/node_state.h>  // Phase 3: For QueuedBlock
#include <net/node.h>     // Phase 1: CNode for event-driven networking
#include <primitives/block.h>  // Phase 3: For uint256
#include <util/time.h>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <set>
#include <mutex>
#include <memory>
#include <atomic>
#include <chrono>

// Forward declaration
class CBlockIndex;

/**
 * CPeer - Represents a network peer connection
 */
class CPeer {
public:
    enum State {
        STATE_DISCONNECTED,
        STATE_CONNECTING,
        STATE_CONNECTED,
        STATE_VERSION_SENT,
        STATE_HANDSHAKE_COMPLETE,
        STATE_BANNED,
    };

    int id;                          // Unique peer ID
    NetProtocol::CAddress addr;      // Peer address
    // SSOT FIX #1: CPeer::state is DEPRECATED - CNode::state is the single source of truth
    // This field is kept for backward compatibility but should not be used for state checks
    // Use CPeerManager::GetNode(peer_id)->state instead
    State state;                     // DEPRECATED: Use CNode::state instead
    int64_t connect_time;            // When connection was established
    int64_t last_recv;               // Last message received time
    int64_t last_send;               // Last message sent time
    int version;                     // Protocol version
    std::string user_agent;          // Peer client version
    int start_height;                // Peer's blockchain height at VERSION time (never updated)
    int best_known_height;           // Best block height we KNOW peer has (updated on headers)
    uint256 best_known_hash;         // Best block hash we KNOW peer has (updated on headers)
    std::chrono::steady_clock::time_point last_tip_update;  // When best_known_hash was last set
    bool relay;                      // Whether peer relays transactions

    // DoS protection
    // Phase 2 port: misbehavior_score field DELETED (Q3=B). Score lives in
    // CPeerScorer (CPeerManager::m_scorer) keyed by peer id; query via
    // CPeerManager::GetMisbehaviorScore(peer_id).
    int64_t ban_time;                // Time when ban expires (0 = not banned)

    // === Phase 2: Socket moved from CConnectionManager to CPeer ===
private:
    std::shared_ptr<CSocket> m_sock;
    mutable std::mutex m_sock_mutex;
    std::vector<uint8_t> m_recv_buffer;
    mutable std::mutex m_recv_mutex;

public:
    bool HasValidSocket() const {
        std::lock_guard<std::mutex> lock(m_sock_mutex);
        return m_sock && m_sock->IsValid();
    }

    std::shared_ptr<CSocket> GetSocket() const {
        std::lock_guard<std::mutex> lock(m_sock_mutex);
        return m_sock;
    }

    void SetSocket(std::shared_ptr<CSocket> sock) {
        std::lock_guard<std::mutex> lock(m_sock_mutex);
        m_sock = std::move(sock);
    }

    void ClearSocket() {
        std::lock_guard<std::mutex> lock(m_sock_mutex);
        if (m_sock) { m_sock->Close(); m_sock.reset(); }
    }

    // === Phase 3: Block Sync State ===
    // DEPRECATED: CBlockTracker is now the single source of truth for block tracking.
    // These fields are kept for backward compatibility with orphan block handling only.
    // All new code should use CBlockTracker via g_node_context.block_tracker.
    std::list<QueuedBlock> vBlocksInFlight;  // DEPRECATED: Use CBlockTracker
    int nBlocksInFlight = 0;                  // DEPRECATED: Use CBlockTracker::GetPeerInFlightCount()
    const CBlockIndex* pindexBestKnownBlock = nullptr;
    const CBlockIndex* pindexLastCommonBlock = nullptr;
    bool fSyncStarted = false;
    bool fPreferredDownload = false;

    std::chrono::steady_clock::time_point m_stalling_since;
    std::chrono::steady_clock::time_point m_downloading_since;
    std::chrono::steady_clock::time_point m_last_block_announcement;
    int nStallingCount = 0;

    std::chrono::milliseconds avgResponseTime{1000};
    int nBlocksDownloaded = 0;
    std::chrono::steady_clock::time_point lastSuccessTime;
    std::chrono::steady_clock::time_point lastStallTime;

    static constexpr int STALL_THRESHOLD = 500;  // Increased from 100 for slow IBD connections
    static constexpr auto STALL_FORGIVENESS_TIMEOUT = std::chrono::minutes(5);

    std::chrono::seconds GetBlockTimeout(bool isManual = false) const {
        // Manual peers (--connect/--addnode) get 3x base timeout to avoid
        // disconnecting relay peers that are busy serving multiple IBD miners
        int base = isManual ? 30 : 10;
        int timeout_seconds = base << std::min(nStallingCount, 5);
        return std::chrono::seconds(timeout_seconds);
    }

    bool IsSuitableForDownload() const {
        auto now = std::chrono::steady_clock::now();
        auto stallAge = std::chrono::duration_cast<std::chrono::minutes>(now - lastStallTime);
        if (stallAge >= STALL_FORGIVENESS_TIMEOUT) return true;
        return nStallingCount < STALL_THRESHOLD;
    }

    CPeer()
        : id(0), state(STATE_DISCONNECTED), connect_time(0),
          last_recv(0), last_send(0), version(0), start_height(0),
          best_known_height(0), relay(true), ban_time(0),
          m_stalling_since(std::chrono::steady_clock::now()),
          m_downloading_since(std::chrono::steady_clock::now()),
          m_last_block_announcement(std::chrono::steady_clock::now()),
          lastSuccessTime(std::chrono::steady_clock::now()),
          lastStallTime(std::chrono::steady_clock::now()) {}

    CPeer(int id_in, const NetProtocol::CAddress& addr_in)
        : id(id_in), addr(addr_in), state(STATE_DISCONNECTED),
          connect_time(GetTime()), last_recv(0), last_send(0),
          version(0), start_height(0), best_known_height(0), relay(true),
          ban_time(0),
          m_stalling_since(std::chrono::steady_clock::now()),
          m_downloading_since(std::chrono::steady_clock::now()),
          m_last_block_announcement(std::chrono::steady_clock::now()),
          lastSuccessTime(std::chrono::steady_clock::now()),
          lastStallTime(std::chrono::steady_clock::now()) {}

    // SSOT FIX #1: These methods now query CNode::state through CPeerManager
    // CPeer::state is deprecated - CNode::state is the single source of truth
    // Note: These methods require CPeerManager context to access CNode
    // For direct access, use CPeerManager::GetNode(peer_id)->IsConnected() instead
    bool IsConnected() const {
        // DEPRECATED: Query CNode::state instead
        // This method kept for backward compatibility but may return stale data
        return state >= STATE_CONNECTED && state < STATE_BANNED;
    }

    bool IsHandshakeComplete() const {
        // DEPRECATED: Query CNode::state instead
        // This method kept for backward compatibility but may return stale data
        return state == STATE_HANDSHAKE_COMPLETE;
    }
    
    // SSOT FIX #1: New method that queries CNode::state (requires CPeerManager context)
    // This is the preferred way to check handshake completion
    bool IsHandshakeComplete(CNode* node) const {
        if (!node) {
            // Fallback to deprecated CPeer::state if CNode not available
            return state == STATE_HANDSHAKE_COMPLETE;
        }
        return node->IsHandshakeComplete();  // Query CNode::state (SSOT)
    }
    
    bool IsConnected(CNode* node) const {
        if (!node) {
            // Fallback to deprecated CPeer::state if CNode not available
            return state >= STATE_CONNECTED && state < STATE_BANNED;
        }
        return node->IsConnected();  // Query CNode::state (SSOT)
    }

    bool IsBanned() const {
        return state == STATE_BANNED || (ban_time > 0 && GetTime() < ban_time);
    }

    // Phase 2 port: CPeer::Misbehaving DELETED. Use
    // CPeerManager::Misbehaving(peer_id, ...) which routes through CPeerScorer.
    void Ban(int64_t ban_until);
    void Disconnect();
    std::string ToString() const;
};

/**
 * CPeerManager - Manages all peer connections
 */
class CPeerManager {
private:
    // NET-009 FIX: Use recursive_mutex to prevent deadlock on recursive acquisition
    // Some operations (like GetStats calling IsConnected) may need to reacquire the lock
    //
    // LOCK ORDERING: cs_vNodes (CConnman) → cs_peers → cs_nodes
    // Code holding cs_peers or cs_nodes must NEVER call into CConnman (PushMessage, GetNode, etc.)
    // When both cs_peers and cs_nodes are needed, use std::scoped_lock for deadlock avoidance.
    mutable std::recursive_mutex cs_peers;
    std::map<int, std::shared_ptr<CPeer>> peers;

    // Phase 1: CNode management (event-driven networking)
    // CNode objects are owned by CConnman. CPeerManager stores raw pointers
    // for state synchronization. DO NOT delete these pointers.
    mutable std::recursive_mutex cs_nodes;
    std::map<int, CNode*> node_refs;  // Non-owning references to CConnman's CNode objects

    // Bitcoin Core-style ban manager with banlist.dat persistence
    // Replaces simple banned_ips map with structured ban entries
    CBanManager banman;

    std::atomic<int> next_peer_id;

    // DNS seeds for peer discovery
    std::vector<std::string> dns_seeds;

    // Hardcoded seed nodes
    std::vector<NetProtocol::CAddress> seed_nodes;

    // Phase 1 port: IAddressManager interface owns either CAddrMan_v2 (default
    // production path; new bucket-secret + tried/new tables) or
    // LegacyAddrManAdapter (operator escape hatch via DILITHION_USE_ADDRMAN_V2=0).
    // Either implementation handles eclipse attack protection via the same
    // two-table bucket invariant.
    std::unique_ptr<::dilithion::net::IAddressManager> addrman;
    std::string data_dir;  // Path to data directory for peers.dat

    // Phase 2 port: misbehavior scoring lives behind the IPeerScorer interface.
    // Default: CPeerScorer (operator can opt out via DILITHION_USE_NEW_PEER_SCORER=0,
    // in which case m_scorer stays null and Misbehaving becomes a tracking-
    // disabled no-op — manual ban via RPC still works, peer-protocol-level
    // disconnects still fire). See port_phase_2_implementation_plan.md §10.
    std::unique_ptr<::dilithion::net::IPeerScorer> m_scorer;
    
    // Network: Enhanced peer discovery
    std::unique_ptr<CPeerDiscovery> peer_discovery;
    
    // Network: Connection quality tracking
    CConnectionQualityTracker connection_quality;

    // F21 (v4.3.3 Track B): single throttle table for future send/recv hooks;
    // RemovePeer on disconnect prevents map growth once RecordTransfer is wired.
    //
    // F24 SSOT contract (v4.3.4 cut Block 10): this field is the SINGLE
    // source of truth for per-peer bandwidth throttling state. The API is
    // defined in <net/bandwidth_throttle.h> (CPerPeerThrottle::RecordTransfer,
    // CheckLimits, RemovePeer, etc.). Future maintainers adding rate-limit
    // logic should extend CPerPeerThrottle's interface and consult this
    // single instance — do NOT introduce a parallel per-peer throttle map
    // elsewhere. Any future code path that needs throttling state for a peer
    // queries this field via CPeerManager (legacy peer manager owns the
    // singleton). Lifetime: same as legacy CPeerManager (NodeContext::peer_manager).
    CPerPeerThrottle m_peer_bandwidth_throttle;

public:
    // Connection limits — public so CPeerScorer (and any future
    // peer-bookkeeping component) can size data structures against the
    // node-wide cap. Moved from private->public per Cursor Phase 2 review
    // Q9 (2026-04-26).
    static const int MAX_OUTBOUND_CONNECTIONS = 8;
    static const int MAX_INBOUND_CONNECTIONS = 117;
    static const int MAX_TOTAL_CONNECTIONS = 125;

    // DoS protection thresholds (public so CPeer can access)
    static const int BAN_THRESHOLD = 100;
    static const int64_t DEFAULT_BAN_TIME = 1 * 60 * 60;  // 1 hour (temporary during DFMP transition)
    static const int64_t PROTOCOL_VERSION_BAN_TIME = 10 * 60;  // 10 minutes for outdated protocol version

    // Constructor takes data directory for peers.dat persistence
    explicit CPeerManager(const std::string& datadir = "");

    // Persistence (peers.dat)
    bool SavePeers();   // Save address database to peers.dat
    bool LoadPeers();   // Load address database from peers.dat

    // Peer management (legacy CPeer - will be deprecated)
    std::shared_ptr<CPeer> AddPeer(const NetProtocol::CAddress& addr);
    std::shared_ptr<CPeer> AddPeerWithId(int peer_id);  // BUG #124: Add peer with specific ID for inbound connections
    void RemovePeer(int peer_id);
    std::shared_ptr<CPeer> GetPeer(int peer_id);
    std::vector<std::shared_ptr<CPeer>> GetAllPeers();
    std::vector<std::shared_ptr<CPeer>> GetConnectedPeers();

    /**
     * @brief Phase 10 PR10.2 — atomic joint snapshot of connected peers
     *        with their per-peer block-download counts.
     *
     * Eliminates the Phase 9 PR9.6-RT-MEDIUM-2 (b) peer-disconnect-during-
     * iteration race in `RPC_GetBlockDownloadStats`. The race fires when
     * `GetConnectedPeers()` snapshots one set of peers, then iterating
     * `block_tracker->GetPeerInFlightCount(id)` per peer happens after
     * cs_peers has been released — peer events between the snapshot and
     * the per-peer reads can introduce inconsistency.
     *
     * This getter holds cs_peers throughout the iteration AND calls
     * `g_node_context.block_tracker->GetPeerInFlightCount(id)` inside
     * the locked region — producing a joint atomic snapshot.
     *
     * **Lock-ordering safety (audited PR10.2 2026-05-01; refined per
     * Layer-2 PR10.2-RT-LOW-1; line numbers corrected per Layer-2
     * PR10.6-RT-LOW-1):** the established Dilithion order is
     * `cs_peers → block_tracker.m_mutex` at TWO genuinely-nested
     * precedent sites (`MarkBlockAsInFlight` defined at peers.cpp:1085,
     * `GetBlocksInFlightForPeer` defined at peers.cpp:1242).
     * `OnPeerDisconnected` is sequential, not nested, so it is not a
     * precedent for this pattern.
     *
     * The inverse order is structurally impossible per block_tracker's
     * encapsulation invariant: `CBlockTracker` only acquires `m_mutex`
     * internally and never calls into CPeerManager from inside the
     * locked region (verified: read every public method on
     * `block_tracker.h`). No path can hold `block_tracker.m_mutex` and
     * then attempt `cs_peers`. Future maintainers adding peer-event
     * callbacks INTO block_tracker would silently break this safety
     * claim — see the invariant comment near
     * `CBlockTracker::m_mutex` declaration.
     *
     * @return Vector of (peer_id, blocks_in_flight) pairs for all
     *         connected peers; empty if g_node_context.block_tracker
     *         is null.
     */
    struct BlockDownloadEntry {
        int peer_id;
        int blocks_in_flight;
    };
    std::vector<BlockDownloadEntry> GetBlockDownloadSnapshot() const;

    // Phase 1: CNode management (event-driven networking)
    // CNode objects are owned by CConnman. These methods manage references only.
    CNode* AddNode(const NetProtocol::CAddress& addr, bool inbound = false);
    // Returns false if IP is banned (caller should NOT add to m_nodes in this case)
    bool RegisterNode(int node_id, CNode* node, const NetProtocol::CAddress& addr, bool inbound);
    void RemoveNode(int node_id);
    CNode* GetNode(int node_id);
    std::vector<CNode*> GetAllNodes();
    std::vector<CNode*> GetConnectedNodes();

    // Connection management
    bool CanAcceptConnection() const;
    size_t GetConnectionCount() const;
    size_t GetOutboundCount() const;
    size_t GetInboundCount() const;

    // Peer discovery
    std::vector<NetProtocol::CAddress> GetPeerAddresses(int max_count = 1000);
    void AddPeerAddress(const NetProtocol::CAddress& addr);
    std::vector<NetProtocol::CAddress> QueryDNSSeeds();

    // Ban management
    void BanPeer(int peer_id, int64_t ban_time_seconds = DEFAULT_BAN_TIME);
    void BanIP(const std::string& ip, int64_t ban_time_seconds = DEFAULT_BAN_TIME);
    void UnbanIP(const std::string& ip);
    bool IsBanned(const std::string& ip) const;
    void ClearBans();

    // DoS protection with structured misbehavior tracking
    void Misbehaving(int peer_id, int howmuch, MisbehaviorType type = MisbehaviorType::NONE);
    void DecayMisbehaviorScores();  // BUG #49: Decay scores over time

    // Phase 2 port: cumulative misbehavior score for a peer. Returns 0 if the
    // peer has no recorded misbehavior or if the scorer is disabled
    // (DILITHION_USE_NEW_PEER_SCORER=0). Replaces direct reads of the deleted
    // CPeer::misbehavior_score field at all call sites.
    int GetMisbehaviorScore(int peer_id) const;

    // Phase 3: typed-reason variant of Misbehaving for HeadersSync-layer
    // call sites. Resolves the weight via maybe_punish_node.h's wrappers
    // (DefaultWeight + Q6=B override for REDOWNLOAD commitment mismatch),
    // then forwards to the existing Misbehaving forwarder (so seed-node
    // protection, banman.Ban, AddrMan signal all still fire). Wires the
    // Phase 3 MaybePunishNodeForHeaders wrapper into the production path.
    void MisbehaveHeaders(
        int peer_id,
        ::dilithion::net::port::HeaderRejectReason reason);

    // Phase 2.5 ticket PHASE-2.5-ADDRMAN-BIAS: test-only accessor for the
    // owned addrman, used by integration tests that need to observe AddrMan
    // state changes from forwarder calls (e.g. RecordAttempt(PeerMisbehaved)
    // wire-up). Returns the underlying IAddressManager*; cast to concrete
    // type via dynamic_cast for impl-specific *ForTest diagnostics.
    ::dilithion::net::IAddressManager* GetAddrManagerForTest() const {
        return addrman.get();
    }

    // Access to ban manager for advanced operations
    CBanManager& GetBanManager() { return banman; }

    // Statistics
    struct Stats {
        size_t total_peers;
        size_t connected_peers;
        size_t outbound_connections;
        size_t inbound_connections;
        size_t banned_ips;
    };
    Stats GetStats() const;

    // BUG #52: IBD detection support
    // Returns the highest chain height reported by any connected peer
    // Used to detect if we're behind the network and should delay mining
    int GetBestPeerHeight() const;

    // BUG #69: Check if any peer has completed VERSION handshake
    // Used to distinguish "waiting for handshakes" from "all peers at height 0"
    bool HasCompletedHandshakes() const;

    // Seed nodes
    void InitializeSeedNodes();
    std::vector<NetProtocol::CAddress> GetSeedNodes() const { return seed_nodes; }
    bool IsSeedNode(const std::string& ip) const;

    // Address database management (NW-003)
    void MarkAddressGood(const NetProtocol::CAddress& addr);  // Mark successful connection
    void MarkAddressTried(const NetProtocol::CAddress& addr); // Mark connection attempt
    std::vector<NetProtocol::CAddress> SelectAddressesToConnect(int count);  // Select addresses for outbound connections
    size_t GetAddressCount() const;  // Total addresses in database

    // Peer eviction (Bitcoin Core-style)
    /**
     * @brief Evict peers when connection limit is reached
     *
     * Bitcoin Core-style eviction logic:
     * - Prefer to keep outbound connections
     * - Evict peers with lowest network group diversity
     * - Evict peers with highest misbehavior scores
     * - Evict peers with oldest last block time
     *
     * @return true if a peer was evicted
     */
    bool EvictPeersIfNeeded();

    /**
     * @brief Periodic maintenance
     *
     * Should be called periodically from main loop:
     * - Decay misbehavior scores
     * - Evict peers if needed
     * - Save peers to disk
     */
    void PeriodicMaintenance();

    // === Phase 3.2: Block tracking (Bitcoin Core CNode pattern) ===
    // DEPRECATED: CBlockTracker is now the single source of truth for block tracking.
    // This map is kept for backward compatibility with orphan block handling only.
    // All new code should use CBlockTracker via g_node_context.block_tracker.
    std::map<uint256, std::pair<int, std::list<QueuedBlock>::iterator>> mapBlocksInFlight;  // DEPRECATED

    // Block flight limits
    // IBD FIX #12: Increased from 64 to 128 for faster single-peer IBD
    // With only 1 active peer and 64 blocks in-flight, sync rate is ~6 blocks/10s
    // Increasing to 128 should improve throughput when validation isn't bottleneck
    static constexpr int MAX_BLOCKS_IN_FLIGHT_PER_PEER = 128;
    static constexpr int MAX_BLOCKS_IN_FLIGHT_TOTAL = 256;

    // Block tracking methods
    bool MarkBlockAsInFlight(int peer_id, const uint256& hash, const CBlockIndex* pindex);
    int MarkBlockAsReceived(const uint256& hash);
    void MarkBlockAsReceived(int peer_id, const uint256& hash);  // BUG #148 FIX: Always decrement peer's nBlocksInFlight
    int RemoveBlockFromFlight(const uint256& hash);
    bool IsBlockInFlight(const uint256& hash) const;
    int GetBlockPeer(const uint256& hash) const;
    std::vector<std::pair<uint256, int>> GetBlocksInFlight() const;
    int GetBlocksInFlightForPeer(int peer_id) const;
    std::vector<uint256> GetAndClearPeerBlocks(int peer_id);
    std::vector<int> CheckForStallingPeers();
    void UpdatePeerStats(int peer_id, bool success, std::chrono::milliseconds responseTime);

    /**
     * @brief BUG #166 FIX: Completely clear a peer's in-flight state
     *
     * When a peer becomes unsuitable, we need to clear ALL tracking state:
     * - vBlocksInFlight (prevents CheckForStallingPeers from incrementing stall count)
     * - mapBlocksInFlight entries for this peer
     * - nBlocksInFlight counter
     * - Reset stall count to allow peer to become suitable again
     *
     * This is different from RemoveBlockFromFlight which only works if hash is found.
     * This method clears by peer_id, handling any desync between tracking structures.
     */
    void ClearPeerInFlightState(int peer_id);

    // SINGLE SOURCE OF TRUTH: New methods for centralized block tracking
    /**
     * @brief Get total blocks in-flight across all peers
     * Used by CBlockDownloadWindow instead of maintaining duplicate tracking
     */
    int GetTotalBlocksInFlight() const { return static_cast<int>(mapBlocksInFlight.size()); }

    /**
     * @brief Get blocks that have timed out (in-flight longer than timeout)
     * @param timeout_seconds Timeout threshold in seconds (default 120)
     * @return Vector of (hash, peer_id) pairs for timed out blocks
     */
    std::vector<std::pair<uint256, int>> GetTimedOutBlocks(int timeout_seconds = 120) const;

    // Peer suitability for download
    std::vector<int> GetValidPeersForDownload() const;
    bool IsPeerSuitableForDownload(int peer_id) const;

    // Update peer's best known height (called when we receive headers from them)
    // This tracks what blocks the peer actually has, updated as we learn more
    void UpdatePeerBestKnownHeight(int peer_id, int height);

    // Update peer's best known tip (height + hash) for fork divergence detection
    void UpdatePeerBestKnownTip(int peer_id, int height, const uint256& hash);

    // Lifecycle callbacks
    bool OnPeerHandshakeComplete(int peer_id, int starting_height, bool preferred);
    void OnPeerDisconnected(int peer_id);
};

/**
 * Global peer manager instance (raw pointer for backward compatibility)
 * Note: Ownership is now managed by g_node_context.peer_manager
 */
// REMOVED: g_peer_manager extern - use NodeContext::peer_manager instead

#endif // DILITHION_NET_PEERS_H
