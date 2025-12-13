// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_PEERS_H
#define DILITHION_NET_PEERS_H

#include <net/protocol.h>
#include <net/addrman.h>  // Bitcoin Core-style address manager
#include <net/banman.h>   // Bitcoin Core-style ban manager with persistence
#include <net/peer_discovery.h>  // Network: Enhanced peer discovery
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
    State state;                     // Connection state
    int64_t connect_time;            // When connection was established
    int64_t last_recv;               // Last message received time
    int64_t last_send;               // Last message sent time
    int version;                     // Protocol version
    std::string user_agent;          // Peer client version
    int start_height;                // Peer's blockchain height
    bool relay;                      // Whether peer relays transactions

    // DoS protection
    int misbehavior_score;           // Accumulated misbehavior points
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
    std::list<QueuedBlock> vBlocksInFlight;
    int nBlocksInFlight = 0;
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

    std::chrono::seconds GetBlockTimeout() const {
        int timeout_seconds = 10 << std::min(nStallingCount, 5);
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
          relay(true), misbehavior_score(0), ban_time(0),
          m_stalling_since(std::chrono::steady_clock::now()),
          m_downloading_since(std::chrono::steady_clock::now()),
          m_last_block_announcement(std::chrono::steady_clock::now()),
          lastSuccessTime(std::chrono::steady_clock::now()),
          lastStallTime(std::chrono::steady_clock::now()) {}

    CPeer(int id_in, const NetProtocol::CAddress& addr_in)
        : id(id_in), addr(addr_in), state(STATE_DISCONNECTED),
          connect_time(GetTime()), last_recv(0), last_send(0),
          version(0), start_height(0), relay(true),
          misbehavior_score(0), ban_time(0),
          m_stalling_since(std::chrono::steady_clock::now()),
          m_downloading_since(std::chrono::steady_clock::now()),
          m_last_block_announcement(std::chrono::steady_clock::now()),
          lastSuccessTime(std::chrono::steady_clock::now()),
          lastStallTime(std::chrono::steady_clock::now()) {}

    bool IsConnected() const {
        return state >= STATE_CONNECTED && state < STATE_BANNED;
    }

    bool IsHandshakeComplete() const {
        return state == STATE_HANDSHAKE_COMPLETE;
    }

    bool IsBanned() const {
        return state == STATE_BANNED || (ban_time > 0 && GetTime() < ban_time);
    }

    bool Misbehaving(int howmuch);
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

    int next_peer_id;

    // DNS seeds for peer discovery
    std::vector<std::string> dns_seeds;

    // Hardcoded seed nodes
    std::vector<NetProtocol::CAddress> seed_nodes;

    // Bitcoin Core-style address manager (replaces simple addr_map)
    // Provides eclipse attack protection via two-table bucket system
    CAddrMan addrman;
    std::string data_dir;  // Path to data directory for peers.dat
    
    // Network: Enhanced peer discovery
    std::unique_ptr<CPeerDiscovery> peer_discovery;
    
    // Network: Connection quality tracking
    CConnectionQualityTracker connection_quality;

    // Connection limits
    static const int MAX_OUTBOUND_CONNECTIONS = 8;
    static const int MAX_INBOUND_CONNECTIONS = 117;
    static const int MAX_TOTAL_CONNECTIONS = 125;

public:
    // DoS protection thresholds (public so CPeer can access)
    static const int BAN_THRESHOLD = 100;
    static const int64_t DEFAULT_BAN_TIME = 24 * 60 * 60;  // 24 hours

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

    // Phase 1: CNode management (event-driven networking)
    // CNode objects are owned by CConnman. These methods manage references only.
    CNode* AddNode(const NetProtocol::CAddress& addr, bool inbound = false);
    void RegisterNode(int node_id, CNode* node, const NetProtocol::CAddress& addr, bool inbound);
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
    // Global block-to-peer mapping for quick lookup
    std::map<uint256, std::pair<int, std::list<QueuedBlock>::iterator>> mapBlocksInFlight;

    // Block flight limits
    // IBD FIX #11: Increased from 16 to 64 for high-latency single-peer IBD
    // With only 1-2 peers and 80+ second cross-region latency, 16 blocks
    // causes 80-second stalls between bursts. 64 allows continuous download.
    static constexpr int MAX_BLOCKS_IN_FLIGHT_PER_PEER = 64;
    static constexpr int MAX_BLOCKS_IN_FLIGHT_TOTAL = 128;

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

    // Peer suitability for download
    std::vector<int> GetValidPeersForDownload() const;
    bool IsPeerSuitableForDownload(int peer_id) const;

    // Lifecycle callbacks
    bool OnPeerHandshakeComplete(int peer_id, int starting_height, bool preferred);
    void OnPeerDisconnected(int peer_id);
};

/**
 * Global peer manager instance (raw pointer for backward compatibility)
 * Note: Ownership is now managed by g_node_context.peer_manager
 */
extern CPeerManager* g_peer_manager;

#endif // DILITHION_NET_PEERS_H
