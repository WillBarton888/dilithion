// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_PEERS_H
#define DILITHION_NET_PEERS_H

#include <net/protocol.h>
#include <util/time.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <memory>

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

    CPeer()
        : id(0), state(STATE_DISCONNECTED), connect_time(0),
          last_recv(0), last_send(0), version(0), start_height(0),
          relay(true), misbehavior_score(0), ban_time(0) {}

    CPeer(int id_in, const NetProtocol::CAddress& addr_in)
        : id(id_in), addr(addr_in), state(STATE_DISCONNECTED),
          connect_time(GetTime()), last_recv(0), last_send(0),
          version(0), start_height(0), relay(true),
          misbehavior_score(0), ban_time(0) {}

    bool IsConnected() const {
        return state >= STATE_CONNECTED && state < STATE_BANNED;
    }

    bool IsHandshakeComplete() const {
        return state == STATE_HANDSHAKE_COMPLETE;
    }

    bool IsBanned() const {
        return state == STATE_BANNED || (ban_time > 0 && GetTime() < ban_time);
    }

    // Increase misbehavior score (returns true if should ban)
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

    // NET-005 FIX: Track ban expiry times instead of just banned status
    // Maps IP address -> ban expiry timestamp (0 = permanent ban)
    // This allows proper LRU eviction when limit is reached
    std::map<std::string, int64_t> banned_ips;

    int next_peer_id;

    // DNS seeds for peer discovery
    std::vector<std::string> dns_seeds;

    // Hardcoded seed nodes
    std::vector<NetProtocol::CAddress> seed_nodes;

    // Peer address database (NW-003)
    struct CAddrInfo {
        NetProtocol::CAddress addr;
        int64_t nTime;          // Last seen time
        int64_t nLastTry;       // Last connection attempt time
        int64_t nLastSuccess;   // Last successful connection time
        int nAttempts;          // Total connection attempts
        int nSuccesses;         // Successful connections
        bool fInTried;          // In "tried" table (vs "new" table)

        CAddrInfo() : nTime(0), nLastTry(0), nLastSuccess(0),
                      nAttempts(0), nSuccesses(0), fInTried(false) {}
    };

    std::map<std::string, CAddrInfo> addr_map;  // IP:port -> address info
    mutable std::mutex cs_addrs;

    // Connection limits
    static const int MAX_OUTBOUND_CONNECTIONS = 8;
    static const int MAX_INBOUND_CONNECTIONS = 117;
    static const int MAX_TOTAL_CONNECTIONS = 125;

    // NET-005 FIX: Ban list limit to prevent unbounded memory growth
    static const size_t MAX_BANNED_IPS = 10000;

public:
    // DoS protection thresholds (public so CPeer can access)
    static const int BAN_THRESHOLD = 100;
    static const int64_t DEFAULT_BAN_TIME = 24 * 60 * 60;  // 24 hours

    CPeerManager();

    // Peer management
    std::shared_ptr<CPeer> AddPeer(const NetProtocol::CAddress& addr);
    void RemovePeer(int peer_id);
    std::shared_ptr<CPeer> GetPeer(int peer_id);
    std::vector<std::shared_ptr<CPeer>> GetAllPeers();
    std::vector<std::shared_ptr<CPeer>> GetConnectedPeers();

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

    // DoS protection
    void Misbehaving(int peer_id, int howmuch);
    void DecayMisbehaviorScores();  // BUG #49: Decay scores over time

    // Statistics
    struct Stats {
        size_t total_peers;
        size_t connected_peers;
        size_t outbound_connections;
        size_t inbound_connections;
        size_t banned_ips;
    };
    Stats GetStats() const;

    // Seed nodes
    void InitializeSeedNodes();
    std::vector<NetProtocol::CAddress> GetSeedNodes() const { return seed_nodes; }

    // Address database management (NW-003)
    void MarkAddressGood(const NetProtocol::CAddress& addr);  // Mark successful connection
    void MarkAddressTried(const NetProtocol::CAddress& addr); // Mark connection attempt
    std::vector<NetProtocol::CAddress> SelectAddressesToConnect(int count);  // Select addresses for outbound connections
    size_t GetAddressCount() const;  // Total addresses in database
};

/**
 * Global peer manager instance
 */
extern std::unique_ptr<CPeerManager> g_peer_manager;

#endif // DILITHION_NET_PEERS_H
