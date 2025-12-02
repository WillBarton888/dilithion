// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Enhanced Peer Discovery
 * Phase: Network Resilience
 * 
 * Improves peer discovery with multiple strategies and better connection management
 */

#ifndef DILITHION_NET_PEER_DISCOVERY_H
#define DILITHION_NET_PEER_DISCOVERY_H

#include <net/protocol.h>
#include <net/addrman.h>
#include <net/netaddress.h>
#include <string>
#include <vector>
#include <chrono>
#include <mutex>

class CPeerManager;

/**
 * Enhanced peer discovery with multiple strategies
 */
class CPeerDiscovery {
public:
    CPeerDiscovery(CPeerManager& peer_mgr, CAddrMan& addrman);
    ~CPeerDiscovery();

    /**
     * Discover peers using multiple strategies
     * @param max_peers Maximum number of peers to discover
     * @return Number of peers discovered
     */
    size_t DiscoverPeers(size_t max_peers = 8);

    /**
     * Check if we need more peers
     * @param current_count Current number of connected peers
     * @param target_count Target number of peers
     * @return true if we need more peers
     */
    bool NeedMorePeers(size_t current_count, size_t target_count = 8) const;

    /**
     * Get connection quality metrics
     */
    struct ConnectionQuality {
        size_t total_peers;
        size_t handshake_complete;
        size_t active_peers;  // Peers with recent activity
        double avg_latency_ms;
        size_t stale_peers;   // Peers with no recent activity
    };
    ConnectionQuality GetConnectionQuality() const;

    /**
     * Detect network partition (if we have no peers for extended period)
     * @return true if network partition detected
     */
    bool DetectNetworkPartition() const;

private:
    CPeerManager& m_peer_manager;
    CAddrMan& m_addrman;

    // Discovery strategies
    size_t DiscoverFromAddrMan(size_t max_peers);
    size_t DiscoverFromDNSSeeds(size_t max_peers);
    size_t DiscoverFromSeedNodes(size_t max_peers);
    size_t DiscoverFromConnectedPeers(size_t max_peers);

    // Network partition detection
    std::chrono::steady_clock::time_point m_last_peer_connection;
    mutable std::mutex m_partition_mutex;
    static constexpr int64_t PARTITION_THRESHOLD_SECONDS = 300;  // 5 minutes
};

#endif // DILITHION_NET_PEER_DISCOVERY_H

