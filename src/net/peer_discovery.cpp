// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Enhanced Peer Discovery Implementation
 */

#include <net/peer_discovery.h>
#include <net/peers.h>
#include <util/logging.h>
#include <util/time.h>
#include <algorithm>

CPeerDiscovery::CPeerDiscovery(CPeerManager& peer_mgr, CAddrMan& addrman)
    : m_peer_manager(peer_mgr), m_addrman(addrman) {
    m_last_peer_connection = std::chrono::steady_clock::now();
}

CPeerDiscovery::~CPeerDiscovery() {
}

size_t CPeerDiscovery::DiscoverPeers(size_t max_peers) {
    size_t discovered = 0;

    // Strategy 1: Use address manager (most reliable)
    discovered += DiscoverFromAddrMan(max_peers - discovered);
    if (discovered >= max_peers) {
        return discovered;
    }

    // Strategy 2: Use seed nodes (if addrman is empty)
    if (discovered == 0) {
        discovered += DiscoverFromSeedNodes(max_peers - discovered);
    }

    // Strategy 3: Use DNS seeds (if still need more)
    if (discovered < max_peers) {
        discovered += DiscoverFromDNSSeeds(max_peers - discovered);
    }

    // Strategy 4: Ask connected peers for addresses (if have some peers)
    if (discovered < max_peers && m_peer_manager.GetConnectionCount() > 0) {
        discovered += DiscoverFromConnectedPeers(max_peers - discovered);
    }

    if (discovered > 0) {
        std::lock_guard<std::mutex> lock(m_partition_mutex);
        m_last_peer_connection = std::chrono::steady_clock::now();
    }

    LogPrintf(ALL, INFO, "Peer discovery: found %zu new peers (target: %zu)", 
              discovered, max_peers);
    return discovered;
}

bool CPeerDiscovery::NeedMorePeers(size_t current_count, size_t target_count) const {
    // Need more if below target
    if (current_count < target_count) {
        return true;
    }

    // Need more if connection quality is poor
    ConnectionQuality quality = GetConnectionQuality();
    if (quality.handshake_complete < target_count / 2) {
        return true;  // Less than half have completed handshake
    }

    if (quality.stale_peers > current_count / 2) {
        return true;  // More than half are stale
    }

    return false;
}

CPeerDiscovery::ConnectionQuality CPeerDiscovery::GetConnectionQuality() const {
    ConnectionQuality quality = {};
    
    // Get peer statistics from peer manager
    size_t total = m_peer_manager.GetConnectionCount();
    quality.total_peers = total;

    // Count handshake complete and active peers
    // (This would need to be implemented in CPeerManager)
    // For now, use estimates
    quality.handshake_complete = total;  // Assume all are complete if connected
    quality.active_peers = total;        // Assume all are active
    quality.stale_peers = 0;             // Would need to track last activity
    quality.avg_latency_ms = 0.0;        // Would need to track latency

    return quality;
}

bool CPeerDiscovery::DetectNetworkPartition() const {
    std::lock_guard<std::mutex> lock(m_partition_mutex);
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - m_last_peer_connection).count();

    if (elapsed > PARTITION_THRESHOLD_SECONDS && 
        m_peer_manager.GetConnectionCount() == 0) {
        return true;
    }

    return false;
}

size_t CPeerDiscovery::DiscoverFromAddrMan(size_t max_peers) {
    size_t discovered = 0;
    
    // Get good addresses from addrman
    std::vector<CNetworkAddr> addrs = m_addrman.GetAddr(max_peers, 23);  // 23% max
    
    for (const auto& addr : addrs) {
        if (discovered >= max_peers) {
            break;
        }

        // Try to connect (this would need CPeerManager::ConnectToPeer)
        // For now, just mark as attempted
        m_addrman.Attempt(addr);
        discovered++;
    }

    return discovered;
}

size_t CPeerDiscovery::DiscoverFromDNSSeeds(size_t max_peers) {
    // DNS seed resolution would go here
    // For now, return 0 (not implemented yet)
    (void)max_peers;
    return 0;
}

size_t CPeerDiscovery::DiscoverFromSeedNodes(size_t max_peers) {
    size_t discovered = 0;
    
    // Get seed nodes from peer manager
    // This would need CPeerManager::GetSeedNodes()
    // For now, use hardcoded seeds
    std::vector<NetProtocol::CAddress> seeds = {
        NetProtocol::CAddress("134.122.4.164", 18444)  // Testnet seed
    };

    for (const auto& seed : seeds) {
        if (discovered >= max_peers) {
            break;
        }

        // Convert NetProtocol::CAddress to CNetworkAddr for addrman
        CService service(seed.ToStringIP(), seed.GetPort());
        CNetworkAddr addr(service, NetProtocol::NODE_NETWORK, GetTime());
        CNetAddr source;  // Empty source
        m_addrman.Add(CAddrInfo(addr, source));
        m_addrman.Good(addr);  // Mark as good
        discovered++;
    }

    return discovered;
}

size_t CPeerDiscovery::DiscoverFromConnectedPeers(size_t max_peers) {
    // Ask connected peers for addresses via GETADDR
    // This would trigger ADDR messages from peers
    // For now, return 0 (would need to implement GETADDR request)
    (void)max_peers;
    return 0;
}

