// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/peers.h>
#include <net/dns.h>
#include <util/strencodings.h>
#include <util/logging.h>
#include <algorithm>
#include <iostream>

// Global peer manager instance (raw pointer - ownership in g_node_context)
CPeerManager* g_peer_manager = nullptr;

// CPeer implementation

bool CPeer::Misbehaving(int howmuch) {
    misbehavior_score += howmuch;
    return misbehavior_score >= CPeerManager::BAN_THRESHOLD;
}

void CPeer::Ban(int64_t ban_until) {
    state = STATE_BANNED;
    ban_time = ban_until;
}

void CPeer::Disconnect() {
    if (state != STATE_BANNED) {
        state = STATE_DISCONNECTED;
    }
}

std::string CPeer::ToString() const {
    return strprintf("CPeer(id=%d, addr=%s, state=%d, version=%d, height=%d, score=%d)",
                    id, addr.ToString().c_str(), state, version,
                    start_height, misbehavior_score);
}

// CPeerManager implementation

CPeerManager::CPeerManager(const std::string& datadir)
    : banman(datadir), next_peer_id(1), data_dir(datadir) {
    InitializeSeedNodes();

    // Load persisted peer addresses from peers.dat
    if (!data_dir.empty()) {
        LoadPeers();
    }
}

bool CPeerManager::SavePeers() {
    if (data_dir.empty()) {
        return false;
    }

    std::string path = data_dir + "/peers.dat";
    bool result = addrman.SaveToFile(path);

    if (result) {
        std::cout << "[PeerManager] Saved " << addrman.Size() << " peer addresses to " << path << std::endl;
    } else {
        std::cerr << "[PeerManager] ERROR: Failed to save peers to " << path << std::endl;
    }

    return result;
}

bool CPeerManager::LoadPeers() {
    if (data_dir.empty()) {
        return false;
    }

    std::string path = data_dir + "/peers.dat";
    bool result = addrman.LoadFromFile(path);

    if (result) {
        std::cout << "[PeerManager] Loaded " << addrman.Size() << " peer addresses from " << path << std::endl;
    } else {
        std::cerr << "[PeerManager] WARNING: Could not load peers from " << path << " (starting fresh)" << std::endl;
    }

    return result;
}

std::shared_ptr<CPeer> CPeerManager::AddPeer(const NetProtocol::CAddress& addr) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // Check if IP is banned using CBanManager
    std::string ip = addr.ToStringIP();
    std::cout << "[HANDSHAKE-DIAG] AddPeer called for " << addr.ToString()
              << " (IP: " << ip << ", current peers: " << peers.size() << "/" << MAX_TOTAL_CONNECTIONS << ")"
              << std::endl;

    if (banman.IsBanned(ip)) {
        std::cout << "[HANDSHAKE-DIAG] REJECT: IP " << ip << " is banned" << std::endl;
        return nullptr;
    }

    // Check connection limit
    if (peers.size() >= MAX_TOTAL_CONNECTIONS) {
        std::cout << "[HANDSHAKE-DIAG] REJECT: Connection limit reached ("
                  << peers.size() << "/" << MAX_TOTAL_CONNECTIONS << ")" << std::endl;
        return nullptr;
    }

    // Create new peer
    auto peer = std::make_shared<CPeer>(next_peer_id++, addr);
    peers[peer->id] = peer;

    std::cout << "[HANDSHAKE-DIAG] ✅ Peer " << peer->id << " added successfully" << std::endl;

    return peer;
}

void CPeerManager::RemovePeer(int peer_id) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    auto it = peers.find(peer_id);
    if (it != peers.end()) {
        it->second->Disconnect();
        peers.erase(it);
    }
}

std::shared_ptr<CPeer> CPeerManager::GetPeer(int peer_id) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    auto it = peers.find(peer_id);
    return (it != peers.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<CPeer>> CPeerManager::GetAllPeers() {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<std::shared_ptr<CPeer>> result;
    for (const auto& pair : peers) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<std::shared_ptr<CPeer>> CPeerManager::GetConnectedPeers() {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<std::shared_ptr<CPeer>> result;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            result.push_back(pair.second);
        }
    }
    return result;
}

bool CPeerManager::CanAcceptConnection() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    return peers.size() < MAX_TOTAL_CONNECTIONS;
}

size_t CPeerManager::GetConnectionCount() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    size_t count = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            count++;
        }
    }
    return count;
}

size_t CPeerManager::GetOutboundCount() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    // For now, simplified - assume first 8 connected peers are outbound
    size_t count = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected() && count < MAX_OUTBOUND_CONNECTIONS) {
            count++;
        }
    }
    return std::min(count, (size_t)MAX_OUTBOUND_CONNECTIONS);
}

size_t CPeerManager::GetInboundCount() const {
    return GetConnectionCount() - GetOutboundCount();
}

std::vector<NetProtocol::CAddress> CPeerManager::GetPeerAddresses(int max_count) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<NetProtocol::CAddress> result;

    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            result.push_back(pair.second->addr);
            if (result.size() >= (size_t)max_count) {
                break;
            }
        }
    }

    return result;
}

void CPeerManager::AddPeerAddress(const NetProtocol::CAddress& addr) {
    // Skip localhost and invalid addresses
    std::string ip = addr.ToStringIP();
    if (ip == "127.0.0.1" || ip == "::1" || ip.empty()) {
        return;
    }

    // Convert NetProtocol::CAddress to CService for CAddrMan
    // Create CNetAddr from IP bytes
    CNetAddr netaddr;

    // Check if IPv4-mapped address (::ffff:x.x.x.x)
    // IPv4-mapped prefix: 00 00 00 00 00 00 00 00 00 00 FF FF
    static const uint8_t ipv4_mapped_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    bool is_ipv4 = (memcmp(addr.ip, ipv4_mapped_prefix, 12) == 0);

    if (is_ipv4) {
        // IPv4 address - extract from last 4 bytes
        uint32_t ipv4 = ((uint32_t)addr.ip[12] << 24) |
                        ((uint32_t)addr.ip[13] << 16) |
                        ((uint32_t)addr.ip[14] << 8) |
                        (uint32_t)addr.ip[15];
        netaddr.SetIPv4(ipv4);
    } else {
        // IPv6 address - pass raw bytes directly
        netaddr.SetIPv6(addr.ip);
    }

    CService service(netaddr, addr.port);

    // Add to AddrMan - bucket system handles deduplication and limits
    addrman.Add(service, CNetAddr());  // No source address for now
}

std::vector<NetProtocol::CAddress> CPeerManager::QueryDNSSeeds() {
    std::vector<NetProtocol::CAddress> result;

    // NW-002: Query DNS seeds for peer discovery
    std::cout << "[PeerManager] Querying DNS seeds for peer discovery..." << std::endl;

    for (const auto& seed_hostname : dns_seeds) {
        std::cout << "[PeerManager] Querying seed: " << seed_hostname << std::endl;

        try {
            // Query the DNS seed
            std::vector<NetProtocol::CAddress> addresses =
                CDNSResolver::QuerySeed(seed_hostname, NetProtocol::DEFAULT_PORT);

            if (addresses.empty()) {
                std::cout << "[PeerManager] No addresses returned from seed: " << seed_hostname << std::endl;
                continue;
            }

            // Add addresses to result
            std::cout << "[PeerManager] Found " << addresses.size()
                      << " peer(s) from seed: " << seed_hostname << std::endl;

            for (const auto& addr : addresses) {
                result.push_back(addr);
                // Also add to peer address database
                AddPeerAddress(addr);
            }

        } catch (const std::exception& e) {
            std::cerr << "[PeerManager] ERROR: Failed to query seed " << seed_hostname
                      << ": " << e.what() << std::endl;
            continue;
        } catch (...) {
            std::cerr << "[PeerManager] ERROR: Unknown error querying seed " << seed_hostname << std::endl;
            continue;
        }
    }

    std::cout << "[PeerManager] DNS seed query complete: Found " << result.size()
              << " total peer address(es)" << std::endl;

    return result;
}

void CPeerManager::BanPeer(int peer_id, int64_t ban_time_seconds) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    auto it = peers.find(peer_id);
    if (it != peers.end()) {
        int64_t ban_until = GetTime() + ban_time_seconds;
        it->second->Ban(ban_until);

        // Add IP to banned list using CBanManager
        std::string ip = it->second->addr.ToStringIP();
        banman.Ban(ip, ban_time_seconds, BanReason::NodeMisbehaving,
                   MisbehaviorType::NONE, it->second->misbehavior_score);
    }
}

void CPeerManager::BanIP(const std::string& ip, int64_t ban_time_seconds) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // Use CBanManager (handles LRU eviction internally)
    banman.Ban(ip, ban_time_seconds, BanReason::ManuallyBanned);

    // Disconnect all peers from this IP
    int64_t ban_until = GetTime() + ban_time_seconds;
    for (auto& pair : peers) {
        if (pair.second->addr.ToStringIP() == ip) {
            pair.second->Ban(ban_until);
        }
    }
}

void CPeerManager::UnbanIP(const std::string& ip) {
    banman.Unban(ip);
}

bool CPeerManager::IsBanned(const std::string& ip) const {
    return banman.IsBanned(ip);
}

void CPeerManager::ClearBans() {
    banman.ClearBanned();
}

void CPeerManager::Misbehaving(int peer_id, int howmuch, MisbehaviorType type) {
    auto peer = GetPeer(peer_id);
    if (!peer) return;

    // Use default score from MisbehaviorType if howmuch is 0
    int score = howmuch > 0 ? howmuch : GetMisbehaviorScore(type);

    if (peer->Misbehaving(score)) {
        // Ban peer if threshold exceeded
        std::lock_guard<std::recursive_mutex> lock(cs_peers);
        int64_t ban_until = GetTime() + DEFAULT_BAN_TIME;
        peer->Ban(ban_until);

        std::string ip = peer->addr.ToStringIP();
        banman.Ban(ip, DEFAULT_BAN_TIME, BanReason::NodeMisbehaving,
                   type, peer->misbehavior_score);
    }
}

void CPeerManager::DecayMisbehaviorScores() {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // BUG #49: Decay misbehavior scores over time
    // Called every 30 seconds, decay by 0.5 points (1 point per minute)
    for (auto& pair : peers) {
        if (pair.second->misbehavior_score > 0) {
            // Reduce by 0.5 points, but don't go below 0
            pair.second->misbehavior_score = std::max(0, pair.second->misbehavior_score - 1);

            // Log significant changes
            if (pair.second->misbehavior_score % 10 == 0) {
                std::cout << "[PeerManager] Peer " << pair.first
                          << " misbehavior score decayed to " << pair.second->misbehavior_score << std::endl;
            }
        }
    }

    // Clean up expired bans using CBanManager
    banman.SweepExpiredBans();
}

CPeerManager::Stats CPeerManager::GetStats() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    Stats stats;
    stats.total_peers = peers.size();
    stats.connected_peers = 0;

    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            stats.connected_peers++;
        }
    }

    // Calculate outbound/inbound inline to avoid deadlock
    size_t outbound = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected() && outbound < MAX_OUTBOUND_CONNECTIONS) {
            outbound++;
        }
    }
    stats.outbound_connections = std::min(outbound, (size_t)MAX_OUTBOUND_CONNECTIONS);
    stats.inbound_connections = stats.connected_peers - stats.outbound_connections;
    stats.banned_ips = banman.GetBannedCount();

    return stats;
}

int CPeerManager::GetBestPeerHeight() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // BUG #52: Returns the highest chain height reported by any connected peer
    // Used for IBD detection - if peers are significantly ahead, we're still syncing
    int best = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsHandshakeComplete() && pair.second->start_height > best) {
            best = pair.second->start_height;
        }
    }
    return best;
}

bool CPeerManager::HasCompletedHandshakes() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // BUG #69 FIX: Check if ANY peer has completed VERSION/VERACK handshake
    // This distinguishes between:
    // 1. "Connections initiated but no VERSION received yet" (return false)
    // 2. "Peers have completed handshake but are at height 0" (return true)
    //
    // Used by IsInitialBlockDownload() to avoid incorrectly staying in IBD mode
    // when all connected peers legitimately have height 0 (bootstrap scenario).
    for (const auto& pair : peers) {
        if (pair.second->IsHandshakeComplete()) {
            return true;  // At least one peer completed handshake
        }
    }
    return false;  // No handshakes completed yet
}

void CPeerManager::InitializeSeedNodes() {
    // Hardcoded seed nodes for Dilithion network
    // These are reliable nodes run by the community

    dns_seeds = {
        "seed.dilithion.com",
        "seed1.dilithion.com",
        "seed2.dilithion.com",
    };

    // Hardcoded IP addresses as fallback
    // Format: IPv4 mapped to IPv6
    seed_nodes.clear();

    // TESTNET SEED NODE #1: NYC (DigitalOcean NYC3)
    // IP: 134.122.4.164, Port: 18444 (testnet)
    NetProtocol::CAddress seed_nyc;
    seed_nyc.services = NetProtocol::NODE_NETWORK;
    seed_nyc.SetIPv4(0x867A04A4);  // 134.122.4.164
    seed_nyc.port = NetProtocol::TESTNET_PORT;
    seed_nyc.time = GetTime();
    seed_nodes.push_back(seed_nyc);

    // TESTNET SEED NODE #2: London (DigitalOcean LON1)
    // IP: 209.97.177.197, Port: 18444 (testnet)
    NetProtocol::CAddress seed_london;
    seed_london.services = NetProtocol::NODE_NETWORK;
    seed_london.SetIPv4(0xD161B1C5);  // 209.97.177.197
    seed_london.port = NetProtocol::TESTNET_PORT;
    seed_london.time = GetTime();
    seed_nodes.push_back(seed_london);

    // TESTNET SEED NODE #3: Singapore (DigitalOcean SGP1)
    // IP: 188.166.255.63, Port: 18444 (testnet)
    NetProtocol::CAddress seed_singapore;
    seed_singapore.services = NetProtocol::NODE_NETWORK;
    seed_singapore.SetIPv4(0xBCA6FF3F);  // 188.166.255.63
    seed_singapore.port = NetProtocol::TESTNET_PORT;
    seed_singapore.time = GetTime();
    seed_nodes.push_back(seed_singapore);

    // FUTURE: Add more seed nodes as they become available
    // Community operators can run seed nodes and submit them via GitHub
    //
    // To add a new seed node:
    //   NetProtocol::CAddress new_seed;
    //   new_seed.services = NetProtocol::NODE_NETWORK;
    //   new_seed.SetIPv4(0xXXXXXXXX);  // Convert IP to hex (e.g., 192.168.0.1 = 0xC0A80001)
    //   new_seed.port = NetProtocol::TESTNET_PORT;  // Use DEFAULT_PORT for mainnet
    //   new_seed.time = GetTime();
    //   seed_nodes.push_back(new_seed);
    //
    // Seed node requirements:
    // - Static IP address with port 18444 (testnet) or 8444 (mainnet) open
    // - 95%+ uptime (24/7 operation)
    // - Minimum 1 Mbps bandwidth
    // - Not mining (relay only)
    // - Latest Dilithion node software
    //
    // Users can also manually configure peers using --addnode command line parameter.
}

// Address database management (NW-003 - now uses Bitcoin Core CAddrMan)

void CPeerManager::MarkAddressGood(const NetProtocol::CAddress& addr) {
    // Convert NetProtocol::CAddress to CService
    CNetAddr netaddr;

    // Check if IPv4-mapped address (::ffff:x.x.x.x)
    static const uint8_t ipv4_mapped_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    bool is_ipv4 = (memcmp(addr.ip, ipv4_mapped_prefix, 12) == 0);

    if (is_ipv4) {
        uint32_t ipv4 = ((uint32_t)addr.ip[12] << 24) |
                        ((uint32_t)addr.ip[13] << 16) |
                        ((uint32_t)addr.ip[14] << 8) |
                        (uint32_t)addr.ip[15];
        netaddr.SetIPv4(ipv4);
    } else {
        netaddr.SetIPv6(addr.ip);
    }

    CService service(netaddr, addr.port);

    // Mark as good in AddrMan (moves to tried table)
    addrman.Good(service);
}

void CPeerManager::MarkAddressTried(const NetProtocol::CAddress& addr) {
    // Convert NetProtocol::CAddress to CService
    CNetAddr netaddr;

    // Check if IPv4-mapped address (::ffff:x.x.x.x)
    static const uint8_t ipv4_mapped_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    bool is_ipv4 = (memcmp(addr.ip, ipv4_mapped_prefix, 12) == 0);

    if (is_ipv4) {
        uint32_t ipv4 = ((uint32_t)addr.ip[12] << 24) |
                        ((uint32_t)addr.ip[13] << 16) |
                        ((uint32_t)addr.ip[14] << 8) |
                        (uint32_t)addr.ip[15];
        netaddr.SetIPv4(ipv4);
    } else {
        netaddr.SetIPv6(addr.ip);
    }

    CService service(netaddr, addr.port);

    // Mark connection attempt in AddrMan (true = count as failure if it fails)
    addrman.Attempt(service, true);
}

std::vector<NetProtocol::CAddress> CPeerManager::SelectAddressesToConnect(int count) {
    std::vector<NetProtocol::CAddress> result;

    // Use AddrMan's deterministic selection algorithm
    // This provides eclipse attack protection via the bucket system
    for (int i = 0; i < count; i++) {
        // Select returns pair<CAddress, int64_t> where int64_t is last try time
        auto [selected_addr, last_try] = addrman.Select();

        // Check if valid address was returned
        if (!selected_addr.IsValid()) {
            break;  // No more addresses available
        }

        // Convert CAddress (which inherits from CService/CNetAddr) back to NetProtocol::CAddress
        NetProtocol::CAddress addr;
        addr.services = NetProtocol::NODE_NETWORK;
        addr.port = selected_addr.GetPort();
        addr.time = GetTime();

        // CService inherits from CNetAddr, so we can access CNetAddr methods directly
        if (selected_addr.IsIPv4()) {
            addr.SetIPv4(selected_addr.GetIPv4());
        } else {
            // Copy raw bytes from CNetAddr
            memcpy(addr.ip, selected_addr.GetAddrBytes(), 16);
        }

        result.push_back(addr);
    }

    return result;
}

size_t CPeerManager::GetAddressCount() const {
    return addrman.Size();
}

bool CPeerManager::EvictPeersIfNeeded() {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // Only evict if we're at or over the limit
    if (peers.size() < MAX_TOTAL_CONNECTIONS) {
        return false;  // No eviction needed
    }

    // Find candidate peers to evict
    // Priority: Keep outbound connections (we initiated), evict inbound with highest misbehavior
    std::vector<std::pair<int, int>> eviction_candidates;  // (peer_id, score)

    int64_t now = GetTime();
    for (const auto& [peer_id, peer] : peers) {
        // Only consider connected peers for eviction
        if (!peer->IsConnected()) {
            continue;
        }

        // Calculate eviction score (higher = more likely to evict)
        int score = peer->misbehavior_score;
        
        // Prefer to evict peers with no recent activity (no messages in last 5 minutes)
        if (peer->last_recv > 0 && (now - peer->last_recv) > 5 * 60) {
            score += 50;  // Inactive peer
        } else if (peer->last_recv == 0) {
            score += 100;  // Never received anything
        }

        // Prefer to evict peers that haven't completed handshake
        if (!peer->IsHandshakeComplete()) {
            score += 200;  // Incomplete handshake
        }

        eviction_candidates.push_back({peer_id, score});
    }

    if (eviction_candidates.empty()) {
        return false;  // No candidates to evict
    }

    // Sort by score (highest first = most likely to evict)
    std::sort(eviction_candidates.begin(), eviction_candidates.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // Evict the worst peer
    int peer_to_evict = eviction_candidates[0].first;
    auto peer = GetPeer(peer_to_evict);
    if (peer) {
        LogPrintf(NET, INFO, "Evicting peer %d (score: %d, addr: %s)",
                  peer_to_evict, eviction_candidates[0].second, peer->addr.ToString().c_str());
        RemovePeer(peer_to_evict);
        return true;
    }

    return false;
}

void CPeerManager::PeriodicMaintenance() {
    // Decay misbehavior scores
    DecayMisbehaviorScores();

    // Evict peers if needed
    EvictPeersIfNeeded();

    // Save peers periodically (every 15 minutes)
    static int64_t last_save_time = 0;
    int64_t now = GetTime();
    if (now - last_save_time > 15 * 60) {
        SavePeers();
        last_save_time = now;
    }
}