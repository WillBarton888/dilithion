// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/peers.h>
#include <net/dns.h>
#include <util/strencodings.h>
#include <algorithm>
#include <iostream>

// Global peer manager instance
std::unique_ptr<CPeerManager> g_peer_manager = nullptr;

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

CPeerManager::CPeerManager() : next_peer_id(1) {
    InitializeSeedNodes();
}

std::shared_ptr<CPeer> CPeerManager::AddPeer(const NetProtocol::CAddress& addr) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // NET-005 FIX: Check if IP is banned (uses updated IsBanned with expiry check)
    std::string ip = addr.ToStringIP();
    std::cout << "[HANDSHAKE-DIAG] AddPeer called for " << addr.ToString()
              << " (IP: " << ip << ", current peers: " << peers.size() << "/" << MAX_TOTAL_CONNECTIONS << ")"
              << std::endl;

    if (IsBanned(ip)) {
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
    std::lock_guard<std::mutex> lock(cs_addrs);

    // Skip localhost and invalid addresses
    std::string ip = addr.ToStringIP();
    if (ip == "127.0.0.1" || ip == "::1" || ip.empty()) {
        return;
    }

    // Create unique key: IP:port
    std::string key = addr.ToString();

    // Check if address already exists
    auto it = addr_map.find(key);
    if (it != addr_map.end()) {
        // Update timestamp
        it->second.nTime = GetTime();
        return;
    }

    // NET-013 FIX: Limit address database size to prevent unbounded growth
    const size_t MAX_ADDR_COUNT = 10000;

    // If at capacity, evict oldest unused address
    if (addr_map.size() >= MAX_ADDR_COUNT) {
        // Find oldest address that hasn't been successfully connected
        auto oldest = addr_map.begin();
        for (auto iter = addr_map.begin(); iter != addr_map.end(); ++iter) {
            if (iter->second.nSuccesses == 0 && iter->second.nTime < oldest->second.nTime) {
                oldest = iter;
            }
        }
        addr_map.erase(oldest);
    }

    // Add new address
    CAddrInfo info;
    info.addr = addr;
    info.nTime = GetTime();
    info.nLastTry = 0;
    info.nLastSuccess = 0;
    info.nAttempts = 0;
    info.nSuccesses = 0;
    info.fInTried = false;

    addr_map[key] = info;
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

        // Add IP to banned list with expiry time
        std::string ip = it->second->addr.ToStringIP();
        BanIP(ip, ban_time_seconds);  // Use BanIP to enforce limits
    }
}

void CPeerManager::BanIP(const std::string& ip, int64_t ban_time_seconds) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // NET-005 FIX: Enforce maximum banned IPs limit with LRU eviction
    if (banned_ips.size() >= MAX_BANNED_IPS) {
        // Find the ban that expires soonest (LRU based on expiry time)
        auto oldest = banned_ips.begin();
        for (auto it = banned_ips.begin(); it != banned_ips.end(); ++it) {
            // Prefer removing entries that expire sooner
            // If permanent ban (0), keep it unless all are permanent
            if (it->second > 0 && (oldest->second == 0 || it->second < oldest->second)) {
                oldest = it;
            }
        }

        std::cout << "[PeerManager] WARNING: Banned IPs at capacity (" << banned_ips.size()
                  << "), removing ban for " << oldest->first << std::endl;
        banned_ips.erase(oldest);
    }

    // Add ban with expiry timestamp
    int64_t ban_until = GetTime() + ban_time_seconds;
    banned_ips[ip] = ban_until;

    // Disconnect all peers from this IP
    for (auto& pair : peers) {
        if (pair.second->addr.ToStringIP() == ip) {
            pair.second->Ban(ban_until);
        }
    }
}

void CPeerManager::UnbanIP(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    banned_ips.erase(ip);
}

bool CPeerManager::IsBanned(const std::string& ip) const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // NET-005 FIX: Check if IP is banned and ban hasn't expired
    auto it = banned_ips.find(ip);
    if (it == banned_ips.end()) {
        return false;  // Not banned
    }

    // Check if ban has expired
    int64_t ban_until = it->second;
    if (ban_until == 0) {
        return true;  // Permanent ban
    }

    if (GetTime() >= ban_until) {
        // Ban expired - remove it (const_cast needed for cleanup in const method)
        // Better: have separate cleanup thread, but this works for now
        return false;  // Expired ban = not banned
    }

    return true;  // Still banned
}

void CPeerManager::ClearBans() {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    banned_ips.clear();
}

void CPeerManager::Misbehaving(int peer_id, int howmuch) {
    auto peer = GetPeer(peer_id);
    if (!peer) return;

    if (peer->Misbehaving(howmuch)) {
        // Ban peer if threshold exceeded
        BanPeer(peer_id, DEFAULT_BAN_TIME);
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

    // Also clean up expired bans
    std::vector<std::string> expired_bans;
    int64_t now = GetTime();

    for (const auto& ban_entry : banned_ips) {
        if (ban_entry.second != 0 && now >= ban_entry.second) {
            expired_bans.push_back(ban_entry.first);
        }
    }

    for (const auto& ip : expired_bans) {
        banned_ips.erase(ip);
        std::cout << "[PeerManager] Ban expired for IP: " << ip << std::endl;
    }
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
    stats.banned_ips = banned_ips.size();

    return stats;
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

// Address database management (NW-003)

void CPeerManager::MarkAddressGood(const NetProtocol::CAddress& addr) {
    std::lock_guard<std::mutex> lock(cs_addrs);

    std::string key = addr.ToString();
    auto it = addr_map.find(key);
    if (it == addr_map.end()) {
        // Address not in database yet, add it
        AddPeerAddress(addr);
        it = addr_map.find(key);
        if (it == addr_map.end()) return;
    }

    // Update success metrics
    it->second.nLastSuccess = GetTime();
    it->second.nSuccesses++;
    it->second.fInTried = true;  // Move to "tried" table
}

void CPeerManager::MarkAddressTried(const NetProtocol::CAddress& addr) {
    std::lock_guard<std::mutex> lock(cs_addrs);

    std::string key = addr.ToString();
    auto it = addr_map.find(key);
    if (it == addr_map.end()) {
        return;  // Address not in database
    }

    // Update attempt metrics
    it->second.nLastTry = GetTime();
    it->second.nAttempts++;
}

std::vector<NetProtocol::CAddress> CPeerManager::SelectAddressesToConnect(int count) {
    std::lock_guard<std::mutex> lock(cs_addrs);

    std::vector<NetProtocol::CAddress> result;

    if (addr_map.empty()) {
        return result;
    }

    // Selection strategy:
    // 1. Prefer addresses we've never tried (nAttempts == 0)
    // 2. Then prefer addresses with successful connections (fInTried && nSuccesses > 0)
    // 3. Then try older addresses (larger time since last attempt)

    std::vector<std::pair<std::string, CAddrInfo*>> candidates;
    candidates.reserve(addr_map.size());

    for (auto& pair : addr_map) {
        candidates.push_back({pair.first, &pair.second});
    }

    // Sort by priority:
    // Priority 1: Never tried (nAttempts == 0)
    // Priority 2: Tried and succeeded (fInTried && nSuccesses > 0)
    // Priority 3: Everything else, sorted by last attempt time (oldest first)
    std::sort(candidates.begin(), candidates.end(),
              [](const auto& a, const auto& b) {
                  // Never tried addresses come first
                  if (a.second->nAttempts == 0 && b.second->nAttempts > 0) return true;
                  if (a.second->nAttempts > 0 && b.second->nAttempts == 0) return false;

                  // Among tried addresses, prioritize successful ones
                  if (a.second->fInTried && a.second->nSuccesses > 0 &&
                      (!b.second->fInTried || b.second->nSuccesses == 0)) return true;
                  if (b.second->fInTried && b.second->nSuccesses > 0 &&
                      (!a.second->fInTried || a.second->nSuccesses == 0)) return false;

                  // Otherwise sort by last attempt time (oldest first)
                  return a.second->nLastTry < b.second->nLastTry;
              });

    // Select up to 'count' addresses
    for (size_t i = 0; i < candidates.size() && result.size() < (size_t)count; i++) {
        result.push_back(candidates[i].second->addr);
    }

    return result;
}

size_t CPeerManager::GetAddressCount() const {
    std::lock_guard<std::mutex> lock(cs_addrs);
    return addr_map.size();
}
