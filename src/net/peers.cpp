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
    std::lock_guard<std::mutex> lock(cs_peers);

    // Check if IP is banned
    std::string ip = addr.ToStringIP();
    if (banned_ips.find(ip) != banned_ips.end()) {
        return nullptr;
    }

    // Check connection limit
    if (peers.size() >= MAX_TOTAL_CONNECTIONS) {
        return nullptr;
    }

    // Create new peer
    auto peer = std::make_shared<CPeer>(next_peer_id++, addr);
    peers[peer->id] = peer;

    return peer;
}

void CPeerManager::RemovePeer(int peer_id) {
    std::lock_guard<std::mutex> lock(cs_peers);
    auto it = peers.find(peer_id);
    if (it != peers.end()) {
        it->second->Disconnect();
        peers.erase(it);
    }
}

std::shared_ptr<CPeer> CPeerManager::GetPeer(int peer_id) {
    std::lock_guard<std::mutex> lock(cs_peers);
    auto it = peers.find(peer_id);
    return (it != peers.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<CPeer>> CPeerManager::GetAllPeers() {
    std::lock_guard<std::mutex> lock(cs_peers);
    std::vector<std::shared_ptr<CPeer>> result;
    for (const auto& pair : peers) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<std::shared_ptr<CPeer>> CPeerManager::GetConnectedPeers() {
    std::lock_guard<std::mutex> lock(cs_peers);
    std::vector<std::shared_ptr<CPeer>> result;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            result.push_back(pair.second);
        }
    }
    return result;
}

bool CPeerManager::CanAcceptConnection() const {
    std::lock_guard<std::mutex> lock(cs_peers);
    return peers.size() < MAX_TOTAL_CONNECTIONS;
}

size_t CPeerManager::GetConnectionCount() const {
    std::lock_guard<std::mutex> lock(cs_peers);
    size_t count = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            count++;
        }
    }
    return count;
}

size_t CPeerManager::GetOutboundCount() const {
    std::lock_guard<std::mutex> lock(cs_peers);
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
    std::lock_guard<std::mutex> lock(cs_peers);
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
    std::lock_guard<std::mutex> lock(cs_peers);
    auto it = peers.find(peer_id);
    if (it != peers.end()) {
        int64_t ban_until = GetTime() + ban_time_seconds;
        it->second->Ban(ban_until);

        // Add IP to banned list
        std::string ip = it->second->addr.ToStringIP();
        banned_ips.insert(ip);
    }
}

void CPeerManager::BanIP(const std::string& ip, int64_t ban_time_seconds) {
    std::lock_guard<std::mutex> lock(cs_peers);
    banned_ips.insert(ip);

    // Disconnect all peers from this IP
    for (auto& pair : peers) {
        if (pair.second->addr.ToStringIP() == ip) {
            int64_t ban_until = GetTime() + ban_time_seconds;
            pair.second->Ban(ban_until);
        }
    }
}

void CPeerManager::UnbanIP(const std::string& ip) {
    std::lock_guard<std::mutex> lock(cs_peers);
    banned_ips.erase(ip);
}

bool CPeerManager::IsBanned(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(cs_peers);
    return banned_ips.find(ip) != banned_ips.end();
}

void CPeerManager::ClearBans() {
    std::lock_guard<std::mutex> lock(cs_peers);
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

CPeerManager::Stats CPeerManager::GetStats() const {
    std::lock_guard<std::mutex> lock(cs_peers);

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
    // In production, these would be reliable nodes run by the community

    dns_seeds = {
        "seed.dilithion.com",
        "seed1.dilithion.com",
        "seed2.dilithion.com",
    };

    // Hardcoded IP addresses as fallback
    // Format: IPv4 mapped to IPv6
    seed_nodes.clear();

    // PRODUCTION TODO: Add real seed node IP addresses here
    // Seed nodes should be publicly accessible nodes run by trusted community members
    //
    // Example format:
    //   NetProtocol::CAddress seed1;
    //   seed1.services = NetProtocol::NODE_NETWORK;
    //   seed1.SetIPv4(0xC0A80001);  // Example: 192.168.0.1
    //   seed1.port = NetProtocol::DEFAULT_PORT;
    //   seed1.time = GetTime();
    //   seed_nodes.push_back(seed1);
    //
    // For testnet launch, operators should manually configure peer addresses
    // using the -addnode command line parameter or peers.dat file.
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
