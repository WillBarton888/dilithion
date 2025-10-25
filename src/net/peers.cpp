// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/peers.h>
#include <util/strencodings.h>
#include <algorithm>

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
    // For now, just store it - in production would have address manager
    // This is a simplified implementation
}

std::vector<NetProtocol::CAddress> CPeerManager::QueryDNSSeeds() {
    std::vector<NetProtocol::CAddress> result;

    // In production, this would query DNS seeds
    // For now, return empty (DNS resolution would require platform-specific code)

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

    // Example seed node (would be real IPs in production)
    NetProtocol::CAddress seed1;
    seed1.services = NetProtocol::NODE_NETWORK;
    seed1.SetIPv4(0x7F000001);  // 127.0.0.1 (localhost for testing)
    seed1.port = NetProtocol::DEFAULT_PORT;
    seed1.time = GetTime();
    seed_nodes.push_back(seed1);

    // Additional seed nodes would be added here
    // NetProtocol::CAddress seed2;
    // seed2.SetIPv4(0xC0A80001);  // 192.168.0.1
    // seed2.port = NetProtocol::DEFAULT_PORT;
    // seed_nodes.push_back(seed2);
}
