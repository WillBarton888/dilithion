// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/peers.h>
#include <net/dns.h>
#include <net/block_tracker.h>
#include <core/node_context.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <node/mempool.h>
#include <net/net.h>
#include <net/connman.h>
#include <net/protocol.h>
#include <digital_dna/digital_dna.h>  // Digital DNA: Sybil-resistant identity
#include <util/strencodings.h>
#include <util/logging.h>
#include <algorithm>
#include <set>

// SSOT: Access to global node context for CBlockTracker
extern NodeContext g_node_context;

// Global peer manager instance (raw pointer - ownership in g_node_context)
// REMOVED: g_peer_manager global - use NodeContext::peer_manager instead

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
    
    // Network: Initialize enhanced peer discovery
    peer_discovery = std::make_unique<CPeerDiscovery>(*this, addrman);
    
    // Network: Connection quality tracker is initialized automatically (default constructor)
}

bool CPeerManager::SavePeers() {
    if (data_dir.empty()) {
        return false;
    }

    std::string path = data_dir + "/peers.dat";
    bool result = addrman.SaveToFile(path);

    if (result) {
        LogPrintf(NET, INFO, "Saved %zu peer addresses to %s", addrman.Size(), path.c_str());
    } else {
        LogPrintf(NET, ERROR, "Failed to save peers to %s", path.c_str());
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
        LogPrintf(NET, INFO, "Loaded %zu peer addresses from %s", addrman.Size(), path.c_str());
    }
    // Silent if no existing peers.dat - normal for new node

    return result;
}

std::shared_ptr<CPeer> CPeerManager::AddPeer(const NetProtocol::CAddress& addr) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // Check if IP is banned using CBanManager
    std::string ip = addr.ToStringIP();

    if (banman.IsBanned(ip)) {
        return nullptr;
    }

    // BUG #105 FIX: Check connection limit using CONNECTED peer count, not map size
    size_t connected = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            connected++;
        }
    }
    if (connected >= MAX_TOTAL_CONNECTIONS) {
        return nullptr;
    }

    // Create new peer
    auto peer = std::make_shared<CPeer>(next_peer_id++, addr);
    peers[peer->id] = peer;


    return peer;
}

std::shared_ptr<CPeer> CPeerManager::AddPeerWithId(int peer_id) {
    // BUG #124 FIX: Add peer with specific ID for inbound connections
    // Inbound connections don't go through AddPeer(), so we need to create the peer
    // with the exact ID that CConnectionManager uses

    // First, try to get address from CNode (need to lock cs_nodes first to avoid deadlock)
    NetProtocol::CAddress addr;
    {
        std::lock_guard<std::recursive_mutex> lock(cs_nodes);
        auto node_it = node_refs.find(peer_id);
        if (node_it != node_refs.end() && node_it->second) {
            addr = node_it->second->addr;
        }
    }

    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // Check if peer already exists
    auto it = peers.find(peer_id);
    if (it != peers.end()) {
        // BUG FIX: Update address if it was zeroed
        if (it->second->addr.IsNull() && !addr.IsNull()) {
            it->second->addr = addr;
        }
        if (it->second->connect_time == 0) {
            it->second->connect_time = GetTime();
        }
        return it->second;
    }

    // BUG #105 FIX: Check connection limit using CONNECTED peer count
    size_t connected = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            connected++;
        }
    }
    if (connected >= MAX_TOTAL_CONNECTIONS) {
        return nullptr;
    }

    // Create new peer with the specified ID and address from CNode
    auto peer = std::make_shared<CPeer>(peer_id, addr);
    peer->state = CPeer::STATE_CONNECTED;
    peers[peer_id] = peer;

    // Update next_peer_id if needed to avoid ID collisions (atomic CAS loop)
    int expected = next_peer_id.load();
    while (peer_id >= expected) {
        if (next_peer_id.compare_exchange_weak(expected, peer_id + 1)) {
            break;
        }
    }

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
    // P5-LOW FIX: Return without std::move to allow RVO (copy elision)
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
    // P5-LOW FIX: Return without std::move to allow RVO (copy elision)
    return result;
}

bool CPeerManager::CanAcceptConnection() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    // BUG #105 FIX: Count only CONNECTED peers, not total map entries
    // Previously used peers.size() which included disconnected/zombie peers
    size_t connected = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            connected++;
        }
    }
    return connected < MAX_TOTAL_CONNECTIONS;
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

    // P5-LOW FIX: Return without std::move to allow RVO
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
    // Must create CNetworkAddr (which extends CService) for proper Add()
    CNetworkAddr networkAddr(service, addr.services, addr.time);
    addrman.Add(networkAddr, CNetAddr());  // No source address for now
}

std::vector<NetProtocol::CAddress> CPeerManager::QueryDNSSeeds() {
    std::vector<NetProtocol::CAddress> result;

    for (const auto& seed_hostname : dns_seeds) {
        try {
            std::vector<NetProtocol::CAddress> addresses =
                CDNSResolver::QuerySeed(seed_hostname, NetProtocol::DEFAULT_PORT);

            if (addresses.empty()) {
                continue;
            }

            for (const auto& addr : addresses) {
                result.push_back(addr);
                AddPeerAddress(addr);
            }

        } catch (const std::exception& e) {
            LogPrintf(NET, WARN, "Failed to query DNS seed %s: %s", seed_hostname.c_str(), e.what());
            continue;
        } catch (...) {
            continue;
        }
    }

    if (!result.empty()) {
        LogPrintf(NET, INFO, "DNS seeds: found %zu peer addresses", result.size());
    }

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

    // Seed node protection: never ban seed nodes for misbehavior.
    // Seed nodes are trusted infrastructure - banning them causes total network isolation.
    // Get peer IP to check against seed list.
    std::string peer_ip = peer->addr.ToStringIP();
    if (peer->addr.IsNull()) {
        std::lock_guard<std::recursive_mutex> node_lock(cs_nodes);
        auto it = node_refs.find(peer_id);
        if (it != node_refs.end() && it->second && !it->second->addr.IsNull()) {
            peer_ip = it->second->addr.ToStringIP();
        }
    }
    if (IsSeedNode(peer_ip)) {
        LogPrintf(NET, WARN, "[CPeerManager] Ignoring misbehavior score for seed node %s (peer %d, type=%s, score=%d)\n",
                  peer_ip.c_str(), peer_id, MisbehaviorTypeToString(type), howmuch);
        return;
    }

    // Use default score from MisbehaviorType if howmuch is 0
    int score = howmuch > 0 ? howmuch : GetMisbehaviorScore(type);

    if (peer->Misbehaving(score)) {
        // Ban peer if threshold exceeded
        std::lock_guard<std::recursive_mutex> lock(cs_peers);
        int64_t ban_until = GetTime() + DEFAULT_BAN_TIME;
        peer->Ban(ban_until);

        // BUG FIX: Get IP from peer first, fall back to CNode if peer's addr is null
        // (race condition can cause peer->addr to be zeroed if AddPeerWithId runs before RegisterNode)
        std::string ip = peer->addr.ToStringIP();

        // BUG #246 FIX: Immediately disconnect banned peer
        // Mark the CNode for disconnect so CConnman removes it on next iteration
        {
            std::lock_guard<std::recursive_mutex> node_lock(cs_nodes);
            auto it = node_refs.find(peer_id);
            if (it != node_refs.end() && it->second) {
                // BUG FIX: If peer's IP is null/zeroed, get it from CNode
                if (peer->addr.IsNull() && !it->second->addr.IsNull()) {
                    ip = it->second->addr.ToStringIP();
                }
                it->second->MarkDisconnect();
            }
        }

        banman.Ban(ip, DEFAULT_BAN_TIME, BanReason::NodeMisbehaving,
                   type, peer->misbehavior_score);

        std::cout << "[BAN] Peer " << peer_id << " (" << ip
                  << ") banned for " << (DEFAULT_BAN_TIME / 3600) << "h - "
                  << MisbehaviorTypeToString(type)
                  << " (score: " << peer->misbehavior_score << ")" << std::endl;
    }
}

void CPeerManager::DecayMisbehaviorScores() {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // BUG #49: Decay misbehavior scores over time
    // Called every 30 seconds, decay by 0.5 points (1 point per minute)
    for (auto& pair : peers) {
        if (pair.second->misbehavior_score > 0) {
            pair.second->misbehavior_score = std::max(0, pair.second->misbehavior_score - 1);
        }
    }

    // Clean up expired bans using CBanManager
    banman.SweepExpiredBans();

    // Clean up old genesis failure tracking entries
    banman.CleanupGenesisFailures();
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

    // Returns the highest chain height reported by any connected peer.
    // Used for IBD detection and progress display.
    //
    // BUG FIX: Don't require full handshake (VERACK) to use start_height.
    // After ProcessVersionMessage, start_height is already set from the peer's
    // VERSION message. Requiring IsHandshakeComplete() creates an unnecessary gap
    // where we know the peer's height but report 0 (confusing during IBD).
    // Also check best_known_height which gets updated during headers sync and
    // may be higher than start_height for long-lived connections.
    int best = 0;
    for (const auto& pair : peers) {
        const auto& peer = pair.second;
        // Accept height from any peer that has completed handshake OR has received
        // a VERSION message (start_height > 0 means we got their VERSION)
        if (peer->IsHandshakeComplete() || peer->start_height > 0) {
            int peer_height = std::max(peer->start_height, peer->best_known_height);
            if (peer_height > best) {
                best = peer_height;
            }
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

    seed_nodes.clear();

    // Check if we're on mainnet or testnet
    bool isTestnet = Dilithion::g_chainParams && Dilithion::g_chainParams->IsTestnet();

    if (isTestnet) {
        // ============================================
        // TESTNET SEED NODES
        // ============================================
        dns_seeds = {
            "seed-testnet.dilithion.org",
            "seed-testnet1.dilithion.org",
            "seed-testnet2.dilithion.org",
        };

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
    } else {
        // ============================================
        // MAINNET SEED NODES
        // ============================================
        dns_seeds = {
            "seed.dilithion.org",
            "seed1.dilithion.org",
            "seed2.dilithion.org",
        };

        // MAINNET SEED NODE #1: NYC (DigitalOcean NYC3)
        // IP: 138.197.68.128, Port: 8444 (mainnet)
        NetProtocol::CAddress seed_nyc;
        seed_nyc.services = NetProtocol::NODE_NETWORK;
        seed_nyc.SetIPv4(0x8AC54480);  // 138.197.68.128
        seed_nyc.port = NetProtocol::DEFAULT_PORT;
        seed_nyc.time = GetTime();
        seed_nodes.push_back(seed_nyc);

        // MAINNET SEED NODE #2: London (DigitalOcean LON1)
        // IP: 167.172.56.119, Port: 8444 (mainnet)
        NetProtocol::CAddress seed_london;
        seed_london.services = NetProtocol::NODE_NETWORK;
        seed_london.SetIPv4(0xA7AC3877);  // 167.172.56.119
        seed_london.port = NetProtocol::DEFAULT_PORT;
        seed_london.time = GetTime();
        seed_nodes.push_back(seed_london);

        // MAINNET SEED NODE #3: Singapore (DigitalOcean SGP1)
        // IP: 165.22.103.114, Port: 8444 (mainnet)
        NetProtocol::CAddress seed_singapore;
        seed_singapore.services = NetProtocol::NODE_NETWORK;
        seed_singapore.SetIPv4(0xA5166772);  // 165.22.103.114
        seed_singapore.port = NetProtocol::DEFAULT_PORT;
        seed_singapore.time = GetTime();
        seed_nodes.push_back(seed_singapore);

        // MAINNET SEED NODE #4: Sydney (DigitalOcean SYD1)
        // IP: 134.199.159.83, Port: 8444 (mainnet)
        NetProtocol::CAddress seed_sydney;
        seed_sydney.services = NetProtocol::NODE_NETWORK;
        seed_sydney.SetIPv4(0x86C79F53);  // 134.199.159.83
        seed_sydney.port = NetProtocol::DEFAULT_PORT;
        seed_sydney.time = GetTime();
        seed_nodes.push_back(seed_sydney);
    }

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

bool CPeerManager::IsSeedNode(const std::string& ip) const {
    for (const auto& seed : seed_nodes) {
        if (seed.ToStringIP() == ip) {
            return true;
        }
    }
    return false;
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

    // NOTE: Since we only call MarkAddressGood for OUTBOUND connections,
    // addr.port is already the correct P2P port (18444 testnet / 8444 mainnet).
    // Inbound connections are excluded at the call site (dilithion-node.cpp).
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
    std::set<std::string> seen_ips;  // Track already-selected addresses to prevent duplicates

    // Use AddrMan's deterministic selection algorithm
    // This provides eclipse attack protection via the bucket system
    int attempts = 0;
    int max_attempts = count * 3;  // Allow some failed attempts due to duplicates

    while ((int)result.size() < count && attempts < max_attempts) {
        attempts++;

        // Select returns pair<CAddress, int64_t> where int64_t is last try time
        auto [selected_addr, last_try] = addrman.Select();

        // Check if valid address was returned
        if (!selected_addr.IsValid()) {
            break;  // No more addresses available
        }

        // Get IP string for deduplication
        std::string ip_str = selected_addr.ToStringIP();
        if (seen_ips.count(ip_str)) {
            continue;  // Skip duplicate
        }
        seen_ips.insert(std::move(ip_str));

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

    // P5-LOW FIX: Return without std::move to allow RVO
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

    // P3-N8 FIX: Disconnect peers with stale handshakes
    // If a peer hasn't completed handshake within 60 seconds, disconnect them
    // This prevents attackers from occupying connection slots indefinitely
    // BUG #148 FIX: Reduced from 300s to 60s - handshake should complete within seconds,
    // not minutes. 300s was causing zombie peers to occupy slots too long.
    {
        std::lock_guard<std::recursive_mutex> lock(cs_peers);
        static const int64_t HANDSHAKE_TIMEOUT = 60;  // BUG #148: Reduced from 300s
        int64_t now = GetTime();

        std::vector<int> peers_to_disconnect;
        for (const auto& pair : peers) {
            CPeer* peer = pair.second.get();
            if (peer->state == CPeer::STATE_CONNECTING ||
                peer->state == CPeer::STATE_CONNECTED ||
                peer->state == CPeer::STATE_VERSION_SENT) {
                // Peer is in handshake state
                int64_t age = now - peer->connect_time;
                if (age > HANDSHAKE_TIMEOUT) {
                    peers_to_disconnect.push_back(peer->id);
                }
            }
        }

        // Disconnect stale peers (outside the loop to avoid iterator invalidation)
        // BUG #144 FIX: Also mark CNode for disconnect so CConnman removes it from m_nodes
        for (int peer_id : peers_to_disconnect) {
            auto it = peers.find(peer_id);
            if (it != peers.end()) {
                it->second->Disconnect();
                // Also mark the CNode for disconnect
                CNode* node = GetNode(peer_id);
                if (node) {
                    node->MarkDisconnect();
                }
            }
        }
    }

    // Save peers periodically (every 15 minutes)
    static int64_t last_save_time = 0;
    int64_t now = GetTime();
    if (now - last_save_time > 15 * 60) {
        SavePeers();
        last_save_time = now;
    }
}

// =============================================================================
// Phase 3.2: Block tracking methods (ported from CNodeStateManager)
// =============================================================================

bool CPeerManager::MarkBlockAsInFlight(int peer_id, const uint256& hash, const CBlockIndex* pindex)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // SSOT: CBlockTracker handles tracking via CBlockFetcher::RequestBlockFromPeer
    // This method is now only for legacy orphan block tracking

    if (mapBlocksInFlight.count(hash)) {
        return false;
    }

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return false;
    }

    CPeer* peer = it->second.get();

    // Use CBlockTracker for capacity check
    int peer_blocks_in_flight = 0;
    if (g_node_context.block_tracker) {
        peer_blocks_in_flight = g_node_context.block_tracker->GetPeerInFlightCount(peer_id);
    }
    if (peer_blocks_in_flight >= MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        return false;
    }

    // Legacy tracking for orphan blocks (no known height)
    QueuedBlock qb(hash, pindex);
    peer->vBlocksInFlight.push_back(qb);
    peer->nBlocksInFlight++;

    auto list_it = std::prev(peer->vBlocksInFlight.end());
    mapBlocksInFlight[hash] = std::make_pair(peer_id, list_it);

    return true;
}

int CPeerManager::MarkBlockAsReceived(const uint256& hash)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        return -1;
    }

    int peer_id = it->second.first;
    auto list_it = it->second.second;

    // Get peer and remove from their list
    auto peer_it = peers.find(peer_id);
    if (peer_it != peers.end()) {
        CPeer* peer = peer_it->second.get();
        peer->vBlocksInFlight.erase(list_it);
        peer->nBlocksInFlight--;

        // Reset stall count on successful receive
        peer->nStallingCount = 0;
        peer->nBlocksDownloaded++;
        peer->lastSuccessTime = std::chrono::steady_clock::now();
    }

    // Remove from global map
    mapBlocksInFlight.erase(it);

    return peer_id;
}

void CPeerManager::MarkBlockAsReceived(int peer_id, const uint256& hash)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // SSOT: CBlockTracker handles tracking via OnBlockReceived
    // This method just updates peer stats

    // Update peer stats
    auto peer_it = peers.find(peer_id);
    if (peer_it != peers.end()) {
        peer_it->second->nBlocksDownloaded++;
        peer_it->second->lastSuccessTime = std::chrono::steady_clock::now();
        peer_it->second->nStallingCount = 0;
    }

    // Legacy: clean up mapBlocksInFlight if present (for orphan blocks)
    auto it = mapBlocksInFlight.find(hash);
    if (it != mapBlocksInFlight.end()) {
        int tracked_peer = it->second.first;
        auto list_it = it->second.second;

        auto tracked_peer_it = peers.find(tracked_peer);
        if (tracked_peer_it != peers.end()) {
            CPeer* peer = tracked_peer_it->second.get();
            peer->vBlocksInFlight.erase(list_it);
            if (peer->nBlocksInFlight > 0) {
                peer->nBlocksInFlight--;
            }
        }
        mapBlocksInFlight.erase(it);
    }
}

int CPeerManager::RemoveBlockFromFlight(const uint256& hash)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        return -1;
    }

    int peer_id = it->second.first;
    auto list_it = it->second.second;

    // Get peer and remove from their list (don't reset stall count - this is timeout)
    auto peer_it = peers.find(peer_id);
    if (peer_it != peers.end()) {
        CPeer* peer = peer_it->second.get();
        peer->vBlocksInFlight.erase(list_it);
        // IBD HANG FIX #21: Guard against going negative
        if (peer->nBlocksInFlight > 0) {
            peer->nBlocksInFlight--;
        }
    }

    // Remove from global map
    mapBlocksInFlight.erase(it);

    return peer_id;
}

bool CPeerManager::IsBlockInFlight(const uint256& hash) const
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    return mapBlocksInFlight.count(hash) > 0;
}

int CPeerManager::GetBlockPeer(const uint256& hash) const
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    auto it = mapBlocksInFlight.find(hash);
    if (it != mapBlocksInFlight.end()) {
        return it->second.first;
    }
    return -1;
}

std::vector<std::pair<uint256, int>> CPeerManager::GetBlocksInFlight() const
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<std::pair<uint256, int>> result;
    for (const auto& entry : mapBlocksInFlight) {
        result.push_back(std::make_pair(entry.first, entry.second.first));
    }
    return result;
}

int CPeerManager::GetBlocksInFlightForPeer(int peer_id) const
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // SSOT: CBlockTracker is the single source of truth for in-flight counts
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->GetPeerInFlightCount(peer_id);
    }

    // Legacy fallback: Count from mapBlocksInFlight
    int count = 0;
    for (const auto& entry : mapBlocksInFlight) {
        if (entry.second.first == peer_id) {
            count++;
        }
    }
    return count;
}

std::vector<std::pair<uint256, int>> CPeerManager::GetTimedOutBlocks(int timeout_seconds) const
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<std::pair<uint256, int>> result;

    auto now = std::chrono::steady_clock::now();
    auto timeout_duration = std::chrono::seconds(timeout_seconds);

    for (const auto& pair : peers) {
        CPeer* peer = pair.second.get();
        for (const auto& qb : peer->vBlocksInFlight) {
            auto elapsed = now - qb.time;
            if (elapsed > timeout_duration) {
                result.push_back(std::make_pair(qb.hash, pair.first));
            }
        }
    }

    return result;
}

std::vector<uint256> CPeerManager::GetAndClearPeerBlocks(int peer_id)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<uint256> result;

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return result;
    }

    CPeer* peer = it->second.get();

    // Collect all block hashes
    for (const auto& qb : peer->vBlocksInFlight) {
        result.push_back(qb.hash);
        mapBlocksInFlight.erase(qb.hash);
    }

    // Clear peer's list
    peer->vBlocksInFlight.clear();
    peer->nBlocksInFlight = 0;

    return result;
}

std::vector<int> CPeerManager::CheckForStallingPeers()
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<int> stallingPeers;
    auto now = std::chrono::steady_clock::now();

    for (auto& pair : peers) {
        CPeer* peer = pair.second.get();
        if (peer->vBlocksInFlight.empty()) {
            continue;
        }

        // Check oldest block in flight
        const QueuedBlock& oldest = peer->vBlocksInFlight.front();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - oldest.time);
        auto timeout = peer->GetBlockTimeout();

        if (elapsed > timeout) {
            peer->nStallingCount++;
            peer->lastStallTime = now;

            // Reset the timer for next check
            peer->vBlocksInFlight.front().time = now;

            // If stalling too many times, mark for disconnection
            if (peer->nStallingCount >= 5) {
                stallingPeers.push_back(pair.first);
            }
        }
    }

    return stallingPeers;
}

void CPeerManager::UpdatePeerStats(int peer_id, bool success, std::chrono::milliseconds responseTime)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return;
    }

    CPeer* peer = it->second.get();

    if (success) {
        peer->nBlocksDownloaded++;
        peer->lastSuccessTime = std::chrono::steady_clock::now();

        // Update average response time (exponential moving average)
        if (responseTime.count() > 0) {
            peer->avgResponseTime = std::chrono::milliseconds(
                (peer->avgResponseTime.count() * 7 + responseTime.count()) / 8
            );
        }
    } else {
        peer->nStallingCount++;
        peer->lastStallTime = std::chrono::steady_clock::now();
    }
}

void CPeerManager::ClearPeerInFlightState(int peer_id)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return;
    }

    CPeer* peer = it->second.get();

    // BUG #166 FIX: Clear vBlocksInFlight and corresponding map entries
    for (const auto& qb : peer->vBlocksInFlight) {
        auto map_it = mapBlocksInFlight.find(qb.hash);
        if (map_it != mapBlocksInFlight.end() && map_it->second.first == peer_id) {
            mapBlocksInFlight.erase(map_it);
        }
    }

    peer->vBlocksInFlight.clear();
    peer->nBlocksInFlight = 0;

    // BUG #166 FIX: Reset stall count so peer can become suitable again
    peer->nStallingCount = 0;
    peer->lastStallTime = std::chrono::steady_clock::now();
}

std::vector<int> CPeerManager::GetValidPeersForDownload() const
{
    std::lock_guard<std::recursive_mutex> lock_peers(cs_peers);
    std::lock_guard<std::recursive_mutex> lock_nodes(cs_nodes);
    std::vector<int> result;

    for (const auto& pair : peers) {
        int peer_id = pair.first;
        CPeer* peer = pair.second.get();

        // Check if CNode still exists
        auto node_it = node_refs.find(peer_id);
        if (node_it == node_refs.end() || node_it->second == nullptr) {
            continue;
        }

        CNode* node = node_it->second;

        // SSOT: Check CNode state (socket, disconnect flag, handshake)
        if (!node->HasValidSocket() || node->fDisconnect.load() || !node->IsHandshakeComplete()) {
            continue;
        }

        // Must be suitable for download (not stalling too much)
        if (!peer->IsSuitableForDownload()) {
            continue;
        }

        result.push_back(peer_id);
    }

    return result;
}

bool CPeerManager::IsPeerSuitableForDownload(int peer_id) const
{
    // BUG #148 FIX: Lock both mutexes to check node validity
    std::lock_guard<std::recursive_mutex> lock_peers(cs_peers);
    std::lock_guard<std::recursive_mutex> lock_nodes(cs_nodes);

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return false;
    }

    CPeer* peer = it->second.get();

    // BUG #148 FIX: Check if CNode still exists
    auto node_it = node_refs.find(peer_id);
    if (node_it == node_refs.end() || node_it->second == nullptr) {
        return false;
    }

    CNode* node = node_it->second;

    // BUG #148 FIX: Check if CNode has valid socket
    if (!node->HasValidSocket() || node->fDisconnect.load()) {
        return false;
    }

    // SSOT FIX #1: Check CNode::state (single source of truth) instead of CPeer::state
    // CNode::state is authoritative - CPeer::state is deprecated
    // Note: 'node' is already obtained from node_refs above
    return node->IsHandshakeComplete() &&  // Query CNode::state (SSOT)
           peer->IsSuitableForDownload();
}

void CPeerManager::UpdatePeerBestKnownHeight(int peer_id, int height)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return;  // Peer not found
    }

    CPeer* peer = it->second.get();

    // Only update if new height is higher (peer can't "un-mine" blocks)
    if (height > peer->best_known_height) {
        peer->best_known_height = height;
    }
}

bool CPeerManager::OnPeerHandshakeComplete(int peer_id, int starting_height, bool preferred)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        // Create peer entry if not exists
        // BUG FIX: Get address from CNode to avoid null addr
        NetProtocol::CAddress addr;
        {
            std::lock_guard<std::recursive_mutex> node_lock(cs_nodes);
            auto node_it = node_refs.find(peer_id);
            if (node_it != node_refs.end() && node_it->second) {
                addr = node_it->second->addr;
            }
        }
        auto new_peer = std::make_shared<CPeer>(peer_id, addr);
        new_peer->state = CPeer::STATE_CONNECTED;
        peers[peer_id] = std::move(new_peer);
        it = peers.find(peer_id);
    }

    CPeer* peer = it->second.get();

    peer->state = CPeer::STATE_HANDSHAKE_COMPLETE;
    peer->start_height = starting_height;
    peer->best_known_height = starting_height;  // Initialize to starting height
    peer->fPreferredDownload = preferred;
    peer->fSyncStarted = false;

    // Initialize timing
    auto now = std::chrono::steady_clock::now();
    peer->m_stalling_since = now;
    peer->m_downloading_since = now;
    peer->m_last_block_announcement = now;
    peer->lastSuccessTime = now;
    peer->lastStallTime = now;

    // Send mempool INV to newly connected peer so they learn about pending transactions.
    // Without this, peers that connect after a tx was broadcast never learn about it.
    // Batches INV messages (max 1000 per message) to handle large mempools.
    {
        extern std::atomic<CTxMemPool*> g_mempool;
        auto* mempool = g_mempool.load();
        if (mempool && g_node_context.connman && g_node_context.message_processor) {
            auto txs = mempool->GetOrderedTxs();
            if (!txs.empty()) {
                size_t total_sent = 0;
                std::vector<NetProtocol::CInv> inv_vec;
                inv_vec.reserve(std::min(txs.size(), (size_t)1000));
                for (const auto& tx : txs) {
                    inv_vec.push_back(NetProtocol::CInv(NetProtocol::MSG_TX_INV, tx->GetHash()));
                    if (inv_vec.size() >= 1000) {
                        CNetMessage inv_msg = g_node_context.message_processor->CreateInvMessage(inv_vec);
                        g_node_context.connman->PushMessage(peer_id, inv_msg);
                        total_sent += inv_vec.size();
                        inv_vec.clear();
                    }
                }
                if (!inv_vec.empty()) {
                    CNetMessage inv_msg = g_node_context.message_processor->CreateInvMessage(inv_vec);
                    g_node_context.connman->PushMessage(peer_id, inv_msg);
                    total_sent += inv_vec.size();
                }
                std::cout << "[TX-RELAY] Sent " << total_sent
                          << " mempool tx INV(s) to new peer " << peer_id << std::endl;
            }
        }
    }

    // Digital DNA: Notify collector about new peer connection
    if (auto collector = g_node_context.GetDNACollector()) {
        // Convert peer address to 20-byte ID (hash of IP:port)
        std::array<uint8_t, 20> peer_dna_id = {};
        std::string addr_str = peer->addr.ToString();
        auto hash = std::hash<std::string>{}(addr_str);
        memcpy(peer_dna_id.data(), &hash, std::min(sizeof(hash), peer_dna_id.size()));
        collector->on_peer_connected(peer_dna_id);
    }

    return true;
}

void CPeerManager::OnPeerDisconnected(int peer_id)
{
    // Re-queue any in-flight blocks from this peer (legacy tracking)
    GetAndClearPeerBlocks(peer_id);

    // SSOT: Also notify CBlockTracker to clear this peer's blocks
    // This prevents "no suitable peers" stalls from stale in-flight blocks
    if (g_node_context.block_tracker) {
        auto heights = g_node_context.block_tracker->OnPeerDisconnected(peer_id);
        if (!heights.empty()) {
            std::cout << "[BLOCK-TRACKER] Cleared " << heights.size()
                      << " in-flight blocks from disconnected peer " << peer_id << std::endl;
        }
    }

    // Digital DNA: Notify collector about peer disconnection
    if (auto collector = g_node_context.GetDNACollector()) {
        // Get peer address for ID computation
        std::lock_guard<std::recursive_mutex> lock(cs_peers);
        auto it = peers.find(peer_id);
        if (it != peers.end()) {
            std::array<uint8_t, 20> peer_dna_id = {};
            std::string addr_str = it->second->addr.ToString();
            auto hash = std::hash<std::string>{}(addr_str);
            memcpy(peer_dna_id.data(), &hash, std::min(sizeof(hash), peer_dna_id.size()));
            collector->on_peer_disconnected(peer_dna_id);
        }
    }

    // The actual peer removal is handled by RemovePeer()
}

// Phase 1: CNode management methods (event-driven networking)
// These methods replace CPeer methods for new event-driven architecture

CNode* CPeerManager::AddNode(const NetProtocol::CAddress& addr, bool inbound) {
    // DEPRECATED: Use CConnman::ConnectNode() or CConnman::AcceptConnection() instead.
    std::string ip = addr.ToStringIP();
    if (banman.IsBanned(ip)) {
        return nullptr;
    }

    if (!CanAcceptConnection()) {
        return nullptr;
    }

    int node_id = next_peer_id++;
    CNode* node_ptr = new CNode(node_id, addr, inbound);

    {
        std::lock_guard<std::recursive_mutex> lock(cs_nodes);
        node_refs[node_id] = node_ptr;
    }

    {
        std::lock_guard<std::recursive_mutex> lock(cs_peers);
        if (peers.find(node_id) == peers.end()) {
            auto peer = std::make_shared<CPeer>(node_id, addr);
            peer->state = inbound ? CPeer::STATE_CONNECTED : CPeer::STATE_CONNECTING;
            peers[node_id] = std::move(peer);
        }
    }

    return node_ptr;
}

bool CPeerManager::RegisterNode(int node_id, CNode* node, const NetProtocol::CAddress& addr, bool inbound) {
    // Store reference to CConnman's CNode (non-owning)
    std::string ip = addr.ToStringIP();

    // BUG #148 ROOT CAUSE FIX: Return false if IP is banned
    // Caller MUST check return value and NOT add to m_nodes if false
    // Otherwise, CNode exists in m_nodes but not in node_refs, causing
    // GetNode() to return nullptr during handshake
    // Seed node exemption: never reject seed nodes even if banned
    if (banman.IsBanned(ip)) {
        if (IsSeedNode(ip)) {
            LogPrintf(NET, WARN, "[CPeerManager] RegisterNode: Seed node %s is banned but allowing connection (seed exemption)\n", ip.c_str());
            banman.Unban(ip);
        } else {
            LogPrintf(NET, WARN, "[CPeerManager] RegisterNode: IP %s is banned, rejecting connection\n", ip.c_str());
            return false;
        }
    }

    {
        std::lock_guard<std::recursive_mutex> lock(cs_nodes);
        node_refs[node_id] = node;
    }

    {
        std::lock_guard<std::recursive_mutex> lock(cs_peers);
        auto it = peers.find(node_id);
        if (it == peers.end()) {
            // Create new peer
            auto peer = std::make_shared<CPeer>(node_id, addr);
            peer->state = inbound ? CPeer::STATE_CONNECTED : CPeer::STATE_CONNECTING;
            peers[node_id] = std::move(peer);
        } else {
            // BUG FIX: Update existing peer's address (may have been created by AddPeerWithId
            // with zeroed address due to race condition)
            it->second->addr = addr;
            if (it->second->connect_time == 0) {
                it->second->connect_time = GetTime();
            }
        }
    }

    // Update next_peer_id if needed to avoid ID collisions (atomic CAS loop)
    int expected = next_peer_id.load();
    while (node_id >= expected) {
        if (next_peer_id.compare_exchange_weak(expected, node_id + 1)) {
            break;
        }
    }

    return true;  // Registration successful
}

void CPeerManager::RemoveNode(int node_id) {
    // RACE FIX v2: Hold BOTH locks atomically using std::scoped_lock
    // This prevents ProcessVerackMessage from seeing partial state during removal.
    //
    // Previous fix (remove peer first, then node) still had a race window:
    //   T1: ThreadMessageHandler calls GetPeer() - succeeds
    //   T2: ThreadSocketHandler acquires cs_peers, erases peer
    //   T2: ThreadSocketHandler releases cs_peers  <-- RACE WINDOW
    //   T1: ThreadMessageHandler calls GetNode() - FAILS (node_refs not yet erased)
    //   T2: ThreadSocketHandler acquires cs_nodes, erases node_refs
    //
    // With std::scoped_lock, both maps are protected for the entire operation.
    // std::scoped_lock uses deadlock-avoidance algorithm (std::lock) internally.
    std::scoped_lock lock(cs_peers, cs_nodes);

    peers.erase(node_id);
    node_refs.erase(node_id);
}

CNode* CPeerManager::GetNode(int node_id) {
    std::lock_guard<std::recursive_mutex> lock(cs_nodes);

    auto it = node_refs.find(node_id);
    if (it != node_refs.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<CNode*> CPeerManager::GetAllNodes() {
    std::lock_guard<std::recursive_mutex> lock(cs_nodes);

    std::vector<CNode*> result;
    result.reserve(node_refs.size());

    for (auto& pair : node_refs) {
        if (pair.second) {
            result.push_back(pair.second);
        }
    }

    return result;
}

std::vector<CNode*> CPeerManager::GetConnectedNodes() {
    std::lock_guard<std::recursive_mutex> lock(cs_nodes);

    std::vector<CNode*> result;

    for (auto& pair : node_refs) {
        CNode* node = pair.second;
        if (node && node->IsConnected()) {
            result.push_back(node);
        }
    }

    return result;
}