// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/net.h>
#include <util/error_format.h>  // UX: Better error messages
#include <net/connection_quality.h>  // Network: Connection quality metrics
#include <net/partition_detector.h>  // Network: Partition detection
#include <consensus/params.h>
#include <net/tx_relay.h>
#include <net/banman.h>  // For MisbehaviorType
#include <net/features.h>  // Feature flags system
#include <core/node_context.h>  // Phase 1.2: NodeContext for global state
#include <net/connman.h>  // Phase 5: For CConnman::PushMessage
#include <util/strencodings.h>
#include <util/time.h>
#include <util/logging.h>  // Bitcoin Core-style logging
#include <core/chainparams.h>
#include <node/mempool.h>
#include <node/utxo_set.h>
#include <consensus/tx_validation.h>
#include <consensus/chain.h>  // BUG #50 FIX: For g_chainstate.GetHeight()
#include <node/genesis.h>     // P2-3: For GetGenesisHash() validation
#include <net/block_fetcher.h>  // BUG #68 FIX: For BlockFetcher peer disconnect notification
// REMOVED: #include <net/node_state.h> - CNodeStateManager replaced by CPeerManager
// REMOVED: #include <net/message_queue.h> - CMessageProcessorQueue was unused
#include <random>
#include <thread>   // BUG #91: For std::this_thread::sleep_for
#include <chrono>   // BUG #91: For std::chrono::milliseconds
#include <cstring>
#include <iostream>
#include <sstream>

// Platform-specific socket headers for error codes (WSAETIMEDOUT, EAGAIN, etc.)
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
// Undefine Windows macros that conflict with our method names
#undef SendMessage
#else
#include <errno.h>
#include <netdb.h>      // For gethostname, getaddrinfo
#include <unistd.h>     // For gethostname
#include <arpa/inet.h>  // For inet_ntop
#endif

// NET-003 FIX: Define consensus limits to prevent integer overflow in vector resize
// These prevent DoS attacks via malicious size values causing heap corruption
static const uint64_t MAX_BLOCK_TRANSACTIONS = 100000;  // Max transactions per block
static const uint64_t MAX_TX_INPUTS = 10000;            // Max inputs per transaction
static const uint64_t MAX_TX_OUTPUTS = 10000;           // Max outputs per transaction
static const uint64_t MAX_SCRIPT_SIZE = 10000;          // Max script size in bytes

// P2-1 FIX: Rate limiting for GETDATA messages (DoS protection)
// Limits: 50 GETDATA messages per second per peer (increased from 10 for IBD sync)
static std::map<int, std::vector<int64_t>> g_peer_getdata_timestamps;
static std::mutex cs_getdata_rate;
static const size_t MAX_GETDATA_PER_SECOND = 50;

// P3-N2 FIX: Rate limiting for HEADERS messages (DoS protection)
// Limits: 3 HEADERS messages per second per peer (headers are large)
static std::map<int, std::vector<int64_t>> g_peer_headers_timestamps;
static std::mutex cs_headers_rate;
static const size_t MAX_HEADERS_PER_SECOND = 3;

// P2-2 FIX: Per-IP connection cooldown to prevent rapid reconnection DoS
// Prevents attackers from exhausting connection slots via reconnection churn
static std::map<std::string, int64_t> g_last_connection_attempt;
static std::mutex cs_connection_cooldown;
static const int64_t CONNECTION_COOLDOWN_SECONDS = 30;

// NET-013 FIX: Maximum size for rate limit maps to prevent memory exhaustion
static const size_t MAX_RATE_LIMIT_MAP_SIZE = 1000;

/**
 * NET-011/NET-013 FIX: Cleanup rate limit state for a disconnected peer
 * Prevents memory leaks from stale peer entries
 */
void CleanupPeerRateLimitState(int peer_id) {
    {
        std::lock_guard<std::mutex> lock(cs_getdata_rate);
        g_peer_getdata_timestamps.erase(peer_id);
    }
    {
        std::lock_guard<std::mutex> lock(cs_headers_rate);
        g_peer_headers_timestamps.erase(peer_id);
    }
}

/**
 * NET-013 FIX: Periodic cleanup of stale rate limit entries
 * Call this periodically (e.g., every 60 seconds) to prevent memory growth
 */
void PeriodicRateLimitCleanup() {
    int64_t now = GetTime();

    {
        std::lock_guard<std::mutex> lock(cs_getdata_rate);
        // Remove entries with no recent activity (older than 60 seconds)
        for (auto it = g_peer_getdata_timestamps.begin(); it != g_peer_getdata_timestamps.end(); ) {
            // Remove timestamps older than 60 seconds
            auto& timestamps = it->second;
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now](int64_t ts) { return now - ts > 60; }),
                timestamps.end());

            // If no timestamps left, remove the entry entirely
            if (timestamps.empty()) {
                it = g_peer_getdata_timestamps.erase(it);
            } else {
                ++it;
            }
        }

        // If map is still too large, remove oldest entries (LRU eviction)
        while (g_peer_getdata_timestamps.size() > MAX_RATE_LIMIT_MAP_SIZE) {
            g_peer_getdata_timestamps.erase(g_peer_getdata_timestamps.begin());
        }
    }

    {
        std::lock_guard<std::mutex> lock(cs_headers_rate);
        for (auto it = g_peer_headers_timestamps.begin(); it != g_peer_headers_timestamps.end(); ) {
            auto& timestamps = it->second;
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now](int64_t ts) { return now - ts > 60; }),
                timestamps.end());

            if (timestamps.empty()) {
                it = g_peer_headers_timestamps.erase(it);
            } else {
                ++it;
            }
        }

        while (g_peer_headers_timestamps.size() > MAX_RATE_LIMIT_MAP_SIZE) {
            g_peer_headers_timestamps.erase(g_peer_headers_timestamps.begin());
        }
    }

    {
        std::lock_guard<std::mutex> lock(cs_connection_cooldown);
        // Clean up old connection cooldown entries (older than 5 minutes)
        for (auto it = g_last_connection_attempt.begin(); it != g_last_connection_attempt.end(); ) {
            if (now - it->second > 300) {  // 5 minutes
                it = g_last_connection_attempt.erase(it);
            } else {
                ++it;
            }
        }
    }
}

// NET-016 FIX: Error message sanitization notes
// Production deployment should implement proper logging framework with:
// - Log levels (DEBUG, INFO, WARN, ERROR)
// - Sanitized production messages (no peer IDs, internal state in ERROR level)
// - Detailed messages only in DEBUG level
// Current implementation uses std::cout for development convenience
// Replace with spdlog or similar for production

// Global network statistics
CNetworkStats g_network_stats;

// P0-5 FIX: Use std::atomic for global pointers to prevent initialization race conditions
// These pointers may be accessed from multiple threads during startup/shutdown

// Global transaction relay manager (Phase 5.3)
std::atomic<CTxRelayManager*> g_tx_relay_manager{nullptr};

// Global pointers for transaction relay (Phase 5.3)
std::atomic<CTxMemPool*> g_mempool{nullptr};
std::atomic<CTransactionValidator*> g_tx_validator{nullptr};
std::atomic<CUTXOSet*> g_utxo_set{nullptr};
std::atomic<unsigned int> g_chain_height{0};

// Global pointers for P2P networking (NW-005)
// Phase 5: Removed g_connection_manager - use CConnman via NodeContext instead
std::atomic<CNetMessageProcessor*> g_message_processor{nullptr};

// Phase 1.2: Block fetcher now accessed via NodeContext
// REMOVED: g_block_fetcher extern - use NodeContext::block_fetcher instead

std::string CNetworkStats::ToString() const {
    // CID 1675175/1675189/1675204/1675227/1675242/1675243/1675259 FIX: Use std::ostringstream for explicit type-safe conversion
    // This completely eliminates any printf format specifier issues and ensures portability
    // across all platforms where size_t may vary in size (32-bit vs 64-bit)
    // 
    // IMPORTANT: This function does NOT use printf format specifiers. It uses std::ostringstream
    // with stream insertion operators (<<), which are type-safe and do not require format specifiers.
    // There are NO printf, sprintf, snprintf, strprintf, or any other printf-style function calls
    // in this function. All string formatting is done via std::ostringstream stream operators.
    // 
    // Note: std::ostringstream::operator<< has overloads for unsigned long long, which safely
    // handles all size_t values regardless of platform. The explicit cast ensures type safety
    // and eliminates any potential format specifier mismatches that static analysis tools
    // might detect with printf-style formatting.
    std::ostringstream oss;
    oss << "CNetworkStats(peers=" << static_cast<unsigned long long>(connected_peers) 
        << "/" << static_cast<unsigned long long>(total_peers)
        << ", handshake=" << static_cast<unsigned long long>(handshake_complete)
        << ", bytes=" << static_cast<unsigned long long>(bytes_recv) 
        << "/" << static_cast<unsigned long long>(bytes_sent)
        << ", msgs=" << static_cast<unsigned long long>(messages_recv) 
        << "/" << static_cast<unsigned long long>(messages_sent) << ")";
    return oss.str();
}

// CNetMessageProcessor implementation

CNetMessageProcessor::CNetMessageProcessor(CPeerManager& peer_mgr)
    : peer_manager(peer_mgr)
{
    // Default handlers do nothing
    on_version = [](int, const NetProtocol::CVersionMessage&) {};
    on_verack = [](int) {};  // BUG #132 FIX: Initialize on_verack to prevent race condition
    on_ping = [](int, uint64_t) {};
    on_pong = [](int, uint64_t) {};
    on_addr = [](int, const std::vector<NetProtocol::CAddress>&) {};
    on_inv = [](int, const std::vector<NetProtocol::CInv>&) {};
    on_getdata = [](int, const std::vector<NetProtocol::CInv>&) {};
    on_block = [](int, const CBlock&) {};
    on_tx = [](int, const CTransaction&) {};
    on_getheaders = [](int, const NetProtocol::CGetHeadersMessage&) {};
    on_headers = [](int, const std::vector<CBlockHeader>&) {};
}

bool CNetMessageProcessor::ProcessMessage(int peer_id, const CNetMessage& message) {
    if (!message.IsValid()) {
        return false;
    }

    std::string command = message.header.GetCommand();
    uint32_t payload_size = message.header.payload_size;

    // NET-003 FIX: Validate payload size before deserialization
    // Prevents memory waste and cache pollution from oversized payloads
    struct MessageSizeLimit {
        uint32_t min_size;
        uint32_t max_size;
    };

    static const std::map<std::string, MessageSizeLimit> size_limits = {
        {"ping",       {8, 8}},                      // Exactly 8 bytes (uint64_t nonce)
        {"pong",       {8, 8}},                      // Exactly 8 bytes (uint64_t nonce)
        {"verack",     {0, 0}},                      // Empty message
        {"version",    {85, 400}},                   // Min 85 bytes, max ~400 bytes with user agent
        {"getaddr",    {0, 0}},                      // Empty message
        {"addr",       {1, 30000 * 30}},             // Max 30k addresses * 30 bytes each
        {"inv",        {1, 50000 * 36}},             // Max 50k inventory items * 36 bytes each
        {"getdata",    {1, 50000 * 36}},             // Max 50k items * 36 bytes each
        {"block",      {80, 8 * 1024 * 1024}},       // Min 80 bytes header, max 8MB blocks
        {"tx",         {60, 1 * 1024 * 1024}},       // Min 60 bytes, max 1MB transactions
        {"getheaders", {33, 8236}},                  // Min 33 bytes (empty locator + stop hash), max ~8KB
        {"headers",    {1, 2000 * 81 + 9}},           // Max 2000 headers * 81 bytes + 9 byte varint count
        {"getblocks",  {36, 8236}},                  // Similar to getheaders
        {"mempool",    {0, 0}},                      // Empty message
        {"reject",     {1, 1024}},                   // Variable, max 1KB for reject messages
    };

    auto it = size_limits.find(command);
    if (it != size_limits.end()) {
        if (payload_size < it->second.min_size || payload_size > it->second.max_size) {
            ErrorMessage error = CErrorFormatter::NetworkError("process message", 
                "Invalid payload size for '" + std::string(command) + "'");
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
            std::cout << "[P2P] ERROR: Invalid payload size for '" << command
                      << "' from peer " << peer_id << " (got " << payload_size
                      << " bytes, expected " << it->second.min_size << "-" << it->second.max_size << ")"
                      << std::endl;
            peer_manager.Misbehaving(peer_id, 20);
            return false;
        }
    }

    CDataStream stream(message.payload);

    g_network_stats.messages_recv++;
    g_network_stats.bytes_recv += message.GetTotalSize();

    // BUG #132 DEBUG: Log all incoming messages to trace handshake
    std::cout << "[MSG-RECV] peer=" << peer_id << " cmd=" << command << std::endl;

    // Dispatch based on command
    if (command == "version") {
        return ProcessVersionMessage(peer_id, stream);
    } else if (command == "verack") {
        return ProcessVerackMessage(peer_id);
    } else if (command == "ping") {
        return ProcessPingMessage(peer_id, stream);
    } else if (command == "pong") {
        return ProcessPongMessage(peer_id, stream);
    } else if (command == "getaddr") {
        return ProcessGetAddrMessage(peer_id);
    } else if (command == "addr") {
        return ProcessAddrMessage(peer_id, stream);
    } else if (command == "inv") {
        return ProcessInvMessage(peer_id, stream);
    } else if (command == "getdata") {
        return ProcessGetDataMessage(peer_id, stream);
    } else if (command == "block") {
        return ProcessBlockMessage(peer_id, stream);
    } else if (command == "tx") {
        return ProcessTxMessage(peer_id, stream);
    } else if (command == "getheaders") {
        return ProcessGetHeadersMessage(peer_id, stream);
    } else if (command == "headers") {
        return ProcessHeadersMessage(peer_id, stream);
    }

    // Unknown message type
    return true;  // Don't penalize for unknown messages
}

bool CNetMessageProcessor::ProcessVersionMessage(int peer_id, CDataStream& stream) {
    try {
        NetProtocol::CVersionMessage msg;

        // Basic fields
        msg.version = stream.ReadInt32();
        msg.services = stream.ReadUint64();
        msg.timestamp = stream.ReadInt64();

        // addr_recv - receiver's network address (26 bytes)
        msg.addr_recv.services = stream.ReadUint64();
        stream.read(msg.addr_recv.ip, 16);
        msg.addr_recv.port = stream.ReadUint16();

        // addr_from - sender's network address (26 bytes)
        msg.addr_from.services = stream.ReadUint64();
        stream.read(msg.addr_from.ip, 16);
        msg.addr_from.port = stream.ReadUint16();

        // Remaining fields
        msg.nonce = stream.ReadUint64();
        msg.user_agent = stream.ReadString();
        msg.start_height = stream.ReadInt32();
        msg.relay = stream.ReadUint8() != 0;

        // NET-001 FIX: Explicit user agent length validation (defense-in-depth)
        // Note: NET-002 already limits ReadString() to 256 bytes, but we validate explicitly
        if (msg.user_agent.length() > 256) {
            ErrorMessage error = CErrorFormatter::NetworkError("process version message", 
                "User agent too long from peer");
            error.severity = ErrorSeverity::WARNING;
            LogPrintf(ALL, WARN, "%s", CErrorFormatter::FormatForLog(error).c_str());
            std::cout << "[P2P] ERROR: User agent too long from peer " << peer_id
                      << " (" << msg.user_agent.length() << " bytes, max 256)" << std::endl;
            peer_manager.Misbehaving(peer_id, 20);
            return false;
        }

        // Protocol version negotiation (Bitcoin Core pattern)
        // Reject peers with incompatible protocol versions
        if (msg.version < NetProtocol::MIN_PEER_PROTO_VERSION) {
            LogPrintf(NET, WARN, "Peer %d has incompatible protocol version %d (minimum: %d)",
                      peer_id, msg.version, NetProtocol::MIN_PEER_PROTO_VERSION);
            ErrorMessage error = CErrorFormatter::NetworkError("process version message", 
                "Peer has incompatible protocol version");
            error.severity = ErrorSeverity::WARNING;
            LogPrintf(ALL, WARN, "%s", CErrorFormatter::FormatForLog(error).c_str());
            std::cout << "[P2P] ERROR: Peer " << peer_id << " has incompatible protocol version "
                      << msg.version << " (minimum: " << NetProtocol::MIN_PEER_PROTO_VERSION << ")" << std::endl;
            // Use proper misbehavior type for protocol version violation
            peer_manager.Misbehaving(peer_id, 50, MisbehaviorType::INVALID_PROTOCOL_VERSION);
            return false;
        }

        // Feature flags validation (Bitcoin Core pattern)
        // Ensure peer supports basic network functionality
        if ((msg.services & NetProtocol::NODE_NETWORK) == 0) {
            LogPrintf(NET, WARN, "Peer %d does not support NODE_NETWORK service flag", peer_id);
            std::cout << "[P2P] WARNING: Peer " << peer_id << " does not support NODE_NETWORK" << std::endl;
            // Don't reject, but log for monitoring
        }

        // Update peer info - create peer if not exists (BUG #124 FIX)
        // Inbound connections don't go through AddPeer(), so we must create the peer here
        auto peer = peer_manager.GetPeer(peer_id);
        if (!peer) {
            // BUG #124: Inbound connections weren't registered in CPeerManager
            // This caused "no suitable peers" error because GetValidPeersForDownload() returned empty
            // Use AddPeerWithId to ensure the peer ID matches the connection manager's ID
            peer = peer_manager.AddPeerWithId(peer_id);
            if (peer) {
                std::cout << "[PeerManager] Created peer " << peer_id << " for inbound connection" << std::endl;
            }
        }

        if (peer) {
            LogPrintf(NET, INFO, "Received VERSION from peer %d (version=%d, agent=%s, height=%d, services=0x%016llx)",
                      peer_id, msg.version, msg.user_agent.c_str(), msg.start_height, msg.services);

            // Store peer data (but DON'T update state yet - handler needs to check state)
            peer->version = msg.version;
            peer->user_agent = msg.user_agent;
            peer->start_height = msg.start_height;
            peer->relay = msg.relay;
        } else {
            std::cout << "[P2P] WARNING: Could not create peer " << peer_id << " (connection limit reached?)" << std::endl;
        }

        // Call handler BEFORE updating state - handler checks state to decide if
        // we need to send VERSION back to inbound peers
        on_version(peer_id, msg);

        // BUG #148 FIX: Update state AFTER handler has had chance to respond
        // This fixes the bug where inbound peers never got our VERSION because
        // we bumped state before the handler could check it
        if (peer) {
            // SSOT FIX #1: Update CNode::state (single source of truth) first
            CNode* node = peer_manager.GetNode(peer_id);
            if (node && node->state.load() < CNode::STATE_VERSION_SENT) {
                node->state.store(CNode::STATE_VERSION_SENT);
                node->fVersionSent.store(true);
            }
            // Update deprecated CPeer::state for backward compatibility
            if (peer->state < CPeer::STATE_VERSION_SENT) {
                peer->state = CPeer::STATE_VERSION_SENT;
            }
        }

        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        std::cout << "[P2P] ERROR: VERSION message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        std::cout << "[P2P] ERROR: VERSION message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

bool CNetMessageProcessor::ProcessVerackMessage(int peer_id) {
    auto peer = peer_manager.GetPeer(peer_id);
    if (!peer) {
        std::cout << "[P2P] ProcessVerackMessage: peer " << peer_id << " not found" << std::endl;
        return true;
    }

    // BUG #148 FIX: More robust VERACK handling - complete handshake if:
    // 1. We're in VERSION_SENT state (normal case), OR
    // 2. We're in CONNECTED state and have received VERSION (race condition case)
    // This prevents stuck handshakes due to race conditions
    bool should_complete = (peer->state == CPeer::STATE_VERSION_SENT) ||
                           (peer->state == CPeer::STATE_CONNECTED && peer->version > 0);

    if (should_complete && peer->state != CPeer::STATE_HANDSHAKE_COMPLETE) {
        peer->state = CPeer::STATE_HANDSHAKE_COMPLETE;
        g_network_stats.handshake_complete++;

        // FIX Issue 2: Also update CNode::state to keep in sync with CPeer::state
        // CNode is owned by CConnman but tracked in CPeerManager::nodes map
        CNode* node = peer_manager.GetNode(peer_id);
        if (node) {
            node->state.store(CNode::STATE_HANDSHAKE_COMPLETE);
            node->fSuccessfullyConnected.store(true);
            node->nVersion = peer->version;
            node->strSubVer = peer->user_agent;
            node->nStartingHeight = peer->start_height;
            node->fRelay = peer->relay;
        } else {
            // BUG #148 DEBUG: Log when GetNode fails - this causes "no suitable peers"
            // because GetValidPeersForDownload checks CNode::state, not CPeer::state
            std::cout << "[P2P] WARNING: ProcessVerackMessage - GetNode(" << peer_id
                      << ") returned nullptr! CNode state NOT updated to HANDSHAKE_COMPLETE. "
                      << "This peer will be excluded from block downloads." << std::endl;
        }

        // Phase 3.2: Notify CPeerManager for unified peer tracking
        // This initializes block sync state in the CPeer object
        // NOTE: CNodeStateManager removed - CPeerManager is now single source of truth
        peer_manager.OnPeerHandshakeComplete(peer_id, peer->start_height, true);

        // Trigger VERACK handler (for IBD initialization)
        if (on_verack) {
            on_verack(peer_id);
        }

        LogPrintf(NET, INFO, "Handshake complete with peer %d (version=%d, height=%d)",
                  peer_id, peer->version, peer->start_height);
    }
    return true;
}

bool CNetMessageProcessor::ProcessPingMessage(int peer_id, CDataStream& stream) {
    try {
        uint64_t nonce = stream.ReadUint64();
        on_ping(peer_id, nonce);
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        std::cout << "[P2P] ERROR: PING message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        std::cout << "[P2P] ERROR: PING message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

bool CNetMessageProcessor::ProcessPongMessage(int peer_id, CDataStream& stream) {
    try {
        uint64_t nonce = stream.ReadUint64();
        on_pong(peer_id, nonce);
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        std::cout << "[P2P] ERROR: PONG message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        std::cout << "[P2P] ERROR: PONG message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

bool CNetMessageProcessor::ProcessGetAddrMessage(int peer_id) {
    // Peer is requesting addresses - respond with known addresses
    // Bitcoin Core pattern: return up to 1000 addresses (23% of AddrMan, capped)

    std::vector<NetProtocol::CAddress> addrs;

    // Get addresses from connected peers (up to 10)
    auto connected_addrs = peer_manager.GetPeerAddresses(10);
    addrs.insert(addrs.end(), connected_addrs.begin(), connected_addrs.end());

    // Get addresses from AddrMan (up to 990 more to reach 1000 total)
    auto addrman_addrs = peer_manager.SelectAddressesToConnect(990);
    for (const auto& addr : addrman_addrs) {
        if (addr.IsRoutable()) {
            addrs.push_back(addr);
        }
    }

    if (addrs.empty()) {
        std::cout << "[P2P] GETADDR from peer " << peer_id << " - no addresses to share" << std::endl;
        return true;
    }

    // Create and send ADDR message
    CNetMessage addr_msg = CreateAddrMessage(addrs);

    // Phase 5: Use CConnman instead of deprecated CConnectionManager
    extern NodeContext g_node_context;
    if (g_node_context.connman) {
        g_node_context.connman->PushMessage(peer_id, addr_msg);
        std::cout << "[P2P] Sent " << addrs.size() << " addresses to peer "
                  << peer_id << " in response to GETADDR" << std::endl;
    }

    return true;
}

bool CNetMessageProcessor::ProcessAddrMessage(int peer_id, CDataStream& stream) {
    try {
        // NET-007 FIX: Rate limiting for ADDR messages
        // Allow max 1 ADDR message per 10 seconds per peer (addresses change slowly)
        const int64_t MAX_ADDR_PER_WINDOW = 1;
        const int64_t RATE_LIMIT_WINDOW = 10;  // 10 seconds

        int64_t now = GetTime();
        {
            std::lock_guard<std::mutex> lock(cs_addr_rate_limit);
            auto& timestamps = peer_addr_timestamps[peer_id];

            // Remove timestamps older than window
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now, RATE_LIMIT_WINDOW](int64_t ts) { return now - ts > RATE_LIMIT_WINDOW; }),
                timestamps.end());

            // Check if peer exceeds rate limit
            if (timestamps.size() >= static_cast<size_t>(MAX_ADDR_PER_WINDOW)) {
                std::cout << "[P2P] ERROR: Peer " << peer_id << " exceeded ADDR rate limit ("
                          << timestamps.size() << " messages in last " << RATE_LIMIT_WINDOW << " seconds)" << std::endl;
                // NET-011 FIX: Penalize peer for rate limit violation
                peer_manager.Misbehaving(peer_id, 10);
                return false;
            }

            // Record this ADDR message
            timestamps.push_back(now);
        }

        uint64_t count = stream.ReadCompactSize();
        if (count > Consensus::MAX_INV_SIZE) {
            std::cout << "[P2P] ERROR: ADDR message too large from peer " << peer_id
                      << " (count=" << count << ")" << std::endl;
            peer_manager.Misbehaving(peer_id, 20);
            return false;
        }

        std::vector<NetProtocol::CAddress> addrs;
        for (uint64_t i = 0; i < count; i++) {
            NetProtocol::CAddress addr;
            addr.time = stream.ReadUint32();
            addr.services = stream.ReadUint64();
            stream.read(addr.ip, 16);
            addr.port = stream.ReadUint16();

            // NET-015 FIX: Validate IP address before accepting
            if (addr.IsRoutable()) {
                addrs.push_back(addr);
            }
            // Silently drop non-routable addresses (loopback, private, multicast)
        }

        on_addr(peer_id, addrs);
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        std::cout << "[P2P] ERROR: ADDR message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        std::cout << "[P2P] ERROR: ADDR message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

bool CNetMessageProcessor::ProcessInvMessage(int peer_id, CDataStream& stream) {
    try {
        // NET-006 FIX: Rate limiting for INV messages
        // Allow max 10 INV messages per second per peer
        const int64_t MAX_INV_PER_SECOND = 10;
        const int64_t RATE_LIMIT_WINDOW = 1;  // 1 second

        int64_t now = GetTime();
        {
            std::lock_guard<std::mutex> lock(cs_inv_rate_limit);
            auto& timestamps = peer_inv_timestamps[peer_id];

            // Remove timestamps older than 1 second
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now, RATE_LIMIT_WINDOW](int64_t ts) { return now - ts > RATE_LIMIT_WINDOW; }),
                timestamps.end());

            // Check if peer exceeds rate limit
            if (timestamps.size() >= static_cast<size_t>(MAX_INV_PER_SECOND)) {
                std::cout << "[P2P] ERROR: Peer " << peer_id << " exceeded INV rate limit ("
                          << timestamps.size() << " messages in last second)" << std::endl;
                // NET-011 FIX: Penalize peer for rate limit violation
                peer_manager.Misbehaving(peer_id, 10);
                return false;
            }

            // Record this INV message
            timestamps.push_back(now);
        }

        uint64_t count = stream.ReadCompactSize();
        if (count > Consensus::MAX_INV_SIZE) {
            std::cout << "[P2P] ERROR: INV message too large from peer " << peer_id
                      << " (count=" << count << ")" << std::endl;
            // NET-011 FIX: Penalize peer for sending oversized message
            peer_manager.Misbehaving(peer_id, 20);
            return false;
        }

        std::vector<NetProtocol::CInv> inv;
        for (uint64_t i = 0; i < count; i++) {
            NetProtocol::CInv item;
            item.type = stream.ReadUint32();
            item.hash = stream.ReadUint256();
            inv.push_back(item);
        }

        // Phase 5.3: Handle transaction inventory announcements
        std::vector<NetProtocol::CInv> vToFetch;

        // P0-5 FIX: Load atomic pointers once for this block
        auto* tx_relay = g_tx_relay_manager.load();
        auto* mempool = g_mempool.load();

        for (const NetProtocol::CInv& inv_item : inv) {
            // NET-014/NET-018 FIX: Validate inventory type before processing
            // Only MSG_TX_INV(1), MSG_BLOCK_INV(2), MSG_FILTERED_BLOCK(3), MSG_CMPCT_BLOCK(4) are valid
            if (inv_item.type < 1 || inv_item.type > 4) {
                std::cout << "[P2P] WARNING: Invalid INV type " << inv_item.type
                          << " from peer " << peer_id << " - penalizing" << std::endl;
                peer_manager.Misbehaving(peer_id, 10);
                continue;  // Skip invalid items but continue processing valid ones
            }

            if (inv_item.type == NetProtocol::MSG_TX_INV) {
                // Check if we need this transaction
                if (tx_relay && mempool) {
                    if (!tx_relay->AlreadyHave(inv_item.hash, *mempool)) {
                        vToFetch.push_back(inv_item);
                        tx_relay->MarkRequested(inv_item.hash, peer_id);

                        std::cout << "[P2P] Requesting transaction "
                                  << inv_item.hash.GetHex().substr(0, 16)
                                  << "... from peer " << peer_id << std::endl;
                    }
                }
            }
            else if (inv_item.type == NetProtocol::MSG_BLOCK_INV) {
                // DISABLED: Block requests must go through headers-first IBD system
                // The high-level SetInvHandler callback will trigger RequestHeaders(),
                // which feeds blocks through the IBD coordinator with proper tracking.
                // Direct GETDATA for blocks bypasses CBlockFetcher, breaking the
                // chunk-based sliding window download system.
                // vToFetch.push_back(inv_item);  // LEGACY - DO NOT USE
            }
            // MSG_FILTERED_BLOCK(3) and MSG_CMPCT_BLOCK(4) are valid but not processed here
        }

        // Request transactions/blocks we don't have
        if (!vToFetch.empty()) {
            // Create GETDATA message
            CNetMessage getdata_msg = CreateGetDataMessage(vToFetch);

            // BUG #106 FIX: Actually send the GETDATA request to the peer!
            // Phase 5: Use CConnman instead of deprecated CConnectionManager
            extern NodeContext g_node_context;
            if (g_node_context.connman) {
                g_node_context.connman->PushMessage(peer_id, getdata_msg);
                std::cout << "[P2P] Sent GETDATA for " << vToFetch.size()
                          << " item(s) to peer " << peer_id << std::endl;
            } else {
                std::cout << "[P2P] Cannot send GETDATA - connman not initialized" << std::endl;
            }
        }

        // Call handler for any additional processing
        on_inv(peer_id, inv);
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        std::cout << "[P2P] ERROR: INV message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        std::cout << "[P2P] ERROR: INV message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

bool CNetMessageProcessor::ProcessGetDataMessage(int peer_id, CDataStream& stream) {
    try {
        // P2-1 FIX: Rate limiting for GETDATA messages
        // Prevents CPU exhaustion DoS via unlimited GETDATA requests
        {
            std::lock_guard<std::mutex> lock(cs_getdata_rate);
            int64_t now = GetTime();
            auto& timestamps = g_peer_getdata_timestamps[peer_id];

            // Remove timestamps older than 1 second
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now](int64_t ts) { return now - ts > 1; }),
                timestamps.end());

            if (timestamps.size() >= MAX_GETDATA_PER_SECOND) {
                std::cout << "[P2P] RATE LIMIT: Too many GETDATA from peer " << peer_id
                          << " (" << timestamps.size() << "/" << MAX_GETDATA_PER_SECOND << " per second)" << std::endl;
                peer_manager.Misbehaving(peer_id, 2);  // Reduced from 10 - IBD sync is legitimate
                return false;
            }
            timestamps.push_back(now);
        }

        // BUG #87 DEBUG: Log GETDATA processing
        std::cout << "[P2P] Processing GETDATA from peer " << peer_id << std::endl;
        // Read number of inv items
        uint64_t count = stream.ReadCompactSize();

        if (count > NetProtocol::MAX_INV_SIZE) {
            std::cout << "[P2P] ERROR: GETDATA message too large from peer " << peer_id
                      << " (count=" << count << ")" << std::endl;
            return false;
        }

        std::vector<NetProtocol::CInv> getdata;
        getdata.reserve(count);

        // Read each inv item
        for (uint64_t i = 0; i < count; i++) {
            NetProtocol::CInv inv;
            inv.type = stream.ReadUint32();
            inv.hash = stream.ReadUint256();

            // NET-020 FIX: Validate inventory type before adding
            if (inv.type < 1 || inv.type > 4) {
                std::cout << "[P2P] WARNING: Invalid GETDATA type " << inv.type
                          << " from peer " << peer_id << " - penalizing" << std::endl;
                peer_manager.Misbehaving(peer_id, 10);
                continue;  // Skip invalid items
            }
            getdata.push_back(inv);
        }

        // Phase 5.3: Handle transaction data requests
        // P0-5 FIX: Load atomic pointer for mempool
        auto* mempool_ptr = g_mempool.load();
        for (const NetProtocol::CInv& inv : getdata) {
            if (inv.type == NetProtocol::MSG_TX_INV) {
                // Try to get transaction from mempool
                if (mempool_ptr) {
                    // Create dummy transaction for mempool lookup
                    CTransactionRef tx_ref = MakeTransactionRef();
                    CTxMemPoolEntry entry(tx_ref, 0, 0, 0);

                    if (mempool_ptr->GetTx(inv.hash, entry)) {
                        CTransactionRef tx = entry.GetSharedTx();

                        // Create TX message
                        CNetMessage tx_msg = CreateTxMessage(*tx);

                        // BUG #106 FIX: Actually send the transaction to the requesting peer!
                        // Phase 5: Use CConnman instead of deprecated CConnectionManager
                        extern NodeContext g_node_context;
                        if (g_node_context.connman) {
                            g_node_context.connman->PushMessage(peer_id, tx_msg);
                            std::cout << "[P2P] Sent transaction "
                                      << inv.hash.GetHex().substr(0, 16)
                                      << "... to peer " << peer_id << std::endl;
                        } else {
                            std::cout << "[P2P] Cannot send transaction - connman not initialized" << std::endl;
                        }
                    } else {
                        std::cout << "[P2P] Transaction "
                                  << inv.hash.GetHex().substr(0, 16)
                                  << "... not found in mempool for peer " << peer_id << std::endl;
                        // Could send "notfound" message here
                    }
                }
            }
            else if (inv.type == NetProtocol::MSG_BLOCK_INV) {
                // Existing block handling (keep as-is)
                // Block serving logic would go here
            }
        }

        // Call handler to serve requested data
        std::cout << "[P2P] Invoking GETDATA handler for " << getdata.size() << " items from peer " << peer_id << std::endl;
        on_getdata(peer_id, getdata);
        return true;

    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        std::cout << "[P2P] ERROR: GETDATA message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        std::cout << "[P2P] ERROR: GETDATA message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

bool CNetMessageProcessor::ProcessBlockMessage(int peer_id, CDataStream& stream) {
    try {
        CBlock block;
        // Deserialize block header
        block.nVersion = stream.ReadInt32();
        block.hashPrevBlock = stream.ReadUint256();
        block.hashMerkleRoot = stream.ReadUint256();
        block.nTime = stream.ReadUint32();
        block.nBits = stream.ReadUint32();
        block.nNonce = stream.ReadUint32();

        // Deserialize transaction data
        uint64_t vtx_size = stream.ReadCompactSize();

        // NET-003 FIX: Validate size before resize to prevent integer overflow
        if (vtx_size > MAX_BLOCK_TRANSACTIONS) {
            // NET-011 FIX: Penalize peer for sending invalid block
            peer_manager.Misbehaving(peer_id, 100);  // Severe penalty - likely attack
            throw std::runtime_error("Block transaction count exceeds limit");
        }

        block.vtx.resize(vtx_size);
        if (vtx_size > 0) {
            stream.read(block.vtx.data(), vtx_size);
        }

        std::cout << "[BLOCK-PROCESS] Deserialized block, calling on_block handler..." << std::endl;
        std::cout.flush();
        on_block(peer_id, block);
        std::cout << "[BLOCK-PROCESS] on_block handler returned" << std::endl;
        std::cout.flush();
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        std::cout << "[P2P] ERROR: BLOCK message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        std::cout << "[P2P] ERROR: BLOCK message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

bool CNetMessageProcessor::ProcessTxMessage(int peer_id, CDataStream& stream) {
    try {
        // Deserialize transaction
        CTransaction tx;
        tx.nVersion = stream.ReadInt32();

        // Read inputs
        uint64_t vin_size = stream.ReadCompactSize();

        // NET-003 FIX: Validate size before resize to prevent integer overflow
        if (vin_size > MAX_TX_INPUTS) {
            // NET-011 FIX: Penalize peer for sending invalid transaction
            peer_manager.Misbehaving(peer_id, 100);  // Severe penalty - likely attack
            throw std::runtime_error("Transaction input count exceeds limit");
        }

        tx.vin.resize(vin_size);
        for (uint64_t i = 0; i < vin_size; i++) {
            tx.vin[i].prevout.hash = stream.ReadUint256();
            tx.vin[i].prevout.n = stream.ReadUint32();

            uint64_t script_size = stream.ReadCompactSize();

            // NET-003 FIX: Validate script size before resize
            if (script_size > MAX_SCRIPT_SIZE) {
                throw std::runtime_error("Script size exceeds limit");
            }

            tx.vin[i].scriptSig.resize(script_size);
            if (script_size > 0) {
                stream.read(tx.vin[i].scriptSig.data(), script_size);
            }

            tx.vin[i].nSequence = stream.ReadUint32();
        }

        // Read outputs
        uint64_t vout_size = stream.ReadCompactSize();

        // NET-003 FIX: Validate size before resize to prevent integer overflow
        if (vout_size > MAX_TX_OUTPUTS) {
            throw std::runtime_error("Transaction output count exceeds limit");
        }

        tx.vout.resize(vout_size);
        for (uint64_t i = 0; i < vout_size; i++) {
            tx.vout[i].nValue = stream.ReadUint64();

            uint64_t script_size = stream.ReadCompactSize();

            // NET-003 FIX: Validate script size before resize
            if (script_size > MAX_SCRIPT_SIZE) {
                throw std::runtime_error("Script size exceeds limit");
            }

            tx.vout[i].scriptPubKey.resize(script_size);
            if (script_size > 0) {
                stream.read(tx.vout[i].scriptPubKey.data(), script_size);
            }
        }

        // Read locktime
        tx.nLockTime = stream.ReadUint32();

        // Get transaction hash
        const uint256 txid = tx.GetHash();

        std::cout << "[P2P] Received transaction " << txid.GetHex().substr(0, 16)
                  << "... from peer " << peer_id << std::endl;

        // P0-5 FIX: Load atomic pointers for transaction processing
        auto* tx_relay = g_tx_relay_manager.load();
        auto* mempool = g_mempool.load();
        auto* tx_validator = g_tx_validator.load();
        auto* utxo_set = g_utxo_set.load();
        unsigned int chain_height = g_chain_height.load();

        // Phase 5.3: Transaction relay processing
        if (tx_relay) {
            // Remove from in-flight
            tx_relay->RemoveInFlight(txid);
        }

        // Check if we already have it
        if (mempool && mempool->Exists(txid)) {
            std::cout << "[P2P] Transaction " << txid.GetHex().substr(0, 16)
                      << "... already in mempool" << std::endl;
            on_tx(peer_id, tx);
            return true;
        }

        // Validate transaction
        if (tx_validator && utxo_set && mempool) {
            std::string error;
            CAmount fee = 0;

            if (!tx_validator->CheckTransaction(tx, *utxo_set, chain_height, fee, error)) {
                std::cout << "[P2P] Invalid transaction " << txid.GetHex().substr(0, 16)
                          << "... from peer " << peer_id << ": " << error << std::endl;
                // DoS hardening: Penalize peer for sending invalid transactions
                // Distinguish between different failure types for appropriate penalties
                bool is_severe = (error.find("double-spend") != std::string::npos ||
                                  error.find("invalid signature") != std::string::npos ||
                                  error.find("malformed") != std::string::npos);
                int penalty = is_severe ? 50 : 10;  // Severe violations get higher penalty
                peer_manager.Misbehaving(peer_id, penalty);
                return false;
            }

            // Add to mempool
            std::string mempool_error;
            int64_t current_time = GetTime();
            CTransactionRef tx_ref = MakeTransactionRef(std::move(tx));

            if (!mempool->AddTx(tx_ref, fee, current_time, chain_height, &mempool_error)) {
                std::cout << "[P2P] Failed to add tx " << txid.GetHex().substr(0, 16)
                          << "... to mempool: " << mempool_error << std::endl;
                return true;  // Not necessarily peer's fault
            }

            std::cout << "[P2P] Accepted transaction " << txid.GetHex().substr(0, 16)
                      << "... from peer " << peer_id << " (fee: " << fee << " ions)" << std::endl;

            // Relay to other peers
            AnnounceTransactionToPeers(txid, peer_id);

            // Call handler
            on_tx(peer_id, *tx_ref);
            return true;
        }

        // If global pointers not set, just call handler
        on_tx(peer_id, tx);
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        std::cout << "[P2P] ERROR: TX message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        std::cout << "[P2P] ERROR: TX message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

bool CNetMessageProcessor::ProcessGetHeadersMessage(int peer_id, CDataStream& stream) {
    try {
        NetProtocol::CGetHeadersMessage msg;

        // Read locator size
        uint64_t locator_size = stream.ReadCompactSize();

        // Validate locator size (max 32 hashes in locator)
        if (locator_size > 32) {
            std::cout << "[P2P] ERROR: GETHEADERS locator size too large: " << locator_size << std::endl;
            peer_manager.Misbehaving(peer_id, 20);
            return false;
        }

        // Read locator hashes
        msg.locator.resize(locator_size);
        for (uint64_t i = 0; i < locator_size; i++) {
            msg.locator[i] = stream.ReadUint256();
        }

        // BUG #149 FIX: Removed overly strict locator validation
        // Bitcoin Core doesn't reject GETHEADERS for unknown locator hashes - it simply
        // iterates through them to find the first common block. The handler will skip
        // unknown hashes and find the first one we know about. This allows peers that
        // are ahead of us (with more headers) to still request more headers from us.
        // The on_getheaders handler in dilithion-node.cpp correctly handles unknown hashes.

        // Read stop hash
        msg.hashStop = stream.ReadUint256();

        std::cout << "[P2P] Received GETHEADERS from peer " << peer_id
                  << " (locator size: " << locator_size << ")" << std::endl;

        // Call handler
        if (on_getheaders) {
            on_getheaders(peer_id, msg);
        }

        return true;
    } catch (const std::out_of_range& e) {
        std::cout << "[P2P] ERROR: GETHEADERS message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        std::cout << "[P2P] ERROR: GETHEADERS message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

bool CNetMessageProcessor::ProcessHeadersMessage(int peer_id, CDataStream& stream) {
    try {
        // P3-N2 FIX: Rate limiting for HEADERS messages
        // Prevents DoS via rapid HEADERS flooding (each can have 2000 headers)
        {
            std::lock_guard<std::mutex> lock(cs_headers_rate);
            int64_t now = GetTime();
            auto& timestamps = g_peer_headers_timestamps[peer_id];

            // Remove timestamps older than 1 second
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now](int64_t ts) { return now - ts > 1; }),
                timestamps.end());

            if (timestamps.size() >= MAX_HEADERS_PER_SECOND) {
                std::cout << "[P2P] RATE LIMIT: Too many HEADERS from peer " << peer_id
                          << " (" << timestamps.size() << "/" << MAX_HEADERS_PER_SECOND << " per second)" << std::endl;
                peer_manager.Misbehaving(peer_id, 10);
                return false;
            }
            timestamps.push_back(now);
        }

        // Read header count
        uint64_t header_count = stream.ReadCompactSize();

        // Validate count (Bitcoin Core max is 2000, wired via Consensus::MAX_HEADERS_RESULTS)
        if (header_count > Consensus::MAX_HEADERS_RESULTS) {
            std::cout << "[P2P] ERROR: HEADERS count too large: " << header_count << std::endl;
            peer_manager.Misbehaving(peer_id, 20);
            return false;
        }

        std::vector<CBlockHeader> headers;
        headers.reserve(header_count);

        // Read each header
        for (uint64_t i = 0; i < header_count; i++) {
            CBlockHeader header;
            header.nVersion = stream.ReadInt32();
            header.hashPrevBlock = stream.ReadUint256();
            header.hashMerkleRoot = stream.ReadUint256();
            header.nTime = stream.ReadUint32();
            header.nBits = stream.ReadUint32();
            header.nNonce = stream.ReadUint32();

            // Skip transaction count (headers message has 0 txs per header)
            uint64_t tx_count = stream.ReadCompactSize();
            if (tx_count != 0) {
                std::cout << "[P2P] ERROR: HEADERS message with tx_count != 0" << std::endl;
                peer_manager.Misbehaving(peer_id, 20);
                return false;
            }

            headers.push_back(header);
        }

        std::cout << "[P2P] Received " << header_count << " headers from peer " << peer_id << std::endl;

        // Call handler
        if (on_headers) {
            on_headers(peer_id, headers);
        }

        return true;
    } catch (const std::out_of_range& e) {
        std::cout << "[P2P] ERROR: HEADERS message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        std::cout << "[P2P] ERROR: HEADERS message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

// Create messages

CNetMessage CNetMessageProcessor::CreateVersionMessage(const NetProtocol::CAddress& addr_recv, const NetProtocol::CAddress& addr_from) {
    // BUG #50 FIX: Get actual blockchain height for VERSION message
    // This allows remote peers to determine if they need to sync from us
    extern CChainState g_chainstate;
    int32_t blockchain_height = g_chainstate.GetHeight();

    // Initialize message with actual blockchain height (Bitcoin Core pattern)
    NetProtocol::CVersionMessage msg(blockchain_height);

    // Populate address fields (Bitcoin Core standard)
    msg.addr_recv = addr_recv;  // Peer's address (where we're sending to)
    msg.addr_from = addr_from;  // Our address (what we believe our external IP to be)

    // Advertise our service flags (Bitcoin Core pattern)
    msg.services = NetFeatures::GetOurServices();

    // Generate random nonce to prevent self-connections (Bitcoin Core standard)
    // Use time + random for uniqueness
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    msg.nonce = gen();

    std::vector<uint8_t> payload = SerializeVersionMessage(msg);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("version", payload);
}

CNetMessage CNetMessageProcessor::CreateVerackMessage() {
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24;

    return CNetMessage("verack", {});
}

CNetMessage CNetMessageProcessor::CreatePingMessage(uint64_t nonce) {
    std::vector<uint8_t> payload = SerializePingPong(nonce);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("ping", payload);
}

CNetMessage CNetMessageProcessor::CreatePongMessage(uint64_t nonce) {
    std::vector<uint8_t> payload = SerializePingPong(nonce);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("pong", payload);
}

CNetMessage CNetMessageProcessor::CreateGetAddrMessage() {
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24;

    return CNetMessage("getaddr", {});
}

CNetMessage CNetMessageProcessor::CreateAddrMessage(
    const std::vector<NetProtocol::CAddress>& addrs)
{
    std::vector<uint8_t> payload = SerializeAddrMessage(addrs);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("addr", payload);
}

CNetMessage CNetMessageProcessor::CreateInvMessage(
    const std::vector<NetProtocol::CInv>& inv)
{
    std::vector<uint8_t> payload = SerializeInvMessage(inv);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("inv", payload);
}

CNetMessage CNetMessageProcessor::CreateGetDataMessage(
    const std::vector<NetProtocol::CInv>& inv)
{
    std::vector<uint8_t> payload = SerializeInvMessage(inv);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("getdata", payload);
}

CNetMessage CNetMessageProcessor::CreateBlockMessage(const CBlock& block) {
    CDataStream stream;

    stream.WriteInt32(block.nVersion);
    stream.WriteUint256(block.hashPrevBlock);
    stream.WriteUint256(block.hashMerkleRoot);
    stream.WriteUint32(block.nTime);
    stream.WriteUint32(block.nBits);
    stream.WriteUint32(block.nNonce);

    // Serialize transaction data
    stream.WriteCompactSize(block.vtx.size());
    if (!block.vtx.empty()) {
        stream.write(block.vtx.data(), block.vtx.size());
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("block", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateTxMessage(const CTransaction& tx) {
    CDataStream stream;

    // Serialize version
    stream.WriteInt32(tx.nVersion);

    // Serialize inputs
    stream.WriteCompactSize(tx.vin.size());
    for (const CTxIn& txin : tx.vin) {
        stream.WriteUint256(txin.prevout.hash);
        stream.WriteUint32(txin.prevout.n);

        stream.WriteCompactSize(txin.scriptSig.size());
        if (!txin.scriptSig.empty()) {
            stream.write(txin.scriptSig.data(), txin.scriptSig.size());
        }

        stream.WriteUint32(txin.nSequence);
    }

    // Serialize outputs
    stream.WriteCompactSize(tx.vout.size());
    for (const CTxOut& txout : tx.vout) {
        stream.WriteUint64(txout.nValue);

        stream.WriteCompactSize(txout.scriptPubKey.size());
        if (!txout.scriptPubKey.empty()) {
            stream.write(txout.scriptPubKey.data(), txout.scriptPubKey.size());
        }
    }

    // Serialize locktime
    stream.WriteUint32(tx.nLockTime);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("tx", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateGetHeadersMessage(const NetProtocol::CGetHeadersMessage& msg) {
    CDataStream stream;

    // Serialize locator size and hashes
    stream.WriteCompactSize(msg.locator.size());
    for (const uint256& hash : msg.locator) {
        stream.WriteUint256(hash);
    }

    // Serialize stop hash
    stream.WriteUint256(msg.hashStop);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("getheaders", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateHeadersMessage(const std::vector<CBlockHeader>& headers) {
    CDataStream stream;

    // Serialize header count
    stream.WriteCompactSize(headers.size());

    // Serialize each header
    for (const CBlockHeader& header : headers) {
        stream.WriteInt32(header.nVersion);
        stream.WriteUint256(header.hashPrevBlock);
        stream.WriteUint256(header.hashMerkleRoot);
        stream.WriteUint32(header.nTime);
        stream.WriteUint32(header.nBits);
        stream.WriteUint32(header.nNonce);

        // Transaction count (always 0 for headers message)
        stream.WriteCompactSize(0);
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("headers", stream.GetData());
}

// Serialization helpers

std::vector<uint8_t> CNetMessageProcessor::SerializeVersionMessage(
    const NetProtocol::CVersionMessage& msg)
{
    CDataStream stream;

    // Basic fields
    stream.WriteInt32(msg.version);
    stream.WriteUint64(msg.services);
    stream.WriteInt64(msg.timestamp);

    // addr_recv - receiver's network address (26 bytes)
    // Note: CAddress has time field, but version message format doesn't include it
    stream.WriteUint64(msg.addr_recv.services);
    stream.write(msg.addr_recv.ip, 16);
    stream.WriteUint16(msg.addr_recv.port);

    // addr_from - sender's network address (26 bytes)
    stream.WriteUint64(msg.addr_from.services);
    stream.write(msg.addr_from.ip, 16);
    stream.WriteUint16(msg.addr_from.port);

    // Remaining fields
    stream.WriteUint64(msg.nonce);
    stream.WriteString(msg.user_agent);
    stream.WriteInt32(msg.start_height);
    stream.WriteUint8(msg.relay ? 1 : 0);

    return stream.GetData();
}

std::vector<uint8_t> CNetMessageProcessor::SerializePingPong(uint64_t nonce) {
    CDataStream stream;
    stream.WriteUint64(nonce);
    return stream.GetData();
}

std::vector<uint8_t> CNetMessageProcessor::SerializeAddrMessage(
    const std::vector<NetProtocol::CAddress>& addrs)
{
    CDataStream stream;
    stream.WriteCompactSize(addrs.size());
    for (const auto& addr : addrs) {
        stream.WriteUint32(addr.time);
        stream.WriteUint64(addr.services);
        stream.write(addr.ip, 16);
        stream.WriteUint16(addr.port);
    }
    return stream.GetData();
}

std::vector<uint8_t> CNetMessageProcessor::SerializeInvMessage(
    const std::vector<NetProtocol::CInv>& inv)
{
    CDataStream stream;
    stream.WriteCompactSize(inv.size());
    for (const auto& item : inv) {
        stream.WriteUint32(item.type);
        stream.WriteUint256(item.hash);
    }
    return stream.GetData();
}

// REMOVED: CConnectionManager implementation - replaced by CConnman
// All methods removed - see CConnman class for equivalent functionality


// ============================================================================
// Phase 5.3: Transaction Relay Functions
// ============================================================================

/**
 * AnnounceTransactionToPeers
 *
 * Announce a transaction to all connected peers via INV message.
 * This is called when:
 * 1. Wallet sends a new transaction
 * 2. Node receives and validates a transaction from a peer (relay)
 *
 * @param txid Transaction hash to announce
 * @param exclude_peer Peer ID to exclude (e.g., originating peer), -1 for none
 */
void AnnounceTransactionToPeers(const uint256& txid, int64_t exclude_peer) {
    // Check if networking infrastructure is initialized
    // Phase 1.2: Use NodeContext for peer manager
    // P0-5 FIX: Load atomic pointer
    auto* tx_relay = g_tx_relay_manager.load();
    extern NodeContext g_node_context;
    // Phase 5: Use CConnman instead of deprecated CConnectionManager
    if (!g_node_context.peer_manager || !g_node_context.connman || !g_node_context.message_processor || !tx_relay) {
        std::cout << "[TX-RELAY] Cannot announce transaction " << txid.GetHex().substr(0, 16)
                  << "... (networking not initialized)" << std::endl;
        return;
    }

    // Get list of connected peers
    std::vector<std::shared_ptr<CPeer>> peers = g_node_context.peer_manager->GetConnectedPeers();

    if (peers.empty()) {
        std::cout << "[TX-RELAY] No connected peers to announce transaction "
                  << txid.GetHex().substr(0, 16) << "..." << std::endl;
        return;
    }

    int announced_count = 0;
    int skipped_count = 0;

    // Announce to each peer
    for (const auto& peer : peers) {
        // Skip excluded peer
        if (peer->id == exclude_peer) {
            continue;
        }

        // Skip if not handshake complete
        if (!peer->IsHandshakeComplete()) {
            continue;
        }

        // Skip if peer doesn't relay transactions
        if (!peer->relay) {
            continue;
        }

        // Check if we should announce to this peer
        if (!tx_relay->ShouldAnnounce(peer->id, txid)) {
            skipped_count++;
            continue;
        }

        // Create INV message
        std::vector<NetProtocol::CInv> inv_vec;
        inv_vec.push_back(NetProtocol::CInv(NetProtocol::MSG_TX_INV, txid));

        CNetMessage inv_message = g_node_context.message_processor->CreateInvMessage(inv_vec);

        // Send INV message to peer
        // Phase 5: Use CConnman instead of deprecated CConnectionManager
        // PushMessage always succeeds (queues message), so we can mark as announced
        g_node_context.connman->PushMessage(peer->id, inv_message);
        // Mark as announced to prevent duplicates
        tx_relay->MarkAnnounced(peer->id, txid);
        announced_count++;
    }

    std::cout << "[TX-RELAY] Announced transaction " << txid.GetHex().substr(0, 16)
              << "... to " << announced_count << " peer(s) "
              << "(skipped " << skipped_count << " already announced, "
              << "excluded peer " << exclude_peer << ")" << std::endl;
}
