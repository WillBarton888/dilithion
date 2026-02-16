// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/net.h>
#include <set>
#include <util/error_format.h>  // UX: Better error messages
#include <net/connection_quality.h>  // Network: Connection quality metrics
#include <net/partition_detector.h>  // Network: Partition detection
#include <consensus/params.h>
#include <consensus/chain.h>  // For CChainState
#include <net/tx_relay.h>
#include <net/banman.h>  // For MisbehaviorType
#include <net/features.h>  // Feature flags system
#include <core/node_context.h>  // Phase 1.2: NodeContext for global state
#include <net/connman.h>  // Phase 5: For CConnman::PushMessage
#include <net/node.h>     // For CNode (genesis mismatch IP tracking)
#include <net/headers_manager.h>  // For CHeadersManager (IBD check)
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
// BUG #178 FIX: Increased from 3 to 10 per second
// During IBD/sync, peers legitimately send many header batches in response to
// GETHEADERS. 3/sec was too aggressive and caused peers to be banned mid-sync.
// 10/sec allows for fast sync while still protecting against DoS floods.
static std::map<int, std::vector<int64_t>> g_peer_headers_timestamps;
static std::mutex cs_headers_rate;
static const size_t MAX_HEADERS_PER_SECOND = 10;

// P2-2 FIX: Per-IP connection cooldown to prevent rapid reconnection DoS
// Prevents attackers from exhausting connection slots via reconnection churn
static std::map<std::string, int64_t> g_last_connection_attempt;
static std::mutex cs_connection_cooldown;
static const int64_t CONNECTION_COOLDOWN_SECONDS = 30;

// Per-connection GETDATA deduplication: track recently-served block hashes per peer
// If a peer re-requests blocks we already served ON THIS CONNECTION, increment misbehavior.
// Legitimate reconnecting peers get a fresh slate (new peer_id = new connection).
static std::map<int, std::set<uint256>> g_peer_served_blocks;
static std::mutex cs_served_blocks;
static const size_t MAX_SERVED_BLOCKS_TRACK = 500;  // Track last N served blocks per peer
static const int DUPLICATE_GETDATA_PENALTY = 2;     // Misbehavior points per duplicate request

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
    {
        std::lock_guard<std::mutex> lock(cs_served_blocks);
        g_peer_served_blocks.erase(peer_id);
    }
}

/**
 * NET-013 FIX: Helper to clean stale entries from a timestamp map
 * CWE-662 FIX: Extracted to separate function to make synchronization explicit for static analysis
 */
static void CleanupTimestampMap(std::map<int, std::vector<int64_t>>& map,
                                 std::mutex& mutex,
                                 int64_t now,
                                 int64_t max_age_seconds) {
    std::lock_guard<std::mutex> lock(mutex);
    for (auto it = map.begin(); it != map.end(); ) {
        auto& timestamps = it->second;
        timestamps.erase(
            std::remove_if(timestamps.begin(), timestamps.end(),
                [now, max_age_seconds](int64_t ts) { return now - ts > max_age_seconds; }),
            timestamps.end());

        if (timestamps.empty()) {
            it = map.erase(it);
        } else {
            ++it;
        }
    }

    // If map is still too large, remove oldest entries (LRU eviction)
    while (map.size() > MAX_RATE_LIMIT_MAP_SIZE) {
        map.erase(map.begin());
    }
}

/**
 * NET-013 FIX: Periodic cleanup of stale rate limit entries
 * Call this periodically (e.g., every 60 seconds) to prevent memory growth
 */
void PeriodicRateLimitCleanup() {
    const int64_t now = GetTime();

    // Clean up GETDATA rate limit entries (stale after 60 seconds)
    CleanupTimestampMap(g_peer_getdata_timestamps, cs_getdata_rate, now, 60);

    // Clean up HEADERS rate limit entries (stale after 60 seconds)
    CleanupTimestampMap(g_peer_headers_timestamps, cs_headers_rate, now, 60);

    // Clean up connection cooldown entries (stale after 5 minutes)
    {
        std::lock_guard<std::mutex> lock(cs_connection_cooldown);
        for (auto it = g_last_connection_attempt.begin(); it != g_last_connection_attempt.end(); ) {
            if (now - it->second > 300) {  // 5 minutes
                it = g_last_connection_attempt.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Clean up served blocks tracking (evict entries for large maps)
    {
        std::lock_guard<std::mutex> lock(cs_served_blocks);
        while (g_peer_served_blocks.size() > MAX_RATE_LIMIT_MAP_SIZE) {
            g_peer_served_blocks.erase(g_peer_served_blocks.begin());
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
    on_sendheaders = [](int) {};  // BIP 130
    // BIP 152: Compact block handlers
    on_sendcmpct = [](int, bool, uint64_t) {};
    on_cmpctblock = [](int, const CBlockHeaderAndShortTxIDs&) {};
    on_getblocktxn = [](int, const BlockTransactionsRequest&) {};
    on_blocktxn = [](int, const BlockTransactions&) {};
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
        {"sendheaders", {0, 0}},                     // BIP 130: Empty message (signal only)
        {"sendcmpct", {9, 9}},                       // BIP 152: bool (1) + uint64_t (8) = 9 bytes
        {"cmpctblock", {88, 8 * 1024 * 1024}},       // BIP 152: Header + short IDs (min 88 bytes header)
        {"getblocktxn", {33, 50000 * 4 + 33}},       // BIP 152: block hash + varint + indices
        {"blocktxn",   {33, 8 * 1024 * 1024}},       // BIP 152: block hash + transactions
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
    } else if (command == "sendheaders") {
        return ProcessSendHeadersMessage(peer_id);  // BIP 130
    } else if (command == "sendcmpct") {
        return ProcessSendCmpctMessage(peer_id, stream);  // BIP 152
    } else if (command == "cmpctblock") {
        return ProcessCmpctBlockMessage(peer_id, stream);  // BIP 152
    } else if (command == "getblocktxn") {
        return ProcessGetBlockTxnMessage(peer_id, stream);  // BIP 152
    } else if (command == "blocktxn") {
        return ProcessBlockTxnMessage(peer_id, stream);  // BIP 152
    } else if (command == "mempool") {
        return ProcessMempoolMessage(peer_id);
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

        // v1.4.2+: Genesis hash validation to prevent cross-chain connections
        // Peers on different genesis chains (e.g., old testnet binary) cause chain sync issues
        uint256 our_genesis = Genesis::GetGenesisHash();
        bool has_genesis_hash = stream.size() >= 32;  // Check if there's more data

        if (has_genesis_hash) {
            stream.read(msg.genesis_hash.data, 32);

            if (msg.genesis_hash != our_genesis) {
                // Peer is on a different blockchain - likely hasn't updated their binary
                // Use IP-based rate limiting to detect and ban probing attacks
                // Get actual connection IP from CNode (not self-reported addr_from which may be 0.0.0.0)
                std::string peer_ip = "0.0.0.0";  // Fallback
                CNode* node = peer_manager.GetNode(peer_id);
                if (node) {
                    peer_ip = node->addr.ToStringIP();
                }
                std::string their_genesis_hex = msg.genesis_hash.GetHex().substr(0, 16);

                // Record failure and check if IP should be banned
                bool should_ban = peer_manager.GetBanManager().RecordGenesisFailure(peer_ip, their_genesis_hex);

                if (should_ban && !peer_manager.IsSeedNode(peer_ip)) {
                    // Ban this IP for 24 hours (repeated genesis probing)
                    // Seed nodes are exempt - genesis mismatch from a seed indicates
                    // a temporary chain fork, not an attack
                    peer_manager.GetBanManager().Ban(peer_ip, CBanManager::DEFAULT_BAN_TIME,
                                                      BanReason::NodeMisbehaving,
                                                      MisbehaviorType::INVALID_GENESIS, 100);

                    std::cout << "[SECURITY] Banned IP " << peer_ip
                              << " for repeated genesis mismatch (probing detected)" << std::endl;
                } else {
                    // First/second failure from this IP - show helpful message
                    LogPrintf(NET, WARN, "Peer %d is on a DIFFERENT BLOCKCHAIN (genesis mismatch)", peer_id);
                    std::cout << "\n[P2P] ================================================" << std::endl;
                    std::cout << "[P2P] CONNECTION REJECTED - DIFFERENT BLOCKCHAIN" << std::endl;
                    std::cout << "[P2P] ================================================" << std::endl;
                    std::cout << "[P2P] Peer " << peer_id << " (" << msg.user_agent << ") from " << peer_ip << std::endl;
                    std::cout << "[P2P] Their genesis: " << their_genesis_hex << "..." << std::endl;
                    std::cout << "[P2P] Our genesis:   " << our_genesis.GetHex().substr(0, 16) << "..." << std::endl;
                    std::cout << "[P2P] " << std::endl;
                    std::cout << "[P2P] HOW TO FIX (for the connecting peer):" << std::endl;
                    std::cout << "[P2P] 1. Download the latest binary: https://github.com/dilithion/dilithion/releases" << std::endl;
                    std::cout << "[P2P] 2. Stop your node" << std::endl;
                    std::cout << "[P2P] 3. Delete your data directory (~/.dilithion or %APPDATA%\\.dilithion)" << std::endl;
                    std::cout << "[P2P] 4. Restart with the new binary" << std::endl;
                    std::cout << "[P2P] ================================================\n" << std::endl;
                }

                return false;
            }
        } else {
            // Old client (pre-v1.4.2) - no genesis hash in VERSION message
            // Allow connection but log warning - they might be on wrong chain
            LogPrintf(NET, WARN, "Peer %d (%s) is running old protocol (no genesis hash)",
                      peer_id, msg.user_agent.c_str());
            std::cout << "[P2P] WARNING: Peer " << peer_id << " (" << msg.user_agent
                      << ") is running old protocol without genesis validation." << std::endl;
            std::cout << "[P2P] Please update to latest version: https://github.com/dilithion/dilithion/releases" << std::endl;
        }

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
                // BUG #125 FIX: Copy actual connection IP from CNode to CPeer
                // AddPeerWithId creates peer without address, causing "no suitable peers"
                // because IBD code can't identify which peer has blocks
                CNode* node = peer_manager.GetNode(peer_id);
                if (node) {
                    peer->addr = node->addr;  // Copy actual TCP connection IP
                }
                std::cout << "[PeerManager] Created peer " << peer_id << " for inbound connection" << std::endl;
            }
        }

        if (peer) {
            LogPrintf(NET, INFO, "Received VERSION from peer %d (version=%d, agent=%s, height=%d, services=0x%016llx)",
                      peer_id, msg.version, msg.user_agent.c_str(), msg.start_height, msg.services);

            // BUG #125 FIX: Ensure peer has valid address (may be null for existing peers)
            if (peer->addr.IsNull()) {
                CNode* node = peer_manager.GetNode(peer_id);
                if (node) {
                    peer->addr = node->addr;
                }
            }

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

        // Per-connection GETDATA deduplication: check for re-requested blocks
        // A legitimate node never re-requests blocks already received on the same connection.
        // Penalize with soft misbehavior scoring (not an instant ban).
        int duplicate_count = 0;
        {
            std::lock_guard<std::mutex> lock(cs_served_blocks);
            auto& served = g_peer_served_blocks[peer_id];
            for (const auto& inv : getdata) {
                if (inv.type == NetProtocol::MSG_BLOCK_INV) {
                    if (served.count(inv.hash)) {
                        ++duplicate_count;
                    }
                }
            }
        }

        if (duplicate_count > 0) {
            int penalty = duplicate_count * DUPLICATE_GETDATA_PENALTY;
            std::cout << "[P2P] DEDUP: Peer " << peer_id << " re-requested "
                      << duplicate_count << " already-served blocks (+"
                      << penalty << " misbehavior)" << std::endl;
            peer_manager.Misbehaving(peer_id, penalty);
        }

        // Call handler to serve requested data (serve even duplicates - don't break sync)
        std::cout << "[P2P] Invoking GETDATA handler for " << getdata.size() << " items from peer " << peer_id << std::endl;
        on_getdata(peer_id, getdata);

        // Record served blocks for future dedup detection
        {
            std::lock_guard<std::mutex> lock(cs_served_blocks);
            auto& served = g_peer_served_blocks[peer_id];
            for (const auto& inv : getdata) {
                if (inv.type == NetProtocol::MSG_BLOCK_INV) {
                    served.insert(inv.hash);
                }
            }
            // Cap tracking set size per peer to prevent memory growth
            if (served.size() > MAX_SERVED_BLOCKS_TRACK) {
                // Evict entries from beginning of set to stay within limit
                auto it = served.begin();
                size_t to_remove = served.size() - MAX_SERVED_BLOCKS_TRACK;
                for (size_t i = 0; i < to_remove; ++i) {
                    it = served.erase(it);
                }
            }
        }

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

        // VDF extension fields (version >= 4)
        if (block.IsVDFBlock()) {
            block.vdfOutput = stream.ReadUint256();
            block.vdfProofHash = stream.ReadUint256();
        }

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
        const uint64_t vin_size_raw = stream.ReadCompactSize();

        // NET-003 FIX: Validate size before resize to prevent integer overflow
        if (vin_size_raw > MAX_TX_INPUTS) {
            // NET-011 FIX: Penalize peer for sending invalid transaction
            peer_manager.Misbehaving(peer_id, 100);  // Severe penalty - likely attack
            throw std::runtime_error("Transaction input count exceeds limit");
        }

        // Create validated const bound for loop (CWE-606 fix: explicit trusted bound)
        const size_t vin_size = static_cast<size_t>(vin_size_raw);
        tx.vin.resize(vin_size);
        for (size_t i = 0; i < vin_size; i++) {
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
        const uint64_t vout_size_raw = stream.ReadCompactSize();

        // NET-003 FIX: Validate size before resize to prevent integer overflow
        if (vout_size_raw > MAX_TX_OUTPUTS) {
            throw std::runtime_error("Transaction output count exceeds limit");
        }

        // Create validated const bound for loop (CWE-606 fix: explicit trusted bound)
        const size_t vout_size = static_cast<size_t>(vout_size_raw);
        tx.vout.resize(vout_size);
        for (size_t i = 0; i < vout_size; i++) {
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

        // If global pointers not set, log warning and drop
        std::cout << "[P2P] WARNING: Cannot validate tx " << txid.GetHex().substr(0, 16)
                  << "... - missing subsystems (validator=" << (tx_validator ? "yes" : "NO")
                  << " utxo=" << (utxo_set ? "yes" : "NO")
                  << " mempool=" << (mempool ? "yes" : "NO") << ")" << std::endl;
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
        // P3-N2 FIX: Rate limiting for HEADERS messages (disabled during IBD)
        // During IBD, we actively request headers and need them rapidly
        // Rate limiting only applies post-IBD to prevent unsolicited flooding
        extern NodeContext g_node_context;
        bool is_ibd = false;
        if (g_node_context.headers_manager) {
            int header_height = g_node_context.headers_manager->GetBestHeight();
            extern CChainState g_chainstate;
            int chain_height = g_chainstate.GetHeight();
            is_ibd = (header_height > chain_height + 10);  // IBD if >10 blocks behind
        }

        if (!is_ibd) {
            std::lock_guard<std::mutex> lock(cs_headers_rate);
            int64_t now = GetTime();
            auto& timestamps = g_peer_headers_timestamps[peer_id];

            // Remove timestamps older than 1 second
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now](int64_t ts) { return now - ts > 1; }),
                timestamps.end());

            if (timestamps.size() >= MAX_HEADERS_PER_SECOND) {
                // Note: We no longer penalize peers for sending many HEADERS.
                // HEADERS are responses to our GETHEADERS requests, so high volume
                // during fork sync is expected and not malicious behavior.
                // We still skip processing to avoid memory pressure, but don't ban.
                std::cout << "[P2P] RATE LIMIT: Skipping HEADERS from peer " << peer_id
                          << " (" << timestamps.size() << "/" << MAX_HEADERS_PER_SECOND << " per second)" << std::endl;
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

            // VDF extension fields (version >= 4)
            if (header.IsVDFBlock()) {
                header.vdfOutput = stream.ReadUint256();
                header.vdfProofHash = stream.ReadUint256();
            }

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

// BIP 130: sendheaders message
bool CNetMessageProcessor::ProcessSendHeadersMessage(int peer_id) {
    // sendheaders is a signal message with no payload
    // When received, the peer is requesting that we send HEADERS instead of INV
    // for new block announcements

    std::cout << "[P2P] Peer " << peer_id << " sent sendheaders (prefers HEADERS over INV)" << std::endl;

    // Call handler to update peer preference
    if (on_sendheaders) {
        on_sendheaders(peer_id);
    }

    return true;
}

// BIP 152: sendcmpct message
bool CNetMessageProcessor::ProcessSendCmpctMessage(int peer_id, CDataStream& stream) {
    try {
        // sendcmpct payload: bool high_bandwidth + uint64_t version
        uint8_t high_bandwidth_byte = stream.ReadUint8();
        bool high_bandwidth = (high_bandwidth_byte != 0);
        uint64_t version = stream.ReadUint64();

        // BIP 152 only supports version 1 (version 2 is for segwit, not applicable to Dilithion)
        if (version != 1) {
            std::cout << "[P2P] Peer " << peer_id << " sent sendcmpct with unsupported version "
                      << version << " (expected 1)" << std::endl;
            return true;  // Ignore but don't disconnect
        }

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[BIP152] Peer " << peer_id << " sent sendcmpct (high_bandwidth="
                      << (high_bandwidth ? "true" : "false") << ", version=" << version << ")" << std::endl;

        // Call handler to update peer preference
        if (on_sendcmpct) {
            on_sendcmpct(peer_id, high_bandwidth, version);
        }

        return true;
    } catch (const std::out_of_range& e) {
        std::cout << "[P2P] ERROR: SENDCMPCT message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        std::cout << "[P2P] ERROR: SENDCMPCT message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

// BIP 152: cmpctblock message
bool CNetMessageProcessor::ProcessCmpctBlockMessage(int peer_id, CDataStream& stream) {
    try {
        CBlockHeaderAndShortTxIDs cmpctblock;

        // Deserialize header
        cmpctblock.header.nVersion = stream.ReadInt32();
        cmpctblock.header.hashPrevBlock = stream.ReadUint256();
        cmpctblock.header.hashMerkleRoot = stream.ReadUint256();
        cmpctblock.header.nTime = stream.ReadUint32();
        cmpctblock.header.nBits = stream.ReadUint32();
        cmpctblock.header.nNonce = stream.ReadUint32();

        // VDF extension fields (version >= 4)
        if (cmpctblock.header.IsVDFBlock()) {
            cmpctblock.header.vdfOutput = stream.ReadUint256();
            cmpctblock.header.vdfProofHash = stream.ReadUint256();
        }

        // Nonce for short ID calculation
        cmpctblock.nonce = stream.ReadUint64();
        // Note: Short ID keys are lazily initialized by GetShortID() when needed

        // Read prefilled transactions
        uint64_t prefilled_count = stream.ReadCompactSize();
        if (prefilled_count > 10000) {  // Sanity limit
            std::cout << "[P2P] ERROR: CMPCTBLOCK with too many prefilled txs from peer "
                      << peer_id << std::endl;
            peer_manager.Misbehaving(peer_id, 100);
            return false;
        }

        cmpctblock.prefilledtxn.reserve(prefilled_count);
        for (uint64_t i = 0; i < prefilled_count; i++) {
            PrefilledTransaction ptx;
            ptx.index = static_cast<uint16_t>(stream.ReadCompactSize());

            // Deserialize transaction
            ptx.tx.nVersion = stream.ReadInt32();

            // Read inputs
            uint64_t vin_size = stream.ReadCompactSize();
            if (vin_size > 10000) {
                throw std::runtime_error("Too many tx inputs");
            }
            ptx.tx.vin.resize(vin_size);
            for (uint64_t j = 0; j < vin_size; j++) {
                ptx.tx.vin[j].prevout.hash = stream.ReadUint256();
                ptx.tx.vin[j].prevout.n = stream.ReadUint32();
                uint64_t script_size = stream.ReadCompactSize();
                if (script_size > 10000) throw std::runtime_error("Script too large");
                ptx.tx.vin[j].scriptSig.resize(script_size);
                if (script_size > 0) {
                    stream.read(ptx.tx.vin[j].scriptSig.data(), script_size);
                }
                ptx.tx.vin[j].nSequence = stream.ReadUint32();
            }

            // Read outputs
            uint64_t vout_size = stream.ReadCompactSize();
            if (vout_size > 10000) {
                throw std::runtime_error("Too many tx outputs");
            }
            ptx.tx.vout.resize(vout_size);
            for (uint64_t j = 0; j < vout_size; j++) {
                ptx.tx.vout[j].nValue = stream.ReadUint64();
                uint64_t script_size = stream.ReadCompactSize();
                if (script_size > 10000) throw std::runtime_error("Script too large");
                ptx.tx.vout[j].scriptPubKey.resize(script_size);
                if (script_size > 0) {
                    stream.read(ptx.tx.vout[j].scriptPubKey.data(), script_size);
                }
            }

            ptx.tx.nLockTime = stream.ReadUint32();
            cmpctblock.prefilledtxn.push_back(std::move(ptx));
        }

        // Read short IDs (6 bytes each)
        uint64_t shortid_count = stream.ReadCompactSize();
        if (shortid_count > 100000) {  // Sanity limit
            std::cout << "[P2P] ERROR: CMPCTBLOCK with too many short IDs from peer "
                      << peer_id << std::endl;
            peer_manager.Misbehaving(peer_id, 100);
            return false;
        }

        cmpctblock.shorttxids.reserve(shortid_count);
        for (uint64_t i = 0; i < shortid_count; i++) {
            // Short IDs are 6 bytes, stored as uint64_t with upper 2 bytes zeroed
            uint8_t shortid_bytes[6];
            stream.read(shortid_bytes, 6);
            uint64_t shortid = 0;
            for (int j = 0; j < 6; j++) {
                shortid |= (static_cast<uint64_t>(shortid_bytes[j]) << (j * 8));
            }
            cmpctblock.shorttxids.push_back(shortid);
        }

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[BIP152] Received CMPCTBLOCK from peer " << peer_id
                      << " (hash=" << cmpctblock.header.GetHash().GetHex().substr(0, 16)
                      << "..., prefilled=" << cmpctblock.prefilledtxn.size()
                      << ", shorttxids=" << cmpctblock.shorttxids.size() << ")" << std::endl;

        // Call handler for block reconstruction
        if (on_cmpctblock) {
            on_cmpctblock(peer_id, cmpctblock);
        }

        return true;
    } catch (const std::out_of_range& e) {
        std::cout << "[P2P] ERROR: CMPCTBLOCK message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        std::cout << "[P2P] ERROR: CMPCTBLOCK message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

// BIP 152: getblocktxn message
bool CNetMessageProcessor::ProcessGetBlockTxnMessage(int peer_id, CDataStream& stream) {
    try {
        BlockTransactionsRequest req;

        // Read block hash
        req.blockhash = stream.ReadUint256();

        // Read requested indices
        uint64_t index_count = stream.ReadCompactSize();
        if (index_count > 50000) {  // Sanity limit
            std::cout << "[P2P] ERROR: GETBLOCKTXN with too many indices from peer "
                      << peer_id << std::endl;
            peer_manager.Misbehaving(peer_id, 100);
            return false;
        }

        req.indexes.reserve(index_count);
        for (uint64_t i = 0; i < index_count; i++) {
            req.indexes.push_back(static_cast<uint16_t>(stream.ReadCompactSize()));
        }

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[BIP152] Received GETBLOCKTXN from peer " << peer_id
                      << " (block=" << req.blockhash.GetHex().substr(0, 16)
                      << "..., " << req.indexes.size() << " txns requested)" << std::endl;

        // Call handler to serve requested transactions
        if (on_getblocktxn) {
            on_getblocktxn(peer_id, req);
        }

        return true;
    } catch (const std::out_of_range& e) {
        std::cout << "[P2P] ERROR: GETBLOCKTXN message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        std::cout << "[P2P] ERROR: GETBLOCKTXN message parsing failed from peer " << peer_id
                  << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10);
        return false;
    }
}

// BIP 152: blocktxn message
bool CNetMessageProcessor::ProcessBlockTxnMessage(int peer_id, CDataStream& stream) {
    try {
        BlockTransactions resp;

        // Read block hash
        resp.blockhash = stream.ReadUint256();

        // Read transactions
        uint64_t tx_count = stream.ReadCompactSize();
        if (tx_count > 100000) {  // Sanity limit
            std::cout << "[P2P] ERROR: BLOCKTXN with too many transactions from peer "
                      << peer_id << std::endl;
            peer_manager.Misbehaving(peer_id, 100);
            return false;
        }

        resp.txn.reserve(tx_count);
        for (uint64_t i = 0; i < tx_count; i++) {
            CTransaction tx;
            tx.nVersion = stream.ReadInt32();

            // Read inputs
            uint64_t vin_size = stream.ReadCompactSize();
            if (vin_size > 10000) {
                throw std::runtime_error("Too many tx inputs");
            }
            tx.vin.resize(vin_size);
            for (uint64_t j = 0; j < vin_size; j++) {
                tx.vin[j].prevout.hash = stream.ReadUint256();
                tx.vin[j].prevout.n = stream.ReadUint32();
                uint64_t script_size = stream.ReadCompactSize();
                if (script_size > 10000) throw std::runtime_error("Script too large");
                tx.vin[j].scriptSig.resize(script_size);
                if (script_size > 0) {
                    stream.read(tx.vin[j].scriptSig.data(), script_size);
                }
                tx.vin[j].nSequence = stream.ReadUint32();
            }

            // Read outputs
            uint64_t vout_size = stream.ReadCompactSize();
            if (vout_size > 10000) {
                throw std::runtime_error("Too many tx outputs");
            }
            tx.vout.resize(vout_size);
            for (uint64_t j = 0; j < vout_size; j++) {
                tx.vout[j].nValue = stream.ReadUint64();
                uint64_t script_size = stream.ReadCompactSize();
                if (script_size > 10000) throw std::runtime_error("Script too large");
                tx.vout[j].scriptPubKey.resize(script_size);
                if (script_size > 0) {
                    stream.read(tx.vout[j].scriptPubKey.data(), script_size);
                }
            }

            tx.nLockTime = stream.ReadUint32();
            resp.txn.push_back(std::move(tx));
        }

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[BIP152] Received BLOCKTXN from peer " << peer_id
                      << " (block=" << resp.blockhash.GetHex().substr(0, 16)
                      << "..., " << resp.txn.size() << " txns)" << std::endl;

        // Call handler to complete block reconstruction
        if (on_blocktxn) {
            on_blocktxn(peer_id, resp);
        }

        return true;
    } catch (const std::out_of_range& e) {
        std::cout << "[P2P] ERROR: BLOCKTXN message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    } catch (const std::exception& e) {
        std::cout << "[P2P] ERROR: BLOCKTXN message parsing failed from peer " << peer_id
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

    // v1.4.2+: Include our genesis hash to prevent cross-chain connections
    msg.genesis_hash = Genesis::GetGenesisHash();

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

    // VDF extension fields (version >= 4)
    if (block.IsVDFBlock()) {
        stream.WriteUint256(block.vdfOutput);
        stream.WriteUint256(block.vdfProofHash);
    }

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

        // VDF extension fields (version >= 4)
        if (header.IsVDFBlock()) {
            stream.WriteUint256(header.vdfOutput);
            stream.WriteUint256(header.vdfProofHash);
        }

        // Transaction count (always 0 for headers message)
        stream.WriteCompactSize(0);
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("headers", stream.GetData());
}

// BIP 130: sendheaders message (empty payload - just a signal)
CNetMessage CNetMessageProcessor::CreateSendHeadersMessage() {
    // sendheaders has no payload - it's just a signal that we prefer HEADERS over INV

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24;  // Just the header, no payload

    return CNetMessage("sendheaders", std::vector<uint8_t>());
}

// BIP 152: sendcmpct message
CNetMessage CNetMessageProcessor::CreateSendCmpctMessage(bool high_bandwidth, uint64_t version) {
    CDataStream stream;

    // Payload: bool (1 byte) + uint64_t version (8 bytes)
    stream.WriteUint8(high_bandwidth ? 1 : 0);
    stream.WriteUint64(version);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("sendcmpct", stream.GetData());
}

// BIP 152: cmpctblock message
CNetMessage CNetMessageProcessor::CreateCmpctBlockMessage(const CBlockHeaderAndShortTxIDs& cmpctblock) {
    CDataStream stream;

    // Serialize header
    stream.WriteInt32(cmpctblock.header.nVersion);
    stream.WriteUint256(cmpctblock.header.hashPrevBlock);
    stream.WriteUint256(cmpctblock.header.hashMerkleRoot);
    stream.WriteUint32(cmpctblock.header.nTime);
    stream.WriteUint32(cmpctblock.header.nBits);
    stream.WriteUint32(cmpctblock.header.nNonce);

    // VDF extension fields (version >= 4)
    if (cmpctblock.header.IsVDFBlock()) {
        stream.WriteUint256(cmpctblock.header.vdfOutput);
        stream.WriteUint256(cmpctblock.header.vdfProofHash);
    }

    // Nonce for short ID calculation
    stream.WriteUint64(cmpctblock.nonce);

    // Prefilled transactions
    stream.WriteCompactSize(cmpctblock.prefilledtxn.size());
    for (const auto& ptx : cmpctblock.prefilledtxn) {
        stream.WriteCompactSize(ptx.index);

        // Serialize transaction
        stream.WriteInt32(ptx.tx.nVersion);

        // Inputs
        stream.WriteCompactSize(ptx.tx.vin.size());
        for (const auto& txin : ptx.tx.vin) {
            stream.WriteUint256(txin.prevout.hash);
            stream.WriteUint32(txin.prevout.n);
            stream.WriteCompactSize(txin.scriptSig.size());
            if (!txin.scriptSig.empty()) {
                stream.write(txin.scriptSig.data(), txin.scriptSig.size());
            }
            stream.WriteUint32(txin.nSequence);
        }

        // Outputs
        stream.WriteCompactSize(ptx.tx.vout.size());
        for (const auto& txout : ptx.tx.vout) {
            stream.WriteUint64(txout.nValue);
            stream.WriteCompactSize(txout.scriptPubKey.size());
            if (!txout.scriptPubKey.empty()) {
                stream.write(txout.scriptPubKey.data(), txout.scriptPubKey.size());
            }
        }

        stream.WriteUint32(ptx.tx.nLockTime);
    }

    // Short IDs (6 bytes each)
    stream.WriteCompactSize(cmpctblock.shorttxids.size());
    for (uint64_t shortid : cmpctblock.shorttxids) {
        // Write lower 6 bytes of the short ID
        for (int i = 0; i < 6; i++) {
            stream.WriteUint8((shortid >> (i * 8)) & 0xFF);
        }
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("cmpctblock", stream.GetData());
}

// BIP 152: getblocktxn message
CNetMessage CNetMessageProcessor::CreateGetBlockTxnMessage(const BlockTransactionsRequest& req) {
    CDataStream stream;

    // Block hash
    stream.WriteUint256(req.blockhash);

    // Indices (field name is 'indexes' per BIP 152)
    stream.WriteCompactSize(req.indexes.size());
    for (uint16_t idx : req.indexes) {
        stream.WriteCompactSize(idx);
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("getblocktxn", stream.GetData());
}

// BIP 152: blocktxn message
CNetMessage CNetMessageProcessor::CreateBlockTxnMessage(const BlockTransactions& resp) {
    CDataStream stream;

    // Block hash
    stream.WriteUint256(resp.blockhash);

    // Transactions
    stream.WriteCompactSize(resp.txn.size());
    for (const auto& tx : resp.txn) {
        stream.WriteInt32(tx.nVersion);

        // Inputs
        stream.WriteCompactSize(tx.vin.size());
        for (const auto& txin : tx.vin) {
            stream.WriteUint256(txin.prevout.hash);
            stream.WriteUint32(txin.prevout.n);
            stream.WriteCompactSize(txin.scriptSig.size());
            if (!txin.scriptSig.empty()) {
                stream.write(txin.scriptSig.data(), txin.scriptSig.size());
            }
            stream.WriteUint32(txin.nSequence);
        }

        // Outputs
        stream.WriteCompactSize(tx.vout.size());
        for (const auto& txout : tx.vout) {
            stream.WriteUint64(txout.nValue);
            stream.WriteCompactSize(txout.scriptPubKey.size());
            if (!txout.scriptPubKey.empty()) {
                stream.write(txout.scriptPubKey.data(), txout.scriptPubKey.size());
            }
        }

        stream.WriteUint32(tx.nLockTime);
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("blocktxn", stream.GetData());
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

    // v1.4.2+: Genesis hash to prevent cross-chain connections
    // Old clients will ignore extra bytes, new clients validate genesis match
    stream.write(msg.genesis_hash.data, 32);

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
 * ProcessMempoolMessage
 *
 * Handle "mempool" P2P message from a peer requesting our mempool contents.
 * Responds with INV messages for all transactions in our mempool.
 * Rate-limited to prevent DoS.
 */
bool CNetMessageProcessor::ProcessMempoolMessage(int peer_id) {
    // Rate limit: track last mempool response per peer
    static std::map<int, std::chrono::steady_clock::time_point> last_mempool_response;
    static std::mutex mempool_rate_mutex;

    {
        std::lock_guard<std::mutex> lock(mempool_rate_mutex);
        auto now = std::chrono::steady_clock::now();
        auto it = last_mempool_response.find(peer_id);
        if (it != last_mempool_response.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
            if (elapsed < 60) {
                return true;  // Rate limited - ignore
            }
        }
        last_mempool_response[peer_id] = now;
    }

    auto* mempool = g_mempool.load();
    if (!mempool) return true;

    extern NodeContext g_node_context;
    if (!g_node_context.connman || !g_node_context.message_processor) return true;

    auto txs = mempool->GetOrderedTxs();
    if (txs.empty()) return true;

    // Send INV for all mempool transactions (batched, max 1000 per message)
    std::vector<NetProtocol::CInv> inv_vec;
    inv_vec.reserve(std::min(txs.size(), (size_t)1000));

    for (const auto& tx : txs) {
        inv_vec.push_back(NetProtocol::CInv(NetProtocol::MSG_TX_INV, tx->GetHash()));
        if (inv_vec.size() >= 1000) {
            CNetMessage inv_msg = g_node_context.message_processor->CreateInvMessage(inv_vec);
            g_node_context.connman->PushMessage(peer_id, inv_msg);
            inv_vec.clear();
        }
    }

    // Send remaining
    if (!inv_vec.empty()) {
        CNetMessage inv_msg = g_node_context.message_processor->CreateInvMessage(inv_vec);
        g_node_context.connman->PushMessage(peer_id, inv_msg);
    }

    std::cout << "[P2P] Sent " << txs.size() << " mempool tx INV(s) to peer "
              << peer_id << " (mempool request)" << std::endl;

    return true;
}

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
void AnnounceTransactionToPeers(const uint256& txid, int64_t exclude_peer, bool force_reannounce) {
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

        // Check if we should announce to this peer (skip for rebroadcast)
        if (!force_reannounce && !tx_relay->ShouldAnnounce(peer->id, txid)) {
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
