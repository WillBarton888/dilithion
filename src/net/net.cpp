// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/net.h>
#include <net/tx_relay.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <core/chainparams.h>
#include <node/mempool.h>
#include <node/utxo_set.h>
#include <consensus/tx_validation.h>
#include <random>
#include <cstring>
#include <iostream>

// Platform-specific socket headers for error codes (WSAETIMEDOUT, EAGAIN, etc.)
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
// Undefine Windows macros that conflict with our method names
#undef SendMessage
#else
#include <errno.h>
#endif

// NET-003 FIX: Define consensus limits to prevent integer overflow in vector resize
// These prevent DoS attacks via malicious size values causing heap corruption
static const uint64_t MAX_BLOCK_TRANSACTIONS = 100000;  // Max transactions per block
static const uint64_t MAX_TX_INPUTS = 10000;            // Max inputs per transaction
static const uint64_t MAX_TX_OUTPUTS = 10000;           // Max outputs per transaction
static const uint64_t MAX_SCRIPT_SIZE = 10000;          // Max script size in bytes

// NET-016 FIX: Error message sanitization notes
// Production deployment should implement proper logging framework with:
// - Log levels (DEBUG, INFO, WARN, ERROR)
// - Sanitized production messages (no peer IDs, internal state in ERROR level)
// - Detailed messages only in DEBUG level
// Current implementation uses std::cout for development convenience
// Replace with spdlog or similar for production

// Global network statistics
CNetworkStats g_network_stats;

// Global transaction relay manager (Phase 5.3)
CTxRelayManager* g_tx_relay_manager = nullptr;

// Global pointers for transaction relay (Phase 5.3)
CTxMemPool* g_mempool = nullptr;
CTransactionValidator* g_tx_validator = nullptr;
CUTXOSet* g_utxo_set = nullptr;
unsigned int g_chain_height = 0;

// Global pointers for P2P networking (NW-005)
CConnectionManager* g_connection_manager = nullptr;
CNetMessageProcessor* g_message_processor = nullptr;

std::string CNetworkStats::ToString() const {
    return strprintf("CNetworkStats(peers=%d/%d, handshake=%d, "
                    "bytes=%d/%d, msgs=%d/%d)",
                    connected_peers, total_peers, handshake_complete,
                    bytes_recv, bytes_sent, messages_recv, messages_sent);
}

// CNetMessageProcessor implementation

CNetMessageProcessor::CNetMessageProcessor(CPeerManager& peer_mgr)
    : peer_manager(peer_mgr)
{
    // Default handlers do nothing
    on_version = [](int, const NetProtocol::CVersionMessage&) {};
    on_ping = [](int, uint64_t) {};
    on_pong = [](int, uint64_t) {};
    on_addr = [](int, const std::vector<NetProtocol::CAddress>&) {};
    on_inv = [](int, const std::vector<NetProtocol::CInv>&) {};
    on_getdata = [](int, const std::vector<NetProtocol::CInv>&) {};
    on_block = [](int, const CBlock&) {};
    on_tx = [](int, const CTransaction&) {};
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
        {"getheaders", {36, 8236}},                  // Min 36 bytes, max ~8KB with many hashes
        {"headers",    {1, 2000 * 81}},              // Max 2000 headers * 81 bytes each
        {"getblocks",  {36, 8236}},                  // Similar to getheaders
        {"mempool",    {0, 0}},                      // Empty message
        {"reject",     {1, 1024}},                   // Variable, max 1KB for reject messages
    };

    auto it = size_limits.find(command);
    if (it != size_limits.end()) {
        if (payload_size < it->second.min_size || payload_size > it->second.max_size) {
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
            std::cout << "[P2P] ERROR: User agent too long from peer " << peer_id
                      << " (" << msg.user_agent.length() << " bytes, max 256)" << std::endl;
            peer_manager.Misbehaving(peer_id, 20);
            return false;
        }

        // Update peer info
        auto peer = peer_manager.GetPeer(peer_id);
        if (peer) {
            peer->version = msg.version;
            peer->user_agent = msg.user_agent;
            peer->start_height = msg.start_height;
            peer->relay = msg.relay;
            peer->state = CPeer::STATE_VERSION_SENT;
        }

        // Call handler
        on_version(peer_id, msg);

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
    if (peer && peer->state == CPeer::STATE_VERSION_SENT) {
        peer->state = CPeer::STATE_HANDSHAKE_COMPLETE;
        g_network_stats.handshake_complete++;
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
    // Peer is requesting addresses
    // Would send back known peer addresses
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
        if (count > NetProtocol::MAX_INV_SIZE) {
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
        if (count > NetProtocol::MAX_INV_SIZE) {
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

        for (const NetProtocol::CInv& inv_item : inv) {
            if (inv_item.type == NetProtocol::MSG_TX_INV) {
                // Check if we need this transaction
                if (g_tx_relay_manager && g_mempool) {
                    if (!g_tx_relay_manager->AlreadyHave(inv_item.hash, *g_mempool)) {
                        vToFetch.push_back(inv_item);
                        g_tx_relay_manager->MarkRequested(inv_item.hash, peer_id);

                        std::cout << "[P2P] Requesting transaction "
                                  << inv_item.hash.GetHex().substr(0, 16)
                                  << "... from peer " << peer_id << std::endl;
                    }
                }
            }
            else if (inv_item.type == NetProtocol::MSG_BLOCK_INV) {
                // Existing block handling (keep as-is)
                vToFetch.push_back(inv_item);
            }
        }

        // Request transactions/blocks we don't have
        if (!vToFetch.empty()) {
            // Create GETDATA message
            CNetMessage getdata_msg = CreateGetDataMessage(vToFetch);

            // Send via connection manager (need to get connection manager reference)
            // For now, use the handler callback
            on_getdata(peer_id, vToFetch);  // This will trigger sending getdata
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
            getdata.push_back(inv);
        }

        // Phase 5.3: Handle transaction data requests
        for (const NetProtocol::CInv& inv : getdata) {
            if (inv.type == NetProtocol::MSG_TX_INV) {
                // Try to get transaction from mempool
                if (g_mempool) {
                    // Create dummy transaction for mempool lookup
                    CTransactionRef tx_ref = MakeTransactionRef();
                    CTxMemPoolEntry entry(tx_ref, 0, 0, 0);

                    if (g_mempool->GetTx(inv.hash, entry)) {
                        CTransactionRef tx = entry.GetSharedTx();

                        // Create TX message and send it
                        CNetMessage tx_msg = CreateTxMessage(*tx);

                        // Note: Actual sending will be done by handler
                        // For now, just log
                        std::cout << "[P2P] Serving transaction "
                                  << inv.hash.GetHex().substr(0, 16)
                                  << "... to peer " << peer_id << std::endl;
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

        on_block(peer_id, block);
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

        // Phase 5.3: Transaction relay processing
        if (g_tx_relay_manager) {
            // Remove from in-flight
            g_tx_relay_manager->RemoveInFlight(txid);
        }

        // Check if we already have it
        if (g_mempool && g_mempool->Exists(txid)) {
            std::cout << "[P2P] Transaction " << txid.GetHex().substr(0, 16)
                      << "... already in mempool" << std::endl;
            on_tx(peer_id, tx);
            return true;
        }

        // Validate transaction
        if (g_tx_validator && g_utxo_set && g_mempool) {
            std::string error;
            CAmount fee = 0;

            if (!g_tx_validator->CheckTransaction(tx, *g_utxo_set, g_chain_height, fee, error)) {
                std::cout << "[P2P] Invalid transaction " << txid.GetHex().substr(0, 16)
                          << "... from peer " << peer_id << ": " << error << std::endl;
                // Could penalize peer here
                return false;
            }

            // Add to mempool
            std::string mempool_error;
            int64_t current_time = GetTime();
            CTransactionRef tx_ref = MakeTransactionRef(std::move(tx));

            if (!g_mempool->AddTx(tx_ref, fee, current_time, g_chain_height, &mempool_error)) {
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

// Create messages

CNetMessage CNetMessageProcessor::CreateVersionMessage() {
    NetProtocol::CVersionMessage msg;
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

// CConnectionManager implementation

CConnectionManager::CConnectionManager(CPeerManager& peer_mgr,
                                       CNetMessageProcessor& msg_proc)
    : peer_manager(peer_mgr), message_processor(msg_proc)
{
}

int CConnectionManager::ConnectToPeer(const NetProtocol::CAddress& addr) {
    // Check if we can accept more connections
    if (!peer_manager.CanAcceptConnection()) {
        return -1;
    }

    // Create socket for outbound connection
    auto socket = std::make_unique<CSocket>();

    // Extract IP from IPv6-mapped IPv4 address (bytes 12-15)
    std::string ip_str = strprintf("%d.%d.%d.%d",
                                    addr.ip[12],
                                    addr.ip[13],
                                    addr.ip[14],
                                    addr.ip[15]);

    // Connect to peer
    if (!socket->Connect(ip_str, addr.port)) {
        return -1;
    }

    // Set socket to non-blocking mode
    socket->SetNonBlocking(true);

    // Set send timeout to prevent blocking on send (5 seconds)
    socket->SetSendTimeout(5000);

    // Add peer
    auto peer = peer_manager.AddPeer(addr);
    if (!peer) {
        socket->Close();
        return -1;
    }

    peer->state = CPeer::STATE_CONNECTED;
    peer->connect_time = GetTime();

    // Store socket
    {
        std::lock_guard<std::mutex> lock(cs_sockets);
        peer_sockets[peer->id] = std::move(socket);
    }

    g_network_stats.connected_peers++;

    return peer->id;
}

int CConnectionManager::AcceptConnection(const NetProtocol::CAddress& addr,
                                         std::unique_ptr<CSocket> socket) {
    // Check if we can accept more connections
    if (!peer_manager.CanAcceptConnection()) {
        return -1;  // Return -1 for failure
    }

    // Add peer
    auto peer = peer_manager.AddPeer(addr);
    if (!peer) {
        return -1;
    }

    peer->state = CPeer::STATE_CONNECTED;
    peer->connect_time = GetTime();

    // Set socket to non-blocking mode (critical for inbound connections!)
    socket->SetNonBlocking(true);

    // Set send timeout to prevent blocking on send (5 seconds)
    socket->SetSendTimeout(5000);

    // Store socket
    {
        std::lock_guard<std::mutex> lock(cs_sockets);
        peer_sockets[peer->id] = std::move(socket);
    }

    g_network_stats.connected_peers++;

    return peer->id;  // Return peer ID on success
}

bool CConnectionManager::PerformHandshake(int peer_id) {
    auto peer = peer_manager.GetPeer(peer_id);
    if (!peer || !peer->IsConnected()) {
        return false;
    }

    // Send version message
    if (!SendVersionMessage(peer_id)) {
        return false;
    }

    peer->state = CPeer::STATE_VERSION_SENT;
    return true;
}

void CConnectionManager::DisconnectPeer(int peer_id, const std::string& reason) {
    // NET-008 FIX: Properly cleanup socket to prevent use-after-free
    // Remove socket from map while holding mutex to ensure no concurrent access
    {
        std::lock_guard<std::mutex> lock(cs_sockets);
        auto it = peer_sockets.find(peer_id);
        if (it != peer_sockets.end()) {
            // Close and remove socket (unique_ptr will handle deletion)
            it->second.reset();  // Explicitly close socket
            peer_sockets.erase(it);
        }
    }

    // Remove peer from peer manager
    peer_manager.RemovePeer(peer_id);

    if (g_network_stats.connected_peers > 0) {
        g_network_stats.connected_peers--;
    }

    std::cout << "[P2P] Disconnected peer " << peer_id << " (reason: " << reason << ")" << std::endl;
}

void CConnectionManager::PeriodicMaintenance() {
    // Send pings to connected peers
    auto peers = peer_manager.GetConnectedPeers();

    for (const auto& peer : peers) {
        int64_t now = GetTime();

        if (peer->IsHandshakeComplete()) {
            // Send ping every 60 seconds
            if (now - peer->last_send > 60) {
                uint64_t nonce = GenerateNonce();
                if (SendPingMessage(peer->id, nonce)) {
                    std::cout << "[P2P] Sent keepalive ping to peer " << peer->id << std::endl;
                } else {
                    std::cout << "[P2P] WARNING: Failed to send ping to peer " << peer->id << std::endl;
                }
            }

            // Check for timeout (5 minutes)
            if (now - peer->last_recv > 300) {
                std::cout << "[P2P] Peer " << peer->id << " timed out (no response for 5 minutes)" << std::endl;
                DisconnectPeer(peer->id, "timeout");
            }
        }
    }
}

uint64_t CConnectionManager::GenerateNonce() {
    // NET-014 FIX: Use cryptographically secure RNG for nonces
    // std::random_device uses OS CSPRNG (CryptGenRandom on Windows, /dev/urandom on Unix)
    // This is suitable for network protocol nonces that need unpredictability
    std::random_device rd;

    // Generate 64-bit nonce from two 32-bit random values
    uint64_t nonce = static_cast<uint64_t>(rd()) << 32 | rd();
    return nonce;
}

bool CConnectionManager::SendMessage(int peer_id, const CNetMessage& message) {
    if (!message.IsValid()) {
        std::cout << "[P2P] ERROR: Invalid message for peer " << peer_id << std::endl;
        return false;
    }

    // Serialize complete message (header + payload)
    std::vector<uint8_t> data = message.Serialize();

    // Get socket and send (hold lock during send to prevent socket deletion)
    {
        std::lock_guard<std::mutex> lock(cs_sockets);
        auto it = peer_sockets.find(peer_id);
        if (it == peer_sockets.end() || !it->second || !it->second->IsValid()) {
            std::cout << "[P2P] ERROR: No valid socket for peer " << peer_id << std::endl;
            return false;
        }

        // Send to socket (with 5-second timeout)
        int sent = it->second->Send(data.data(), data.size());
        if (sent != static_cast<int>(data.size())) {
            int error_code = it->second->GetLastError();
            std::string error_str = it->second->GetLastErrorString();

            // Check if this is a timeout error
            bool is_timeout = false;
#ifdef _WIN32
            is_timeout = (error_code == WSAETIMEDOUT);
#else
            is_timeout = (error_code == EAGAIN || error_code == EWOULDBLOCK);
#endif

            if (is_timeout) {
                std::cout << "[P2P] WARNING: Send timeout to peer " << peer_id
                          << " (sent " << sent << " of " << data.size() << " bytes) - continuing to next peer" << std::endl;
            } else {
                std::cout << "[P2P] ERROR: Send failed to peer " << peer_id
                          << " (sent " << sent << " of " << data.size() << " bytes, error: " << error_str << ")" << std::endl;
            }
            return false;
        }

        // NET-005 FIX: Update peer last_send time INSIDE mutex to prevent race
        // Previously this was done after releasing lock, creating TOCTOU vulnerability
        auto peer = peer_manager.GetPeer(peer_id);
        if (peer) {
            peer->last_send = GetTime();
        }
    }

    return true;
}

void CConnectionManager::ReceiveMessages(int peer_id) {
    uint8_t header_buf[24];
    int received = 0;

    // Read message header (hold lock during receive)
    {
        std::lock_guard<std::mutex> lock(cs_sockets);
        auto it = peer_sockets.find(peer_id);
        if (it == peer_sockets.end() || !it->second || !it->second->IsValid()) {
            return;  // Socket not found - normal, skip silently
        }

        received = it->second->Recv(header_buf, 24);
    }

    if (received <= 0) {
        return;  // No data or error - normal for non-blocking sockets
    }

    if (received != 24) {
        std::cout << "[P2P] ERROR: Incomplete header from peer " << peer_id
                  << " (" << received << " bytes)" << std::endl;
        return;
    }

    // Parse header (manual deserialization)
    CNetMessage message;
    std::memcpy(&message.header.magic, header_buf, 4);
    std::memcpy(message.header.command, header_buf + 4, 12);
    std::memcpy(&message.header.payload_size, header_buf + 16, 4);
    std::memcpy(&message.header.checksum, header_buf + 20, 4);

    // Validate header
    if (!message.header.IsValid(NetProtocol::g_network_magic)) {
        std::cout << "[P2P] ERROR: Invalid magic from peer " << peer_id
                  << " (got 0x" << std::hex << message.header.magic
                  << ", expected 0x" << NetProtocol::g_network_magic << std::dec << ")" << std::endl;
        return;
    }

    // Read payload if present
    if (message.header.payload_size > 0) {
        if (message.header.payload_size > NetProtocol::MAX_MESSAGE_SIZE) {
            std::cout << "[P2P] ERROR: Payload too large from peer " << peer_id
                      << " (" << message.header.payload_size << " bytes)" << std::endl;
            return;
        }

        message.payload.resize(message.header.payload_size);

        // Read payload (hold lock during receive)
        int payload_received = 0;
        {
            std::lock_guard<std::mutex> lock(cs_sockets);
            auto it = peer_sockets.find(peer_id);
            if (it == peer_sockets.end() || !it->second || !it->second->IsValid()) {
                std::cout << "[P2P] ERROR: Socket disappeared while reading from peer " << peer_id << std::endl;
                return;
            }

            payload_received = it->second->Recv(message.payload.data(),
                                                 message.header.payload_size);
        }

        if (payload_received != static_cast<int>(message.header.payload_size)) {
            std::cout << "[P2P] ERROR: Incomplete payload from peer " << peer_id
                      << " (got " << payload_received << ", expected "
                      << message.header.payload_size << " bytes)" << std::endl;
            return;
        }

        // NET-004 FIX: Verify checksum after reading payload
        uint32_t calculated_checksum = CDataStream::CalculateChecksum(message.payload);
        if (calculated_checksum != message.header.checksum) {
            std::cout << "[P2P] ERROR: Checksum mismatch from peer " << peer_id
                      << " (got 0x" << std::hex << message.header.checksum
                      << ", expected 0x" << calculated_checksum << std::dec << ")" << std::endl;
            return;
        }
    }

    // Update peer last_recv time
    auto peer = peer_manager.GetPeer(peer_id);
    if (peer) {
        peer->last_recv = GetTime();
    }

    // Process message
    message_processor.ProcessMessage(peer_id, message);
}

bool CConnectionManager::SendVersionMessage(int peer_id) {
    CNetMessage msg = message_processor.CreateVersionMessage();
    return SendMessage(peer_id, msg);
}

bool CConnectionManager::SendVerackMessage(int peer_id) {
    CNetMessage msg = message_processor.CreateVerackMessage();
    return SendMessage(peer_id, msg);
}

bool CConnectionManager::SendPingMessage(int peer_id, uint64_t nonce) {
    CNetMessage msg = message_processor.CreatePingMessage(nonce);

    // Track pending ping
    pending_pings[peer_id] = {nonce, GetTime()};

    return SendMessage(peer_id, msg);
}

bool CConnectionManager::SendPongMessage(int peer_id, uint64_t nonce) {
    CNetMessage msg = message_processor.CreatePongMessage(nonce);
    return SendMessage(peer_id, msg);
}

void CConnectionManager::Cleanup() {
    std::lock_guard<std::mutex> lock(cs_sockets);

    // Close all sockets
    for (auto& pair : peer_sockets) {
        if (pair.second && pair.second->IsValid()) {
            pair.second->Close();
        }
    }

    // Clear socket map
    peer_sockets.clear();
    pending_pings.clear();
}

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
    if (!g_peer_manager || !g_connection_manager || !g_message_processor || !g_tx_relay_manager) {
        std::cout << "[TX-RELAY] Cannot announce transaction " << txid.GetHex().substr(0, 16)
                  << "... (networking not initialized)" << std::endl;
        return;
    }

    // Get list of connected peers
    std::vector<std::shared_ptr<CPeer>> peers = g_peer_manager->GetConnectedPeers();

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
        if (!g_tx_relay_manager->ShouldAnnounce(peer->id, txid)) {
            skipped_count++;
            continue;
        }

        // Create INV message
        std::vector<NetProtocol::CInv> inv_vec;
        inv_vec.push_back(NetProtocol::CInv(NetProtocol::MSG_TX_INV, txid));

        CNetMessage inv_message = g_message_processor->CreateInvMessage(inv_vec);

        // Send INV message to peer
        // Only mark as announced if send succeeds (audit recommendation)
        if (g_connection_manager->SendMessage(peer->id, inv_message)) {
            // Mark as announced to prevent duplicates
            g_tx_relay_manager->MarkAnnounced(peer->id, txid);
            announced_count++;
        } else {
            // Send failed - don't mark as announced, will retry on next call
            skipped_count++;
        }
    }

    std::cout << "[TX-RELAY] Announced transaction " << txid.GetHex().substr(0, 16)
              << "... to " << announced_count << " peer(s) "
              << "(skipped " << skipped_count << " already announced, "
              << "excluded peer " << exclude_peer << ")" << std::endl;
}
