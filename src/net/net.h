// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_NET_H
#define DILITHION_NET_NET_H

#include <net/protocol.h>
#include <net/serialize.h>
#include <net/peers.h>
#include <net/socket.h>
#include <net/bandwidth_throttle.h>  // Network: Bandwidth throttling
#include <net/partition_detector.h>  // Network: Partition detection
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <map>
#include <mutex>
#include <atomic>

/**
 * CNetMessage - Network message processor
 *
 * Handles incoming and outgoing network messages, maintains P2P state machine
 */
class CNetMessageProcessor {
public:
    // Message handler callbacks
    using VersionHandler = std::function<void(int peer_id, const NetProtocol::CVersionMessage&)>;
    using VerackHandler = std::function<void(int peer_id)>;
    using PingHandler = std::function<void(int peer_id, uint64_t nonce)>;
    using PongHandler = std::function<void(int peer_id, uint64_t nonce)>;
    using AddrHandler = std::function<void(int peer_id, const std::vector<NetProtocol::CAddress>&)>;
    using InvHandler = std::function<void(int peer_id, const std::vector<NetProtocol::CInv>&)>;
    using GetDataHandler = std::function<void(int peer_id, const std::vector<NetProtocol::CInv>&)>;
    using BlockHandler = std::function<void(int peer_id, const CBlock&)>;
    using TxHandler = std::function<void(int peer_id, const CTransaction&)>;
    using GetHeadersHandler = std::function<void(int peer_id, const NetProtocol::CGetHeadersMessage&)>;
    using HeadersHandler = std::function<void(int peer_id, const std::vector<CBlockHeader>&)>;

    CNetMessageProcessor(CPeerManager& peer_mgr);

    // Process incoming message
    bool ProcessMessage(int peer_id, const CNetMessage& message);

    // Create outgoing messages
    CNetMessage CreateVersionMessage(const NetProtocol::CAddress& addr_recv, const NetProtocol::CAddress& addr_from);
    CNetMessage CreateVerackMessage();
    CNetMessage CreatePingMessage(uint64_t nonce);
    CNetMessage CreatePongMessage(uint64_t nonce);
    CNetMessage CreateGetAddrMessage();
    CNetMessage CreateAddrMessage(const std::vector<NetProtocol::CAddress>& addrs);
    CNetMessage CreateInvMessage(const std::vector<NetProtocol::CInv>& inv);
    CNetMessage CreateGetDataMessage(const std::vector<NetProtocol::CInv>& inv);
    CNetMessage CreateBlockMessage(const CBlock& block);
    CNetMessage CreateTxMessage(const CTransaction& tx);
    CNetMessage CreateGetHeadersMessage(const NetProtocol::CGetHeadersMessage& msg);
    CNetMessage CreateHeadersMessage(const std::vector<CBlockHeader>& headers);

    // Register handlers
    void SetVersionHandler(VersionHandler handler) { on_version = handler; }
    void SetVerackHandler(VerackHandler handler) { on_verack = handler; }
    void SetPingHandler(PingHandler handler) { on_ping = handler; }
    void SetPongHandler(PongHandler handler) { on_pong = handler; }
    void SetAddrHandler(AddrHandler handler) { on_addr = handler; }
    void SetInvHandler(InvHandler handler) { on_inv = handler; }
    void SetGetDataHandler(GetDataHandler handler) { on_getdata = handler; }
    void SetBlockHandler(BlockHandler handler) { on_block = handler; }
    void SetTxHandler(TxHandler handler) { on_tx = handler; }
    void SetGetHeadersHandler(GetHeadersHandler handler) { on_getheaders = handler; }
    void SetHeadersHandler(HeadersHandler handler) { on_headers = handler; }

private:
    CPeerManager& peer_manager;

    // NET-006 & NET-007 FIX: Rate limiting for INV and ADDR messages
    // Track recent INV/ADDR messages per peer to prevent flooding
    std::map<int, std::vector<int64_t>> peer_inv_timestamps;   // peer_id -> timestamps
    std::map<int, std::vector<int64_t>> peer_addr_timestamps;  // peer_id -> timestamps
    mutable std::mutex cs_inv_rate_limit;
    mutable std::mutex cs_addr_rate_limit;

    // Message handlers
    VersionHandler on_version;
    VerackHandler on_verack;
    PingHandler on_ping;
    PongHandler on_pong;
    AddrHandler on_addr;
    InvHandler on_inv;
    GetDataHandler on_getdata;
    BlockHandler on_block;
    TxHandler on_tx;
    GetHeadersHandler on_getheaders;
    HeadersHandler on_headers;

    // Process specific message types
    bool ProcessVersionMessage(int peer_id, CDataStream& stream);
    bool ProcessVerackMessage(int peer_id);
    bool ProcessPingMessage(int peer_id, CDataStream& stream);
    bool ProcessPongMessage(int peer_id, CDataStream& stream);
    bool ProcessGetAddrMessage(int peer_id);
    bool ProcessAddrMessage(int peer_id, CDataStream& stream);
    bool ProcessInvMessage(int peer_id, CDataStream& stream);
    bool ProcessGetDataMessage(int peer_id, CDataStream& stream);
    bool ProcessBlockMessage(int peer_id, CDataStream& stream);
    bool ProcessTxMessage(int peer_id, CDataStream& stream);
    bool ProcessGetHeadersMessage(int peer_id, CDataStream& stream);
    bool ProcessHeadersMessage(int peer_id, CDataStream& stream);

    // Serialization helpers
    std::vector<uint8_t> SerializeVersionMessage(const NetProtocol::CVersionMessage& msg);
    std::vector<uint8_t> SerializePingPong(uint64_t nonce);
    std::vector<uint8_t> SerializeAddrMessage(const std::vector<NetProtocol::CAddress>& addrs);
    std::vector<uint8_t> SerializeInvMessage(const std::vector<NetProtocol::CInv>& inv);
};

/**
 * Connection handshake helper
 *
 * DEPRECATED: This class is being replaced by CConnman (event-driven networking).
 * CConnman now owns CNode objects and handles socket I/O with proper select() blocking.
 * This class remains for backward compatibility with:
 * - headers_manager.cpp (SendMessage for GETHEADERS)
 * - net.cpp (SendMessage for VERACK)
 *
 * Migration plan: Move all SendMessage calls to use CConnman::PushMessage(),
 * then remove this class entirely.
 */
class [[deprecated("Use CConnman instead")]] CConnectionManager {
public:
    CConnectionManager(CPeerManager& peer_mgr, CNetMessageProcessor& msg_proc);

    // Initiate outbound connection (returns peer_id on success, -1 on failure)
    int ConnectToPeer(const NetProtocol::CAddress& addr);

    // Handle inbound connection (NEW signature - stores socket)
    int AcceptConnection(const NetProtocol::CAddress& addr, std::unique_ptr<CSocket> socket);

    // Perform handshake
    bool PerformHandshake(int peer_id);

    // Disconnect peer
    void DisconnectPeer(int peer_id, const std::string& reason);

    // Periodic maintenance
    void PeriodicMaintenance();

    // NEW: Message send/receive
    bool SendMessage(int peer_id, const CNetMessage& message);
    void ReceiveMessages(int peer_id);

    // NEW: Convenience methods for specific messages
    bool SendVersionMessage(int peer_id);
    bool SendVerackMessage(int peer_id);
    bool SendPingMessage(int peer_id, uint64_t nonce);
    bool SendPongMessage(int peer_id, uint64_t nonce);

    // NEW: Cleanup
    void Cleanup();

private:
    CPeerManager& peer_manager;
    CNetMessageProcessor& message_processor;

    // NEW: Socket storage
    std::map<int, std::unique_ptr<CSocket>> peer_sockets;
    mutable std::mutex cs_sockets;

    // BUG #45 FIX: Per-peer receive buffers for partial read handling
    // Non-blocking sockets can return partial data, we must accumulate it
    std::map<int, std::vector<uint8_t>> peer_recv_buffers;
    mutable std::mutex cs_recv_buffers;
    
    // Network: Connection quality tracking and partition detection
    CConnectionQualityTracker connection_quality;
    CPartitionDetector partition_detector;

    // Ping tracking
    struct PingInfo {
        uint64_t nonce;
        int64_t sent_time;
    };
    std::map<int, PingInfo> pending_pings;

    // Generate random nonce
    uint64_t GenerateNonce();
};

/**
 * Network statistics
 */
struct CNetworkStats {
    size_t total_peers;
    size_t connected_peers;
    size_t handshake_complete;
    size_t bytes_sent;
    size_t bytes_recv;
    size_t messages_sent;
    size_t messages_recv;

    CNetworkStats()
        : total_peers(0), connected_peers(0), handshake_complete(0),
          bytes_sent(0), bytes_recv(0), messages_sent(0), messages_recv(0) {}

    std::string ToString() const;
};

/**
 * Global network statistics
 */
extern CNetworkStats g_network_stats;

/**
 * Global transaction relay manager (Phase 5.3)
 * P0-5 FIX: Use std::atomic to prevent initialization race conditions
 */
class CTxRelayManager;
extern std::atomic<CTxRelayManager*> g_tx_relay_manager;

/**
 * Global pointers for transaction relay (Phase 5.3)
 * P0-5 FIX: Use std::atomic to prevent initialization race conditions
 */
class CTxMemPool;
class CTransactionValidator;
class CUTXOSet;
extern std::atomic<CTxMemPool*> g_mempool;
extern std::atomic<CTransactionValidator*> g_tx_validator;
extern std::atomic<CUTXOSet*> g_utxo_set;
extern std::atomic<unsigned int> g_chain_height;

// Global P2P networking pointers (NW-005)
// P0-5 FIX: Use std::atomic to prevent initialization race conditions
extern std::atomic<CConnectionManager*> g_connection_manager;
extern std::atomic<CNetMessageProcessor*> g_message_processor;

/**
 * Announce a transaction to all connected peers (Phase 5.3)
 * @param txid Transaction hash to announce
 * @param exclude_peer Peer ID to exclude (e.g., originating peer), -1 for none
 */
void AnnounceTransactionToPeers(const uint256& txid, int64_t exclude_peer);

#endif // DILITHION_NET_NET_H
