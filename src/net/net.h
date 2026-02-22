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
#include <net/blockencodings.h>      // BIP 152: Compact blocks
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
    using SendHeadersHandler = std::function<void(int peer_id)>;  // BIP 130
    // BIP 152: Compact block handlers
    using SendCmpctHandler = std::function<void(int peer_id, bool high_bandwidth, uint64_t version)>;
    using CmpctBlockHandler = std::function<void(int peer_id, const CBlockHeaderAndShortTxIDs&)>;
    using GetBlockTxnHandler = std::function<void(int peer_id, const BlockTransactionsRequest&)>;
    using BlockTxnHandler = std::function<void(int peer_id, const BlockTransactions&)>;
    // Digital DNA: P2P identity measurement protocol
    using DNALatencyPingHandler = std::function<void(int peer_id, uint64_t nonce)>;
    using DNALatencyPongHandler = std::function<void(int peer_id, uint64_t nonce, uint64_t recv_timestamp_us)>;
    using DNATimeSyncHandler = std::function<void(int peer_id, uint64_t sender_ts_us,
        uint64_t sender_wall_ms, uint64_t nonce, bool is_response, uint64_t local_send_ts_us)>;
    using DNABWTestHandler = std::function<void(int peer_id, uint32_t payload_size,
        uint64_t nonce, uint64_t send_wall_ms)>;
    using DNABWResultHandler = std::function<void(int peer_id, uint64_t nonce,
        double upload_mbps, double download_mbps)>;

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
    CNetMessage CreateSendHeadersMessage();  // BIP 130
    // BIP 152: Compact block messages
    CNetMessage CreateSendCmpctMessage(bool high_bandwidth, uint64_t version);
    CNetMessage CreateCmpctBlockMessage(const CBlockHeaderAndShortTxIDs& cmpctblock);
    CNetMessage CreateGetBlockTxnMessage(const BlockTransactionsRequest& req);
    CNetMessage CreateBlockTxnMessage(const BlockTransactions& resp);
    // Digital DNA: P2P measurement messages
    CNetMessage CreateDNALatencyPingMessage(uint64_t nonce);
    CNetMessage CreateDNALatencyPongMessage(uint64_t nonce);
    CNetMessage CreateDNATimeSyncMessage(uint64_t sender_ts_us, uint64_t sender_wall_ms,
                                          uint64_t nonce, bool is_response);
    CNetMessage CreateDNABWTestMessage(uint64_t nonce, uint32_t payload_size);
    CNetMessage CreateDNABWResultMessage(uint64_t nonce, double upload_mbps, double download_mbps);

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
    void SetSendHeadersHandler(SendHeadersHandler handler) { on_sendheaders = handler; }  // BIP 130
    // BIP 152: Compact block handler setters
    void SetSendCmpctHandler(SendCmpctHandler handler) { on_sendcmpct = handler; }
    void SetCmpctBlockHandler(CmpctBlockHandler handler) { on_cmpctblock = handler; }
    void SetGetBlockTxnHandler(GetBlockTxnHandler handler) { on_getblocktxn = handler; }
    void SetBlockTxnHandler(BlockTxnHandler handler) { on_blocktxn = handler; }
    // Digital DNA handler setters
    void SetDNALatencyPingHandler(DNALatencyPingHandler handler) { on_dna_latency_ping = handler; }
    void SetDNALatencyPongHandler(DNALatencyPongHandler handler) { on_dna_latency_pong = handler; }
    void SetDNATimeSyncHandler(DNATimeSyncHandler handler) { on_dna_time_sync = handler; }
    void SetDNABWTestHandler(DNABWTestHandler handler) { on_dna_bw_test = handler; }
    void SetDNABWResultHandler(DNABWResultHandler handler) { on_dna_bw_result = handler; }
    // DNA nonce management (public for initiator logic in node)
    void RegisterDNANonce(uint64_t nonce, int peer_id, uint64_t send_timestamp_us = 0);
    bool ValidateDNANonce(uint64_t nonce, int peer_id);
    uint64_t GetDNANonceSendTimestamp(uint64_t nonce) const;  // Read without erasing
    void CleanupDNANonces();

private:
    CPeerManager& peer_manager;

    // NET-006 & NET-007 FIX: Rate limiting for INV and ADDR messages
    // Track recent INV/ADDR messages per peer to prevent flooding
    std::map<int, std::vector<int64_t>> peer_inv_timestamps;   // peer_id -> timestamps
    std::map<int, std::vector<int64_t>> peer_addr_timestamps;  // peer_id -> timestamps
    mutable std::mutex cs_inv_rate_limit;
    mutable std::mutex cs_addr_rate_limit;

    // Digital DNA: Rate limiting and nonce tracking for DNA messages
    std::map<int, int64_t> peer_dna_ping_timestamps;   // peer_id -> last dnalping time
    std::map<int, int64_t> peer_dna_tsync_timestamps;  // peer_id -> last dnatsync time
    std::map<int, int64_t> peer_dna_bwtest_timestamps; // peer_id -> last dnabwtest time
    std::atomic<int> dna_bwtest_global_count_{0};       // Global concurrent BW tests
    mutable std::mutex cs_dna_rate_limit;
    // Nonce tracking: nonce -> {peer_id, send_time_sec, send_timestamp_us}
    struct DNANonceInfo {
        int peer_id;
        int64_t send_time_sec;      // For expiry checks
        uint64_t send_timestamp_us; // For clock drift calculation
    };
    std::map<uint64_t, DNANonceInfo> dna_pending_nonces_;
    mutable std::mutex cs_dna_nonces;

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
    SendHeadersHandler on_sendheaders;  // BIP 130
    // BIP 152: Compact block handlers
    SendCmpctHandler on_sendcmpct;
    CmpctBlockHandler on_cmpctblock;
    GetBlockTxnHandler on_getblocktxn;
    BlockTxnHandler on_blocktxn;
    // Digital DNA handlers
    DNALatencyPingHandler on_dna_latency_ping;
    DNALatencyPongHandler on_dna_latency_pong;
    DNATimeSyncHandler on_dna_time_sync;
    DNABWTestHandler on_dna_bw_test;
    DNABWResultHandler on_dna_bw_result;

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
    bool ProcessSendHeadersMessage(int peer_id);  // BIP 130
    // BIP 152: Compact block message processing
    bool ProcessSendCmpctMessage(int peer_id, CDataStream& stream);
    bool ProcessCmpctBlockMessage(int peer_id, CDataStream& stream);
    bool ProcessGetBlockTxnMessage(int peer_id, CDataStream& stream);
    bool ProcessBlockTxnMessage(int peer_id, CDataStream& stream);
    // Mempool request handler
    bool ProcessMempoolMessage(int peer_id);
    // Digital DNA message processing
    bool ProcessDNALatencyPingMessage(int peer_id, CDataStream& stream);
    bool ProcessDNALatencyPongMessage(int peer_id, CDataStream& stream);
    bool ProcessDNATimeSyncMessage(int peer_id, CDataStream& stream);
    bool ProcessDNABWTestMessage(int peer_id, CDataStream& stream);
    bool ProcessDNABWResultMessage(int peer_id, CDataStream& stream);

    // Serialization helpers
    std::vector<uint8_t> SerializeVersionMessage(const NetProtocol::CVersionMessage& msg);
    std::vector<uint8_t> SerializePingPong(uint64_t nonce);
    std::vector<uint8_t> SerializeAddrMessage(const std::vector<NetProtocol::CAddress>& addrs);
    std::vector<uint8_t> SerializeInvMessage(const std::vector<NetProtocol::CInv>& inv);
};

// REMOVED: CConnectionManager class - replaced by CConnman
// All code now uses CConnman for connection management and message sending

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
// Phase 5: Removed g_connection_manager - use CConnman via NodeContext instead
extern std::atomic<CNetMessageProcessor*> g_message_processor;

/**
 * Announce a transaction to all connected peers (Phase 5.3)
 * @param txid Transaction hash to announce
 * @param exclude_peer Peer ID to exclude (e.g., originating peer), -1 for none
 * @param force_reannounce If true, skip "already announced" check (for periodic rebroadcast)
 */
void AnnounceTransactionToPeers(const uint256& txid, int64_t exclude_peer, bool force_reannounce = false);

/**
 * A4/A5: Send a reject message to a peer before banning/disconnecting.
 * Best-effort delivery - peer may disconnect before receiving.
 * Helps miners understand WHY they were banned.
 * Uses Bitcoin BIP 61 wire format: var_str(cmd) + uint8(code) + var_str(reason)
 */
// Bitcoin BIP 61 reject codes
static constexpr uint8_t REJECT_MALFORMED   = 0x01;
static constexpr uint8_t REJECT_INVALID     = 0x10;
static constexpr uint8_t REJECT_OBSOLETE    = 0x11;
static constexpr uint8_t REJECT_DUPLICATE   = 0x12;

void SendRejectMessage(int peer_id, const std::string& command, const std::string& reason,
                       uint8_t code = REJECT_INVALID);

#endif // DILITHION_NET_NET_H
