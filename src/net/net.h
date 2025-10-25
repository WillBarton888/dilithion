// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_NET_H
#define DILITHION_NET_NET_H

#include <net/protocol.h>
#include <net/serialize.h>
#include <net/peers.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>

/**
 * CNetMessage - Network message processor
 *
 * Handles incoming and outgoing network messages, maintains P2P state machine
 */
class CNetMessageProcessor {
public:
    // Message handler callbacks
    using VersionHandler = std::function<void(int peer_id, const NetProtocol::CVersionMessage&)>;
    using PingHandler = std::function<void(int peer_id, uint64_t nonce)>;
    using PongHandler = std::function<void(int peer_id, uint64_t nonce)>;
    using AddrHandler = std::function<void(int peer_id, const std::vector<NetProtocol::CAddress>&)>;
    using InvHandler = std::function<void(int peer_id, const std::vector<NetProtocol::CInv>&)>;
    using BlockHandler = std::function<void(int peer_id, const CBlock&)>;
    using TxHandler = std::function<void(int peer_id, const CTransaction&)>;

    CNetMessageProcessor();

    // Process incoming message
    bool ProcessMessage(int peer_id, const CNetMessage& message);

    // Create outgoing messages
    CNetMessage CreateVersionMessage();
    CNetMessage CreateVerackMessage();
    CNetMessage CreatePingMessage(uint64_t nonce);
    CNetMessage CreatePongMessage(uint64_t nonce);
    CNetMessage CreateGetAddrMessage();
    CNetMessage CreateAddrMessage(const std::vector<NetProtocol::CAddress>& addrs);
    CNetMessage CreateInvMessage(const std::vector<NetProtocol::CInv>& inv);
    CNetMessage CreateGetDataMessage(const std::vector<NetProtocol::CInv>& inv);
    CNetMessage CreateBlockMessage(const CBlock& block);
    CNetMessage CreateTxMessage(const CTransaction& tx);

    // Register handlers
    void SetVersionHandler(VersionHandler handler) { on_version = handler; }
    void SetPingHandler(PingHandler handler) { on_ping = handler; }
    void SetPongHandler(PongHandler handler) { on_pong = handler; }
    void SetAddrHandler(AddrHandler handler) { on_addr = handler; }
    void SetInvHandler(InvHandler handler) { on_inv = handler; }
    void SetBlockHandler(BlockHandler handler) { on_block = handler; }
    void SetTxHandler(TxHandler handler) { on_tx = handler; }

private:
    // Message handlers
    VersionHandler on_version;
    PingHandler on_ping;
    PongHandler on_pong;
    AddrHandler on_addr;
    InvHandler on_inv;
    BlockHandler on_block;
    TxHandler on_tx;

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

    // Serialization helpers
    std::vector<uint8_t> SerializeVersionMessage(const NetProtocol::CVersionMessage& msg);
    std::vector<uint8_t> SerializePingPong(uint64_t nonce);
    std::vector<uint8_t> SerializeAddrMessage(const std::vector<NetProtocol::CAddress>& addrs);
    std::vector<uint8_t> SerializeInvMessage(const std::vector<NetProtocol::CInv>& inv);
};

/**
 * Connection handshake helper
 */
class CConnectionManager {
public:
    CConnectionManager(CPeerManager& peer_mgr, CNetMessageProcessor& msg_proc);

    // Initiate outbound connection
    bool ConnectToPeer(const NetProtocol::CAddress& addr);

    // Handle inbound connection
    bool AcceptConnection(const NetProtocol::CAddress& addr);

    // Perform handshake
    bool PerformHandshake(int peer_id);

    // Disconnect peer
    void DisconnectPeer(int peer_id, const std::string& reason);

    // Periodic maintenance
    void PeriodicMaintenance();

private:
    CPeerManager& peer_manager;
    CNetMessageProcessor& message_processor;

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

#endif // DILITHION_NET_NET_H
