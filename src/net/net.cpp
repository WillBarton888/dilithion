// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/net.h>
#include <util/strencodings.h>
#include <random>
#include <cstring>

// Global network statistics
CNetworkStats g_network_stats;

std::string CNetworkStats::ToString() const {
    return strprintf("CNetworkStats(peers=%d/%d, handshake=%d, "
                    "bytes=%d/%d, msgs=%d/%d)",
                    connected_peers, total_peers, handshake_complete,
                    bytes_recv, bytes_sent, messages_recv, messages_sent);
}

// CNetMessageProcessor implementation

CNetMessageProcessor::CNetMessageProcessor() {
    // Default handlers do nothing
    on_version = [](int, const NetProtocol::CVersionMessage&) {};
    on_ping = [](int, uint64_t) {};
    on_pong = [](int, uint64_t) {};
    on_addr = [](int, const std::vector<NetProtocol::CAddress>&) {};
    on_inv = [](int, const std::vector<NetProtocol::CInv>&) {};
    on_block = [](int, const CBlock&) {};
    on_tx = [](int, const CTransaction&) {};
}

bool CNetMessageProcessor::ProcessMessage(int peer_id, const CNetMessage& message) {
    if (!message.IsValid()) {
        return false;
    }

    std::string command = message.header.GetCommand();
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
        msg.version = stream.ReadInt32();
        msg.services = stream.ReadUint64();
        msg.timestamp = stream.ReadInt64();

        // Read addresses (simplified - skip for now)
        // msg.addr_recv = ...
        // msg.addr_from = ...

        msg.nonce = stream.ReadUint64();
        msg.user_agent = stream.ReadString();
        msg.start_height = stream.ReadInt32();
        msg.relay = stream.ReadUint8() != 0;

        // Update peer info
        auto peer = g_peer_manager->GetPeer(peer_id);
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
    } catch (const std::exception& e) {
        return false;
    }
}

bool CNetMessageProcessor::ProcessVerackMessage(int peer_id) {
    auto peer = g_peer_manager->GetPeer(peer_id);
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
    } catch (const std::exception& e) {
        return false;
    }
}

bool CNetMessageProcessor::ProcessPongMessage(int peer_id, CDataStream& stream) {
    try {
        uint64_t nonce = stream.ReadUint64();
        on_pong(peer_id, nonce);
        return true;
    } catch (const std::exception& e) {
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
            addrs.push_back(addr);
        }

        on_addr(peer_id, addrs);
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

bool CNetMessageProcessor::ProcessInvMessage(int peer_id, CDataStream& stream) {
    try {
        uint64_t count = stream.ReadCompactSize();
        if (count > NetProtocol::MAX_INV_SIZE) {
            return false;
        }

        std::vector<NetProtocol::CInv> inv;
        for (uint64_t i = 0; i < count; i++) {
            NetProtocol::CInv item;
            item.type = stream.ReadUint32();
            item.hash = stream.ReadUint256();
            inv.push_back(item);
        }

        on_inv(peer_id, inv);
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

bool CNetMessageProcessor::ProcessGetDataMessage(int peer_id, CDataStream& stream) {
    // Peer is requesting data (blocks/transactions)
    // Would look up requested items and send them
    return true;
}

bool CNetMessageProcessor::ProcessBlockMessage(int peer_id, CDataStream& stream) {
    try {
        CBlock block;
        // Simplified block deserialization
        block.nVersion = stream.ReadInt32();
        block.hashPrevBlock = stream.ReadUint256();
        block.hashMerkleRoot = stream.ReadUint256();
        block.nTime = stream.ReadUint32();
        block.nBits = stream.ReadUint32();
        block.nNonce = stream.ReadUint32();

        on_block(peer_id, block);
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

bool CNetMessageProcessor::ProcessTxMessage(int peer_id, CDataStream& stream) {
    try {
        CTransaction tx;
        tx.nVersion = stream.ReadInt32();
        // Simplified - would read full transaction

        on_tx(peer_id, tx);
        return true;
    } catch (const std::exception& e) {
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

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("block", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateTxMessage(const CTransaction& tx) {
    CDataStream stream;
    stream.WriteInt32(tx.nVersion);
    // Would serialize full transaction

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("tx", stream.GetData());
}

// Serialization helpers

std::vector<uint8_t> CNetMessageProcessor::SerializeVersionMessage(
    const NetProtocol::CVersionMessage& msg)
{
    CDataStream stream;
    stream.WriteInt32(msg.version);
    stream.WriteUint64(msg.services);
    stream.WriteInt64(msg.timestamp);
    // Addresses (simplified)
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

bool CConnectionManager::ConnectToPeer(const NetProtocol::CAddress& addr) {
    // Check if we can accept more connections
    if (!peer_manager.CanAcceptConnection()) {
        return false;
    }

    // Add peer
    auto peer = peer_manager.AddPeer(addr);
    if (!peer) {
        return false;
    }

    peer->state = CPeer::STATE_CONNECTING;

    // In production, would initiate TCP connection here
    // For now, just mark as connected
    peer->state = CPeer::STATE_CONNECTED;
    peer->connect_time = GetTime();

    g_network_stats.connected_peers++;

    return true;
}

bool CConnectionManager::AcceptConnection(const NetProtocol::CAddress& addr) {
    // Check if we can accept more connections
    if (!peer_manager.CanAcceptConnection()) {
        return false;
    }

    // Add peer
    auto peer = peer_manager.AddPeer(addr);
    if (!peer) {
        return false;
    }

    peer->state = CPeer::STATE_CONNECTED;
    peer->connect_time = GetTime();

    g_network_stats.connected_peers++;

    return true;
}

bool CConnectionManager::PerformHandshake(int peer_id) {
    auto peer = peer_manager.GetPeer(peer_id);
    if (!peer || !peer->IsConnected()) {
        return false;
    }

    // Send version message
    CNetMessage version_msg = message_processor.CreateVersionMessage();
    // In production, would actually send the message

    return true;
}

void CConnectionManager::DisconnectPeer(int peer_id, const std::string& reason) {
    peer_manager.RemovePeer(peer_id);
    if (g_network_stats.connected_peers > 0) {
        g_network_stats.connected_peers--;
    }
}

void CConnectionManager::PeriodicMaintenance() {
    // Send pings to connected peers
    auto peers = peer_manager.GetConnectedPeers();

    for (const auto& peer : peers) {
        if (peer->IsHandshakeComplete()) {
            int64_t now = GetTime();

            // Send ping every 60 seconds
            if (now - peer->last_send > 60) {
                uint64_t nonce = GenerateNonce();
                CNetMessage ping = message_processor.CreatePingMessage(nonce);

                pending_pings[peer->id] = {nonce, now};
                peer->last_send = now;
            }

            // Check for timeout (5 minutes)
            if (now - peer->last_recv > 300) {
                DisconnectPeer(peer->id, "timeout");
            }
        }
    }
}

uint64_t CConnectionManager::GenerateNonce() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    return dis(gen);
}
