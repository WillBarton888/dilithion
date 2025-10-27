// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/net.h>
#include <util/strencodings.h>
#include <core/chainparams.h>
#include <random>
#include <cstring>
#include <iostream>

// Global network statistics
CNetworkStats g_network_stats;

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
    } catch (const std::exception& e) {
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
    try {
        // Read number of inv items
        uint64_t count = stream.ReadCompactSize();

        std::vector<NetProtocol::CInv> getdata;
        getdata.reserve(count);

        // Read each inv item
        for (uint64_t i = 0; i < count; i++) {
            NetProtocol::CInv inv;
            inv.type = stream.ReadUint32();
            inv.hash = stream.ReadUint256();
            getdata.push_back(inv);
        }

        // Call handler to serve requested data
        on_getdata(peer_id, getdata);
        return true;

    } catch (...) {
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
        block.vtx.resize(vtx_size);
        if (vtx_size > 0) {
            stream.read(block.vtx.data(), vtx_size);
        }

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
    peer_manager.RemovePeer(peer_id);
    if (g_network_stats.connected_peers > 0) {
        g_network_stats.connected_peers--;
    }
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
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    return dis(gen);
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

        // Send to socket
        int sent = it->second->Send(data.data(), data.size());
        if (sent != static_cast<int>(data.size())) {
            std::cout << "[P2P] ERROR: Send failed to peer " << peer_id
                      << " (sent " << sent << " of " << data.size() << " bytes)" << std::endl;
            return false;
        }
    }

    // Update peer last_send time
    auto peer = peer_manager.GetPeer(peer_id);
    if (peer) {
        peer->last_send = GetTime();
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
