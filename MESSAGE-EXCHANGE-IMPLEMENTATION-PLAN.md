# Message Exchange Implementation Plan
## Phase 2: P2P Protocol Message Handling

**Created**: October 26, 2025
**For**: Next Development Session (Session 3)
**Estimated Duration**: 4-5 hours
**Priority**: HIGH
**Prerequisites**: Path A (P2P Server) ✅ COMPLETE

---

## Executive Summary

This document provides a complete implementation plan for adding message exchange functionality to the Dilithion P2P networking layer. The infrastructure (sockets, serialization, peer management) is already in place. This phase will connect these components to enable actual protocol communication between nodes.

**Current State**: Nodes can establish connections but cannot exchange messages.
**Goal State**: Nodes can perform version/verack handshake, exchange ping/pong, and log successful protocol communication.

---

## Infrastructure Assessment

### What Already Exists ✅

1. **Socket Infrastructure** (src/net/socket.h)
   - CSocket class with Send/Recv methods
   - Non-blocking I/O support
   - Connection management

2. **Peer Management** (src/net/peers.h)
   - CPeer with state machine (STATE_CONNECTED → STATE_VERSION_SENT → STATE_HANDSHAKE_COMPLETE)
   - CPeerManager for tracking peers
   - Connection limits and ban management

3. **Message Serialization** (src/net/serialize.h)
   - CDataStream for binary serialization
   - CNetMessage with header/payload
   - Checksum validation

4. **Protocol Definitions** (src/net/protocol.h)
   - Message types (version, verack, ping, pong, addr, inv, block, tx)
   - CVersionMessage structure
   - CPingPong structure
   - Network magic bytes

5. **Message Processing** (src/net/net.h)
   - CNetMessageProcessor with Create* methods
   - Message handler callbacks (on_version, on_ping, etc.)
   - ProcessMessage() framework

6. **Connection Manager** (src/net/net.h)
   - CConnectionManager with ConnectToPeer and AcceptConnection
   - PerformHandshake() placeholder

### What's Missing ⚠️

1. **Socket Storage**
   - Client sockets from Accept() are not stored anywhere
   - No mapping between peer_id and socket

2. **Message Receive Loops**
   - No code reading messages from sockets
   - No header parsing from socket data
   - No payload reading after header

3. **Message Send Implementation**
   - No code actually calling socket.Send() with messages
   - No send queue management

4. **Handshake Execution**
   - PerformHandshake() is called but not implemented
   - Version message creation needs peer_id → socket mapping

5. **State Transitions**
   - Peer state changes based on received messages not implemented

---

## Implementation Plan

### Phase 1: Socket Storage System (1 hour)

#### Task 1.1: Add Socket Storage to CConnectionManager

**File**: `src/net/net.h`

**Changes Needed**:
```cpp
class CConnectionManager {
private:
    CPeerManager& peer_manager;
    CNetMessageProcessor& message_processor;

    // NEW: Socket storage
    std::map<int, std::unique_ptr<CSocket>> peer_sockets;
    std::mutex cs_sockets;

    // NEW: Send queue
    struct QueuedMessage {
        int peer_id;
        CNetMessage message;
    };
    std::deque<QueuedMessage> send_queue;
    std::mutex cs_send_queue;

    // ... existing code ...
```

#### Task 1.2: Store Socket on Accept

**File**: `src/node/dilithion-node.cpp` (P2P accept thread)

**Current Code** (lines ~324-329):
```cpp
if (connection_manager.AcceptConnection(addr)) {
    std::cout << "[P2P] Peer accepted and added to connection pool" << std::endl;
} else {
    std::cout << "[P2P] Failed to accept peer connection" << std::endl;
    client->Close();
}
```

**New Implementation**:
```cpp
int peer_id = connection_manager.AcceptConnection(addr, std::move(client));
if (peer_id > 0) {
    std::cout << "[P2P] Peer " << peer_id << " accepted: " << peer_addr
              << ":" << peer_port << std::endl;
} else {
    std::cout << "[P2P] Failed to accept peer connection" << std::endl;
}
```

**Changes to AcceptConnection**:
```cpp
// OLD signature
bool AcceptConnection(const NetProtocol::CAddress& addr);

// NEW signature
int AcceptConnection(const NetProtocol::CAddress& addr, std::unique_ptr<CSocket> socket);
```

#### Task 1.3: Store Socket on Connect

**File**: `src/net/net.h` (CConnectionManager implementation)

**ConnectToPeer needs to**:
1. Create socket
2. Call socket.Connect()
3. Store socket in peer_sockets map
4. Return peer_id

---

### Phase 2: Message Receive Implementation (1.5 hours)

#### Task 2.1: Create Message Receive Thread

**File**: `src/node/dilithion-node.cpp`

**Location**: After P2P accept thread launch (around line 340)

**New Code**:
```cpp
// Launch P2P receive thread
std::thread p2p_recv_thread([&connection_manager, &peer_manager]() {
    std::cout << "  ✓ P2P receive thread started" << std::endl;

    while (g_node_state.running) {
        // Get all connected peers
        auto peers = peer_manager.GetConnectedPeers();

        for (auto& peer : peers) {
            // Try to receive message from this peer
            connection_manager.ReceiveMessages(peer->id);
        }

        // Sleep briefly to avoid busy-wait
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "  P2P receive thread stopping..." << std::endl;
});
```

#### Task 2.2: Implement ReceiveMessages Method

**File**: `src/net/net.h` + implementation file

**Signature**:
```cpp
void ReceiveMessages(int peer_id);
```

**Implementation Steps**:
1. Get socket for peer_id from peer_sockets map
2. Try to read 24-byte header (non-blocking)
3. If header complete, parse it
4. Read payload_size bytes
5. Validate checksum
6. Create CNetMessage
7. Call ProcessMessage()
8. Update peer last_recv timestamp

**Pseudo-code**:
```cpp
void CConnectionManager::ReceiveMessages(int peer_id) {
    std::lock_guard<std::mutex> lock(cs_sockets);

    auto it = peer_sockets.find(peer_id);
    if (it == peer_sockets.end()) return;

    CSocket* socket = it->second.get();
    if (!socket || !socket->IsValid()) return;

    // Read header (24 bytes)
    uint8_t header_buf[24];
    int bytes_read = socket->Recv(header_buf, 24);
    if (bytes_read != 24) return;  // Not ready yet

    // Parse header
    std::vector<uint8_t> header_data(header_buf, header_buf + 24);
    NetProtocol::CMessageHeader header = CDataStream::DeserializeHeader(header_data);

    // Validate header
    if (!header.IsValid(NetProtocol::g_network_magic)) {
        std::cout << "[P2P] Invalid header from peer " << peer_id << std::endl;
        return;
    }

    // Read payload
    std::vector<uint8_t> payload(header.payload_size);
    if (header.payload_size > 0) {
        int payload_read = socket->RecvAll(payload.data(), header.payload_size);
        if (payload_read != (int)header.payload_size) {
            std::cout << "[P2P] Incomplete payload from peer " << peer_id << std::endl;
            return;
        }
    }

    // Create message
    CNetMessage msg;
    msg.header = header;
    msg.payload = payload;

    // Validate checksum
    if (!msg.IsValid()) {
        std::cout << "[P2P] Invalid message checksum from peer " << peer_id << std::endl;
        return;
    }

    // Process message
    std::string command = msg.header.GetCommand();
    std::cout << "[P2P] Received '" << command << "' from peer " << peer_id << std::endl;

    message_processor.ProcessMessage(peer_id, msg);

    // Update peer last_recv time
    auto peer = peer_manager.GetPeer(peer_id);
    if (peer) {
        peer->last_recv = GetTime();
    }
}
```

---

### Phase 3: Message Send Implementation (1 hour)

#### Task 3.1: Implement SendMessage Method

**File**: `src/net/net.h`

**Signature**:
```cpp
bool SendMessage(int peer_id, const CNetMessage& message);
```

**Implementation**:
```cpp
bool CConnectionManager::SendMessage(int peer_id, const CNetMessage& message) {
    std::lock_guard<std::mutex> lock(cs_sockets);

    auto it = peer_sockets.find(peer_id);
    if (it == peer_sockets.end()) {
        std::cout << "[P2P] No socket for peer " << peer_id << std::endl;
        return false;
    }

    CSocket* socket = it->second.get();
    if (!socket || !socket->IsValid()) {
        std::cout << "[P2P] Invalid socket for peer " << peer_id << std::endl;
        return false;
    }

    // Serialize message
    std::vector<uint8_t> data = message.Serialize();

    // Send all bytes
    int sent = socket->SendAll(data.data(), data.size());
    if (sent != (int)data.size()) {
        std::cout << "[P2P] Failed to send message to peer " << peer_id << std::endl;
        return false;
    }

    std::string command = message.header.GetCommand();
    std::cout << "[P2P] Sent '" << command << "' to peer " << peer_id
              << " (" << data.size() << " bytes)" << std::endl;

    // Update peer last_send time
    auto peer = peer_manager.GetPeer(peer_id);
    if (peer) {
        peer->last_send = GetTime();
    }

    return true;
}
```

#### Task 3.2: Add Convenience Methods

```cpp
bool SendVersionMessage(int peer_id);
bool SendVerackMessage(int peer_id);
bool SendPingMessage(int peer_id, uint64_t nonce);
bool SendPongMessage(int peer_id, uint64_t nonce);
```

---

### Phase 4: Version/Verack Handshake (1 hour)

#### Task 4.1: Implement PerformHandshake

**File**: `src/net/net.h` (CConnectionManager)

**Current**:
```cpp
bool PerformHandshake(int peer_id);  // Declared but not implemented
```

**Implementation**:
```cpp
bool CConnectionManager::PerformHandshake(int peer_id) {
    auto peer = peer_manager.GetPeer(peer_id);
    if (!peer) return false;

    // Create version message
    CNetMessage version_msg = message_processor.CreateVersionMessage();

    // Send version
    if (!SendMessage(peer_id, version_msg)) {
        std::cout << "[P2P] Failed to send version to peer " << peer_id << std::endl;
        return false;
    }

    // Update peer state
    peer->state = CPeer::STATE_VERSION_SENT;

    std::cout << "[P2P] Handshake initiated with peer " << peer_id << std::endl;

    // Note: We'll receive version+verack in the receive loop
    // and update state to STATE_HANDSHAKE_COMPLETE

    return true;
}
```

#### Task 4.2: Handle Received Version Message

**File**: `src/net/net.h` (CNetMessageProcessor)

**Register Handler**:
```cpp
message_processor.SetVersionHandler([&](int peer_id, const NetProtocol::CVersionMessage& ver) {
    std::cout << "[P2P] Received version from peer " << peer_id << std::endl;
    std::cout << "  Protocol: " << ver.version << std::endl;
    std::cout << "  User Agent: " << ver.user_agent << std::endl;
    std::cout << "  Start Height: " << ver.start_height << std::endl;

    // Update peer info
    auto peer = peer_manager.GetPeer(peer_id);
    if (peer) {
        peer->version = ver.version;
        peer->user_agent = ver.user_agent;
        peer->start_height = ver.start_height;
        peer->relay = ver.relay;
    }

    // Send verack
    CNetMessage verack = message_processor.CreateVerackMessage();
    connection_manager.SendMessage(peer_id, verack);

    // If we haven't sent version yet, send it now
    if (peer && peer->state == CPeer::STATE_CONNECTED) {
        connection_manager.PerformHandshake(peer_id);
    }
});
```

#### Task 4.3: Handle Received Verack Message

```cpp
// In message processor setup
if (command == "verack") {
    auto peer = peer_manager.GetPeer(peer_id);
    if (peer && peer->state == CPeer::STATE_VERSION_SENT) {
        peer->state = CPeer::STATE_HANDSHAKE_COMPLETE;
        std::cout << "[P2P] Handshake complete with peer " << peer_id << std::endl;
    }
}
```

---

### Phase 5: Ping/Pong Keepalive (30 minutes)

#### Task 5.1: Periodic Ping Thread

**File**: `src/node/dilithion-node.cpp`

**New Thread** (after receive thread):
```cpp
// Launch P2P ping thread
std::thread p2p_ping_thread([&connection_manager, &peer_manager]() {
    std::cout << "  ✓ P2P ping thread started" << std::endl;

    while (g_node_state.running) {
        // Send ping to all connected peers every 30 seconds
        auto peers = peer_manager.GetConnectedPeers();

        for (auto& peer : peers) {
            if (peer->IsHandshakeComplete()) {
                uint64_t nonce = GenerateNonce();
                connection_manager.SendPingMessage(peer->id, nonce);
            }
        }

        // Sleep 30 seconds
        for (int i = 0; i < 30 && g_node_state.running; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    std::cout << "  P2P ping thread stopping..." << std::endl;
});
```

#### Task 5.2: Handle Ping Messages

```cpp
message_processor.SetPingHandler([&](int peer_id, uint64_t nonce) {
    std::cout << "[P2P] Received ping from peer " << peer_id << std::endl;

    // Send pong with same nonce
    connection_manager.SendPongMessage(peer_id, nonce);
});
```

#### Task 5.3: Handle Pong Messages

```cpp
message_processor.SetPongHandler([&](int peer_id, uint64_t nonce) {
    std::cout << "[P2P] Received pong from peer " << peer_id
              << " (nonce: " << nonce << ")" << std::endl;

    // Could track RTT here if we stored ping send times
});
```

---

### Phase 6: Connection Cleanup and Shutdown (30 minutes)

#### Task 6.1: Thread Joining in Shutdown

**File**: `src/node/dilithion-node.cpp` (shutdown section)

**Add after P2P socket close**:
```cpp
std::cout << "  Stopping P2P server..." << std::endl;
p2p_socket.Close();

// Join all P2P threads
if (p2p_thread.joinable()) {
    p2p_thread.join();
}
if (p2p_recv_thread.joinable()) {
    p2p_recv_thread.join();
}
if (p2p_ping_thread.joinable()) {
    p2p_ping_thread.join();
}
```

#### Task 6.2: Socket Cleanup

```cpp
// In CConnectionManager destructor or cleanup method
void CConnectionManager::Cleanup() {
    std::lock_guard<std::mutex> lock(cs_sockets);

    for (auto& [peer_id, socket] : peer_sockets) {
        if (socket && socket->IsValid()) {
            socket->Close();
        }
    }

    peer_sockets.clear();
}
```

---

## Testing Plan

### Test 1: Version/Verack Handshake

**Setup**: Start 2 nodes
```bash
# Terminal 1
./dilithion-node --testnet --port=18444 --rpcport=18332

# Terminal 2
./dilithion-node --testnet --port=18445 --rpcport=18333 --connect=127.0.0.1:18444 --datadir=.dilithion-testnet-2
```

**Expected Output** (Terminal 1):
```
[P2P] New peer connected: 127.0.0.1:XXXXX
[P2P] Peer 1 accepted: 127.0.0.1:XXXXX
[P2P] Received 'version' from peer 1
  Protocol: 70001
  User Agent: Dilithion:1.0.0
  Start Height: 0
[P2P] Sent 'verack' to peer 1
[P2P] Handshake complete with peer 1
```

**Expected Output** (Terminal 2):
```
[P2P] Connecting to 127.0.0.1:18444...
[P2P] Connected to peer 1
[P2P] Sent 'version' to peer 1
[P2P] Received 'version' from peer 1
[P2P] Sent 'verack' to peer 1
[P2P] Received 'verack' from peer 1
[P2P] Handshake complete with peer 1
```

### Test 2: Ping/Pong

**Expected Output** (every 30 seconds):
```
[P2P] Sent 'ping' to peer 1
[P2P] Received 'pong' from peer 1 (nonce: 123456789)
```

### Test 3: Multi-Node Network

**Setup**: Start 3 nodes as before

**Verification**:
- Each node completes handshake with connected peers
- Ping/pong exchanges work for all connections
- No crashes or deadlocks

---

## File Modifications Summary

### Files to Modify

| File | Changes | Complexity |
|------|---------|------------|
| src/net/net.h | Add socket storage, send/receive methods | HIGH |
| src/net/net.cpp | Implement new methods | HIGH |
| src/node/dilithion-node.cpp | Add receive/ping threads, register handlers | MEDIUM |

### New Methods to Implement

**CConnectionManager**:
- `int AcceptConnection(addr, socket)` - Modified signature
- `void ReceiveMessages(peer_id)` - NEW
- `bool SendMessage(peer_id, message)` - NEW
- `bool SendVersionMessage(peer_id)` - NEW
- `bool SendVerackMessage(peer_id)` - NEW
- `bool SendPingMessage(peer_id, nonce)` - NEW
- `bool SendPongMessage(peer_id, nonce)` - NEW
- `bool PerformHandshake(peer_id)` - Implement existing declaration
- `void Cleanup()` - NEW

**Main Application**:
- P2P receive thread
- P2P ping thread
- Message handler registration
- Thread cleanup in shutdown

---

## Risk Assessment

### Potential Issues

1. **Race Conditions**
   - **Risk**: Multiple threads accessing sockets/peers
   - **Mitigation**: Use mutexes consistently (cs_sockets, cs_peers)

2. **Deadlocks**
   - **Risk**: Circular lock dependencies
   - **Mitigation**: Always acquire locks in same order

3. **Socket Blocking**
   - **Risk**: RecvAll could block if peer doesn't send full message
   - **Mitigation**: Use non-blocking sockets, implement timeout

4. **Memory Leaks**
   - **Risk**: Unique_ptr socket ownership transfer
   - **Mitigation**: Use std::move correctly, ensure cleanup in all paths

5. **Protocol Errors**
   - **Risk**: Malformed messages crash node
   - **Mitigation**: Validate all messages, catch exceptions

---

## Estimated Timeline

| Phase | Task | Estimated Time |
|-------|------|----------------|
| 1 | Socket Storage System | 1 hour |
| 2 | Message Receive | 1.5 hours |
| 3 | Message Send | 1 hour |
| 4 | Version/Verack Handshake | 1 hour |
| 5 | Ping/Pong Keepalive | 30 min |
| 6 | Cleanup & Shutdown | 30 min |
| **Testing** | Multi-node validation | 30 min |
| **TOTAL** | | **5 hours** |

---

## Success Criteria

- [ ] Sockets stored and mapped to peer_ids
- [ ] Messages successfully received from sockets
- [ ] Messages successfully sent to sockets
- [ ] Version/verack handshake completes
- [ ] Handshake logged in both nodes
- [ ] Ping/pong exchanges work
- [ ] Multi-node network (3 nodes) all complete handshakes
- [ ] No crashes or memory leaks
- [ ] Clean shutdown with thread joining

---

## Next Steps After Completion

Once message exchange is working:

1. **Block Propagation** (3-4 hours)
   - Implement inv/getdata/block messages
   - Block validation and storage
   - Blockchain synchronization

2. **Transaction Broadcasting** (2-3 hours)
   - Implement tx messages
   - Transaction relay
   - Mempool synchronization

3. **Mining Block Template Fix** (2-3 hours)
   - From Path B technical debt
   - Proper coinbase creation
   - Target calculation from nBits

---

## References

**Existing Infrastructure**:
- PATH-A-COMPLETION-REPORT.md - P2P server implementation
- MULTI-NODE-TEST-RESULTS.md - Testing validation
- src/net/*.h - All protocol definitions

**Bitcoin Protocol Reference**:
- https://en.bitcoin.it/wiki/Protocol_documentation
- Version message format
- Handshake sequence

---

**Created By**: Claude Code (Project Coordinator)
**Session**: Preparation for Session 3
**Quality Standard**: A++ Planning and Documentation
**Commitment**: Professional, robust, methodical implementation

**Ready for**: Next development session focused on message exchange implementation

