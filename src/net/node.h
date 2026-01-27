// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// CNode - Unified peer node with socket and message queues (Bitcoin Core pattern)
// Combines socket management with peer state for event-driven I/O
// See: docs/developer/LIBEVENT-NETWORKING-PORT-PLAN.md

#ifndef DILITHION_NET_NODE_H
#define DILITHION_NET_NODE_H

#include <net/protocol.h>
#include <atomic>
#include <cstdint>
#include <deque>
#include <list>
#include <mutex>
#include <string>
#include <vector>

/**
 * CProcessedMsg - Complete network message ready for processing
 * (Named to avoid conflict with CNetMessage in serialize.h)
 */
struct CProcessedMsg {
    std::string command;
    std::vector<uint8_t> data;
    int64_t nTime = 0;  // Time message was received

    CProcessedMsg() = default;
    CProcessedMsg(std::string cmd, std::vector<uint8_t> payload)
        : command(std::move(cmd)), data(std::move(payload)), nTime(0) {}
};

/**
 * CSerializedNetMsg - Serialized message ready for sending
 */
struct CSerializedNetMsg {
    std::string command;
    std::vector<uint8_t> data;  // Full serialized message including header

    CSerializedNetMsg() = default;
    CSerializedNetMsg(std::string cmd, std::vector<uint8_t> payload)
        : command(std::move(cmd)), data(std::move(payload)) {}

    // Move semantics
    CSerializedNetMsg(CSerializedNetMsg&&) = default;
    CSerializedNetMsg& operator=(CSerializedNetMsg&&) = default;

    // No copy (large data)
    CSerializedNetMsg(const CSerializedNetMsg&) = delete;
    CSerializedNetMsg& operator=(const CSerializedNetMsg&) = delete;
};

/**
 * CNode - Unified peer node (Bitcoin Core pattern)
 *
 * Combines:
 * - Socket handle and I/O state
 * - Message receive/send queues
 * - Peer protocol state
 * - Connection statistics
 *
 * Key design:
 * - Socket I/O handled by CConnman::ThreadSocketHandler
 * - Messages processed by CConnman::ThreadMessageHandler
 * - All socket access protected by m_sock_mutex
 * - Message queues protected by cs_vProcessMsg / cs_vSendMsg
 */
class CNode {
public:
    //
    // Connection state (mirrors CPeer::State)
    //
    enum State {
        STATE_DISCONNECTED,
        STATE_CONNECTING,
        STATE_CONNECTED,
        STATE_VERSION_SENT,
        STATE_HANDSHAKE_COMPLETE,
        STATE_BANNED,
    };

    //
    // Identity
    //
    const int id;                           // Unique node ID
    NetProtocol::CAddress addr;             // Remote address
    bool fInbound = false;                  // True if inbound connection

    //
    // Connection state
    //
    // SSOT FIX #2: CNode::state is the single source of truth for peer connection state
    // CPeer::state is deprecated - all code should check CNode::state
    std::atomic<State> state{STATE_DISCONNECTED};
    std::atomic<bool> fDisconnect{false};   // Set to trigger disconnect
    // SSOT FIX #2: fSuccessfullyConnected is redundant with state == STATE_HANDSHAKE_COMPLETE
    // Kept for backward compatibility but state is authoritative
    std::atomic<bool> fSuccessfullyConnected{false};  // DEPRECATED: Use state == STATE_HANDSHAKE_COMPLETE
    std::atomic<bool> fVersionSent{false};  // VERSION message sent (BUG #139)

    //
    // Protocol state
    //
    int nVersion = 0;                       // Protocol version
    std::string strSubVer;                  // User agent
    int nStartingHeight = 0;                // Peer's starting height
    bool fRelay = true;                     // Whether peer relays tx

    //
    // BIP 130: sendheaders preference
    //
    std::atomic<bool> fPreferHeaders{false};    // Peer sent sendheaders (wants HEADERS not INV)
    std::atomic<bool> fSentSendHeaders{false};  // We sent sendheaders to this peer

    //
    // BIP 152: Compact block preference
    //
    std::atomic<bool> fSupportsCompactBlocks{false};  // Peer supports compact blocks
    std::atomic<bool> fHighBandwidth{false};          // High-bandwidth mode (unsolicited cmpctblock)
    std::atomic<bool> fSentSendCmpct{false};          // We sent sendcmpct to this peer

    //
    // Timestamps
    //
    int64_t nTimeConnected = 0;             // Connection time
    std::atomic<int64_t> nLastRecv{0};      // Last receive time
    std::atomic<int64_t> nLastSend{0};      // Last send time
    std::atomic<int64_t> nLastTXTime{0};    // Last transaction time

    //
    // DoS protection
    //
    std::atomic<int> nMisbehavior{0};       // Misbehavior score
    int64_t nBanTime = 0;                   // Ban expiry time

    //
    // I/O pause flags (for flow control)
    //
    std::atomic<bool> fPauseRecv{false};    // Pause receiving
    std::atomic<bool> fPauseSend{false};    // Pause sending

    //
    // Statistics
    //
    std::atomic<uint64_t> nSendBytes{0};    // Total bytes sent
    std::atomic<uint64_t> nRecvBytes{0};    // Total bytes received

    // NOTE: Block sync state is managed by CPeer, NOT CNode.
    // See CPeerManager::MarkBlockAsInFlight(), etc.
    // This avoids duplicate state that can get out of sync.

    //
    // Constructor
    //
    explicit CNode(int id_in, const NetProtocol::CAddress& addr_in, bool inbound = false);
    ~CNode();

    // No copy
    CNode(const CNode&) = delete;
    CNode& operator=(const CNode&) = delete;

    //
    // Socket management
    //

    /**
     * Set socket handle
     * @param sock Socket file descriptor (takes ownership)
     */
    void SetSocket(int sock);

    /**
     * Get socket handle
     * @return Socket fd or -1 if invalid
     */
    int GetSocket() const;

    /**
     * Check if socket is valid
     */
    bool HasValidSocket() const;

    /**
     * Close socket
     */
    void CloseSocket();

    //
    // Receive buffer (raw bytes from socket)
    // Accessed by ThreadSocketHandler
    //

    /**
     * Append received bytes to buffer
     * @param data Pointer to received data
     * @param len Length of data
     */
    void AppendRecvBytes(const uint8_t* data, size_t len);

    /**
     * Get receive buffer for processing (DEPRECATED - use GetLockedRecvBuffer)
     * Returns reference, caller must hold lock from GetRecvMutex()
     * @warning This is not thread-safe by itself - use GetLockedRecvBuffer() instead
     */
    std::vector<uint8_t>& GetRecvBuffer();

    /**
     * Lock for receive buffer access
     */
    std::mutex& GetRecvMutex() { return cs_vRecv; }

    /**
     * Thread-safe locked access to receive buffer
     * Returns a pair of lock guard and buffer reference
     * Lock is held for the lifetime of the returned lock_guard
     */
    std::pair<std::unique_lock<std::mutex>, std::vector<uint8_t>&> GetLockedRecvBuffer() {
        std::unique_lock<std::mutex> lock(cs_vRecv);
        return {std::move(lock), vRecvMsg};
    }

    //
    // Message queues
    //

    /**
     * Push complete message to processing queue
     * Called by ReceiveMsgBytes when message is complete
     */
    void PushProcessMsg(CProcessedMsg&& msg);

    /**
     * Pop message from processing queue
     * Called by ThreadMessageHandler
     * @return Message or empty if queue empty
     */
    bool PopProcessMsg(CProcessedMsg& msg);

    /**
     * Check if messages waiting
     */
    bool HasProcessMsgs() const;

    /**
     * Push message to send queue
     */
    void PushSendMsg(CSerializedNetMsg&& msg);

    /**
     * Get next message to send (peek, doesn't remove)
     * @return Pointer to message or nullptr
     */
    const CSerializedNetMsg* GetSendMsg() const;

    /**
     * Get current send offset (for partial sends)
     * @return Current offset into first message
     */
    size_t GetSendOffset() const;

    /**
     * Mark bytes as sent, remove message if complete
     * @param bytes Number of bytes sent
     */
    void MarkBytesSent(size_t bytes);

    /**
     * Check if messages waiting to send
     */
    bool HasSendMsgs() const;

    //
    // State helpers
    //

    bool IsConnected() const {
        State s = state.load();
        return s >= STATE_CONNECTED && s < STATE_BANNED && !fDisconnect.load();
    }

    bool IsHandshakeComplete() const {
        return state.load() == STATE_HANDSHAKE_COMPLETE;
    }

    bool IsBanned() const {
        return state.load() == STATE_BANNED;
    }

    /**
     * Mark node for disconnection
     */
    void MarkDisconnect() {
        fDisconnect.store(true);
    }

    /**
     * Get string representation
     */
    std::string ToString() const;

private:
    //
    // Socket
    //
    int m_socket = -1;
    mutable std::mutex m_sock_mutex;

    //
    // Receive buffer (raw bytes)
    //
    std::vector<uint8_t> vRecvMsg;
    mutable std::mutex cs_vRecv;

    //
    // Processing queue (complete messages)
    //
    std::list<CProcessedMsg> vProcessMsg;
    mutable std::mutex cs_vProcessMsg;

    //
    // Send queue
    //
    std::deque<CSerializedNetMsg> vSendMsg;
    size_t nSendOffset = 0;  // Offset into first message
    mutable std::mutex cs_vSendMsg;
};

#endif // DILITHION_NET_NODE_H
