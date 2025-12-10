// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// CConnman - Event-driven connection manager (Bitcoin Core pattern)
// Replaces polling-based CConnectionManager with proper select() blocking
// See: docs/developer/LIBEVENT-NETWORKING-PORT-PLAN.md

#ifndef DILITHION_NET_CONNMAN_H
#define DILITHION_NET_CONNMAN_H

#include <net/node.h>
#include <net/protocol.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

// Forward declarations
class CPeerManager;
class CNetMessageProcessor;

/**
 * Connection manager options
 */
struct CConnmanOptions {
    int nMaxOutbound = 8;
    int nMaxInbound = 117;
    int nMaxTotal = 125;
    std::vector<NetProtocol::CAddress> vSeedNodes;
    bool fListen = true;
    uint16_t nListenPort = 18444;
};

/**
 * CConnman - Central connection manager with event-driven I/O
 *
 * Bitcoin Core pattern: Two-thread architecture
 * - ThreadSocketHandler: Handles all socket I/O with proper select() blocking
 * - ThreadMessageHandler: Processes messages from queue, decoupled from I/O
 *
 * Key improvements over CConnectionManager:
 * - select() blocks until data is available (no busy-polling)
 * - Condition variable wake mechanism (no fixed sleep intervals)
 * - Complete decoupling of I/O from message processing
 */
class CConnman {
public:
    CConnman();
    ~CConnman();

    // Disable copy
    CConnman(const CConnman&) = delete;
    CConnman& operator=(const CConnman&) = delete;

    //
    // Lifecycle management
    //

    /**
     * Start the connection manager
     * @param peer_mgr Peer manager for node tracking
     * @param msg_proc Message processor for handling messages
     * @param options Configuration options
     * @return true if started successfully
     */
    bool Start(CPeerManager& peer_mgr, CNetMessageProcessor& msg_proc, const CConnmanOptions& options);

    /**
     * Stop the connection manager gracefully
     * Waits for threads to finish and cleans up resources
     */
    void Stop();

    /**
     * Interrupt the connection manager
     * Signals threads to stop but doesn't wait for completion
     */
    void Interrupt();

    /**
     * Check if running
     */
    bool IsRunning() const { return !interruptNet.load(); }

    //
    // Connection management
    //

    /**
     * Initiate outbound connection
     * @param addr Address to connect to
     * @return CNode pointer on success, nullptr on failure
     */
    CNode* ConnectNode(const NetProtocol::CAddress& addr);

    /**
     * Accept inbound connection
     * @param socket Accepted socket (takes ownership)
     * @param addr Remote address
     * @return true if accepted
     */
    bool AcceptConnection(std::unique_ptr<class CSocket> socket, const NetProtocol::CAddress& addr);

    /**
     * Disconnect a node
     * @param nodeid Node ID to disconnect
     * @param reason Reason for disconnection (for logging)
     */
    void DisconnectNode(int nodeid, const std::string& reason = "");

    /**
     * Get all connected nodes
     */
    std::vector<CNode*> GetNodes() const;

    /**
     * Get node by ID
     */
    CNode* GetNode(int nodeid) const;

    /**
     * Get connection count
     */
    size_t GetNodeCount() const;

    //
    // Message sending
    //

    /**
     * Push message to outgoing queue
     * Thread-safe, can be called from any thread
     * @param pnode Target node
     * @param msg Message to send
     */
    void PushMessage(CNode* pnode, CSerializedNetMsg&& msg);

    /**
     * Push message by node ID
     */
    void PushMessage(int nodeid, CSerializedNetMsg&& msg);

    /**
     * Push CNetMessage (converts to CSerializedNetMsg)
     * Convenience method for compatibility with existing code
     */
    void PushMessage(int nodeid, const class CNetMessage& msg);

    //
    // Message handler registration
    //

    using MessageHandler = std::function<bool(CNode*, const std::string&, const std::vector<uint8_t>&)>;

    /**
     * Set message handler callback
     * Called by ThreadMessageHandler for each complete message
     */
    void SetMessageHandler(MessageHandler handler) { m_msg_handler = handler; }

private:
    //
    // Thread functions
    //

    /**
     * Socket handler thread (Bitcoin Core: ThreadSocketHandler)
     * - Manages all socket I/O with proper select() blocking
     * - Reads data into node receive buffers
     * - Writes data from node send buffers
     * - Wakes message handler when data is available
     */
    void ThreadSocketHandler();

    /**
     * Message handler thread (Bitcoin Core: ThreadMessageHandler)
     * - Processes messages from node queues
     * - Decoupled from I/O for better performance
     * - Waits on condition variable when idle
     */
    void ThreadMessageHandler();

    /**
     * Open connections thread
     * - Manages outbound connection attempts
     * - Connects to seed nodes
     */
    void ThreadOpenConnections();

    //
    // Socket handling
    //

    /**
     * Main socket event loop
     * Called by ThreadSocketHandler
     */
    void SocketHandler();

    /**
     * Wait for socket events using select()
     * @param recv_set Sockets to check for read readiness (modified)
     * @param send_set Sockets to check for write readiness (modified)
     * @param error_set Sockets to check for errors (modified)
     * @return true if events occurred, false on timeout/interrupt
     */
    bool SocketEventsSelect(std::set<int>& recv_set, std::set<int>& send_set, std::set<int>& error_set);

    /**
     * Receive data from node socket into buffer
     * @param pnode Node to receive from
     * @return true if socket still valid, false on disconnect
     */
    bool ReceiveMsgBytes(CNode* pnode);

    /**
     * Send pending data from node buffer
     * @param pnode Node to send to
     * @return true if socket still valid, false on disconnect
     */
    bool SendMessages(CNode* pnode);

    /**
     * Extract complete messages from node's receive buffer
     * Parses message headers, validates checksums, and pushes to processing queue
     * @param pnode Node to extract messages from
     */
    void ExtractMessages(CNode* pnode);

    /**
     * Wake up the message handler thread
     * Called when new messages are available
     */
    void WakeMessageHandler();

    /**
     * Process disconnected nodes
     * Cleans up nodes marked for disconnect
     */
    void DisconnectNodes();

    /**
     * Check if an address is our own (for self-connection prevention)
     * @param addr Address to check
     * @return true if this is our own address
     */
    bool IsOurAddress(const NetProtocol::CAddress& addr) const;

    //
    // Node management
    //

    std::vector<std::unique_ptr<CNode>> m_nodes;
    mutable std::mutex cs_vNodes;
    int m_next_node_id = 1;

    // Listen socket
    int m_listen_socket = -1;

    //
    // Thread control
    //

    std::atomic<bool> interruptNet{false};
    std::atomic<bool> flagInterruptMsgProc{false};

    // Message handler wake mechanism
    std::condition_variable condMsgProc;
    std::mutex mutexMsgProc;
    std::atomic<bool> fMsgProcWake{false};

    // Threads
    std::thread threadSocketHandler;
    std::thread threadMessageHandler;
    std::thread threadOpenConnections;

    //
    // Configuration
    //

    CConnmanOptions m_options;

    // Local addresses (for self-connection prevention)
    mutable std::mutex cs_localAddresses;
    std::set<std::string> m_localAddresses;

    //
    // External references (set in Start())
    //

    CPeerManager* m_peer_manager = nullptr;
    CNetMessageProcessor* m_msg_processor = nullptr;
    MessageHandler m_msg_handler;
};

#endif // DILITHION_NET_CONNMAN_H
