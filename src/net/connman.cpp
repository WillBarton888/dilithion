// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// CConnman - Event-driven connection manager implementation
// See: docs/developer/LIBEVENT-NETWORKING-PORT-PLAN.md

#include <net/connman.h>
#include <net/peers.h>
#include <net/net.h>
#include <net/socket.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/serialize.h>
#include <net/banman.h>  // For MisbehaviorType
#include <util/time.h>
#include <util/logging.h>
#include <util/strencodings.h>  // For strprintf

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>  // For std::cout
#include <map>       // For std::map in InactivityCheck
#include <thread>  // For std::this_thread

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
#endif

#include <atomic>

// Socket timeout for select() in milliseconds
static constexpr int SELECT_TIMEOUT_MS = 50;

// BLOCK PIPELINE COUNTERS - Track exactly where blocks are lost
static std::atomic<int> g_blocks_extracted{0};        // Step 1: Extracted from TCP
static std::atomic<int> g_blocks_pushed_to_node{0};   // Step 2: Pushed to node's vProcessMsg
static std::atomic<int> g_blocks_popped_from_node{0}; // Step 3: Popped from vProcessMsg
static std::atomic<int> g_blocks_routed_to_queue{0};  // Step 4: Pushed to m_blocks_queue
static std::atomic<int> g_blocks_worker_received{0};  // Step 5: Popped by BlocksWorkerThread
static std::atomic<int> g_blocks_processed{0};        // Step 6: ProcessQueuedMessage returned

CConnman::CConnman() = default;

CConnman::~CConnman() {
    Interrupt();
    Stop();
}

bool CConnman::Start(CPeerManager& peer_mgr, CNetMessageProcessor& msg_proc, const CConnmanOptions& options) {
    m_peer_manager = &peer_mgr;
    m_msg_processor = &msg_proc;
    m_options = options;

    // Reset interrupt flags
    interruptNet.store(false);
    flagInterruptMsgProc.store(false);

    // Detect local addresses for self-connection prevention
    {
        std::lock_guard<std::mutex> lock(cs_localAddresses);
        m_localAddresses.insert("127.0.0.1");
        m_localAddresses.insert("0.0.0.0");

#ifdef _WIN32
        // Windows: Use gethostname + getaddrinfo
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            struct addrinfo hints, *res, *p;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(hostname, nullptr, &hints, &res) == 0) {
                for (p = res; p != nullptr; p = p->ai_next) {
                    struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ipv4->sin_addr, ip_str, sizeof(ip_str));
                    m_localAddresses.insert(ip_str);
                    LogPrintf(NET, INFO, "[CConnman] Detected local address: %s\n", ip_str);
                }
                freeaddrinfo(res);
            }
        }
#else
        // Linux/macOS: Use getifaddrs
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == 0) {
            for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr == nullptr) continue;
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    struct sockaddr_in* ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ipv4->sin_addr, ip_str, sizeof(ip_str));
                    m_localAddresses.insert(ip_str);
                    LogPrintf(NET, INFO, "[CConnman] Detected local address: %s\n", ip_str);
                }
            }
            freeifaddrs(ifaddr);
        }
#endif
    }

    // Phase 2: Create listen socket if fListen
    if (m_options.fListen) {
        m_listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_listen_socket < 0) {
            LogPrintf(NET, ERROR, "[CConnman] Failed to create listen socket\n");
            return false;
        }

        // Set socket options
        int reuse = 1;
        setsockopt(m_listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

        // Bind to port
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(m_options.nListenPort);

        if (bind(m_listen_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            LogPrintf(NET, ERROR, "[CConnman] Failed to bind listen socket to port %d\n", m_options.nListenPort);
#ifdef _WIN32
            closesocket(m_listen_socket);
#else
            close(m_listen_socket);
#endif
            m_listen_socket = -1;
            return false;
        }

        // Listen
        if (listen(m_listen_socket, 10) < 0) {
            LogPrintf(NET, ERROR, "[CConnman] Failed to listen on socket\n");
#ifdef _WIN32
            closesocket(m_listen_socket);
#else
            close(m_listen_socket);
#endif
            m_listen_socket = -1;
            return false;
        }

        // Set non-blocking
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(m_listen_socket, FIONBIO, &mode);
#else
        int flags = fcntl(m_listen_socket, F_GETFL, 0);
        fcntl(m_listen_socket, F_SETFL, flags | O_NONBLOCK);
#endif

        LogPrintf(NET, INFO, "[CConnman] Listening on port %d\n", m_options.nListenPort);
    }

    // Phase 2: Start ThreadSocketHandler
    try {
        threadSocketHandler = std::thread(&CConnman::ThreadSocketHandler, this);
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to start ThreadSocketHandler: %s\n", e.what());
        return false;
    }

    // Phase 2: Start ThreadMessageHandler
    try {
        threadMessageHandler = std::thread(&CConnman::ThreadMessageHandler, this);
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to start ThreadMessageHandler: %s\n", e.what());
        Interrupt();
        if (threadSocketHandler.joinable()) {
            threadSocketHandler.join();
        }
        return false;
    }

    // Phase 2: Start ThreadOpenConnections
    try {
        threadOpenConnections = std::thread(&CConnman::ThreadOpenConnections, this);
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to start ThreadOpenConnections: %s\n", e.what());
        Interrupt();
        if (threadSocketHandler.joinable()) {
            threadSocketHandler.join();
        }
        if (threadMessageHandler.joinable()) {
            threadMessageHandler.join();
        }
        return false;
    }

    // IBD Redesign Phase 1: Start async message worker threads
    // Headers and blocks are processed in dedicated threads to avoid blocking message handler
    try {
        m_headers_worker_thread = std::thread(&CConnman::HeadersWorkerThread, this);
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to start HeadersWorkerThread: %s\n", e.what());
        Interrupt();
        if (threadSocketHandler.joinable()) threadSocketHandler.join();
        if (threadMessageHandler.joinable()) threadMessageHandler.join();
        if (threadOpenConnections.joinable()) threadOpenConnections.join();
        return false;
    }

    // Start multiple block worker threads for parallel processing
    // This prevents queue bottlenecks when multiple peers send blocks simultaneously
    try {
        for (int i = 0; i < NUM_BLOCK_WORKERS; i++) {
            m_blocks_worker_threads.emplace_back(&CConnman::BlocksWorkerThread, this);
        }
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to start BlocksWorkerThreads: %s\n", e.what());
        Interrupt();
        if (threadSocketHandler.joinable()) threadSocketHandler.join();
        if (threadMessageHandler.joinable()) threadMessageHandler.join();
        if (threadOpenConnections.joinable()) threadOpenConnections.join();
        if (m_headers_worker_thread.joinable()) m_headers_worker_thread.join();
        for (auto& t : m_blocks_worker_threads) {
            if (t.joinable()) t.join();
        }
        return false;
    }

    LogPrintf(NET, INFO, "[CConnman] Started successfully (with async headers + %d parallel block workers)\n", NUM_BLOCK_WORKERS);
    return true;
}

void CConnman::Stop() {
    // Signal interrupt
    Interrupt();

    // Wait for threads
    if (threadSocketHandler.joinable()) {
        threadSocketHandler.join();
    }
    if (threadMessageHandler.joinable()) {
        threadMessageHandler.join();
    }
    if (threadOpenConnections.joinable()) {
        threadOpenConnections.join();
    }

    // IBD Redesign Phase 1: Join async worker threads
    if (m_headers_worker_thread.joinable()) {
        m_headers_worker_thread.join();
    }
    // Join all block worker threads
    for (auto& t : m_blocks_worker_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    m_blocks_worker_threads.clear();

    // Close listen socket
    if (m_listen_socket >= 0) {
#ifdef _WIN32
        closesocket(m_listen_socket);
#else
        close(m_listen_socket);
#endif
        m_listen_socket = -1;
    }

    // Disconnect all nodes
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        for (auto& node : m_nodes) {
            node->CloseSocket();
        }
        m_nodes.clear();
    }

    LogPrintf(NET, INFO, "[CConnman] Stopped\n");
}

void CConnman::Interrupt() {
    interruptNet.store(true);
    flagInterruptMsgProc.store(true);

    // Wake message handler
    WakeMessageHandler();

    // IBD Redesign Phase 1: Wake async worker threads so they can exit
    m_headers_cv.notify_all();
    m_blocks_cv.notify_all();
}

CNode* CConnman::ConnectNode(const NetProtocol::CAddress& addr) {
    // Phase 2: Implement outbound connection

    // Extract IP string from address (needed for logging and self-connection check)
    std::string ip_str = strprintf("%d.%d.%d.%d",
                                   addr.ip[12], addr.ip[13], addr.ip[14], addr.ip[15]);

    // Prevent self-connection: check if target is our own listen address
    if (m_options.fListen && addr.port == m_options.nListenPort) {
        // Check if connecting to our own IP (or localhost)
        if (IsOurAddress(addr)) {
            LogPrintf(NET, WARN, "[CConnman] Preventing self-connection to %s:%d\n",
                      ip_str.c_str(), addr.port);
            return nullptr;
        }
    }

    // Check connection limits
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        size_t outbound_count = 0;
        for (const auto& node : m_nodes) {
            if (!node->fInbound) {
                outbound_count++;
            }
        }
        if (outbound_count >= static_cast<size_t>(m_options.nMaxOutbound)) {
            LogPrintf(NET, WARN, "[CConnman] Outbound connection limit reached (%zu/%d)\n",
                      outbound_count, m_options.nMaxOutbound);
            return nullptr;
        }
    }

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to create socket for %s:%d\n",
                  ip_str.c_str(), addr.port);
        return nullptr;
    }

    // Set non-blocking
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    // Connect
    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip_str.c_str(), &sockaddr.sin_addr);
    sockaddr.sin_port = htons(addr.port);

    int result = connect(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr));
#ifdef _WIN32
    int err = WSAGetLastError();
    if (result < 0 && err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
        closesocket(sock);
        LogPrintf(NET, ERROR, "[CConnman] Failed to connect to %s:%d (error %d)\n",
                  ip_str.c_str(), addr.port, err);
        return nullptr;
    }
#else
    if (result < 0 && errno != EINPROGRESS && errno != EAGAIN) {
        close(sock);
        LogPrintf(NET, ERROR, "[CConnman] Failed to connect to %s:%d (error %d)\n",
                  ip_str.c_str(), addr.port, errno);
        return nullptr;
    }
#endif

    // Phase 2: Create CNode directly (CConnman owns nodes)
    int node_id = m_next_node_id++;
    auto node = std::make_unique<CNode>(node_id, addr, false);  // false = outbound
    CNode* pnode = node.get();

    // Set socket and state
    pnode->SetSocket(sock);
    pnode->state.store(CNode::STATE_CONNECTING);

    // Add to m_nodes
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        m_nodes.push_back(std::move(node));
    }

    // Register with CPeerManager for state synchronization
    // FIX Issue 1: Pass CNode pointer so CPeerManager can sync state
    m_peer_manager->RegisterNode(node_id, pnode, addr, false);

    LogPrintf(NET, INFO, "[CConnman] Connecting to %s:%d (node %d)\n",
              ip_str.c_str(), addr.port, pnode->id);
    return pnode;
}

bool CConnman::AcceptConnection(std::unique_ptr<CSocket> socket, const NetProtocol::CAddress& addr) {
    // Phase 2: Implement inbound connection acceptance
    if (!socket || !socket->IsValid()) {
        LogPrintf(NET, ERROR, "[CConnman] AcceptConnection: invalid socket\n");
        return false;
    }

    // Check connection limits
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        size_t inbound_count = 0;
        size_t total_count = m_nodes.size();
        for (const auto& node : m_nodes) {
            if (node->fInbound) {
                inbound_count++;
            }
        }
        if (inbound_count >= static_cast<size_t>(m_options.nMaxInbound)) {
            LogPrintf(NET, WARN, "[CConnman] Inbound connection limit reached (%zu/%d)\n",
                      inbound_count, m_options.nMaxInbound);
            return false;
        }
        if (total_count >= static_cast<size_t>(m_options.nMaxTotal)) {
            LogPrintf(NET, WARN, "[CConnman] Total connection limit reached (%zu/%d)\n",
                      total_count, m_options.nMaxTotal);
            return false;
        }
    }

    // Extract IP string
    std::string ip_str = strprintf("%d.%d.%d.%d",
                                   addr.ip[12], addr.ip[13], addr.ip[14], addr.ip[15]);

    // Check if IP is banned
    if (m_peer_manager && m_peer_manager->IsBanned(ip_str)) {
        LogPrintf(NET, WARN, "[CConnman] Rejecting connection from banned IP %s\n", ip_str.c_str());
        return false;
    }

    // Phase 2: Create CNode directly (CConnman owns nodes)
    int node_id = m_next_node_id++;
    auto node = std::make_unique<CNode>(node_id, addr, true);  // true = inbound
    CNode* pnode = node.get();

    // Get socket FD from CSocket and release ownership
    // ReleaseFD() transfers ownership so CSocket won't close it
    int sock_fd = socket->ReleaseFD();
    if (sock_fd < 0) {
        LogPrintf(NET, ERROR, "[CConnman] AcceptConnection: failed to get socket FD\n");
        return false;
    }
    
    // Set socket options on the raw FD
    // Set non-blocking
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock_fd, FIONBIO, &mode);
#else
    int flags = fcntl(sock_fd, F_GETFL, 0);
    fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);
#endif

    pnode->SetSocket(sock_fd);
    pnode->state.store(CNode::STATE_CONNECTED);

    // Socket is now released and owned by CNode
    socket.reset();

    // Add to m_nodes
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        m_nodes.push_back(std::move(node));
    }

    // Register with CPeerManager for state synchronization
    // FIX Issue 1: Pass CNode pointer so CPeerManager can sync state
    m_peer_manager->RegisterNode(node_id, pnode, addr, true);

    LogPrintf(NET, INFO, "[CConnman] Accepted connection from %s:%d (node %d)\n",
              ip_str.c_str(), addr.port, node_id);
    return true;
}

void CConnman::DisconnectNode(int nodeid, const std::string& reason) {
    std::lock_guard<std::mutex> lock(cs_vNodes);
    for (auto& node : m_nodes) {
        if (node->id == nodeid) {
            if (!reason.empty()) {
                LogPrintf(NET, INFO, "[CConnman] Disconnecting node %d: %s\n", nodeid, reason.c_str());
            }
            node->MarkDisconnect();
            return;
        }
    }
}

std::vector<CNode*> CConnman::GetNodes() const {
    std::vector<CNode*> result;
    std::lock_guard<std::mutex> lock(cs_vNodes);
    result.reserve(m_nodes.size());
    for (const auto& node : m_nodes) {
        result.push_back(node.get());
    }
    return result;
}

CNode* CConnman::GetNode(int nodeid) const {
    std::lock_guard<std::mutex> lock(cs_vNodes);
    for (const auto& node : m_nodes) {
        if (node->id == nodeid) {
            return node.get();
        }
    }
    return nullptr;
}

size_t CConnman::GetNodeCount() const {
    std::lock_guard<std::mutex> lock(cs_vNodes);
    return m_nodes.size();
}

void CConnman::PushMessage(CNode* pnode, CSerializedNetMsg&& msg) {
    if (!pnode) return;
    pnode->PushSendMsg(std::move(msg));
}

bool CConnman::PushMessage(int nodeid, CSerializedNetMsg&& msg) {
    CNode* pnode = GetNode(nodeid);
    if (!pnode) {
        LogPrintf(NET, WARN, "[CConnman] PushMessage failed: node %d not found\n", nodeid);
        return false;
    }
    PushMessage(pnode, std::move(msg));
    return true;
}

bool CConnman::PushMessage(int nodeid, const CNetMessage& msg) {
    // Convert CNetMessage to CSerializedNetMsg
    std::string command = msg.header.GetCommand();
    std::vector<uint8_t> data = msg.Serialize();
    CSerializedNetMsg serialized(std::move(command), std::move(data));
    return PushMessage(nodeid, std::move(serialized));
}

void CConnman::PushMessage(CNode* pnode, const CNetMessage& msg) {
    if (!pnode) return;
    // Convert CNetMessage to CSerializedNetMsg
    std::string command = msg.header.GetCommand();
    std::vector<uint8_t> data = msg.Serialize();
    CSerializedNetMsg serialized(std::move(command), std::move(data));
    PushMessage(pnode, std::move(serialized));
}

void CConnman::WakeMessageHandler() {
    {
        std::lock_guard<std::mutex> lock(mutexMsgProc);
        fMsgProcWake.store(true);
    }
    condMsgProc.notify_one();
}

void CConnman::ThreadSocketHandler() {
    LogPrintf(NET, INFO, "[CConnman] ThreadSocketHandler started\n");

    // Track when we last ran inactivity check (don't run every iteration)
    auto last_inactivity_check = std::chrono::steady_clock::now();
    static constexpr int INACTIVITY_CHECK_INTERVAL_SECONDS = 10;

    while (!interruptNet.load()) {
        DisconnectNodes();
        SocketHandler();

        // Run inactivity check periodically (every 10 seconds)
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_inactivity_check).count()
                >= INACTIVITY_CHECK_INTERVAL_SECONDS) {
            InactivityCheck();
            last_inactivity_check = now;
        }
    }

    LogPrintf(NET, INFO, "[CConnman] ThreadSocketHandler stopped\n");
}

void CConnman::ThreadMessageHandler() {
    LogPrintf(NET, INFO, "[CConnman] ThreadMessageHandler started (async dispatch mode)\n");

    while (!flagInterruptMsgProc.load()) {
        bool fMoreWork = false;

        // IBD Redesign Phase 1: Collect messages and route by type
        // Headers and blocks go to async queues (never block this thread)
        // Control messages (version, verack, ping, pong, etc.) process inline (fast)

        struct PendingMessage {
            int node_id;
            CProcessedMsg msg;
        };
        std::vector<PendingMessage> pending_messages;

        // Collect messages while holding cs_vNodes (short lock duration)
        {
            std::lock_guard<std::mutex> lock(cs_vNodes);

            // Fairness: Max messages per node per batch
            constexpr int MAX_MSGS_PER_NODE_PER_BATCH = 50;
            // Global batch limit
            constexpr int MAX_MSGS_TOTAL_PER_BATCH = 500;

            for (auto& node : m_nodes) {
                if (node->fDisconnect.load()) {
                    continue;
                }

                int msgs_from_this_node = 0;
                CProcessedMsg processed_msg;
                while (node->PopProcessMsg(processed_msg)) {
                    // PIPELINE COUNTER: Step 3 - Block popped from node's vProcessMsg
                    if (processed_msg.command == "block") {
                        g_blocks_popped_from_node++;
                    }
                    pending_messages.push_back({node->id, std::move(processed_msg)});
                    msgs_from_this_node++;

                    if (msgs_from_this_node >= MAX_MSGS_PER_NODE_PER_BATCH) {
                        break;
                    }
                    if (pending_messages.size() >= static_cast<size_t>(MAX_MSGS_TOTAL_PER_BATCH)) {
                        fMoreWork = true;
                        break;
                    }
                }

                if (node->HasProcessMsgs()) {
                    fMoreWork = true;
                }

                if (pending_messages.size() >= static_cast<size_t>(MAX_MSGS_TOTAL_PER_BATCH)) {
                    break;
                }
            }
        }
        // cs_vNodes released

        // Route messages by type
        int headers_queued = 0;
        int blocks_queued = 0;
        int control_processed = 0;

        for (const auto& pending : pending_messages) {
            const std::string& cmd = pending.msg.command;

            // IBD Redesign: Route headers and blocks to async queues
            if (cmd == "headers") {
                // Queue for async processing - NEVER BLOCK HERE
                {
                    std::lock_guard<std::mutex> lock(m_headers_queue_mutex);
                    m_headers_queue.push({pending.node_id, pending.msg.command, pending.msg.data});
                }
                m_headers_cv.notify_one();
                headers_queued++;
            }
            else if (cmd == "block") {
                // Queue for async processing - NEVER BLOCK HERE
                {
                    std::lock_guard<std::mutex> lock(m_blocks_queue_mutex);
                    m_blocks_queue.push({pending.node_id, pending.msg.command, pending.msg.data});
                }
                m_blocks_cv.notify_one();
                blocks_queued++;
                // PIPELINE COUNTER: Step 4 - Block pushed to m_blocks_queue
                g_blocks_routed_to_queue++;
            }
            else {
                // Control messages: process inline (fast - version, verack, ping, pong, inv, getdata, etc.)
                bool success = ProcessQueuedMessage({pending.node_id, pending.msg.command, pending.msg.data});
                if (!success) {
                    LogPrintf(NET, WARN, "[CConnman] Failed to process control message '%s' from node %d\n",
                              cmd.c_str(), pending.node_id);
                }
                control_processed++;
            }
        }

        // Log routing summary (reduced logging)
        if (headers_queued > 0 || blocks_queued > 0) {
            LogPrintf(NET, DEBUG, "[CConnman] Routed: %d headers, %d blocks to async; %d control inline\n",
                      headers_queued, blocks_queued, control_processed);
        }

        // Wait for more work
        if (!fMoreWork && !flagInterruptMsgProc.load()) {
            std::unique_lock<std::mutex> lock(mutexMsgProc);
            condMsgProc.wait_for(lock, std::chrono::milliseconds(100), [this] {
                return fMsgProcWake.load() || flagInterruptMsgProc.load();
            });
            fMsgProcWake.store(false);
        }
    }

    LogPrintf(NET, INFO, "[CConnman] ThreadMessageHandler stopped\n");
}

// IBD Redesign Phase 1: Helper to process a queued message
bool CConnman::ProcessQueuedMessage(const QueuedMessage& msg) {
    // Convert to CNetMessage
    CNetMessage message(msg.command, msg.data);

    // Process using message processor or fallback handler
    bool success = false;
    if (m_msg_processor) {
        success = m_msg_processor->ProcessMessage(msg.node_id, message);
    } else if (m_msg_handler) {
        // Fallback to callback if processor not set
        std::lock_guard<std::mutex> lock(cs_vNodes);
        for (auto& node : m_nodes) {
            if (node->id == msg.node_id && !node->fDisconnect.load()) {
                success = m_msg_handler(node.get(), msg.command, msg.data);
                break;
            }
        }
    }

    // Handle misbehavior tracking on failure
    if (!success && m_peer_manager) {
        auto peer = m_peer_manager->GetPeer(msg.node_id);
        if (peer && peer->misbehavior_score > 100) {
            LogPrintf(NET, INFO, "[CConnman] Disconnecting node %d due to misbehavior (score: %d)\n",
                      msg.node_id, peer->misbehavior_score);
            std::lock_guard<std::mutex> lock(cs_vNodes);
            for (auto& node : m_nodes) {
                if (node->id == msg.node_id) {
                    node->MarkDisconnect();
                    break;
                }
            }
        }
    }

    return success;
}

// IBD Redesign Phase 1: Headers worker thread
// Processes headers messages asynchronously - headers processing can take 100+ seconds
// for 2000 headers with RandomX, so this MUST NOT block the message handler
void CConnman::HeadersWorkerThread() {
    LogPrintf(NET, INFO, "[CConnman] HeadersWorkerThread started\n");

    while (!flagInterruptMsgProc.load()) {
        QueuedMessage msg;

        // Wait for work
        {
            std::unique_lock<std::mutex> lock(m_headers_queue_mutex);
            m_headers_cv.wait(lock, [this] {
                return !m_headers_queue.empty() || flagInterruptMsgProc.load();
            });

            if (flagInterruptMsgProc.load()) {
                break;
            }

            if (m_headers_queue.empty()) {
                continue;
            }

            msg = std::move(m_headers_queue.front());
            m_headers_queue.pop();
        }

        // Process headers message (expensive - RandomX hash computation)
        LogPrintf(NET, DEBUG, "[HeadersWorker] Processing headers from node %d\n", msg.node_id);
        auto start = std::chrono::steady_clock::now();

        bool success = ProcessQueuedMessage(msg);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        LogPrintf(NET, DEBUG, "[HeadersWorker] Processed headers from node %d in %lld ms (success=%d)\n",
                  msg.node_id, elapsed, success);
    }

    LogPrintf(NET, INFO, "[CConnman] HeadersWorkerThread stopped\n");
}

// IBD Redesign Phase 1: Blocks worker thread
// Processes block messages asynchronously - block validation can take time
// and we don't want to block the message handler
void CConnman::BlocksWorkerThread() {
    LogPrintf(NET, INFO, "[CConnman] BlocksWorkerThread started\n");

    while (!flagInterruptMsgProc.load()) {
        QueuedMessage msg;

        // Wait for work
        {
            std::unique_lock<std::mutex> lock(m_blocks_queue_mutex);
            m_blocks_cv.wait(lock, [this] {
                return !m_blocks_queue.empty() || flagInterruptMsgProc.load();
            });

            if (flagInterruptMsgProc.load()) {
                break;
            }

            if (m_blocks_queue.empty()) {
                continue;
            }

            msg = std::move(m_blocks_queue.front());
            m_blocks_queue.pop();
        }

        // PIPELINE COUNTER: Step 5 - Block popped by BlocksWorkerThread
        g_blocks_worker_received++;

        // Process block message
        LogPrintf(NET, DEBUG, "[BlocksWorker] Processing block from node %d\n", msg.node_id);
        auto start = std::chrono::steady_clock::now();

        bool success = ProcessQueuedMessage(msg);

        // PIPELINE COUNTER: Step 6 - Block processed
        g_blocks_processed++;

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        LogPrintf(NET, DEBUG, "[BlocksWorker] Processed block from node %d in %lld ms (success=%d)\n",
                  msg.node_id, elapsed, success);

        // PIPELINE COUNTER SUMMARY - Log every block to find where they drop
        LogPrintf(NET, INFO, "[PIPELINE] extracted=%d pushed=%d popped=%d routed=%d worker=%d processed=%d\n",
                  g_blocks_extracted.load(), g_blocks_pushed_to_node.load(),
                  g_blocks_popped_from_node.load(), g_blocks_routed_to_queue.load(),
                  g_blocks_worker_received.load(), g_blocks_processed.load());
    }

    LogPrintf(NET, INFO, "[CConnman] BlocksWorkerThread stopped\n");
}

void CConnman::ThreadOpenConnections() {
    LogPrintf(NET, INFO, "[CConnman] ThreadOpenConnections started\n");

    // Bitcoin Core pattern: Maintain target of 8 outbound connections
    constexpr size_t TARGET_OUTBOUND = 8;
    constexpr int CONNECTION_INTERVAL_SECONDS = 60;  // Check every minute

    while (!interruptNet.load()) {
        // Wait for connection interval or interrupt
        for (int i = 0; i < CONNECTION_INTERVAL_SECONDS && !interruptNet.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        if (interruptNet.load()) {
            break;
        }

        if (!m_peer_manager || !m_msg_processor) {
            continue;  // Not initialized yet
        }

        // Check if we need more outbound connections
        size_t outbound_count = m_peer_manager->GetOutboundCount();
        if (outbound_count >= TARGET_OUTBOUND) {
            continue;  // Already have enough
        }

        size_t needed = TARGET_OUTBOUND - outbound_count;
        LogPrintf(NET, DEBUG, "[CConnman] Need %zu more outbound connections (have %zu, target %zu)\n",
                  needed, outbound_count, TARGET_OUTBOUND);

        // Get addresses from AddrMan (request extra in case some fail or are connected)
        auto addrs = m_peer_manager->SelectAddressesToConnect(static_cast<int>(needed * 3));
        if (addrs.empty()) {
            LogPrintf(NET, DEBUG, "[CConnman] No addresses available for outbound connections\n");
            continue;
        }

        // Get currently connected peer IPs to skip
        std::set<std::string> connected_ips;
        {
            std::lock_guard<std::mutex> lock(cs_vNodes);
            for (const auto& node : m_nodes) {
                if (node && !node->fInbound && !node->fDisconnect.load()) {
                    connected_ips.insert(node->addr.ToStringIP());
                }
            }
        }

        // Attempt connections
        size_t connections_made = 0;
        for (const auto& addr : addrs) {
            if (connections_made >= needed) {
                break;
            }

            std::string ip_str = addr.ToStringIP();

            // Skip already connected
            if (connected_ips.count(ip_str)) {
                continue;
            }

            // Skip non-routable
            if (!addr.IsRoutable()) {
                continue;
            }

            // Mark as tried before attempting
            m_peer_manager->MarkAddressTried(addr);

            // Attempt connection
            CNode* pnode = ConnectNode(addr);
            if (pnode) {
                // BUG #139 FIX: Don't send VERSION here - SocketHandler will send it
                // after connection completes (STATE_CONNECTING -> STATE_CONNECTED)
                LogPrintf(NET, INFO, "[CConnman] ThreadOpenConnections: initiated connection to %s (node %d)\n",
                          ip_str.c_str(), pnode->id);
                connections_made++;
                // Mark as good on successful connection
                m_peer_manager->MarkAddressGood(addr);
            }
        }

        if (connections_made > 0) {
            LogPrintf(NET, INFO, "[CConnman] Made %zu new outbound connection(s)\n", connections_made);
        }
    }

    LogPrintf(NET, INFO, "[CConnman] ThreadOpenConnections stopped\n");
}

void CConnman::SocketHandler() {
    std::set<int> recv_set, send_set, error_set;

    // Collect sockets
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        for (const auto& node : m_nodes) {
            int sock = node->GetSocket();
            if (sock < 0) continue;
            if (node->fDisconnect.load()) {
                LogPrintf(NET, DEBUG, "[CConnman] Node %d marked for disconnect, skipping\n", node->id);
                continue;
            }

            recv_set.insert(sock);
            // Add to send_set if: has messages to send OR connection is in progress
            // For non-blocking connect(), writability indicates connection completed
            int node_state = node->state.load();
            bool has_send = node->HasSendMsgs();
            if (has_send || node_state == CNode::STATE_CONNECTING) {
                send_set.insert(sock);
            }
            error_set.insert(sock);

            // Debug: Log each node's state periodically (every 100th call)
            static int call_count = 0;
            if (++call_count % 100 == 0) {
                LogPrintf(NET, DEBUG, "[CConnman] SocketHandler: node %d state=%d has_send=%d sock=%d\n",
                          node->id, node_state, has_send, sock);
            }
        }
    }

    // Add listen socket
    if (m_listen_socket >= 0) {
        recv_set.insert(m_listen_socket);
    }

    // Wait for events
    if (!SocketEventsSelect(recv_set, send_set, error_set)) {
        return;  // Timeout or interrupt
    }

    // Handle listen socket (new connections)
    // BUG #137 FIX: Loop to accept ALL pending connections, not just one
    // Multiple connections can arrive between select() calls
    if (m_listen_socket >= 0 && recv_set.count(m_listen_socket)) {
        while (true) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);

            int client_fd = accept(m_listen_socket, (struct sockaddr*)&client_addr, &addr_len);
            if (client_fd < 0) {
#ifdef _WIN32
                int err = WSAGetLastError();
                if (err != WSAEWOULDBLOCK) {
                    LogPrintf(NET, ERROR, "[CConnman] Accept failed: %d\n", err);
                }
#else
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    LogPrintf(NET, ERROR, "[CConnman] Accept failed: %d\n", errno);
                }
#endif
                break;  // No more pending connections
            }

            // Set non-blocking
#ifdef _WIN32
            u_long mode = 1;
            ioctlsocket(client_fd, FIONBIO, &mode);
#else
            int flags = fcntl(client_fd, F_GETFL, 0);
            fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
#endif

            // Extract address
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
            uint16_t port = ntohs(client_addr.sin_port);

            // Create address
            NetProtocol::CAddress addr;
            // Convert IP string to bytes (IPv4-mapped IPv6 format)
            struct in_addr in;
            inet_pton(AF_INET, ip_str, &in);
            // Set IPv4 address in IPv6-mapped format (bytes 12-15)
            memset(addr.ip, 0, 16);
            memcpy(&addr.ip[12], &in.s_addr, 4);
            addr.port = port;
            addr.services = NetProtocol::NODE_NETWORK;

            // Create CNode
            int node_id = m_next_node_id++;
            auto node = std::make_unique<CNode>(node_id, addr, true);  // true = inbound
            CNode* pnode = node.get();

            pnode->SetSocket(client_fd);
            pnode->state.store(CNode::STATE_CONNECTED);

            // Add to m_nodes
            {
                std::lock_guard<std::mutex> lock(cs_vNodes);
                m_nodes.push_back(std::move(node));
            }

            // Register with CPeerManager for state synchronization
            m_peer_manager->RegisterNode(node_id, pnode, addr, true);

            LogPrintf(NET, INFO, "[CConnman] Accepted inbound connection from %s:%d (node %d)\n",
                      ip_str, port, node_id);
        }
    }

    // Handle each node
    bool fWakeMessageHandler = false;

    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        for (auto& node : m_nodes) {
            int sock = node->GetSocket();
            if (sock < 0) continue;

            // Check for errors
            if (error_set.count(sock)) {
                node->MarkDisconnect();
                continue;
            }

            // Check for connect completion (writability on CONNECTING socket)
            if (node->state.load() == CNode::STATE_CONNECTING && send_set.count(sock)) {
                // Check if connection completed successfully
                int error = 0;
                socklen_t len = sizeof(error);
#ifdef _WIN32
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len) == 0) {
#else
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
#endif
                    if (error == 0) {
                        // Connection succeeded
                        node->state.store(CNode::STATE_CONNECTED);
                        LogPrintf(NET, INFO, "[CConnman] Connection established to node %d\n", node->id);

                        // BUG #139 FIX: Send VERSION immediately after connection completes
                        // Only send if node is outbound and VERSION hasn't been sent yet
                        if (!node->fInbound && !node->fVersionSent.load()) {
                            if (m_msg_processor) {
                                NetProtocol::CAddress local_addr;
                                local_addr.services = NetProtocol::NODE_NETWORK;
                                local_addr.SetIPv4(0);
                                local_addr.port = 0;
                                CNetMessage version_msg = m_msg_processor->CreateVersionMessage(node->addr, local_addr);
                                PushMessage(node.get(), version_msg);
                                node->fVersionSent.store(true);
                                // BUG #148 FIX: Also update CNode::state to prevent state drift
                                node->state.store(CNode::STATE_VERSION_SENT);
                                LogPrintf(NET, INFO, "[CConnman] Sent VERSION to node %d after connect\n", node->id);

                                // SSOT FIX #1: Update CNode::state (single source of truth) first
                                // CNode::state is authoritative - CPeer::state is deprecated
                                node->state.store(CNode::STATE_VERSION_SENT);
                                node->fVersionSent.store(true);
                                // Update deprecated CPeer::state for backward compatibility
                                if (m_peer_manager) {
                                    auto peer = m_peer_manager->GetPeer(node->id);
                                    if (peer) {
                                        peer->state = CPeer::STATE_VERSION_SENT;
                                    }
                                }
                            } else {
                                LogPrintf(NET, WARN, "[CConnman] Cannot send VERSION to node %d - m_msg_processor is null\n", node->id);
                            }
                        }
                    } else {
                        // Connection failed
                        LogPrintf(NET, WARN, "[CConnman] Connection to node %d failed: error %d\n", node->id, error);
                        node->MarkDisconnect();
                        continue;
                    }
                } else {
                    // getsockopt failed
                    node->MarkDisconnect();
                    continue;
                }
            }

            // Receive
            if (recv_set.count(sock)) {
                if (!ReceiveMsgBytes(node.get())) {
                    node->MarkDisconnect();
                } else if (node->HasProcessMsgs()) {
                    fWakeMessageHandler = true;
                }
            }

            // Send (only if not just connecting)
            if (send_set.count(sock) && node->state.load() != CNode::STATE_CONNECTING) {
                if (!SendMessages(node.get())) {
                    node->MarkDisconnect();
                }
            }
        }
    }

    if (fWakeMessageHandler) {
        WakeMessageHandler();
    }
}

bool CConnman::SocketEventsSelect(std::set<int>& recv_set, std::set<int>& send_set, std::set<int>& error_set) {
    if (recv_set.empty() && send_set.empty()) {
        // Nothing to wait for, just sleep briefly
        std::this_thread::sleep_for(std::chrono::milliseconds(SELECT_TIMEOUT_MS));
        return false;
    }

    fd_set fd_recv, fd_send, fd_error;
    FD_ZERO(&fd_recv);
    FD_ZERO(&fd_send);
    FD_ZERO(&fd_error);

    int max_fd = 0;

    for (int sock : recv_set) {
        FD_SET(sock, &fd_recv);
        if (sock > max_fd) max_fd = sock;
    }
    for (int sock : send_set) {
        FD_SET(sock, &fd_send);
        if (sock > max_fd) max_fd = sock;
    }
    for (int sock : error_set) {
        FD_SET(sock, &fd_error);
        if (sock > max_fd) max_fd = sock;
    }

    struct timeval timeout;
    timeout.tv_sec = SELECT_TIMEOUT_MS / 1000;
    timeout.tv_usec = (SELECT_TIMEOUT_MS % 1000) * 1000;

    int result = select(max_fd + 1, &fd_recv, &fd_send, &fd_error, &timeout);

    if (result <= 0) {
        recv_set.clear();
        send_set.clear();
        error_set.clear();
        return false;
    }

    // Update sets to only include ready sockets
    std::set<int> ready_recv, ready_send, ready_error;
    for (int sock : recv_set) {
        if (FD_ISSET(sock, &fd_recv)) ready_recv.insert(sock);
    }
    for (int sock : send_set) {
        if (FD_ISSET(sock, &fd_send)) ready_send.insert(sock);
    }
    for (int sock : error_set) {
        if (FD_ISSET(sock, &fd_error)) ready_error.insert(sock);
    }

    recv_set = std::move(ready_recv);
    send_set = std::move(ready_send);
    error_set = std::move(ready_error);

    return true;
}

bool CConnman::ReceiveMsgBytes(CNode* pnode) {
    if (!pnode) return false;

    int sock = pnode->GetSocket();
    if (sock < 0) return false;

    uint8_t buf[4096];
    int nBytes;

#ifdef _WIN32
    nBytes = recv(sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
    if (nBytes == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return true;  // No data, but socket OK
        }
        LogPrintf(NET, DEBUG, "[CConnman] recv() error on node %d: %d\n", pnode->id, err);
        return false;  // Real error
    }
#else
    nBytes = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
    if (nBytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return true;  // No data, but socket OK
        }
        LogPrintf(NET, DEBUG, "[CConnman] recv() error on node %d: errno=%d\n", pnode->id, errno);
        return false;  // Real error
    }
#endif

    if (nBytes == 0) {
        LogPrintf(NET, INFO, "[CConnman] Connection closed by peer (node %d)\n", pnode->id);
        return false;  // Connection closed
    }

    // Append to node's receive buffer
    pnode->AppendRecvBytes(buf, nBytes);
    pnode->nRecvBytes.fetch_add(nBytes);
    pnode->nLastRecv.store(GetTime());

    // Extract complete messages from buffer and push to processing queue
    ExtractMessages(pnode);

    return true;
}

bool CConnman::SendMessages(CNode* pnode) {
    if (!pnode) return false;

    int sock = pnode->GetSocket();
    if (sock < 0) return false;

    while (pnode->HasSendMsgs()) {
        const CSerializedNetMsg* msg = pnode->GetSendMsg();
        if (!msg || msg->data.empty()) break;

        // Get current send offset (for partial sends)
        size_t offset = pnode->GetSendOffset();
        size_t remaining = msg->data.size() - offset;
        
        if (remaining == 0) {
            // Message fully sent, move to next
            pnode->MarkBytesSent(msg->data.size());
            continue;
        }

        int nBytes;
#ifdef _WIN32
        nBytes = send(sock, reinterpret_cast<const char*>(msg->data.data() + offset),
                      static_cast<int>(remaining), 0);
        if (nBytes == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                break;  // Would block, try later
            }
            return false;  // Real error
        }
#else
        nBytes = send(sock, msg->data.data() + offset, remaining, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (nBytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  // Would block, try later
            }
            return false;  // Real error
        }
#endif

        if (nBytes > 0) {
            pnode->MarkBytesSent(nBytes);
            pnode->nSendBytes.fetch_add(nBytes);
            pnode->nLastSend.store(GetTime());
        }
    }

    return true;
}

void CConnman::ExtractMessages(CNode* pnode) {
    if (!pnode) return;

    // Extract complete messages from receive buffer
    // Loop until no more complete messages can be extracted
    while (true) {
        std::lock_guard<std::mutex> lock(pnode->GetRecvMutex());
        auto& buffer = pnode->GetRecvBuffer();

        // Need at least 24 bytes for message header
        if (buffer.size() < 24) {
            break;  // Not enough data for header
        }

        // Parse message header
        NetProtocol::CMessageHeader header;
        std::memcpy(&header.magic, buffer.data(), 4);
        std::memcpy(header.command, buffer.data() + 4, 12);
        std::memcpy(&header.payload_size, buffer.data() + 16, 4);
        std::memcpy(&header.checksum, buffer.data() + 20, 4);

        // DEBUG: Log parsed header
        std::string cmd = header.GetCommand();
        std::cout << "[EXTRACT-DEBUG] node=" << pnode->id << " cmd=" << cmd
                  << " payload_size=" << header.payload_size
                  << " buffer=" << buffer.size() << std::endl;

        // Validate header
        if (!header.IsValid(NetProtocol::g_network_magic)) {
            std::cout << "[P2P] ERROR: Invalid magic from node " << pnode->id
                      << " (got 0x" << std::hex << header.magic
                      << ", expected 0x" << NetProtocol::g_network_magic << std::dec << ")" << std::endl;
            
            // Clear buffer and disconnect on invalid magic
            buffer.clear();
            pnode->MarkDisconnect();
            return;
        }

        // Check payload size
        if (header.payload_size > NetProtocol::MAX_MESSAGE_SIZE) {
            std::cout << "[P2P] ERROR: Payload too large from node " << pnode->id
                      << " (" << header.payload_size << " bytes)" << std::endl;
            
            // Clear buffer and disconnect on oversized message
            buffer.clear();
            pnode->MarkDisconnect();
            return;
        }

        // Calculate total message size
        size_t total_size = 24 + header.payload_size;

        // Check if we have the complete message
        if (buffer.size() < total_size) {
            // DEBUG: Log partial message waiting
            if (cmd == "block") {
                std::cout << "[EXTRACT-PARTIAL] node=" << pnode->id << " cmd=" << cmd
                          << " need=" << total_size << " have=" << buffer.size() << std::endl;
            }
            break;  // Partial message, need more data
        }

        // Extract payload
        std::vector<uint8_t> payload;
        if (header.payload_size > 0) {
            payload.assign(buffer.begin() + 24, buffer.begin() + 24 + header.payload_size);

            // Verify checksum (Bitcoin Core pattern - critical for message integrity)
            uint32_t calculated_checksum = CDataStream::CalculateChecksum(payload);
            if (calculated_checksum != header.checksum) {
                std::cout << "[P2P] ERROR: Checksum mismatch from node " << pnode->id
                          << " (got 0x" << std::hex << header.checksum
                          << ", expected 0x" << calculated_checksum << std::dec << ")" << std::endl;
                
                // Clear buffer and disconnect on checksum failure
                buffer.clear();
                pnode->MarkDisconnect();
                
                // Penalize node for checksum failure (could be attack or corruption)
                if (m_peer_manager) {
                    // Find corresponding peer if it exists
                    auto peers = m_peer_manager->GetAllPeers();
                    for (auto& peer : peers) {
                        if (peer->id == pnode->id) {
                            m_peer_manager->Misbehaving(peer->id, 50, MisbehaviorType::INVALID_CHECKSUM);
                            break;
                        }
                    }
                }
                return;
            }
        }

        // Remove processed message from buffer
        buffer.erase(buffer.begin(), buffer.begin() + total_size);

        // Create processed message and push to queue
        std::string command = header.GetCommand();

        // DEBUG: Log when message is fully extracted and pushed to queue
        std::cout << "[EXTRACT-PUSHED] node=" << pnode->id << " cmd=" << command
                  << " payload_size=" << header.payload_size << std::endl;

        // PIPELINE COUNTER: Step 1 & 2 - Block extracted from TCP and pushed to vProcessMsg
        // Note: Steps 1 & 2 are atomic (PushProcessMsg is just a vector push)
        bool is_block = (command == "block");
        if (is_block) {
            g_blocks_extracted++;
            g_blocks_pushed_to_node++;
        }

        CProcessedMsg processed_msg(std::move(command), std::move(payload));
        pnode->PushProcessMsg(std::move(processed_msg));
    }
}

void CConnman::DisconnectNodes() {
    // BUG #148 + BUG #153 FIX: Remove from CPeerManager BEFORE destroying CNode
    // This eliminates race window where node_refs could point to freed memory
    std::vector<int> nodes_to_remove;

    {
        std::lock_guard<std::mutex> lock(cs_vNodes);

        auto it = m_nodes.begin();
        while (it != m_nodes.end()) {
            if ((*it)->fDisconnect.load()) {
                int node_id = (*it)->id;
                nodes_to_remove.push_back(node_id);

                // BUG #153 FIX: Remove from CPeerManager BEFORE destroying CNode
                // This ensures node_refs is cleared while CNode still exists
                if (m_peer_manager) {
                    m_peer_manager->RemoveNode(node_id);
                }

                (*it)->CloseSocket();
                it = m_nodes.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Notify disconnection AFTER erase (safe since peer already removed)
    if (m_peer_manager) {
        for (int node_id : nodes_to_remove) {
            m_peer_manager->OnPeerDisconnected(node_id);
        }
    }
}

void CConnman::InactivityCheck() {
    // Constants for keepalive
    static constexpr int64_t PING_INTERVAL_SECONDS = 60;      // Send ping after 60s of inactivity
    static constexpr int64_t TIMEOUT_SECONDS = 120;           // Disconnect after 120s of no response

    // Track last ping sent time per node (static to persist across calls)
    static std::map<int, int64_t> last_ping_sent;

    int64_t now = GetTime();
    std::vector<int> nodes_to_disconnect;

    {
        std::lock_guard<std::mutex> lock(cs_vNodes);

        for (auto& node : m_nodes) {
            if (node->fDisconnect.load()) continue;

            // Skip nodes that haven't completed handshake
            if (node->state.load() != CNode::STATE_CONNECTED) continue;

            int64_t last_recv = node->nLastRecv.load();
            int node_id = node->id;

            // If we've never received anything, use connect time
            if (last_recv == 0) {
                // Node just connected, give it time
                continue;
            }

            int64_t idle_time = now - last_recv;

            // Check if node is completely unresponsive (no data for TIMEOUT_SECONDS)
            if (idle_time > TIMEOUT_SECONDS) {
                // Check if we already sent a ping and got no response
                auto it = last_ping_sent.find(node_id);
                if (it != last_ping_sent.end() && (now - it->second) > PING_INTERVAL_SECONDS) {
                    // Ping was sent but no response - disconnect
                    LogPrintf(NET, WARN, "[CConnman] Node %d unresponsive for %llds, disconnecting\n",
                              node_id, idle_time);
                    nodes_to_disconnect.push_back(node_id);
                    last_ping_sent.erase(it);
                    continue;
                }
            }

            // Send ping if idle for PING_INTERVAL_SECONDS and we haven't pinged recently
            if (idle_time > PING_INTERVAL_SECONDS) {
                auto it = last_ping_sent.find(node_id);
                bool should_ping = (it == last_ping_sent.end()) ||
                                   (now - it->second > PING_INTERVAL_SECONDS);

                if (should_ping && m_msg_processor) {
                    // Generate random nonce for ping
                    uint64_t nonce = ((uint64_t)rand() << 32) | rand();
                    CNetMessage ping_msg = m_msg_processor->CreatePingMessage(nonce);
                    PushMessage(node.get(), ping_msg);
                    last_ping_sent[node_id] = now;

                    LogPrintf(NET, INFO, "[CConnman] Sent keepalive ping to node %d (idle %llds)\n",
                              node_id, idle_time);
                }
            }
        }
    }

    // Disconnect unresponsive nodes
    for (int node_id : nodes_to_disconnect) {
        DisconnectNode(node_id, "inactivity timeout");
    }

    // Clean up stale entries from last_ping_sent for disconnected nodes
    for (auto it = last_ping_sent.begin(); it != last_ping_sent.end(); ) {
        bool found = false;
        {
            std::lock_guard<std::mutex> lock(cs_vNodes);
            for (const auto& node : m_nodes) {
                if (node->id == it->first) {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            it = last_ping_sent.erase(it);
        } else {
            ++it;
        }
    }
}

bool CConnman::IsOurAddress(const NetProtocol::CAddress& addr) const {
    // Extract IP string from address
    std::string ip_str = strprintf("%d.%d.%d.%d",
                                   addr.ip[12], addr.ip[13], addr.ip[14], addr.ip[15]);

    // Check localhost variants
    if (ip_str == "127.0.0.1" || ip_str == "0.0.0.0") {
        return true;
    }

    // Check against known local addresses
    std::lock_guard<std::mutex> lock(cs_localAddresses);
    return m_localAddresses.count(ip_str) > 0;
}
