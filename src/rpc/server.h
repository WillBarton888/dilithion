// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_RPC_SERVER_H
#define DILITHION_RPC_SERVER_H

#include <wallet/wallet.h>
#include <miner/controller.h>
#include <net/net.h>
#include <rpc/ratelimiter.h>
#include <rpc/permissions.h>
#include <rpc/logger.h>
#include <rpc/ssl_wrapper.h>
#include <rpc/websocket.h>

#include <string>
#include <sstream>
#include <map>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
#include <atomic>
#include <queue>
#include <condition_variable>

/**
 * JSON-RPC 2.0 Request
 */
struct RPCRequest {
    std::string jsonrpc;  // Should be "2.0"
    std::string method;
    std::string params;   // JSON string
    std::string id;

    RPCRequest() : jsonrpc("2.0") {}
};

/**
 * JSON-RPC 2.0 Response
 */
struct RPCResponse {
    std::string jsonrpc;  // Should be "2.0"
    std::string result;   // JSON string (if success)
    std::string error;    // JSON string (if error)
    std::string id;

    RPCResponse() : jsonrpc("2.0") {}

    static RPCResponse Success(const std::string& result, const std::string& id) {
        RPCResponse resp;
        resp.result = result;
        resp.id = id;
        return resp;
    }

    static RPCResponse Error(int code, const std::string& message, const std::string& id) {
        RPCResponse resp;
        resp.error = "{\"code\":" + std::to_string(code) +
                     ",\"message\":\"" + message + "\"}";
        resp.id = id;
        return resp;
    }
    
    // UX: Enhanced error response with structured information
    static RPCResponse ErrorStructured(int code, const std::string& message, 
                                       const std::string& id,
                                       const std::string& error_code = "",
                                       const std::vector<std::string>& recovery_steps = {}) {
        RPCResponse resp;
        std::ostringstream oss;
        oss << "{\"code\":" << code << ",\"message\":\"" << message << "\"";
        if (!error_code.empty()) {
            oss << ",\"error_code\":\"" << error_code << "\"";
        }
        if (!recovery_steps.empty()) {
            oss << ",\"recovery_steps\":[";
            for (size_t i = 0; i < recovery_steps.size(); ++i) {
                if (i > 0) oss << ",";
                oss << "\"" << recovery_steps[i] << "\"";
            }
            oss << "]";
        }
        oss << "}";
        resp.error = oss.str();
        resp.id = id;
        return resp;
    }
};

/**
 * RPC Handler function type
 * Takes params JSON string, returns result JSON string
 * Throws std::runtime_error on error
 */
using RPCHandler = std::function<std::string(const std::string&)>;

/**
 * RPC Server - Lightweight JSON-RPC 2.0 over HTTP
 *
 * Features:
 * - JSON-RPC 2.0 protocol
 * - HTTP/1.1 transport
 * - Thread-safe request handling
 * - Wallet, mining, and network endpoints
 *
 * Usage:
 *   CRPCServer server(8332);
 *   server.RegisterWallet(&wallet);
 *   server.RegisterMiner(&miner);
 *   server.Start();
 */
class CRPCServer {
private:
    uint16_t m_port;
    std::atomic<bool> m_running{false};
    std::thread m_serverThread;
    std::thread m_cleanupThread;  // Rate limiter cleanup thread

    // RPC-002: Thread Pool Implementation
    std::vector<std::thread> m_workerThreads;
    std::queue<int> m_clientQueue;        // Queue of pending client sockets
    std::mutex m_queueMutex;              // Protects client queue
    std::condition_variable m_queueCV;    // Notifies workers of new work
    size_t m_threadPoolSize;              // Number of worker threads (default 8)

    // Component references
    CWallet* m_wallet;
    CMiningController* m_miner;
    class CTxMemPool* m_mempool;
    class CBlockchainDB* m_blockchain;
    class CUTXOSet* m_utxo_set;
    class CChainState* m_chainstate;

    // Network configuration
    bool m_testnet{false};
    // CNetworkManager* m_network;  // TODO: Implement network manager

    // RPC handlers
    std::map<std::string, RPCHandler> m_handlers;
    std::mutex m_handlersMutex;

    // Rate limiting
    CRateLimiter m_rateLimiter;

    // FIX-014: Role-based access control (RBAC)
    std::unique_ptr<CRPCPermissions> m_permissions;

    // Phase 1: Request logging and auditing
    std::unique_ptr<CRPCLogger> m_logger;

    // Phase 3: SSL/TLS support
    std::unique_ptr<CSSLWrapper> m_ssl_wrapper;
    bool m_ssl_enabled;
    std::map<int, SSL*> m_ssl_connections;  // Map socket to SSL connection
    std::mutex m_ssl_mutex;  // Protects SSL connections map

    // Phase 4: WebSocket server
    std::unique_ptr<class CWebSocketServer> m_websocket_server;

    // Server socket
    int m_serverSocket;

    /**
     * Server thread function
     */
    void ServerThread();

    /**
     * Worker thread function (RPC-002)
     * Processes client connections from the queue
     */
    void WorkerThread();

    /**
     * Cleanup thread function (rate limiter maintenance)
     */
    void CleanupThread();

    /**
     * Handle a single client connection
     */
    void HandleClient(int clientSocket);

    /**
     * Parse HTTP POST request, extract JSON-RPC body
     */
    bool ParseHTTPRequest(const std::string& request, std::string& jsonrpc);

    /**
     * Build HTTP response
     */
    std::string BuildHTTPResponse(const std::string& body);

    /**
     * Build HTTP 401 Unauthorized response
     */
    std::string BuildHTTPUnauthorized();

    /**
     * Extract Authorization header from HTTP request
     */
    bool ExtractAuthHeader(const std::string& request, std::string& authHeader);

    /**
     * Parse JSON-RPC request
     */
    RPCRequest ParseRPCRequest(const std::string& json);

    /**
     * Phase 2: Parse batch JSON-RPC request
     */
    std::vector<RPCRequest> ParseBatchRPCRequest(const std::string& json);

    /**
     * Execute RPC method
     */
    RPCResponse ExecuteRPC(const RPCRequest& request);
    
    /**
     * Phase 2: Execute batch RPC requests
     * @param requests Vector of RPCRequest objects
     * @param clientIP Client IP address (for logging)
     * @param username Username (for logging)
     * @return Vector of RPCResponse objects
     */
    std::vector<RPCResponse> ExecuteBatchRPC(const std::vector<RPCRequest>& requests,
                                            const std::string& clientIP,
                                            const std::string& username);

    /**
     * Convert RPCResponse to JSON string
     */
    std::string SerializeResponse(const RPCResponse& response);
    
    /**
     * Phase 2: Serialize batch RPC responses to JSON array string
     * @param responses Vector of RPCResponse objects
     * @return JSON array string
     */
    std::string SerializeBatchResponse(const std::vector<RPCResponse>& responses);

    // RPC method handlers

    // Wallet information methods
    std::string RPC_GetNewAddress(const std::string& params);
    std::string RPC_GetBalance(const std::string& params);
    std::string RPC_GetAddresses(const std::string& params);
    std::string RPC_ListUnspent(const std::string& params);

    // Transaction creation methods
    std::string RPC_SendToAddress(const std::string& params);
    std::string RPC_SignRawTransaction(const std::string& params);
    std::string RPC_SendRawTransaction(const std::string& params);

    // Transaction query methods
    std::string RPC_GetTransaction(const std::string& params);
    std::string RPC_ListTransactions(const std::string& params);
    std::string RPC_GetMempoolInfo(const std::string& params);

    // Blockchain query methods
    std::string RPC_GetBlockchainInfo(const std::string& params);
    std::string RPC_GetBlock(const std::string& params);
    std::string RPC_GetBlockHash(const std::string& params);
    std::string RPC_GetTxOut(const std::string& params);
    std::string RPC_CheckChain(const std::string& params);

    // Wallet encryption methods
    std::string RPC_EncryptWallet(const std::string& params);
    std::string RPC_WalletPassphrase(const std::string& params);
    std::string RPC_WalletLock(const std::string& params);
    std::string RPC_WalletPassphraseChange(const std::string& params);

    // HD Wallet methods
    std::string RPC_CreateHDWallet(const std::string& params);
    std::string RPC_RestoreHDWallet(const std::string& params);
    std::string RPC_ExportMnemonic(const std::string& params);
    std::string RPC_GetHDWalletInfo(const std::string& params);
    std::string RPC_ListHDAddresses(const std::string& params);

    // Mining methods
    std::string RPC_GetMiningInfo(const std::string& params);
    std::string RPC_StartMining(const std::string& params);
    std::string RPC_StopMining(const std::string& params);

    // Network methods
    std::string RPC_GetNetworkInfo(const std::string& params);
    std::string RPC_GetPeerInfo(const std::string& params);
    std::string RPC_GetConnectionCount(const std::string& params);

    // General methods
    std::string RPC_Help(const std::string& params);
    std::string RPC_Stop(const std::string& params);

    // Missing blockchain query methods (for functional tests)
    std::string RPC_GetBlockCount(const std::string& params);
    std::string RPC_GetBestBlockHash(const std::string& params);
    std::string RPC_GetChainTips(const std::string& params);

    // Missing mempool methods
    std::string RPC_GetRawMempool(const std::string& params);

    // Missing mining methods
    std::string RPC_GenerateToAddress(const std::string& params);

    // Missing transaction methods
    std::string RPC_GetRawTransaction(const std::string& params);
    std::string RPC_DecodeRawTransaction(const std::string& params);

    // Missing network methods
    std::string RPC_AddNode(const std::string& params);

    // Helper functions
    std::string FormatAmount(CAmount amount) const;
    bool ValidateAddress(const std::string& addressStr, CDilithiumAddress& addressOut) const;
    std::string EscapeJSON(const std::string& str) const;

public:
    /**
     * Constructor
     * @param port RPC server port (default 8332)
     */
    explicit CRPCServer(uint16_t port = 8332);

    /**
     * Destructor - ensures server is stopped
     */
    ~CRPCServer();

    // Prevent copying
    CRPCServer(const CRPCServer&) = delete;
    CRPCServer& operator=(const CRPCServer&) = delete;

    /**
     * Register wallet instance
     */
    void RegisterWallet(CWallet* wallet) { m_wallet = wallet; }

    /**
     * Register miner instance
     */
    void RegisterMiner(CMiningController* miner) { m_miner = miner; }

    /**
     * Register mempool instance
     */
    void RegisterMempool(class CTxMemPool* mempool) { m_mempool = mempool; }

    /**
     * Register blockchain database instance
     */
    void RegisterBlockchain(class CBlockchainDB* blockchain) { m_blockchain = blockchain; }

    /**
     * Register UTXO set instance
     */
    void RegisterUTXOSet(class CUTXOSet* utxo_set) { m_utxo_set = utxo_set; }

    /**
     * Register chain state instance
     */
    void RegisterChainState(class CChainState* chainstate) { m_chainstate = chainstate; }

    /**
     * Set testnet mode
     */
    void SetTestnet(bool testnet) { m_testnet = testnet; }

    /**
     * Register network manager instance
     * TODO: Implement when network manager is ready
     */
    // void RegisterNetwork(CNetworkManager* network) { m_network = network; }

    /**
     * Start RPC server
     * @return true if started successfully
     */
    bool Start();

    /**
     * Stop RPC server
     */
    void Stop();

    /**
     * FIX-014: Initialize permission system
     *
     * Loads user permissions from configuration file. If file doesn't exist
     * or cannot be loaded, falls back to legacy mode (single admin user).
     *
     * This must be called before Start() to enable authorization checking.
     *
     * @param configPath Path to rpc_permissions.json (e.g., "~/.dilithion/rpc_permissions.json")
     * @param legacyUser Legacy username (used if config file missing)
     * @param legacyPassword Legacy password (used if config file missing)
     * @return true if initialized successfully, false on error
     *
     * Example:
     *   server.InitializePermissions("~/.dilithion/rpc_permissions.json", "admin", "password");
     */
    bool InitializePermissions(const std::string& configPath,
                              const std::string& legacyUser,
                              const std::string& legacyPassword);

    /**
     * Check if server is running
     */
    bool IsRunning() const { return m_running; }

    /**
     * Get server port
     */
    uint16_t GetPort() const { return m_port; }

    /**
     * Phase 1: Initialize logging
     * @param log_file Path to request log file (empty = disabled)
     * @param audit_file Path to audit log file (empty = disabled)
     * @param level Minimum log level
     */
    void InitializeLogging(const std::string& log_file = "",
                          const std::string& audit_file = "",
                          CRPCLogger::LogLevel level = CRPCLogger::LogLevel::INFO);

    /**
     * Phase 3: Initialize SSL/TLS support
     * @param cert_file Path to certificate file (PEM format)
     * @param key_file Path to private key file (PEM format)
     * @param ca_file Optional path to CA certificate file
     * @return true if initialization successful, false on error
     */
    bool InitializeSSL(const std::string& cert_file,
                      const std::string& key_file,
                      const std::string& ca_file = "");

    /**
     * Phase 3: Check if SSL is enabled
     */
    bool IsSSLEnabled() const { return m_ssl_enabled; }

    /**
     * Phase 4: Get WebSocket server instance
     */
    class CWebSocketServer* GetWebSocketServer() const { return m_websocket_server.get(); }
    
    /**
     * Phase 4: Initialize WebSocket server
     * @param port WebSocket server port (0 = disabled)
     * @return true if initialized successfully
     */
    bool InitializeWebSocket(uint16_t port = 0);
};

#endif // DILITHION_RPC_SERVER_H
