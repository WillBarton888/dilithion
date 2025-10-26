// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_RPC_SERVER_H
#define DILITHION_RPC_SERVER_H

#include <wallet/wallet.h>
#include <miner/controller.h>
#include <net/net.h>
#include <rpc/ratelimiter.h>

#include <string>
#include <map>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>

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

    // Component references
    CWallet* m_wallet;
    CMiningController* m_miner;
    // CNetworkManager* m_network;  // TODO: Implement network manager

    // RPC handlers
    std::map<std::string, RPCHandler> m_handlers;
    std::mutex m_handlersMutex;

    // Rate limiting
    CRateLimiter m_rateLimiter;

    // Server socket
    int m_serverSocket;

    /**
     * Server thread function
     */
    void ServerThread();

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
     * Execute RPC method
     */
    RPCResponse ExecuteRPC(const RPCRequest& request);

    /**
     * Convert RPCResponse to JSON string
     */
    std::string SerializeResponse(const RPCResponse& response);

    // RPC method handlers

    // Wallet methods
    std::string RPC_GetNewAddress(const std::string& params);
    std::string RPC_GetBalance(const std::string& params);
    std::string RPC_GetAddresses(const std::string& params);
    std::string RPC_SendToAddress(const std::string& params);

    // Wallet encryption methods
    std::string RPC_EncryptWallet(const std::string& params);
    std::string RPC_WalletPassphrase(const std::string& params);
    std::string RPC_WalletLock(const std::string& params);
    std::string RPC_WalletPassphraseChange(const std::string& params);

    // Mining methods
    std::string RPC_GetMiningInfo(const std::string& params);
    std::string RPC_StartMining(const std::string& params);
    std::string RPC_StopMining(const std::string& params);

    // Network methods
    std::string RPC_GetNetworkInfo(const std::string& params);
    std::string RPC_GetPeerInfo(const std::string& params);

    // General methods
    std::string RPC_Help(const std::string& params);
    std::string RPC_Stop(const std::string& params);

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
     * Check if server is running
     */
    bool IsRunning() const { return m_running; }

    /**
     * Get server port
     */
    uint16_t GetPort() const { return m_port; }
};

#endif // DILITHION_RPC_SERVER_H
