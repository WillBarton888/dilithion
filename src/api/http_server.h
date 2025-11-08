// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_API_HTTP_SERVER_H
#define DILITHION_API_HTTP_SERVER_H

#include <string>
#include <thread>
#include <atomic>
#include <functional>

/**
 * CHttpServer - Lightweight HTTP server for REST API
 *
 * Provides simple HTTP server for exposing node statistics via REST API.
 * Supports:
 * - GET /api/stats - Returns JSON with current node statistics
 * - CORS headers for cross-origin requests
 * - Non-blocking operation with background thread
 * - Graceful shutdown
 *
 * Usage:
 *   CHttpServer server(8334);
 *   server.SetStatsHandler([]() { return GetNodeStats(); });
 *   server.Start();
 */
class CHttpServer {
public:
    /**
     * Stats handler function type
     * Should return JSON string with current node statistics
     */
    using StatsHandler = std::function<std::string()>;

    /**
     * Constructor
     * @param port Port to listen on (default: 8334 for testnet)
     */
    explicit CHttpServer(int port = 8334);

    /**
     * Destructor - ensures server is stopped
     */
    ~CHttpServer();

    // Disable copy/move
    CHttpServer(const CHttpServer&) = delete;
    CHttpServer& operator=(const CHttpServer&) = delete;

    /**
     * Set stats handler function
     * @param handler Function that returns JSON stats string
     */
    void SetStatsHandler(StatsHandler handler);

    /**
     * Start the HTTP server
     * @return true if started successfully
     */
    bool Start();

    /**
     * Stop the HTTP server
     */
    void Stop();

    /**
     * Check if server is running
     * @return true if server thread is active
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * Get server port
     * @return Port number
     */
    int GetPort() const { return m_port; }

private:
    /**
     * Server thread main loop
     * Listens for HTTP connections and handles requests
     */
    void ServerThread();

    /**
     * Handle a single HTTP request
     * @param client_socket Socket file descriptor for client connection
     */
    void HandleRequest(int client_socket);

    /**
     * Parse HTTP request and extract method and path
     * @param request Raw HTTP request string
     * @param method Output parameter for HTTP method (GET, POST, etc)
     * @param path Output parameter for request path
     * @return true if parsed successfully
     */
    bool ParseRequest(const std::string& request, std::string& method, std::string& path);

    /**
     * Send HTTP response
     * @param client_socket Socket file descriptor
     * @param status_code HTTP status code (200, 404, etc)
     * @param content_type Content-Type header value
     * @param body Response body
     */
    void SendResponse(int client_socket, int status_code,
                     const std::string& content_type,
                     const std::string& body);

    /**
     * Send 404 Not Found response
     * @param client_socket Socket file descriptor
     */
    void Send404(int client_socket);

    /**
     * Send 500 Internal Server Error response
     * @param client_socket Socket file descriptor
     */
    void Send500(int client_socket);

    // Configuration
    int m_port;                          // Server port
    StatsHandler m_stats_handler;         // Stats handler function

    // Server state
    std::thread m_server_thread;          // Server worker thread
    std::atomic<bool> m_running{false};   // Running flag
    int m_server_socket{-1};              // Server socket file descriptor
};

/**
 * Global HTTP server instance (initialized in dilithion-node.cpp)
 */
extern CHttpServer* g_http_server;

#endif // DILITHION_API_HTTP_SERVER_H
