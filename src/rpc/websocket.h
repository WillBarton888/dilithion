// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_RPC_WEBSOCKET_H
#define DILITHION_RPC_WEBSOCKET_H

#include <string>
#include <functional>
#include <memory>
#include <map>
#include <mutex>
#include <vector>

// Forward declarations for OpenSSL types (same pattern as ssl_wrapper.h)
struct ssl_st;
typedef struct ssl_st SSL;

/**
 * Phase 4: WebSocket Server for Real-Time Updates
 * 
 * Implements WebSocket protocol (RFC 6455) for bidirectional communication.
 * Supports:
 * - WebSocket handshake
 * - Frame encoding/decoding
 * - Text and binary messages
 * - Ping/pong for keepalive
 * - Close handshake
 */
class CWebSocketServer {
public:
    /**
     * WebSocket frame opcodes
     */
    enum class Opcode {
        CONTINUATION = 0x0,
        TEXT = 0x1,
        BINARY = 0x2,
        CLOSE = 0x8,
        PING = 0x9,
        PONG = 0xA
    };

    /**
     * WebSocket connection state
     */
    struct WebSocketConnection {
        int socket_fd;
        SSL* ssl;  // Phase 3: SSL connection if TLS enabled
        bool is_ssl;
        bool handshake_complete;
        std::string client_ip;
        std::string subprotocol;
        
        WebSocketConnection() : socket_fd(-1), ssl(nullptr), is_ssl(false),
                               handshake_complete(false) {}
    };

    /**
     * Message callback type
     * Called when a message is received from a WebSocket client
     */
    using MessageCallback = std::function<void(int connection_id, const std::string& message, bool is_text)>;

    /**
     * Constructor
     * @param port WebSocket server port (default: same as RPC port + 1)
     */
    explicit CWebSocketServer(uint16_t port);

    /**
     * Destructor
     */
    ~CWebSocketServer();

    /**
     * Start WebSocket server
     * @return true if started successfully, false on error
     */
    bool Start();

    /**
     * Stop WebSocket server
     */
    void Stop();

    /**
     * Check if server is running
     */
    bool IsRunning() const { return m_running; }

    /**
     * Set message callback
     * @param callback Function called when message is received
     */
    void SetMessageCallback(MessageCallback callback) { m_message_callback = callback; }

    /**
     * Send message to WebSocket client
     * @param connection_id Connection ID
     * @param message Message to send
     * @param is_text true for text message, false for binary
     * @return true if sent successfully, false on error
     */
    bool SendMessage(int connection_id, const std::string& message, bool is_text = true);

    /**
     * Broadcast message to all connected clients
     * @param message Message to broadcast
     * @param is_text true for text message, false for binary
     * @return Number of clients message was sent to
     */
    size_t BroadcastMessage(const std::string& message, bool is_text = true);

    /**
     * Close WebSocket connection
     * @param connection_id Connection ID
     */
    void CloseConnection(int connection_id);

    /**
     * Get number of connected clients
     */
    size_t GetConnectionCount() const;

    /**
     * Phase 3: Initialize SSL/TLS for WebSocket
     * @param cert_file Path to certificate file
     * @param key_file Path to private key file
     * @return true if initialized successfully
     */
    bool InitializeSSL(const std::string& cert_file, const std::string& key_file);

private:
    uint16_t m_port;
    std::atomic<bool> m_running{false};
    int m_server_socket;
    std::thread m_server_thread;
    
    // Connections
    std::map<int, std::unique_ptr<WebSocketConnection>> m_connections;
    std::mutex m_connections_mutex;
    int m_next_connection_id;
    
    // Message callback
    MessageCallback m_message_callback;
    
    // Phase 3: SSL support
    std::unique_ptr<class CSSLWrapper> m_ssl_wrapper;
    bool m_ssl_enabled;

    /**
     * Server thread function
     */
    void ServerThread();

    /**
     * Handle new client connection
     * @param client_socket Client socket file descriptor
     */
    void HandleClient(int client_socket);

    /**
     * Perform WebSocket handshake
     * @param request HTTP request string
     * @param connection Connection to complete handshake for
     * @return true if handshake successful, false on error
     */
    bool PerformHandshake(const std::string& request, WebSocketConnection& connection);

    /**
     * Read WebSocket frame
     * @param connection WebSocket connection
     * @param frame_data Output frame data
     * @param opcode Output opcode
     * @return true if frame read successfully, false on error
     */
    bool ReadFrame(WebSocketConnection& connection, std::string& frame_data, Opcode& opcode);

    /**
     * Write WebSocket frame
     * @param connection WebSocket connection
     * @param data Frame data
     * @param opcode Frame opcode
     * @return true if frame written successfully, false on error
     */
    bool WriteFrame(WebSocketConnection& connection, const std::string& data, Opcode opcode);

    /**
     * Generate WebSocket accept key
     * @param client_key Client's Sec-WebSocket-Key
     * @return Accept key
     */
    std::string GenerateAcceptKey(const std::string& client_key);

    /**
     * Read from socket (works with both plain and SSL)
     */
    int SocketRead(WebSocketConnection& connection, void* buffer, int size);

    /**
     * Write to socket (works with both plain and SSL)
     */
    int SocketWrite(WebSocketConnection& connection, const void* buffer, int size);
};

#endif // DILITHION_RPC_WEBSOCKET_H

