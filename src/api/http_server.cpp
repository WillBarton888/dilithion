// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <api/http_server.h>
#include <api/wallet_html.h>
#include <iostream>
#include <cstring>
#include <sstream>
#ifndef _WIN32
#include <errno.h>
#endif

// Cross-platform socket headers
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")

    // Windows socket compatibility
    typedef int socklen_t;
    #define SHUT_RDWR SD_BOTH
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <fcntl.h>

    // Linux socket compatibility
    typedef int SOCKET;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

// Constructor
CHttpServer::CHttpServer(int port)
    : m_port(port) {
}

// Destructor
CHttpServer::~CHttpServer() {
    Stop();
}

// Set stats handler function
void CHttpServer::SetStatsHandler(StatsHandler handler) {
    m_stats_handler = handler;
}

// Start the HTTP server
bool CHttpServer::Start() {
    if (m_running.load()) {
        std::cerr << "[HttpServer] Already running" << std::endl;
        return false;
    }

#ifdef _WIN32
    // Initialize Winsock on Windows
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "[HttpServer] WSAStartup failed: " << result << std::endl;
        return false;
    }
#endif

    // Create server socket
    m_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_server_socket == INVALID_SOCKET) {
        std::cerr << "[HttpServer] Failed to create socket" << std::endl;
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    // Set socket options to allow reuse
    int opt = 1;
#ifdef _WIN32
    if (setsockopt(m_server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
#else
    if (setsockopt(m_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
#endif
        std::cerr << "[HttpServer] Failed to set socket options" << std::endl;
        close(m_server_socket);
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    // Bind to port
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(m_port);

    if (bind(m_server_socket, (struct sockaddr*)&address, sizeof(address)) == SOCKET_ERROR) {
        std::cerr << "[HttpServer] Failed to bind to port " << m_port << std::endl;
        close(m_server_socket);
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    // Listen for connections
    if (listen(m_server_socket, 10) == SOCKET_ERROR) {
        std::cerr << "[HttpServer] Failed to listen on port " << m_port << std::endl;
        close(m_server_socket);
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    m_running.store(true);

    // Launch server thread
    try {
        m_server_thread = std::thread(&CHttpServer::ServerThread, this);
        std::cout << "[HttpServer] Started on port " << m_port << std::endl;
        return true;
    } catch (const std::exception& e) {
        m_running.store(false);
        close(m_server_socket);
#ifdef _WIN32
        WSACleanup();
#endif
        std::cerr << "[HttpServer] Failed to start server thread: " << e.what() << std::endl;
        return false;
    }
}

// Stop the HTTP server
void CHttpServer::Stop() {
    if (!m_running.load()) {
        return;
    }

    std::cout << "[HttpServer] Stopping..." << std::endl;

    // Signal server to stop
    m_running.store(false);

    // Close server socket to unblock accept()
    if (m_server_socket != INVALID_SOCKET) {
        shutdown(m_server_socket, SHUT_RDWR);
        close(m_server_socket);
        m_server_socket = INVALID_SOCKET;
    }

    // Wait for server thread to finish
    if (m_server_thread.joinable()) {
        m_server_thread.join();
    }

#ifdef _WIN32
    // Cleanup Winsock on Windows
    WSACleanup();
#endif

    std::cout << "[HttpServer] Stopped" << std::endl;
}

// Server thread main loop
void CHttpServer::ServerThread() {
    std::cout << "[HttpServer] Server thread started" << std::endl;

    while (m_running.load()) {
        // Accept connection
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);
        SOCKET client_socket = accept(m_server_socket,
                                       (struct sockaddr*)&client_address,
                                       &client_len);

        if (client_socket == INVALID_SOCKET) {
            if (m_running.load()) {
                std::cerr << "[HttpServer] Failed to accept connection" << std::endl;
            }
            continue;
        }

        // Handle request (synchronous for simplicity)
        try {
            HandleRequest(client_socket);
        } catch (const std::exception& e) {
            std::cerr << "[HttpServer] Exception handling request: " << e.what() << std::endl;
        }

        // Close client socket
        close(client_socket);
    }

    std::cout << "[HttpServer] Server thread stopped" << std::endl;
}

// Handle a single HTTP request
void CHttpServer::HandleRequest(SOCKET client_socket) {
    // Read request
    char buffer[4096];
#ifdef _WIN32
    int bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
#else
    ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
#endif

    if (bytes_read <= 0) {
        return;
    }

    buffer[bytes_read] = '\0';
    std::string request(buffer);

    // Parse request
    std::string method, path;
    if (!ParseRequest(request, method, path)) {
        Send500(client_socket);
        return;
    }

    // Handle GET /wallet or /wallet.html - serve embedded web wallet
    if (method == "GET" && (path == "/wallet" || path == "/wallet.html" || path == "/")) {
        try {
            const std::string& html = GetWalletHTML();
            SendResponse(client_socket, 200, "text/html; charset=utf-8", html);
        } catch (const std::exception& e) {
            std::cerr << "[HttpServer] Error serving wallet: " << e.what() << std::endl;
            Send500(client_socket);
        }
        return;
    }

    // Handle GET /api/stats
    if (method == "GET" && path == "/api/stats") {
        if (!m_stats_handler) {
            Send500(client_socket);
            return;
        }

        try {
            std::string json = m_stats_handler();
            SendResponse(client_socket, 200, "application/json", json);
        } catch (const std::exception& e) {
            std::cerr << "[HttpServer] Error generating stats: " << e.what() << std::endl;
            Send500(client_socket);
        }
        return;
    }

    // Handle OPTIONS (for CORS preflight)
    if (method == "OPTIONS") {
        SendResponse(client_socket, 200, "text/plain", "");
        return;
    }

    // Not found
    Send404(client_socket);
}

// Parse HTTP request
bool CHttpServer::ParseRequest(const std::string& request,
                               std::string& method,
                               std::string& path) {
    std::istringstream stream(request);
    std::string http_version;

    // Parse first line: METHOD PATH HTTP/1.1
    if (!(stream >> method >> path >> http_version)) {
        return false;
    }

    return true;
}

// Send HTTP response
void CHttpServer::SendResponse(SOCKET client_socket,
                               int status_code,
                               const std::string& content_type,
                               const std::string& body) {
    std::ostringstream response;

    // Status line
    response << "HTTP/1.1 " << status_code << " ";
    switch (status_code) {
        case 200: response << "OK"; break;
        case 404: response << "Not Found"; break;
        case 500: response << "Internal Server Error"; break;
        default: response << "Unknown"; break;
    }
    response << "\r\n";

    // CORS headers
    response << "Access-Control-Allow-Origin: *\r\n";
    response << "Access-Control-Allow-Methods: GET, OPTIONS\r\n";
    response << "Access-Control-Allow-Headers: Content-Type\r\n";

    // Content headers
    response << "Content-Type: " << content_type << "\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";

    // Body
    response << body;

    // Send response
    std::string response_str = response.str();
    // CID 1675271 FIX: Check return value of send to ensure data was sent successfully
    // send() returns number of bytes sent on success, or SOCKET_ERROR (-1) on error
    // On Windows, SOCKET_ERROR is -1. On Unix, -1 indicates error and errno is set.
    size_t response_len = response_str.length();
#ifdef _WIN32
    int bytes_sent = send(client_socket, response_str.c_str(), static_cast<int>(response_len), 0);
    if (bytes_sent == SOCKET_ERROR) {
        // Failed to send response - log error but continue (connection may be closed)
        int error = WSAGetLastError();
        std::cerr << "[HttpServer] Warning: Failed to send HTTP response (error: " << error << ")" << std::endl;
    } else if (static_cast<size_t>(bytes_sent) != response_len) {
        // Partial send - log warning (connection may be closing)
        std::cerr << "[HttpServer] Warning: Partial HTTP response sent (" << bytes_sent 
                  << " of " << response_len << " bytes)" << std::endl;
    }
#else
    ssize_t bytes_sent = send(client_socket, response_str.c_str(), response_len, MSG_NOSIGNAL);
    if (bytes_sent < 0) {
        // Failed to send response - log error but continue (connection may be closed)
        std::cerr << "[HttpServer] Warning: Failed to send HTTP response (" << strerror(errno) << ")" << std::endl;
    } else if (static_cast<size_t>(bytes_sent) != response_len) {
        // Partial send - log warning (connection may be closing)
        std::cerr << "[HttpServer] Warning: Partial HTTP response sent (" << bytes_sent 
                  << " of " << response_len << " bytes)" << std::endl;
    }
#endif
}

// Send 404 Not Found
void CHttpServer::Send404(SOCKET client_socket) {
    std::string body = R"({"error": "Not Found"})";
    SendResponse(client_socket, 404, "application/json", body);
}

// Send 500 Internal Server Error
void CHttpServer::Send500(SOCKET client_socket) {
    std::string body = R"({"error": "Internal Server Error"})";
    SendResponse(client_socket, 500, "application/json", body);
}
