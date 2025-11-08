// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <api/http_server.h>
#include <iostream>
#include <cstring>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

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

    // Create server socket
    m_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_server_socket < 0) {
        std::cerr << "[HttpServer] Failed to create socket" << std::endl;
        return false;
    }

    // Set socket options to allow reuse
    int opt = 1;
    if (setsockopt(m_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "[HttpServer] Failed to set socket options" << std::endl;
        close(m_server_socket);
        return false;
    }

    // Bind to port
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(m_port);

    if (bind(m_server_socket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "[HttpServer] Failed to bind to port " << m_port << std::endl;
        close(m_server_socket);
        return false;
    }

    // Listen for connections
    if (listen(m_server_socket, 10) < 0) {
        std::cerr << "[HttpServer] Failed to listen on port " << m_port << std::endl;
        close(m_server_socket);
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
    if (m_server_socket >= 0) {
        shutdown(m_server_socket, SHUT_RDWR);
        close(m_server_socket);
        m_server_socket = -1;
    }

    // Wait for server thread to finish
    if (m_server_thread.joinable()) {
        m_server_thread.join();
    }

    std::cout << "[HttpServer] Stopped" << std::endl;
}

// Server thread main loop
void CHttpServer::ServerThread() {
    std::cout << "[HttpServer] Server thread started" << std::endl;

    while (m_running.load()) {
        // Accept connection
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);
        int client_socket = accept(m_server_socket,
                                   (struct sockaddr*)&client_address,
                                   &client_len);

        if (client_socket < 0) {
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
void CHttpServer::HandleRequest(int client_socket) {
    // Read request
    char buffer[4096];
    ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

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
void CHttpServer::SendResponse(int client_socket,
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
    send(client_socket, response_str.c_str(), response_str.length(), 0);
}

// Send 404 Not Found
void CHttpServer::Send404(int client_socket) {
    std::string body = R"({"error": "Not Found"})";
    SendResponse(client_socket, 404, "application/json", body);
}

// Send 500 Internal Server Error
void CHttpServer::Send500(int client_socket) {
    std::string body = R"({"error": "Internal Server Error"})";
    SendResponse(client_socket, 500, "application/json", body);
}
