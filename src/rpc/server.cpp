// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/server.h>

#include <sstream>
#include <cstring>
#include <iostream>

#ifdef _WIN32
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

CRPCServer::CRPCServer(uint16_t port)
    : m_port(port), m_wallet(nullptr), m_miner(nullptr), m_serverSocket(INVALID_SOCKET)
{
    // Register RPC handlers
    m_handlers["getnewaddress"] = [this](const std::string& p) { return RPC_GetNewAddress(p); };
    m_handlers["getbalance"] = [this](const std::string& p) { return RPC_GetBalance(p); };
    m_handlers["getaddresses"] = [this](const std::string& p) { return RPC_GetAddresses(p); };
    m_handlers["sendtoaddress"] = [this](const std::string& p) { return RPC_SendToAddress(p); };
    m_handlers["getmininginfo"] = [this](const std::string& p) { return RPC_GetMiningInfo(p); };
    m_handlers["startmining"] = [this](const std::string& p) { return RPC_StartMining(p); };
    m_handlers["stopmining"] = [this](const std::string& p) { return RPC_StopMining(p); };
    m_handlers["getnetworkinfo"] = [this](const std::string& p) { return RPC_GetNetworkInfo(p); };
    m_handlers["getpeerinfo"] = [this](const std::string& p) { return RPC_GetPeerInfo(p); };
    m_handlers["help"] = [this](const std::string& p) { return RPC_Help(p); };
    m_handlers["stop"] = [this](const std::string& p) { return RPC_Stop(p); };
}

CRPCServer::~CRPCServer() {
    Stop();
}

bool CRPCServer::Start() {
    if (m_running) {
        return false;
    }

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
#endif

    // Create socket
    m_serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_serverSocket == INVALID_SOCKET) {
        return false;
    }

    // Set socket options
    int opt = 1;
    setsockopt(m_serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    // Bind to port
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // Only listen on localhost for security
    addr.sin_port = htons(m_port);

    if (bind(m_serverSocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
        return false;
    }

    // Listen
    if (listen(m_serverSocket, 10) == SOCKET_ERROR) {
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
        return false;
    }

    // Start server thread
    m_running = true;
    m_serverThread = std::thread(&CRPCServer::ServerThread, this);

    return true;
}

void CRPCServer::Stop() {
    if (!m_running) {
        return;
    }

    m_running = false;

    // Close server socket
    if (m_serverSocket != INVALID_SOCKET) {
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
    }

    // Wait for server thread
    if (m_serverThread.joinable()) {
        m_serverThread.join();
    }

#ifdef _WIN32
    WSACleanup();
#endif
}

void CRPCServer::ServerThread() {
    while (m_running) {
        // Accept client connection
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSocket = accept(m_serverSocket, (struct sockaddr*)&clientAddr, &clientLen);

        if (clientSocket == INVALID_SOCKET) {
            if (m_running) {
                // Error occurred
                continue;
            } else {
                // Server stopped
                break;
            }
        }

        // Handle client in this thread (for simplicity)
        // In production, would use thread pool
        HandleClient(clientSocket);
        closesocket(clientSocket);
    }
}

void CRPCServer::HandleClient(int clientSocket) {
    // Read HTTP request
    char buffer[4096];
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesRead <= 0) {
        return;
    }
    buffer[bytesRead] = '\0';

    std::string request(buffer);

    // Parse HTTP request
    std::string jsonrpc;
    if (!ParseHTTPRequest(request, jsonrpc)) {
        // Invalid HTTP request
        std::string response = BuildHTTPResponse("{\"error\":\"Invalid HTTP request\"}");
        send(clientSocket, response.c_str(), response.size(), 0);
        return;
    }

    // Parse JSON-RPC request
    RPCRequest rpcReq;
    try {
        rpcReq = ParseRPCRequest(jsonrpc);
    } catch (...) {
        RPCResponse rpcResp = RPCResponse::Error(-32700, "Parse error", "");
        std::string response = BuildHTTPResponse(SerializeResponse(rpcResp));
        send(clientSocket, response.c_str(), response.size(), 0);
        return;
    }

    // Execute RPC
    RPCResponse rpcResp = ExecuteRPC(rpcReq);

    // Send response
    std::string response = BuildHTTPResponse(SerializeResponse(rpcResp));
    send(clientSocket, response.c_str(), response.size(), 0);
}

bool CRPCServer::ParseHTTPRequest(const std::string& request, std::string& jsonrpc) {
    // Find the end of headers (blank line)
    size_t pos = request.find("\r\n\r\n");
    if (pos == std::string::npos) {
        pos = request.find("\n\n");
        if (pos == std::string::npos) {
            return false;
        }
        jsonrpc = request.substr(pos + 2);
    } else {
        jsonrpc = request.substr(pos + 4);
    }

    return !jsonrpc.empty();
}

std::string CRPCServer::BuildHTTPResponse(const std::string& body) {
    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n";
    oss << "Content-Type: application/json\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";
    oss << "\r\n";
    oss << body;
    return oss.str();
}

RPCRequest CRPCServer::ParseRPCRequest(const std::string& json) {
    RPCRequest req;

    // Simple JSON parsing (just extract method and id)
    // In production, would use proper JSON library

    // Extract method
    size_t methodPos = json.find("\"method\"");
    if (methodPos != std::string::npos) {
        size_t colonPos = json.find(":", methodPos);
        size_t quoteStart = json.find("\"", colonPos);
        size_t quoteEnd = json.find("\"", quoteStart + 1);
        if (quoteStart != std::string::npos && quoteEnd != std::string::npos) {
            req.method = json.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
        }
    }

    // Extract id
    size_t idPos = json.find("\"id\"");
    if (idPos != std::string::npos) {
        size_t colonPos = json.find(":", idPos);
        size_t quoteStart = json.find("\"", colonPos);
        if (quoteStart != std::string::npos) {
            size_t quoteEnd = json.find("\"", quoteStart + 1);
            if (quoteEnd != std::string::npos) {
                req.id = json.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
            }
        } else {
            // Numeric id
            size_t numStart = colonPos + 1;
            while (numStart < json.size() && isspace(json[numStart])) numStart++;
            size_t numEnd = numStart;
            while (numEnd < json.size() && (isdigit(json[numEnd]) || json[numEnd] == '-')) numEnd++;
            if (numEnd > numStart) {
                req.id = json.substr(numStart, numEnd - numStart);
            }
        }
    }

    // Extract params (store as-is for now)
    size_t paramsPos = json.find("\"params\"");
    if (paramsPos != std::string::npos) {
        size_t colonPos = json.find(":", paramsPos);
        size_t arrayStart = json.find("[", colonPos);
        if (arrayStart != std::string::npos) {
            size_t arrayEnd = json.find("]", arrayStart);
            if (arrayEnd != std::string::npos) {
                req.params = json.substr(arrayStart, arrayEnd - arrayStart + 1);
            }
        }
    }

    return req;
}

RPCResponse CRPCServer::ExecuteRPC(const RPCRequest& request) {
    std::lock_guard<std::mutex> lock(m_handlersMutex);

    // Find handler
    auto it = m_handlers.find(request.method);
    if (it == m_handlers.end()) {
        return RPCResponse::Error(-32601, "Method not found", request.id);
    }

    // Execute handler
    try {
        std::string result = it->second(request.params);
        return RPCResponse::Success(result, request.id);
    } catch (const std::exception& e) {
        return RPCResponse::Error(-32603, e.what(), request.id);
    }
}

std::string CRPCServer::SerializeResponse(const RPCResponse& response) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"jsonrpc\":\"2.0\",";
    if (!response.error.empty()) {
        oss << "\"error\":" << response.error << ",";
    } else {
        oss << "\"result\":" << response.result << ",";
    }
    oss << "\"id\":";
    if (response.id.empty() || response.id == "null") {
        oss << "null";
    } else if (isdigit(response.id[0]) || response.id[0] == '-') {
        oss << response.id;
    } else {
        oss << "\"" << response.id << "\"";
    }
    oss << "}";
    return oss.str();
}

// RPC Method Implementations

std::string CRPCServer::RPC_GetNewAddress(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    CAddress addr = m_wallet->GetNewAddress();
    if (!addr.IsValid()) {
        throw std::runtime_error("Failed to get address");
    }

    return "\"" + addr.ToString() + "\"";
}

std::string CRPCServer::RPC_GetBalance(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    int64_t balance = m_wallet->GetBalance();
    return std::to_string(balance);
}

std::string CRPCServer::RPC_GetAddresses(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    auto addresses = m_wallet->GetAddresses();

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < addresses.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << addresses[i].ToString() << "\"";
    }
    oss << "]";
    return oss.str();
}

std::string CRPCServer::RPC_SendToAddress(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    // TODO: Implement transaction creation
    throw std::runtime_error("Not implemented yet");
}

std::string CRPCServer::RPC_GetMiningInfo(const std::string& params) {
    if (!m_miner) {
        throw std::runtime_error("Miner not initialized");
    }

    std::ostringstream oss;
    oss << "{";
    oss << "\"mining\":" << (m_miner->IsMining() ? "true" : "false") << ",";
    oss << "\"hashrate\":" << m_miner->GetHashRate() << ",";
    oss << "\"threads\":" << m_miner->GetThreadCount();
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_StartMining(const std::string& params) {
    if (!m_miner) {
        throw std::runtime_error("Miner not initialized");
    }

    // TODO: Get block template from blockchain
    // For now, just return status
    return m_miner->IsMining() ? "true" : "false";
}

std::string CRPCServer::RPC_StopMining(const std::string& params) {
    if (!m_miner) {
        throw std::runtime_error("Miner not initialized");
    }

    m_miner->StopMining();
    return "true";
}

std::string CRPCServer::RPC_GetNetworkInfo(const std::string& params) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"version\":\"1.0.0\",";
    oss << "\"subversion\":\"/Dilithion:1.0.0/\",";
    oss << "\"protocolversion\":1";
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetPeerInfo(const std::string& params) {
    // TODO: Get from network manager
    return "[]";
}

std::string CRPCServer::RPC_Help(const std::string& params) {
    std::ostringstream oss;
    oss << "[";
    oss << "\"getnewaddress\",";
    oss << "\"getbalance\",";
    oss << "\"getaddresses\",";
    oss << "\"getmininginfo\",";
    oss << "\"stopmining\",";
    oss << "\"getnetworkinfo\",";
    oss << "\"help\",";
    oss << "\"stop\"";
    oss << "]";
    return oss.str();
}

std::string CRPCServer::RPC_Stop(const std::string& params) {
    // Stop the server gracefully
    std::thread([this]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        Stop();
    }).detach();

    return "\"Dilithion server stopping\"";
}
