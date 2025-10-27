// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/server.h>
#include <rpc/auth.h>
#include <node/mempool.h>
#include <node/blockchain_storage.h>
#include <node/utxo_set.h>
#include <consensus/chain.h>
#include <amount.h>

#include <sstream>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <algorithm>

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

// Helper function to extract IP address from client socket
static std::string GetClientIP(int clientSocket) {
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    int res = getpeername(clientSocket, (struct sockaddr *)&addr, &addr_size);
    if (res != 0) {
        return "unknown";
    }
    return std::string(inet_ntoa(addr.sin_addr));
}

CRPCServer::CRPCServer(uint16_t port)
    : m_port(port), m_wallet(nullptr), m_miner(nullptr), m_mempool(nullptr),
      m_blockchain(nullptr), m_utxo_set(nullptr), m_chainstate(nullptr),
      m_serverSocket(INVALID_SOCKET)
{
    // Register RPC handlers - Wallet information
    m_handlers["getnewaddress"] = [this](const std::string& p) { return RPC_GetNewAddress(p); };
    m_handlers["getbalance"] = [this](const std::string& p) { return RPC_GetBalance(p); };
    m_handlers["getaddresses"] = [this](const std::string& p) { return RPC_GetAddresses(p); };
    m_handlers["listunspent"] = [this](const std::string& p) { return RPC_ListUnspent(p); };

    // Transaction creation
    m_handlers["sendtoaddress"] = [this](const std::string& p) { return RPC_SendToAddress(p); };
    m_handlers["signrawtransaction"] = [this](const std::string& p) { return RPC_SignRawTransaction(p); };
    m_handlers["sendrawtransaction"] = [this](const std::string& p) { return RPC_SendRawTransaction(p); };

    // Transaction query
    m_handlers["gettransaction"] = [this](const std::string& p) { return RPC_GetTransaction(p); };
    m_handlers["listtransactions"] = [this](const std::string& p) { return RPC_ListTransactions(p); };
    m_handlers["getmempoolinfo"] = [this](const std::string& p) { return RPC_GetMempoolInfo(p); };

    // Blockchain query
    m_handlers["getblockchaininfo"] = [this](const std::string& p) { return RPC_GetBlockchainInfo(p); };
    m_handlers["getblock"] = [this](const std::string& p) { return RPC_GetBlock(p); };
    m_handlers["getblockhash"] = [this](const std::string& p) { return RPC_GetBlockHash(p); };
    m_handlers["gettxout"] = [this](const std::string& p) { return RPC_GetTxOut(p); };

    // Wallet encryption
    m_handlers["encryptwallet"] = [this](const std::string& p) { return RPC_EncryptWallet(p); };
    m_handlers["walletpassphrase"] = [this](const std::string& p) { return RPC_WalletPassphrase(p); };
    m_handlers["walletlock"] = [this](const std::string& p) { return RPC_WalletLock(p); };
    m_handlers["walletpassphrasechange"] = [this](const std::string& p) { return RPC_WalletPassphraseChange(p); };

    // Mining
    m_handlers["getmininginfo"] = [this](const std::string& p) { return RPC_GetMiningInfo(p); };
    m_handlers["startmining"] = [this](const std::string& p) { return RPC_StartMining(p); };
    m_handlers["stopmining"] = [this](const std::string& p) { return RPC_StopMining(p); };

    // Network and general
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
    // Get client IP for rate limiting
    std::string clientIP = GetClientIP(clientSocket);

    // Check if IP is locked out due to failed auth attempts
    if (m_rateLimiter.IsLockedOut(clientIP)) {
        std::string response = BuildHTTPResponse(
            "{\"error\":\"Too many failed authentication attempts. Try again later.\"}"
        );
        send(clientSocket, response.c_str(), response.size(), 0);
        return;
    }

    // Check rate limit
    if (!m_rateLimiter.AllowRequest(clientIP)) {
        std::string response = BuildHTTPResponse(
            "{\"error\":\"Rate limit exceeded. Please slow down your requests.\"}"
        );
        send(clientSocket, response.c_str(), response.size(), 0);
        return;
    }

    // Read HTTP request
    char buffer[4096];
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesRead <= 0) {
        return;
    }
    buffer[bytesRead] = '\0';

    std::string request(buffer);

    // Check authentication if configured
    if (RPCAuth::IsAuthConfigured()) {
        std::string authHeader;
        if (!ExtractAuthHeader(request, authHeader)) {
            // No Authorization header
            std::string response = BuildHTTPUnauthorized();
            send(clientSocket, response.c_str(), response.size(), 0);
            return;
        }

        // Parse credentials
        std::string username, password;
        if (!RPCAuth::ParseAuthHeader(authHeader, username, password)) {
            // Malformed Authorization header
            std::string response = BuildHTTPUnauthorized();
            send(clientSocket, response.c_str(), response.size(), 0);
            return;
        }

        // Authenticate
        if (!RPCAuth::AuthenticateRequest(username, password)) {
            // Invalid credentials - record failure
            m_rateLimiter.RecordAuthFailure(clientIP);
            std::string response = BuildHTTPUnauthorized();
            send(clientSocket, response.c_str(), response.size(), 0);
            return;
        }

        // Authentication successful - reset failure counter
        m_rateLimiter.RecordAuthSuccess(clientIP);
    }

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

std::string CRPCServer::BuildHTTPUnauthorized() {
    std::string body = "{\"error\":\"Unauthorized - Invalid or missing credentials\"}";
    std::ostringstream oss;
    oss << "HTTP/1.1 401 Unauthorized\r\n";
    oss << "WWW-Authenticate: Basic realm=\"Dilithion RPC\"\r\n";
    oss << "Content-Type: application/json\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";
    oss << "\r\n";
    oss << body;
    return oss.str();
}

bool CRPCServer::ExtractAuthHeader(const std::string& request, std::string& authHeader) {
    // Look for "Authorization:" header (case-insensitive)
    size_t pos = 0;
    while (pos < request.size()) {
        // Find line start
        if (pos > 0 && request[pos - 1] != '\n') {
            pos++;
            continue;
        }

        // Check if this line starts with "Authorization:"
        if (request.compare(pos, 14, "Authorization:") == 0) {
            // Found it - extract the value
            size_t valueStart = pos + 14;
            // Skip whitespace
            while (valueStart < request.size() &&
                   (request[valueStart] == ' ' || request[valueStart] == '\t')) {
                valueStart++;
            }

            // Find end of line
            size_t valueEnd = request.find('\r', valueStart);
            if (valueEnd == std::string::npos) {
                valueEnd = request.find('\n', valueStart);
            }
            if (valueEnd == std::string::npos) {
                valueEnd = request.size();
            }

            authHeader = request.substr(valueStart, valueEnd - valueStart);
            return true;
        }

        pos++;
    }

    return false;  // No Authorization header found
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

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Format amount from ions to DIL with proper decimal places
 * 1 DIL = 100,000,000 ions (like Bitcoin satoshis)
 */
std::string CRPCServer::FormatAmount(CAmount amount) const {
    const CAmount COIN = 100000000;
    bool negative = amount < 0;
    if (negative) amount = -amount;

    CAmount wholePart = amount / COIN;
    CAmount fractionalPart = amount % COIN;

    std::ostringstream oss;
    if (negative) oss << "-";
    oss << wholePart << ".";
    oss << std::setfill('0') << std::setw(8) << fractionalPart;
    return oss.str();
}

/**
 * Validate and parse a Dilithion address string
 */
bool CRPCServer::ValidateAddress(const std::string& addressStr, CAddress& addressOut) const {
    if (addressStr.empty()) {
        return false;
    }

    CAddress addr;
    if (!addr.SetString(addressStr)) {
        return false;
    }

    if (!addr.IsValid()) {
        return false;
    }

    addressOut = addr;
    return true;
}

/**
 * Escape special characters for JSON strings
 */
std::string CRPCServer::EscapeJSON(const std::string& str) const {
    std::ostringstream oss;
    for (char c : str) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b";  break;
            case '\f': oss << "\\f";  break;
            case '\n': oss << "\\n";  break;
            case '\r': oss << "\\r";  break;
            case '\t': oss << "\\t";  break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

// ============================================================================
// RPC Method Implementations
// ============================================================================

// ----------------------------------------------------------------------------
// Wallet Information RPCs
// ----------------------------------------------------------------------------

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
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    // Get current height
    unsigned int currentHeight = m_chainstate->GetHeight();

    // Get available balance (excludes immature coinbase)
    CAmount balance = m_wallet->GetAvailableBalance(*m_utxo_set, currentHeight);

    // Get all unspent outputs to calculate unconfirmed and immature
    std::vector<CWalletTx> utxos = m_wallet->ListUnspentOutputs(*m_utxo_set, currentHeight);

    CAmount unconfirmedBalance = 0;  // For future: transactions with 0 confirmations
    CAmount immatureBalance = 0;     // Coinbase outputs not yet mature

    // Calculate immature balance from coinbase UTXOs
    for (const auto& utxo : utxos) {
        CUTXOEntry entry;
        COutPoint outpoint(utxo.txid, utxo.vout);
        if (m_utxo_set->GetUTXO(outpoint, entry)) {
            if (entry.fCoinBase) {
                unsigned int confirmations = currentHeight - entry.nHeight + 1;
                if (confirmations < 100) {  // COINBASE_MATURITY
                    immatureBalance += utxo.nValue;
                }
            }
        }
    }

    std::ostringstream oss;
    oss << "{";
    oss << "\"balance\":" << FormatAmount(balance) << ",";
    oss << "\"unconfirmed_balance\":" << FormatAmount(unconfirmedBalance) << ",";
    oss << "\"immature_balance\":" << FormatAmount(immatureBalance);
    oss << "}";
    return oss.str();
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

std::string CRPCServer::RPC_ListUnspent(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    unsigned int currentHeight = m_chainstate->GetHeight();
    std::vector<CWalletTx> utxos = m_wallet->ListUnspentOutputs(*m_utxo_set, currentHeight);

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < utxos.size(); ++i) {
        if (i > 0) oss << ",";

        // Get confirmations
        unsigned int confirmations = 0;
        if (utxos[i].nHeight > 0 && currentHeight >= utxos[i].nHeight) {
            confirmations = currentHeight - utxos[i].nHeight + 1;
        }

        oss << "{";
        oss << "\"txid\":\"" << utxos[i].txid.GetHex() << "\",";
        oss << "\"vout\":" << utxos[i].vout << ",";
        oss << "\"address\":\"" << utxos[i].address.ToString() << "\",";
        oss << "\"amount\":" << FormatAmount(utxos[i].nValue) << ",";
        oss << "\"confirmations\":" << confirmations;
        oss << "}";
    }
    oss << "]";
    return oss.str();
}

// ----------------------------------------------------------------------------
// Transaction Creation RPCs
// ----------------------------------------------------------------------------

std::string CRPCServer::RPC_SendToAddress(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    // Parse params - expecting {"address":"DLT1...", "amount":1.5}
    std::string address_str;
    CAmount amount = 0;

    // Extract address
    size_t addr_pos = params.find("\"address\"");
    if (addr_pos != std::string::npos) {
        size_t colon = params.find(":", addr_pos);
        size_t quote1 = params.find("\"", colon);
        size_t quote2 = params.find("\"", quote1 + 1);
        if (quote1 != std::string::npos && quote2 != std::string::npos) {
            address_str = params.substr(quote1 + 1, quote2 - quote1 - 1);
        }
    }

    // Extract amount
    size_t amt_pos = params.find("\"amount\"");
    if (amt_pos != std::string::npos) {
        size_t colon = params.find(":", amt_pos);
        size_t num_start = colon + 1;
        while (num_start < params.length() && isspace(params[num_start])) num_start++;
        size_t num_end = num_start;
        while (num_end < params.length() &&
               (isdigit(params[num_end]) || params[num_end] == '.' || params[num_end] == '-')) {
            num_end++;
        }
        if (num_end > num_start) {
            double amt_dbl = std::stod(params.substr(num_start, num_end - num_start));
            amount = static_cast<CAmount>(amt_dbl * 100000000);  // Convert DIL to ions
        }
    }

    // Validate inputs
    if (address_str.empty()) {
        throw std::runtime_error("Missing or invalid address parameter");
    }
    if (amount <= 0) {
        throw std::runtime_error("Invalid amount (must be positive)");
    }

    // Validate address
    CAddress recipient_address;
    if (!ValidateAddress(address_str, recipient_address)) {
        throw std::runtime_error("Invalid Dilithion address: " + address_str);
    }

    // Create transaction
    unsigned int currentHeight = m_chainstate->GetHeight();
    CAmount fee = CWallet::EstimateFee();
    CTransactionRef tx;
    std::string error;

    if (!m_wallet->CreateTransaction(recipient_address, amount, fee,
                                     *m_utxo_set, currentHeight, tx, error)) {
        throw std::runtime_error("Failed to create transaction: " + error);
    }

    // Send transaction
    if (!m_wallet->SendTransaction(tx, *m_mempool, *m_utxo_set, currentHeight, error)) {
        throw std::runtime_error("Failed to send transaction: " + error);
    }

    // Return txid
    uint256 txid = tx->GetHash();
    std::ostringstream oss;
    oss << "{\"txid\":\"" << txid.GetHex() << "\"}";
    return oss.str();
}

std::string CRPCServer::RPC_SignRawTransaction(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }

    // Parse params - expecting {"hex":"..."}
    size_t hex_pos = params.find("\"hex\"");
    if (hex_pos == std::string::npos) {
        throw std::runtime_error("Missing hex parameter");
    }

    size_t colon = params.find(":", hex_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid hex parameter format");
    }

    std::string hex_str = params.substr(quote1 + 1, quote2 - quote1 - 1);

    // Deserialize transaction from hex
    // TODO: Implement hex deserialization for CTransaction
    // For now, return error
    throw std::runtime_error("signrawtransaction not fully implemented - use sendtoaddress instead");
}

std::string CRPCServer::RPC_SendRawTransaction(const std::string& params) {
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    // Parse params - expecting {"hex":"..."}
    size_t hex_pos = params.find("\"hex\"");
    if (hex_pos == std::string::npos) {
        throw std::runtime_error("Missing hex parameter");
    }

    size_t colon = params.find(":", hex_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid hex parameter format");
    }

    std::string hex_str = params.substr(quote1 + 1, quote2 - quote1 - 1);

    // Deserialize transaction from hex
    // TODO: Implement hex deserialization for CTransaction
    // For now, return error
    throw std::runtime_error("sendrawtransaction not fully implemented - use sendtoaddress instead");
}

// ----------------------------------------------------------------------------
// Transaction Query RPCs
// ----------------------------------------------------------------------------

std::string CRPCServer::RPC_GetTransaction(const std::string& params) {
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }

    // Parse params - expecting {"txid":"..."}
    size_t txid_pos = params.find("\"txid\"");
    if (txid_pos == std::string::npos) {
        throw std::runtime_error("Missing txid parameter");
    }

    size_t colon = params.find(":", txid_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid txid parameter format");
    }

    std::string txid_str = params.substr(quote1 + 1, quote2 - quote1 - 1);
    uint256 txid;
    txid.SetHex(txid_str);

    // Try mempool first
    if (m_mempool->Exists(txid)) {
        std::ostringstream oss;
        oss << "{";
        oss << "\"txid\":\"" << txid.GetHex() << "\",";
        oss << "\"confirmations\":0,";
        oss << "\"in_mempool\":true";
        oss << "}";
        return oss.str();
    }

    // TODO: Search blockchain for confirmed transactions
    throw std::runtime_error("Transaction not found in mempool (blockchain search not yet implemented)");
}

std::string CRPCServer::RPC_ListTransactions(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    // For now, return wallet UTXOs as "received" transactions
    unsigned int currentHeight = m_chainstate->GetHeight();
    std::vector<CWalletTx> utxos = m_wallet->ListUnspentOutputs(*m_utxo_set, currentHeight);

    std::ostringstream oss;
    oss << "{\"transactions\":[";
    for (size_t i = 0; i < utxos.size(); ++i) {
        if (i > 0) oss << ",";

        unsigned int confirmations = 0;
        if (utxos[i].nHeight > 0 && currentHeight >= utxos[i].nHeight) {
            confirmations = currentHeight - utxos[i].nHeight + 1;
        }

        oss << "{";
        oss << "\"txid\":\"" << utxos[i].txid.GetHex() << "\",";
        oss << "\"address\":\"" << utxos[i].address.ToString() << "\",";
        oss << "\"category\":\"receive\",";
        oss << "\"amount\":" << FormatAmount(utxos[i].nValue) << ",";
        oss << "\"confirmations\":" << confirmations << ",";
        oss << "\"blockhash\":\"\"";  // TODO: Get block hash from height
        oss << "}";
    }
    oss << "]}";
    return oss.str();
}

std::string CRPCServer::RPC_GetMempoolInfo(const std::string& params) {
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }

    size_t size, bytes;
    double min_fee_rate, max_fee_rate;
    m_mempool->GetStats(size, bytes, min_fee_rate, max_fee_rate);

    std::ostringstream oss;
    oss << "{";
    oss << "\"size\":" << size << ",";
    oss << "\"bytes\":" << bytes << ",";
    oss << "\"usage\":" << bytes << ",";
    oss << "\"min_fee_rate\":" << min_fee_rate << ",";
    oss << "\"max_fee_rate\":" << max_fee_rate;
    oss << "}";
    return oss.str();
}

// ----------------------------------------------------------------------------
// Blockchain Query RPCs
// ----------------------------------------------------------------------------

std::string CRPCServer::RPC_GetBlockchainInfo(const std::string& params) {
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    int height = m_chainstate->GetHeight();
    uint256 bestBlockHash;
    if (!m_blockchain->ReadBestBlock(bestBlockHash)) {
        throw std::runtime_error("Failed to read best block");
    }

    std::ostringstream oss;
    oss << "{";
    oss << "\"chain\":\"main\",";
    oss << "\"blocks\":" << height << ",";
    oss << "\"bestblockhash\":\"" << bestBlockHash.GetHex() << "\",";
    oss << "\"difficulty\":0,";  // TODO: Calculate difficulty from nBits
    oss << "\"mediantime\":0,";  // TODO: Calculate median time
    oss << "\"chainwork\":\"" << m_chainstate->GetChainWork().GetHex() << "\"";
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetBlock(const std::string& params) {
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }

    // Parse params - expecting {"hash":"..."}
    size_t hash_pos = params.find("\"hash\"");
    if (hash_pos == std::string::npos) {
        throw std::runtime_error("Missing hash parameter");
    }

    size_t colon = params.find(":", hash_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid hash parameter format");
    }

    std::string hash_str = params.substr(quote1 + 1, quote2 - quote1 - 1);
    uint256 hash;
    hash.SetHex(hash_str);

    CBlock block;
    if (!m_blockchain->ReadBlock(hash, block)) {
        throw std::runtime_error("Block not found");
    }

    CBlockIndex blockIndex;
    int height = -1;
    if (m_blockchain->ReadBlockIndex(hash, blockIndex)) {
        height = blockIndex.nHeight;
    }

    std::ostringstream oss;
    oss << "{";
    oss << "\"hash\":\"" << hash.GetHex() << "\",";
    oss << "\"height\":" << height << ",";
    oss << "\"version\":" << block.nVersion << ",";
    oss << "\"previousblockhash\":\"" << block.hashPrevBlock.GetHex() << "\",";
    oss << "\"merkleroot\":\"" << block.hashMerkleRoot.GetHex() << "\",";
    oss << "\"time\":" << block.nTime << ",";
    oss << "\"bits\":\"0x" << std::hex << block.nBits << std::dec << "\",";
    oss << "\"nonce\":" << block.nNonce << ",";
    oss << "\"tx_count\":" << (block.vtx.size() > 0 ? 1 : 0);  // Simplified
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetBlockHash(const std::string& params) {
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }

    // Parse params - expecting {"height":100}
    size_t height_pos = params.find("\"height\"");
    if (height_pos == std::string::npos) {
        throw std::runtime_error("Missing height parameter");
    }

    size_t colon = params.find(":", height_pos);
    size_t num_start = colon + 1;
    while (num_start < params.length() && isspace(params[num_start])) num_start++;
    size_t num_end = num_start;
    while (num_end < params.length() && isdigit(params[num_end])) num_end++;

    if (num_end <= num_start) {
        throw std::runtime_error("Invalid height parameter format");
    }

    int height = std::stoi(params.substr(num_start, num_end - num_start));

    // Get blocks at this height
    std::vector<uint256> hashes = m_chainstate->GetBlocksAtHeight(height);
    if (hashes.empty()) {
        throw std::runtime_error("No block found at height " + std::to_string(height));
    }

    // Return first block (on main chain)
    std::ostringstream oss;
    oss << "{\"blockhash\":\"" << hashes[0].GetHex() << "\"}";
    return oss.str();
}

std::string CRPCServer::RPC_GetTxOut(const std::string& params) {
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    // Parse params - expecting {"txid":"...", "n":0}
    size_t txid_pos = params.find("\"txid\"");
    if (txid_pos == std::string::npos) {
        throw std::runtime_error("Missing txid parameter");
    }

    size_t colon = params.find(":", txid_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid txid parameter format");
    }

    std::string txid_str = params.substr(quote1 + 1, quote2 - quote1 - 1);
    uint256 txid;
    txid.SetHex(txid_str);

    // Parse n
    size_t n_pos = params.find("\"n\"", quote2);
    if (n_pos == std::string::npos) {
        throw std::runtime_error("Missing n parameter");
    }

    colon = params.find(":", n_pos);
    size_t num_start = colon + 1;
    while (num_start < params.length() && isspace(params[num_start])) num_start++;
    size_t num_end = num_start;
    while (num_end < params.length() && isdigit(params[num_end])) num_end++;

    if (num_end <= num_start) {
        throw std::runtime_error("Invalid n parameter format");
    }

    uint32_t n = std::stoul(params.substr(num_start, num_end - num_start));

    // Look up UTXO
    COutPoint outpoint(txid, n);
    CUTXOEntry entry;
    if (!m_utxo_set->GetUTXO(outpoint, entry)) {
        return "null";  // UTXO doesn't exist or already spent
    }

    unsigned int currentHeight = m_chainstate->GetHeight();
    unsigned int confirmations = 0;
    if (entry.nHeight > 0 && currentHeight >= entry.nHeight) {
        confirmations = currentHeight - entry.nHeight + 1;
    }

    uint256 bestBlockHash;
    m_blockchain->ReadBestBlock(bestBlockHash);

    std::ostringstream oss;
    oss << "{";
    oss << "\"bestblock\":\"" << bestBlockHash.GetHex() << "\",";
    oss << "\"confirmations\":" << confirmations << ",";
    oss << "\"value\":" << FormatAmount(entry.out.nValue) << ",";
    oss << "\"scriptPubKey\":{";
    oss << "\"hex\":\"";
    for (uint8_t byte : entry.out.scriptPubKey) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    oss << std::dec << "\"";
    oss << "},";
    oss << "\"coinbase\":" << (entry.fCoinBase ? "true" : "false");
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_EncryptWallet(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (m_wallet->IsCrypted()) {
        throw std::runtime_error("Error: Wallet is already encrypted");
    }

    // Parse params to get passphrase
    // Expected format: {"passphrase":"password"}
    size_t pos = params.find("\"passphrase\"");
    if (pos == std::string::npos) {
        throw std::runtime_error("Missing passphrase parameter");
    }

    pos = params.find(":", pos);
    if (pos == std::string::npos) {
        throw std::runtime_error("Invalid passphrase format");
    }

    pos = params.find("\"", pos + 1);
    if (pos == std::string::npos) {
        throw std::runtime_error("Invalid passphrase format");
    }

    size_t end = params.find("\"", pos + 1);
    if (end == std::string::npos) {
        throw std::runtime_error("Invalid passphrase format");
    }

    std::string passphrase = params.substr(pos + 1, end - pos - 1);

    if (passphrase.empty()) {
        throw std::runtime_error("Error: Passphrase cannot be empty");
    }

    if (!m_wallet->EncryptWallet(passphrase)) {
        throw std::runtime_error("Error: Failed to encrypt wallet");
    }

    return "\"Wallet encrypted. Please backup your wallet and remember your passphrase!\"";
}

std::string CRPCServer::RPC_WalletPassphrase(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (!m_wallet->IsCrypted()) {
        throw std::runtime_error("Error: Wallet is not encrypted");
    }

    // Parse params: {"passphrase":"password", "timeout":60}
    size_t pos = params.find("\"passphrase\"");
    if (pos == std::string::npos) {
        throw std::runtime_error("Missing passphrase parameter");
    }

    pos = params.find(":", pos);
    pos = params.find("\"", pos + 1);
    size_t end = params.find("\"", pos + 1);
    std::string passphrase = params.substr(pos + 1, end - pos - 1);

    // Parse timeout (optional, default 60 seconds)
    int64_t timeout = 60;
    size_t timeoutPos = params.find("\"timeout\"");
    if (timeoutPos != std::string::npos) {
        timeoutPos = params.find(":", timeoutPos);
        size_t numStart = timeoutPos + 1;
        while (numStart < params.length() && isspace(params[numStart])) numStart++;
        size_t numEnd = numStart;
        while (numEnd < params.length() && isdigit(params[numEnd])) numEnd++;
        if (numEnd > numStart) {
            timeout = std::stoll(params.substr(numStart, numEnd - numStart));
        }
    }

    if (!m_wallet->Unlock(passphrase, timeout)) {
        throw std::runtime_error("Error: The wallet passphrase entered was incorrect");
    }

    std::ostringstream oss;
    oss << "\"Wallet unlocked";
    if (timeout > 0) {
        oss << " for " << timeout << " seconds";
    }
    oss << "\"";
    return oss.str();
}

std::string CRPCServer::RPC_WalletLock(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (!m_wallet->IsCrypted()) {
        throw std::runtime_error("Error: Wallet is not encrypted");
    }

    if (!m_wallet->Lock()) {
        throw std::runtime_error("Error: Failed to lock wallet");
    }

    return "\"Wallet locked\"";
}

std::string CRPCServer::RPC_WalletPassphraseChange(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (!m_wallet->IsCrypted()) {
        throw std::runtime_error("Error: Wallet is not encrypted");
    }

    // Parse params: {"oldpassphrase":"old", "newpassphrase":"new"}
    size_t pos = params.find("\"oldpassphrase\"");
    if (pos == std::string::npos) {
        throw std::runtime_error("Missing oldpassphrase parameter");
    }

    pos = params.find(":", pos);
    pos = params.find("\"", pos + 1);
    size_t end = params.find("\"", pos + 1);
    std::string oldPass = params.substr(pos + 1, end - pos - 1);

    pos = params.find("\"newpassphrase\"", end);
    if (pos == std::string::npos) {
        throw std::runtime_error("Missing newpassphrase parameter");
    }

    pos = params.find(":", pos);
    pos = params.find("\"", pos + 1);
    end = params.find("\"", pos + 1);
    std::string newPass = params.substr(pos + 1, end - pos - 1);

    if (newPass.empty()) {
        throw std::runtime_error("Error: New passphrase cannot be empty");
    }

    if (!m_wallet->ChangePassphrase(oldPass, newPass)) {
        throw std::runtime_error("Error: The wallet passphrase entered was incorrect");
    }

    return "\"Wallet passphrase changed successfully\"";
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
    oss << "{\"commands\":[";

    // Wallet information
    oss << "\"getnewaddress - Get a new receiving address\",";
    oss << "\"getbalance - Get wallet balance (available, unconfirmed, immature)\",";
    oss << "\"getaddresses - List all wallet addresses\",";
    oss << "\"listunspent - List unspent transaction outputs\",";

    // Transaction creation
    oss << "\"sendtoaddress - Send coins to an address\",";
    oss << "\"signrawtransaction - Sign a raw transaction (not fully implemented)\",";
    oss << "\"sendrawtransaction - Broadcast a raw transaction (not fully implemented)\",";

    // Transaction query
    oss << "\"gettransaction - Get transaction details by txid\",";
    oss << "\"listtransactions - List wallet transactions\",";
    oss << "\"getmempoolinfo - Get mempool statistics\",";

    // Blockchain query
    oss << "\"getblockchaininfo - Get blockchain information\",";
    oss << "\"getblock - Get block by hash\",";
    oss << "\"getblockhash - Get block hash by height\",";
    oss << "\"gettxout - Get UTXO information\",";

    // Wallet encryption
    oss << "\"encryptwallet - Encrypt wallet with passphrase\",";
    oss << "\"walletpassphrase - Unlock wallet for a timeout period\",";
    oss << "\"walletlock - Lock encrypted wallet\",";
    oss << "\"walletpassphrasechange - Change wallet passphrase\",";

    // Mining
    oss << "\"getmininginfo - Get mining status and hashrate\",";
    oss << "\"startmining - Start mining (not fully implemented)\",";
    oss << "\"stopmining - Stop mining\",";

    // Network and general
    oss << "\"getnetworkinfo - Get network information\",";
    oss << "\"getpeerinfo - Get peer information\",";
    oss << "\"help - This help message\",";
    oss << "\"stop - Stop the Dilithion node\"";

    oss << "]}";
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
