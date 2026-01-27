// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_RPC_REST_API_H
#define DILITHION_RPC_REST_API_H

#include <string>
#include <map>
#include <functional>
#include <memory>
#include <cstdint>

// Forward declarations
class CTxMemPool;
class CBlockchainDB;
class CUTXOSet;
class CChainState;
class CRateLimiter;

/**
 * REST API for Light Wallets
 *
 * Provides a public REST API for light wallet clients to:
 * - Query balances and UTXOs by address
 * - Get transaction and blockchain info
 * - Broadcast signed raw transactions
 *
 * Security Model:
 * - Private keys NEVER touch the server
 * - Clients sign locally, server only provides blockchain data and transaction relay
 * - Rate limited per endpoint
 * - No authentication required (public read-only + broadcast)
 *
 * Endpoints:
 * - GET  /api/v1/balance/{address}  - Get confirmed balance
 * - GET  /api/v1/utxos/{address}    - Get unspent outputs
 * - GET  /api/v1/tx/{txid}          - Get transaction details
 * - POST /api/v1/broadcast          - Broadcast raw transaction
 * - GET  /api/v1/info               - Get blockchain info
 * - GET  /api/v1/fee                - Get recommended fee rate
 */
class CRestAPI {
private:
    // Component references (borrowed, not owned)
    CTxMemPool* m_mempool;
    CBlockchainDB* m_blockchain;
    CUTXOSet* m_utxo_set;
    CChainState* m_chainstate;
    CRateLimiter* m_rateLimiter;

    // Endpoint handlers
    std::string HandleBalance(const std::string& address, const std::string& clientIP);
    std::string HandleUTXOs(const std::string& address, const std::string& clientIP);
    std::string HandleTransaction(const std::string& txid, const std::string& clientIP);
    std::string HandleBroadcast(const std::string& body, const std::string& clientIP);
    std::string HandleInfo(const std::string& clientIP);
    std::string HandleFee(const std::string& clientIP);

    // Helper methods
    std::string BuildJSONResponse(int statusCode, const std::string& body);
    std::string BuildErrorResponse(int httpCode, int errorCode, const std::string& message);
    std::string EscapeJSON(const std::string& str) const;
    std::string FormatAmount(int64_t amount) const;
    bool ValidateAddress(const std::string& address) const;
    bool ValidateTxid(const std::string& txid) const;

    // Rate limit check
    bool CheckRateLimit(const std::string& clientIP, const std::string& endpoint);

public:
    CRestAPI();
    ~CRestAPI() = default;

    // Prevent copying
    CRestAPI(const CRestAPI&) = delete;
    CRestAPI& operator=(const CRestAPI&) = delete;

    /**
     * Register component references
     */
    void RegisterMempool(CTxMemPool* mempool) { m_mempool = mempool; }
    void RegisterBlockchain(CBlockchainDB* blockchain) { m_blockchain = blockchain; }
    void RegisterUTXOSet(CUTXOSet* utxo_set) { m_utxo_set = utxo_set; }
    void RegisterChainState(CChainState* chainstate) { m_chainstate = chainstate; }
    void RegisterRateLimiter(CRateLimiter* rateLimiter) { m_rateLimiter = rateLimiter; }

    /**
     * Check if a request path is a REST API request
     * @param path HTTP request path (e.g., "/api/v1/info")
     * @return true if this is a REST API request
     */
    static bool IsRESTRequest(const std::string& path);

    /**
     * Handle a REST API request
     * @param method HTTP method (GET, POST)
     * @param path HTTP request path (e.g., "/api/v1/balance/Dxxxx")
     * @param body Request body (for POST requests)
     * @param clientIP Client IP address for rate limiting
     * @return HTTP response (headers + body)
     */
    std::string HandleRequest(const std::string& method,
                              const std::string& path,
                              const std::string& body,
                              const std::string& clientIP);

    /**
     * Build HTTP response with CORS headers for browser access
     * @param statusCode HTTP status code
     * @param body Response body (JSON)
     * @return Complete HTTP response
     */
    static std::string BuildHTTPResponse(int statusCode, const std::string& body);

    /**
     * Build HTTP 429 Too Many Requests response
     */
    static std::string BuildRateLimitResponse();

    /**
     * Build HTTP 404 Not Found response
     */
    static std::string BuildNotFoundResponse();

    /**
     * Build HTTP 405 Method Not Allowed response
     */
    static std::string BuildMethodNotAllowedResponse();
};

#endif // DILITHION_RPC_REST_API_H
