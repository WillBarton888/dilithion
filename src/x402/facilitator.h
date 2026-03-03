// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_X402_FACILITATOR_H
#define DILITHION_X402_FACILITATOR_H

#include <x402/x402_types.h>
#include <x402/vma.h>
#include <string>
#include <memory>

// Forward declarations
class CUTXOSet;
class CTxMemPool;
class CChainState;

namespace x402 {

/**
 * x402 Facilitator Service
 *
 * Implements the x402 facilitator role for DilV payments.
 * Handles payment verification and settlement via REST API endpoints.
 *
 * REST API endpoints (mounted under /x402/):
 *
 *   POST /x402/verify    - Verify a payment without broadcasting
 *                          Body: {"rawTransaction":"hex", "recipient":"addr", "amount":ions}
 *                          Returns: VerifyResult JSON
 *
 *   POST /x402/settle    - Verify + broadcast a payment
 *                          Body: {"rawTransaction":"hex", "recipient":"addr", "amount":ions}
 *                          Returns: SettlementResult JSON
 *
 *   GET  /x402/supported - List supported schemes, networks, assets
 *                          Returns: FacilitatorInfo JSON
 *
 *   GET  /x402/status/{txid} - Check payment confirmation status
 *                          Returns: {"confirmations":N, "tier":"micropayment"|"standard"}
 *
 * The facilitator runs as part of the DilV node's existing HTTP server.
 * No separate process or port is needed.
 */
class CFacilitator {
public:
    CFacilitator();
    ~CFacilitator() = default;

    // Register node components
    void RegisterUTXOSet(CUTXOSet* utxo_set);
    void RegisterMempool(CTxMemPool* mempool);
    void RegisterChainState(CChainState* chainstate);

    /**
     * Check if a request path is an x402 facilitator request
     */
    static bool IsX402Request(const std::string& path);

    /**
     * Handle an x402 REST API request
     *
     * @param method    HTTP method (GET, POST)
     * @param path      Request path (e.g., "/x402/verify")
     * @param body      Request body (for POST)
     * @param clientIP  Client IP for logging
     * @return Complete HTTP response (headers + body)
     */
    std::string HandleRequest(const std::string& method,
                              const std::string& path,
                              const std::string& body,
                              const std::string& clientIP);

    /**
     * Get the VMA instance for direct API access (used by RPC commands)
     */
    CVerifiedMempoolAcceptance& GetVMA() { return m_vma; }

private:
    CVerifiedMempoolAcceptance m_vma;

    // Endpoint handlers
    std::string HandleVerify(const std::string& body, const std::string& clientIP);
    std::string HandleSettle(const std::string& body, const std::string& clientIP);
    std::string HandleSupported(const std::string& clientIP);
    std::string HandleStatus(const std::string& txid, const std::string& clientIP);

    // Response helpers
    static std::string BuildHTTPResponse(int statusCode, const std::string& body);
    static std::string BuildErrorResponse(int httpCode, const std::string& message);

    // JSON parsing helpers
    static bool ExtractString(const std::string& json, const std::string& key, std::string& value);
    static bool ExtractInt(const std::string& json, const std::string& key, int64_t& value);
};

} // namespace x402

#endif // DILITHION_X402_FACILITATOR_H
