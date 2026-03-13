// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_X402_FACILITATOR_H
#define DILITHION_X402_FACILITATOR_H

#include <x402/x402_types.h>
#include <x402/vma.h>
#include <string>
#include <memory>
#include <map>
#include <mutex>

// Forward declarations
class CUTXOSet;
class CTxMemPool;
class CChainState;
struct NodeContext;

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
 *                          Body: {"rawTransaction":"hex", "recipient":"addr", "amount":volts}
 *                          Returns: VerifyResult JSON
 *
 *   POST /x402/settle    - Verify + broadcast a payment
 *                          Body: {"rawTransaction":"hex", "recipient":"addr", "amount":volts}
 *                          Returns: SettlementResult JSON
 *
 *   GET  /x402/supported - List supported schemes, networks, assets
 *                          Returns: FacilitatorInfo JSON
 *
 *   GET  /x402/status/{txid} - Check payment confirmation status
 *                          Returns: {"confirmations":N, "tier":"micropayment"|"standard"}
 *
 * Extension endpoints:
 *
 *   GET  /x402/dna-attest?address=ADDR - Get DNA trust attestation
 *                          Returns: DnaTrustAttestation JSON
 *
 *   POST /x402/vdf-challenge  - Request a VDF challenge
 *                          Body: {"iterations":N, "address":"addr"}
 *                          Returns: VdfChallengeResponse JSON
 *
 *   POST /x402/vdf-verify     - Submit VDF proof for verification
 *                          Body: {"challengeId":"hex", "output":"hex", "proof":"hex", "iterations":N}
 *                          Returns: VdfVerifyResult JSON
 *
 *   POST /x402/siwx/challenge - Request SIWX challenge
 *                          Body: {"address":"addr", "domain":"example.com"}
 *                          Returns: SIWXChallenge JSON
 *
 *   POST /x402/siwx/verify    - Verify SIWX signature
 *                          Body: {"challengeId":"hex", "signature":"hex", "publicKey":"hex", "address":"addr"}
 *                          Returns: SIWXResult JSON
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
    void RegisterNodeContext(NodeContext* ctx);

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
    NodeContext* m_node_ctx{nullptr};

    // Pending SIWX challenges (challengeId -> SIWXChallenge)
    std::map<std::string, SIWXChallenge> m_siwx_challenges;
    mutable std::mutex m_siwx_mutex;

    // Pending VDF challenges (challengeId -> seed hex)
    struct VdfPendingChallenge {
        std::string seed;        // 32-byte seed hex
        uint64_t iterations;
        uint64_t issuedAt;       // Unix timestamp
        uint64_t timeoutSec;
    };
    std::map<std::string, VdfPendingChallenge> m_vdf_challenges;
    mutable std::mutex m_vdf_mutex;

    // Core endpoint handlers
    std::string HandleVerify(const std::string& body, const std::string& clientIP);
    std::string HandleSettle(const std::string& body, const std::string& clientIP);
    std::string HandleSupported(const std::string& clientIP);
    std::string HandleStatus(const std::string& txid, const std::string& clientIP);

    // Extension endpoint handlers
    std::string HandleDnaAttest(const std::string& query, const std::string& clientIP);
    std::string HandleVdfChallenge(const std::string& body, const std::string& clientIP);
    std::string HandleVdfVerify(const std::string& body, const std::string& clientIP);
    std::string HandleSiwxChallenge(const std::string& body, const std::string& clientIP);
    std::string HandleSiwxVerify(const std::string& body, const std::string& clientIP);

    // Response helpers
    static std::string BuildHTTPResponse(int statusCode, const std::string& body);
    static std::string BuildErrorResponse(int httpCode, const std::string& message);

    // JSON parsing helpers
    static bool ExtractString(const std::string& json, const std::string& key, std::string& value);
    static bool ExtractInt(const std::string& json, const std::string& key, int64_t& value);

    // Hex helpers
    static std::string BytesToHex(const uint8_t* data, size_t len);
    static bool HexToBytes(const std::string& hex, std::vector<uint8_t>& out);

    // Cleanup expired challenges
    void CleanupExpiredChallenges();
};

} // namespace x402

#endif // DILITHION_X402_FACILITATOR_H
