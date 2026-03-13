// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_X402_TYPES_H
#define DILITHION_X402_TYPES_H

#include <string>
#include <vector>
#include <cstdint>
#include <map>

namespace x402 {

/**
 * x402 Payment Protocol — Core Data Types
 *
 * Implements the x402 v2 protocol data structures for Dilithion chains.
 * Reference: https://docs.x402.org
 *
 * Network identifiers use CAIP-2 (bip122 namespace):
 *   DIL:  bip122:0000009eaa5e7781ba6d14525c3f75c3
 *   DilV: bip122:3e9a5bfb202db1de714e493fecd165a2
 */

// CAIP-2 network identifiers (bip122:<first 32 hex of genesis hash>)
static const char* SCHEME_ID = "exact";
static const char* NETWORK_ID_DIL  = "bip122:0000009eaa5e7781ba6d14525c3f75c3";
static const char* NETWORK_ID_DILV = "bip122:3e9a5bfb202db1de714e493fecd165a2";
static const char* NETWORK_ID = NETWORK_ID_DILV;  // Default: DilV (payment chain)
static const char* ASSET_ID = "DILV";  // Native coin

// Payment tiers for Verified Mempool Acceptance
static const int64_t MICROPAYMENT_THRESHOLD = 100000000;  // 1 DilV (in volts)

/**
 * ResourceInfo — describes the resource being purchased
 */
struct ResourceInfo {
    std::string url;         // Resource URL
    std::string description; // Human-readable description
    std::string mimeType;    // Expected response MIME type
};

/**
 * PaymentOption — one accepted payment method
 */
struct PaymentOption {
    std::string scheme;      // "exact" (fixed amount)
    std::string network;     // "dilv:mainnet"
    std::string asset;       // "DILV"
    int64_t amount;          // Amount in volts (1 DilV = 100,000,000 volts)
    std::string recipient;   // DilV address (Base58Check)
    int64_t timeout;         // Payment validity window (seconds)
};

/**
 * PaymentRequired — server's 402 response
 *
 * Sent when a client requests a paid resource without valid payment.
 * Contains the payment options and resource information.
 */
struct PaymentRequired {
    int version;                        // Protocol version (2)
    std::string error;                  // "payment_required"
    ResourceInfo resource;              // What the client is buying
    std::vector<PaymentOption> accepts; // Accepted payment methods

    // Serialize to JSON for HTTP response
    std::string ToJSON() const;

    // Parse from JSON
    static bool FromJSON(const std::string& json, PaymentRequired& out, std::string& error);
};

/**
 * PaymentPayload — client's payment proof
 *
 * Contains a signed DilV transaction that pays the required amount
 * to the recipient address specified in PaymentRequired.
 */
struct PaymentPayload {
    int version;                 // Protocol version (2)
    std::string scheme;          // "exact"
    std::string network;         // "dilv:mainnet"
    std::string resource;        // Resource URL being purchased
    std::string rawTransaction;  // Hex-encoded signed CTransaction
    std::string payerAddress;    // Sender's DilV address

    // Serialize to JSON for HTTP header
    std::string ToJSON() const;

    // Parse from JSON (from PAYMENT-SIGNATURE header)
    static bool FromJSON(const std::string& json, PaymentPayload& out, std::string& error);
};

/**
 * VerifyResult — facilitator's verification response
 */
struct VerifyResult {
    bool valid;              // Payment is valid
    std::string reason;      // Human-readable reason (if invalid)
    std::string payerAddress;// Payer's DilV address
    int64_t amount;          // Verified amount (volts)

    std::string ToJSON() const;
};

/**
 * SettlementResult — facilitator's settlement response
 */
struct SettlementResult {
    bool success;            // Transaction broadcast successfully
    std::string error;       // Error message (if failed)
    std::string txHash;      // Transaction hash
    std::string payerAddress;// Payer's address
    std::string network;     // "dilv:mainnet"
    int confirmations;       // Number of confirmations (0 = mempool)

    std::string ToJSON() const;
};

/**
 * FacilitatorInfo — advertised facilitator capabilities
 *
 * Returned by GET /x402/supported to let clients discover
 * what this facilitator supports.
 */
struct FacilitatorInfo {
    std::string version;             // "2.0"
    std::vector<std::string> schemes;// ["exact"]
    std::vector<std::string> networks; // ["dilv:mainnet"]
    std::vector<std::string> assets; // ["DILV"]
    int64_t micropaymentThreshold;   // Below this = 0-conf accepted
    bool vmaEnabled;                 // Verified Mempool Acceptance supported

    std::string ToJSON() const;
};

// ============================================================================
// Extension Types — DNA Trust, VDF Challenge, SIWX
// ============================================================================

/**
 * DnaTrustRequest — client requests a trust attestation for an address
 */
struct DnaTrustRequest {
    std::string address;         // DilV address to check
    std::string network;         // CAIP-2 network ID
    double minScore;             // Minimum trust score required (0-100)
    std::string minTier;         // Minimum trust tier ("UNTRUSTED","NEW","ESTABLISHED","TRUSTED","VETERAN")
};

/**
 * DnaTrustAttestation — facilitator's signed trust attestation
 *
 * Returned by GET /x402/dna-attest?address=...
 * Used by x402 servers to gate access based on payer trust level.
 */
struct DnaTrustAttestation {
    std::string address;         // DilV address
    std::string network;         // CAIP-2 network ID
    double trustScore;           // Current trust score (0-100)
    std::string trustTier;       // "UNTRUSTED","NEW","ESTABLISHED","TRUSTED","VETERAN"
    uint32_t registrationHeight; // Block height of DNA registration
    uint32_t consecutiveHeartbeats; // Consecutive heartbeat count
    uint64_t timestamp;          // Attestation timestamp (unix seconds)
    bool isRegistered;           // Whether address has Digital DNA

    std::string ToJSON() const;
};

/**
 * VdfChallengeRequest — client requests a VDF challenge
 */
struct VdfChallengeRequest {
    uint64_t iterations;         // Requested iteration count (0 = use default)
    std::string address;         // Payer address (for challenge seed)
    std::string network;         // CAIP-2 network ID
};

/**
 * VdfChallengeResponse — facilitator issues a VDF challenge
 *
 * Returned by POST /x402/vdf-challenge
 */
struct VdfChallengeResponse {
    std::string challengeId;     // Unique challenge ID (hex)
    std::string seed;            // 32-byte challenge seed (hex)
    uint64_t iterations;         // Required iterations
    uint64_t timeoutSec;         // Seconds to complete
    std::string network;         // CAIP-2 network ID

    std::string ToJSON() const;
};

/**
 * VdfProofSubmission — client submits VDF proof
 */
struct VdfProofSubmission {
    std::string challengeId;     // Matches VdfChallengeResponse.challengeId
    std::string output;          // 32-byte VDF output (hex)
    std::string proof;           // Wesolowski proof (hex)
    uint64_t iterations;         // Iterations performed
};

/**
 * VdfVerifyResult — facilitator's VDF proof verification
 *
 * Returned by POST /x402/vdf-verify
 */
struct VdfVerifyResult {
    bool valid;                  // Proof is cryptographically valid
    std::string challengeId;     // Challenge this proof answers
    uint64_t iterations;         // Verified iteration count
    std::string reason;          // Human-readable reason if invalid

    std::string ToJSON() const;
};

/**
 * SIWXChallenge — Sign-In-With-X challenge (Dilithium3)
 *
 * Returned by POST /x402/siwx/challenge
 * Client signs the nonce with their Dilithium3 key.
 */
struct SIWXChallenge {
    std::string challengeId;     // Unique challenge ID (hex)
    std::string nonce;           // 32-byte random nonce (hex)
    std::string domain;          // Requesting domain
    std::string address;         // Claimed DilV address
    std::string network;         // CAIP-2 network ID
    uint64_t issuedAt;           // Unix timestamp
    uint64_t expiresAt;          // Unix timestamp

    std::string ToJSON() const;
};

/**
 * SIWXAuth — client's signed authentication proof
 *
 * Sent to POST /x402/siwx/verify
 */
struct SIWXAuth {
    std::string challengeId;     // Matches SIWXChallenge.challengeId
    std::string signature;       // Dilithium3 signature over nonce (hex)
    std::string publicKey;       // Dilithium3 public key (hex, 1952 bytes)
    std::string address;         // Claimed DilV address
};

/**
 * SIWXResult — facilitator's SIWX verification result
 *
 * Returned by POST /x402/siwx/verify
 */
struct SIWXResult {
    bool valid;                  // Signature verified and address matches
    std::string address;         // Verified DilV address
    std::string reason;          // Human-readable reason if invalid
    std::string network;         // CAIP-2 network ID

    std::string ToJSON() const;
};

} // namespace x402

#endif // DILITHION_X402_TYPES_H
