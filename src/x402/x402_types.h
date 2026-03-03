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
 * Implements the x402 v2 protocol data structures for DilV chain.
 * Reference: https://docs.x402.org
 *
 * DilV uses a UTXO-based payment model with Dilithium (post-quantum) signatures.
 * Network identifier: "dilv:mainnet" (CAIP-2 style, pending registration)
 */

// DilV network identifier for x402
static const char* SCHEME_ID = "exact";
static const char* NETWORK_ID = "dilv:mainnet";
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

} // namespace x402

#endif // DILITHION_X402_TYPES_H
