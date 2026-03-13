// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DNA_VERIFICATION_H
#define DILITHION_DNA_VERIFICATION_H

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace digital_dna {
namespace verification {

// ============================================================================
// Verification Status
// ============================================================================

enum class VerificationStatus : uint8_t {
    UNVERIFIED = 0,  // No attestations or below quorum
    PENDING    = 1,  // Verification in progress (challenges sent)
    VERIFIED   = 2,  // >= ATTESTATION_QUORUM PASS attestations
    FAILED     = 3   // Majority FAIL attestations
};

inline const char* VerificationStatusName(VerificationStatus s) {
    switch (s) {
        case VerificationStatus::UNVERIFIED: return "UNVERIFIED";
        case VerificationStatus::PENDING:    return "PENDING";
        case VerificationStatus::VERIFIED:   return "VERIFIED";
        case VerificationStatus::FAILED:     return "FAILED";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Constants
// ============================================================================

static constexpr size_t VERIFIER_COUNT = 7;           // Number of verifiers selected
static constexpr size_t ATTESTATION_QUORUM = 5;       // PASS attestations needed for VERIFIED
static constexpr uint64_t VDF_CHALLENGE_ITERS = 100000; // 100K iterations (~1.3s)
static constexpr double VDF_TIMING_TOLERANCE = 0.25;  // ±25%
static constexpr double BW_TOLERANCE = 0.40;          // ±40%
static constexpr int64_t VDF_CHALLENGE_TIMEOUT_SEC = 30;
static constexpr int64_t BW_CHALLENGE_TIMEOUT_SEC = 60;
static constexpr int64_t LATENCY_TIMEOUT_SEC = 10;
static constexpr int MAX_CONCURRENT_VERIFICATIONS = 3;
static constexpr int64_t VERIFICATION_RATE_LIMIT_SEC = 86400; // 24 hours
static constexpr int MAX_ATTESTATIONS_PER_PEER_PER_HOUR = 10;

// ============================================================================
// Verification Challenge (verifier → target)
// ============================================================================

struct VerificationChallenge {
    std::array<uint8_t, 20> target_mik;
    std::array<uint8_t, 20> verifier_mik;
    uint32_t registration_height;         // Height where DNA was registered
    std::array<uint8_t, 32> vdf_seed;     // SHA3(block_hash || verifier_mik || target_mik || "vdf")
    uint64_t vdf_iterations;              // VDF_CHALLENGE_ITERS
    uint64_t nonce;                       // For matching response

    std::vector<uint8_t> serialize() const;
    static std::optional<VerificationChallenge> deserialize(const std::vector<uint8_t>& data);

    // Wire format size: 20 + 20 + 4 + 32 + 8 + 8 = 92 bytes
    static constexpr size_t WIRE_SIZE = 92;
};

// ============================================================================
// Verification Response (target → verifier)
// ============================================================================

struct VerificationResponse {
    uint64_t nonce;                       // Matches challenge nonce
    std::array<uint8_t, 20> target_mik;
    // VDF computation result
    std::array<uint8_t, 32> vdf_output;
    std::vector<uint8_t> vdf_proof;       // Wesolowski proof (~100-200 bytes)
    uint64_t vdf_elapsed_us;              // How long the computation took

    std::vector<uint8_t> serialize() const;
    static std::optional<VerificationResponse> deserialize(const std::vector<uint8_t>& data);

    // Wire format: 8 + 20 + 32 + 2(len) + proof + 8 = 70 + proof_len
};

// ============================================================================
// Dimension Result (per-dimension measurement in attestation)
// ============================================================================

struct DimensionResult {
    double measured_value;
    double claimed_value;
    bool pass;

    // 8 + 8 + 1 = 17 bytes serialized
    std::vector<uint8_t> serialize() const;
    static std::optional<DimensionResult> deserialize(const uint8_t* data, size_t len);
    static constexpr size_t WIRE_SIZE = 17;
};

// ============================================================================
// DNA Attestation (verifier → network broadcast)
// ============================================================================

struct DNAAttestation {
    std::array<uint8_t, 20> target_mik;
    std::array<uint8_t, 20> verifier_mik;
    uint32_t registration_height;
    uint64_t timestamp;

    // Per-dimension measurement results
    DimensionResult vdf_timing;       // iterations_per_second
    DimensionResult bandwidth_up;     // Mbps
    DimensionResult bandwidth_down;   // Mbps
    double latency_rtt_ms;            // Measured RTT (informational, no pass/fail)

    bool overall_pass;

    // Dilithium3 signature over serialized body
    std::vector<uint8_t> signature;       // 3,309 bytes
    std::vector<uint8_t> verifier_pubkey; // 1,952 bytes

    // Serialize body only (for signing/verification)
    std::vector<uint8_t> serialize_body() const;

    // Serialize full attestation (body + signature + pubkey)
    std::vector<uint8_t> serialize() const;
    static std::optional<DNAAttestation> deserialize(const std::vector<uint8_t>& data);

    // Verify the Dilithium3 signature over the body
    bool verify_signature() const;

    // Body size: 20 + 20 + 4 + 8 + 3×17 + 8 + 1 = 112 bytes
    // Full size: 112 + 4(sig_len) + 3309 + 4(pk_len) + 1952 = ~5381 bytes
};

// ============================================================================
// Verifier Selection
// ============================================================================

/**
 * Deterministically select verifiers for a DNA registration.
 *
 * Algorithm: For each candidate MIK, compute SHA3(block_hash || target_mik || candidate_mik).
 * Interpret the first 8 bytes as uint64 score. Sort descending. Return top `count`.
 * Target MIK is excluded from candidates.
 *
 * @param block_hash Hash of the block at which registration was confirmed
 * @param target_mik MIK being verified
 * @param candidate_miks All registered MIKs (from DNA registry)
 * @param count Number of verifiers to select (default VERIFIER_COUNT=7)
 * @return Selected verifier MIKs, ordered by score
 */
std::vector<std::array<uint8_t, 20>> SelectVerifiers(
    const std::array<uint8_t, 32>& block_hash,
    const std::array<uint8_t, 20>& target_mik,
    const std::vector<std::array<uint8_t, 20>>& candidate_miks,
    size_t count = VERIFIER_COUNT);

} // namespace verification
} // namespace digital_dna

#endif // DILITHION_DNA_VERIFICATION_H
