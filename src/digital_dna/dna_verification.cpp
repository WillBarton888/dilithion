// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <digital_dna/dna_verification.h>
#include <crypto/sha3.h>
#include <cstring>
#include <algorithm>

// Dilithium3 verification (from MIK)
extern "C" {
    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

namespace digital_dna {
namespace verification {

// ============================================================================
// Serialization helpers (little-endian, matching trust_score.cpp pattern)
// ============================================================================

static void write_u32(std::vector<uint8_t>& out, uint32_t val) {
    for (int i = 0; i < 4; i++)
        out.push_back(static_cast<uint8_t>(val >> (i * 8)));
}

static void write_u64(std::vector<uint8_t>& out, uint64_t val) {
    for (int i = 0; i < 8; i++)
        out.push_back(static_cast<uint8_t>(val >> (i * 8)));
}

static void write_double(std::vector<uint8_t>& out, double val) {
    uint64_t bits;
    std::memcpy(&bits, &val, sizeof(double));
    write_u64(out, bits);
}

static void write_u16(std::vector<uint8_t>& out, uint16_t val) {
    out.push_back(static_cast<uint8_t>(val & 0xFF));
    out.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
}

static void write_bytes(std::vector<uint8_t>& out, const uint8_t* data, size_t len) {
    out.insert(out.end(), data, data + len);
}

static void write_vec_with_len(std::vector<uint8_t>& out, const std::vector<uint8_t>& vec) {
    write_u16(out, static_cast<uint16_t>(vec.size()));
    out.insert(out.end(), vec.begin(), vec.end());
}

static uint32_t read_u32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0])
         | (static_cast<uint32_t>(data[1]) << 8)
         | (static_cast<uint32_t>(data[2]) << 16)
         | (static_cast<uint32_t>(data[3]) << 24);
}

static uint64_t read_u64(const uint8_t* data) {
    uint64_t val = 0;
    for (int i = 0; i < 8; i++)
        val |= static_cast<uint64_t>(data[i]) << (i * 8);
    return val;
}

static double read_double(const uint8_t* data) {
    uint64_t bits = read_u64(data);
    double val;
    std::memcpy(&val, &bits, sizeof(double));
    return val;
}

static uint16_t read_u16(const uint8_t* data) {
    return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
}

// ============================================================================
// VerificationChallenge
// ============================================================================

std::vector<uint8_t> VerificationChallenge::serialize() const {
    std::vector<uint8_t> out;
    out.reserve(WIRE_SIZE);
    write_bytes(out, target_mik.data(), 20);
    write_bytes(out, verifier_mik.data(), 20);
    write_u32(out, registration_height);
    write_bytes(out, vdf_seed.data(), 32);
    write_u64(out, vdf_iterations);
    write_u64(out, nonce);
    return out;
}

std::optional<VerificationChallenge> VerificationChallenge::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < WIRE_SIZE) return std::nullopt;
    VerificationChallenge c;
    size_t pos = 0;
    std::memcpy(c.target_mik.data(), data.data() + pos, 20); pos += 20;
    std::memcpy(c.verifier_mik.data(), data.data() + pos, 20); pos += 20;
    c.registration_height = read_u32(data.data() + pos); pos += 4;
    std::memcpy(c.vdf_seed.data(), data.data() + pos, 32); pos += 32;
    c.vdf_iterations = read_u64(data.data() + pos); pos += 8;
    c.nonce = read_u64(data.data() + pos);
    return c;
}

// ============================================================================
// VerificationResponse
// ============================================================================

std::vector<uint8_t> VerificationResponse::serialize() const {
    std::vector<uint8_t> out;
    out.reserve(70 + vdf_proof.size());
    write_u64(out, nonce);
    write_bytes(out, target_mik.data(), 20);
    write_bytes(out, vdf_output.data(), 32);
    write_vec_with_len(out, vdf_proof);
    write_u64(out, vdf_elapsed_us);
    return out;
}

std::optional<VerificationResponse> VerificationResponse::deserialize(const std::vector<uint8_t>& data) {
    // Minimum: 8 + 20 + 32 + 2 + 0 + 8 = 70 bytes
    if (data.size() < 70) return std::nullopt;
    VerificationResponse r;
    size_t pos = 0;
    r.nonce = read_u64(data.data() + pos); pos += 8;
    std::memcpy(r.target_mik.data(), data.data() + pos, 20); pos += 20;
    std::memcpy(r.vdf_output.data(), data.data() + pos, 32); pos += 32;

    if (pos + 2 > data.size()) return std::nullopt;
    uint16_t proof_len = read_u16(data.data() + pos); pos += 2;
    if (pos + proof_len + 8 > data.size()) return std::nullopt;
    r.vdf_proof.assign(data.data() + pos, data.data() + pos + proof_len); pos += proof_len;
    r.vdf_elapsed_us = read_u64(data.data() + pos);
    return r;
}

// ============================================================================
// DimensionResult
// ============================================================================

std::vector<uint8_t> DimensionResult::serialize() const {
    std::vector<uint8_t> out;
    out.reserve(WIRE_SIZE);
    write_double(out, measured_value);
    write_double(out, claimed_value);
    out.push_back(pass ? 1 : 0);
    return out;
}

std::optional<DimensionResult> DimensionResult::deserialize(const uint8_t* data, size_t len) {
    if (len < WIRE_SIZE) return std::nullopt;
    DimensionResult d;
    d.measured_value = read_double(data);
    d.claimed_value = read_double(data + 8);
    d.pass = (data[16] != 0);
    return d;
}

// ============================================================================
// DNAAttestation
// ============================================================================

std::vector<uint8_t> DNAAttestation::serialize_body() const {
    std::vector<uint8_t> out;
    out.reserve(112);

    write_bytes(out, target_mik.data(), 20);
    write_bytes(out, verifier_mik.data(), 20);
    write_u32(out, registration_height);
    write_u64(out, timestamp);

    // 3 dimension results (17 bytes each = 51 bytes)
    auto vdf_bytes = vdf_timing.serialize();
    out.insert(out.end(), vdf_bytes.begin(), vdf_bytes.end());
    auto bw_up_bytes = bandwidth_up.serialize();
    out.insert(out.end(), bw_up_bytes.begin(), bw_up_bytes.end());
    auto bw_down_bytes = bandwidth_down.serialize();
    out.insert(out.end(), bw_down_bytes.begin(), bw_down_bytes.end());

    write_double(out, latency_rtt_ms);
    out.push_back(overall_pass ? 1 : 0);

    return out;
}

std::vector<uint8_t> DNAAttestation::serialize() const {
    auto body = serialize_body();
    std::vector<uint8_t> out;
    out.reserve(body.size() + 4 + signature.size() + 4 + verifier_pubkey.size());

    // Body
    out.insert(out.end(), body.begin(), body.end());

    // Signature with length prefix
    write_u16(out, static_cast<uint16_t>(signature.size()));
    out.insert(out.end(), signature.begin(), signature.end());

    // Public key with length prefix
    write_u16(out, static_cast<uint16_t>(verifier_pubkey.size()));
    out.insert(out.end(), verifier_pubkey.begin(), verifier_pubkey.end());

    return out;
}

std::optional<DNAAttestation> DNAAttestation::deserialize(const std::vector<uint8_t>& data) {
    // Body minimum: 20+20+4+8+51+8+1 = 112 bytes
    if (data.size() < 112) return std::nullopt;

    DNAAttestation a;
    size_t pos = 0;

    std::memcpy(a.target_mik.data(), data.data() + pos, 20); pos += 20;
    std::memcpy(a.verifier_mik.data(), data.data() + pos, 20); pos += 20;
    a.registration_height = read_u32(data.data() + pos); pos += 4;
    a.timestamp = read_u64(data.data() + pos); pos += 8;

    // 3 dimension results
    if (pos + DimensionResult::WIRE_SIZE > data.size()) return std::nullopt;
    auto vdf = DimensionResult::deserialize(data.data() + pos, data.size() - pos);
    if (!vdf) return std::nullopt;
    a.vdf_timing = *vdf; pos += DimensionResult::WIRE_SIZE;

    if (pos + DimensionResult::WIRE_SIZE > data.size()) return std::nullopt;
    auto bw_up = DimensionResult::deserialize(data.data() + pos, data.size() - pos);
    if (!bw_up) return std::nullopt;
    a.bandwidth_up = *bw_up; pos += DimensionResult::WIRE_SIZE;

    if (pos + DimensionResult::WIRE_SIZE > data.size()) return std::nullopt;
    auto bw_down = DimensionResult::deserialize(data.data() + pos, data.size() - pos);
    if (!bw_down) return std::nullopt;
    a.bandwidth_down = *bw_down; pos += DimensionResult::WIRE_SIZE;

    if (pos + 9 > data.size()) return std::nullopt;
    a.latency_rtt_ms = read_double(data.data() + pos); pos += 8;
    a.overall_pass = (data[pos] != 0); pos += 1;

    // Signature
    if (pos + 2 > data.size()) return std::nullopt;
    uint16_t sig_len = read_u16(data.data() + pos); pos += 2;
    if (pos + sig_len > data.size()) return std::nullopt;
    a.signature.assign(data.data() + pos, data.data() + pos + sig_len); pos += sig_len;

    // Public key
    if (pos + 2 > data.size()) return std::nullopt;
    uint16_t pk_len = read_u16(data.data() + pos); pos += 2;
    if (pos + pk_len > data.size()) return std::nullopt;
    a.verifier_pubkey.assign(data.data() + pos, data.data() + pos + pk_len);

    return a;
}

bool DNAAttestation::verify_signature() const {
    if (signature.size() != 3309 || verifier_pubkey.size() != 1952)
        return false;

    auto body = serialize_body();
    int result = pqcrystals_dilithium3_ref_verify(
        signature.data(), signature.size(),
        body.data(), body.size(),
        nullptr, 0,
        verifier_pubkey.data()
    );
    return (result == 0);
}

// ============================================================================
// Verifier Selection
// ============================================================================

std::vector<std::array<uint8_t, 20>> SelectVerifiers(
    const std::array<uint8_t, 32>& block_hash,
    const std::array<uint8_t, 20>& target_mik,
    const std::vector<std::array<uint8_t, 20>>& candidate_miks,
    size_t count)
{
    struct ScoredCandidate {
        std::array<uint8_t, 20> mik;
        uint64_t score;
    };

    std::vector<ScoredCandidate> scored;
    scored.reserve(candidate_miks.size());

    // Preimage: block_hash(32) || target_mik(20) || candidate_mik(20) = 72 bytes
    std::vector<uint8_t> preimage(72);
    std::memcpy(preimage.data(), block_hash.data(), 32);
    std::memcpy(preimage.data() + 32, target_mik.data(), 20);

    for (const auto& candidate : candidate_miks) {
        // Skip self-verification
        if (candidate == target_mik) continue;

        std::memcpy(preimage.data() + 52, candidate.data(), 20);

        uint8_t hash[32];
        SHA3_256(preimage.data(), preimage.size(), hash);

        // First 8 bytes of hash as score (little-endian)
        uint64_t score = read_u64(hash);
        scored.push_back({candidate, score});
    }

    // Sort by score descending
    std::sort(scored.begin(), scored.end(),
        [](const ScoredCandidate& a, const ScoredCandidate& b) {
            return a.score > b.score;
        });

    // Take top `count`
    std::vector<std::array<uint8_t, 20>> result;
    size_t n = std::min(count, scored.size());
    result.reserve(n);
    for (size_t i = 0; i < n; i++) {
        result.push_back(scored[i].mik);
    }

    return result;
}

} // namespace verification
} // namespace digital_dna
