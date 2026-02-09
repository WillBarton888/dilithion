/**
 * Dilithion VDF Implementation
 *
 * Uses chiavdf (Chia's class group VDF) for production-grade
 * Verifiable Delay Function computation and verification.
 *
 * The class group VDF provides:
 * - Sequential: Cannot be parallelized (no hashrate advantage)
 * - Verifiable: Wesolowski proof checks in ~1ms
 * - Deterministic: Same input always produces same output
 * - Secure: Based on assumed hardness of class group order computation
 */

#include "vdf.h"

#include <crypto/sha3.h>
#include <cstring>
#include <algorithm>
#include <chrono>

// chiavdf C wrapper API
#include <c_bindings/c_wrapper.h>

namespace {

// BQFC serialized form size for 1024-bit discriminant
// Formula: ((BQFC_MAX_D_BITS + 31) / 32 * 3 + 4) = ((1024 + 31) / 32 * 3 + 4) = 100
static constexpr int CHIAVDF_FORM_SIZE = 100;

// Default initial form (generator): a=2, b=1 in BQFC serialization
// The byte 0x08 encodes the generator element (2, 1, c) where c = (1-D)/8
// This is the standard class group generator used by chiavdf
static const uint8_t DEFAULT_INITIAL_FORM[CHIAVDF_FORM_SIZE] = { 0x08 };

} // anonymous namespace

namespace vdf {

// Serialize VDF result to bytes
std::vector<uint8_t> VDFResult::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(32 + 8 + 8 + 4 + proof.size());

    // Output (32 bytes)
    data.insert(data.end(), output.begin(), output.end());

    // Iterations (8 bytes, little-endian)
    for (int i = 0; i < 8; i++)
        data.push_back(static_cast<uint8_t>(iterations >> (i * 8)));

    // Duration (8 bytes, little-endian)
    for (int i = 0; i < 8; i++)
        data.push_back(static_cast<uint8_t>(duration_us >> (i * 8)));

    // Proof length (4 bytes, little-endian)
    uint32_t proof_len = static_cast<uint32_t>(proof.size());
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(proof_len >> (i * 8)));

    // Proof data
    data.insert(data.end(), proof.begin(), proof.end());

    return data;
}

std::optional<VDFResult> VDFResult::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 52) return std::nullopt;  // Minimum: 32 + 8 + 8 + 4

    VDFResult result;
    size_t offset = 0;

    // Output
    std::copy(data.begin(), data.begin() + 32, result.output.begin());
    offset += 32;

    // Iterations
    result.iterations = 0;
    for (int i = 0; i < 8; i++)
        result.iterations |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
    offset += 8;

    // Duration
    result.duration_us = 0;
    for (int i = 0; i < 8; i++)
        result.duration_us |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
    offset += 8;

    // Proof length
    uint32_t proof_len = 0;
    for (int i = 0; i < 4; i++)
        proof_len |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
    offset += 4;

    if (data.size() < offset + proof_len) return std::nullopt;

    // Proof data
    result.proof.assign(data.begin() + offset, data.begin() + offset + proof_len);

    return result;
}

std::array<uint8_t, 32> VDFResult::proof_hash() const {
    std::array<uint8_t, 32> hash;
    SHA3_256(proof.data(), proof.size(), hash.data());
    return hash;
}

// Compute VDF using chiavdf class group squarings with Wesolowski proof
VDFResult compute(
    const std::array<uint8_t, 32>& challenge,
    uint64_t iterations,
    const VDFConfig& config,
    ProgressCallback progress
) {
    (void)progress;  // chiavdf doesn't support progress callbacks

    VDFResult result;
    result.iterations = iterations;

    auto start = std::chrono::high_resolution_clock::now();

    // chiavdf prove_wrapper:
    // 1. Creates class group discriminant from challenge hash
    // 2. Deserializes initial form from DEFAULT_INITIAL_FORM (generator element)
    // 3. Performs 'iterations' sequential class group squarings
    // 4. Generates Wesolowski proof (compact ~100 byte proof)
    // Returns: SerializeForm(y) + SerializeForm(proof) = 200 bytes
    ByteArray proof_result = prove_wrapper(
        challenge.data(), challenge.size(),
        DEFAULT_INITIAL_FORM, CHIAVDF_FORM_SIZE,
        config.discriminant_bits, iterations
    );

    auto end = std::chrono::high_resolution_clock::now();
    result.duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    if (proof_result.data == nullptr || proof_result.length == 0) {
        // Computation failed or was cancelled
        result.output.fill(0);
        return result;
    }

    // Hash the y form (first CHIAVDF_FORM_SIZE bytes) to get deterministic 32-byte output
    // This output is used for lottery comparison (lower value wins the block)
    SHA3_256(proof_result.data, CHIAVDF_FORM_SIZE, result.output.data());

    // Store the full proof blob (y + proof = 200 bytes for 1024-bit discriminant)
    result.proof.assign(proof_result.data, proof_result.data + proof_result.length);

    // Free chiavdf allocated memory
    delete_byte_array(proof_result);

    return result;
}

// Verify VDF proof using Wesolowski verification (~1ms)
bool verify(
    const std::array<uint8_t, 32>& challenge,
    const VDFResult& result,
    const VDFConfig& config
) {
    if (result.proof.empty()) return false;

    // Expected proof size: 2 * CHIAVDF_FORM_SIZE (y form + proof form)
    if (result.proof.size() != 2u * CHIAVDF_FORM_SIZE) return false;

    // Verify the output matches the y form hash in the proof
    std::array<uint8_t, 32> expected_output;
    SHA3_256(result.proof.data(), CHIAVDF_FORM_SIZE, expected_output.data());
    if (expected_output != result.output) return false;

    // Create discriminant from challenge (exports |D| as big-endian bytes)
    size_t disc_byte_size = (config.discriminant_bits + 7) / 8;
    std::vector<uint8_t> disc_bytes(disc_byte_size, 0);
    if (!create_discriminant_wrapper(
            challenge.data(), challenge.size(),
            config.discriminant_bits, disc_bytes.data())) {
        return false;
    }

    // Verify Wesolowski proof
    // verify_n_wesolowski_wrapper internally:
    // 1. Imports |D| from disc_bytes
    // 2. Negates to get D (class group discriminant is negative)
    // 3. Checks proof: x^r * pi^(2^T) == y where B = H(x||y)
    return verify_n_wesolowski_wrapper(
        disc_bytes.data(), disc_byte_size,
        DEFAULT_INITIAL_FORM,
        result.proof.data(), result.proof.size(),
        result.iterations,
        0  // recursion depth: 0 = simple Wesolowski (no n-wesolowski segments)
    );
}

// Compute VDF challenge from block data
std::array<uint8_t, 32> compute_challenge(
    const std::array<uint8_t, 32>& prev_hash,
    uint32_t height,
    const std::array<uint8_t, 20>& miner_address
) {
    // Concatenate: prev_hash (32) || height (4) || miner_address (20) = 56 bytes
    uint8_t input[56];
    std::copy(prev_hash.begin(), prev_hash.end(), input);

    // Height in little-endian
    input[32] = static_cast<uint8_t>(height);
    input[33] = static_cast<uint8_t>(height >> 8);
    input[34] = static_cast<uint8_t>(height >> 16);
    input[35] = static_cast<uint8_t>(height >> 24);

    std::copy(miner_address.begin(), miner_address.end(), input + 36);

    std::array<uint8_t, 32> challenge;
    SHA3_256(input, 56, challenge.data());

    return challenge;
}

// Compare VDF outputs (lower wins)
int compare_outputs(
    const std::array<uint8_t, 32>& a,
    const std::array<uint8_t, 32>& b
) {
    // Compare as big-endian 256-bit integers
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// Benchmark VDF performance on this hardware
uint64_t benchmark(uint64_t sample_iterations) {
    std::array<uint8_t, 32> challenge = {};
    challenge[0] = 0x42;  // Arbitrary starting value

    VDFConfig config;
    auto result = compute(challenge, sample_iterations, config, nullptr);

    if (result.duration_us == 0) return sample_iterations * 1'000'000;  // Avoid div by zero
    return (sample_iterations * 1'000'000) / result.duration_us;
}

// Calculate recommended iterations for target block time
uint64_t calculate_iterations(double target_seconds, uint64_t measured_ips) {
    return static_cast<uint64_t>(target_seconds * measured_ips);
}

// Library init/cleanup
bool init() { return true; }
void shutdown() {}

const char* version() {
    return "Dilithion VDF 1.0.0 (chiavdf class group)";
}

} // namespace vdf
