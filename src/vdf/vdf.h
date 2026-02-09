/**
 * Dilithion VDF (Verifiable Delay Function) Interface
 *
 * Provides time-locked computation for fair mining lottery.
 * Uses Chia's class group VDF implementation (chiavdf).
 *
 * Key properties:
 * - Sequential: Cannot be parallelized (no hashrate advantage)
 * - Verifiable: Proof can be checked quickly (~1ms)
 * - Deterministic: Same input always produces same output
 */

#ifndef DILITHION_VDF_H
#define DILITHION_VDF_H

#include <array>
#include <vector>
#include <cstdint>
#include <string>
#include <chrono>
#include <optional>
#include <functional>

namespace vdf {

// VDF computation result
struct VDFResult {
    std::array<uint8_t, 32> output;      // 256-bit VDF output (y)
    std::vector<uint8_t> proof;          // Wesolowski proof (~100 bytes)
    uint64_t iterations;                  // Number of squarings performed
    uint64_t duration_us;                 // Time taken in microseconds

    // Serialize to bytes (for network/storage)
    std::vector<uint8_t> serialize() const;
    static std::optional<VDFResult> deserialize(const std::vector<uint8_t>& data);

    // Hash of proof for compact storage in block header
    std::array<uint8_t, 32> proof_hash() const;
};

// VDF configuration
struct VDFConfig {
    // Target iterations for ~200 second computation on average hardware
    // Adjusted based on network difficulty
    uint64_t target_iterations = 200'000'000;

    // Discriminant size in bits (security parameter)
    // 1024 bits provides ~128 bits of security
    uint32_t discriminant_bits = 1024;

    // Progress callback interval (0 = no callbacks)
    uint64_t progress_interval = 1'000'000;
};

// Progress callback type
using ProgressCallback = std::function<void(uint64_t current, uint64_t total)>;

/**
 * Compute VDF output and proof.
 *
 * @param challenge 32-byte input (typically: SHA3(prev_hash || height || miner_addr))
 * @param iterations Number of sequential squarings to perform
 * @param config Optional configuration parameters
 * @param progress Optional progress callback
 * @return VDF result with output and proof
 */
VDFResult compute(
    const std::array<uint8_t, 32>& challenge,
    uint64_t iterations,
    const VDFConfig& config = VDFConfig(),
    ProgressCallback progress = nullptr
);

/**
 * Verify a VDF proof.
 *
 * Verification is fast (~1ms) compared to computation (~200s).
 *
 * @param challenge Original 32-byte input
 * @param result VDF result to verify
 * @param config Configuration (must match computation)
 * @return true if proof is valid
 */
bool verify(
    const std::array<uint8_t, 32>& challenge,
    const VDFResult& result,
    const VDFConfig& config = VDFConfig()
);

/**
 * Compute VDF challenge from block data.
 *
 * challenge = SHA3-256(prev_block_hash || height || miner_address)
 *
 * This ensures each miner computes a unique VDF per block.
 */
std::array<uint8_t, 32> compute_challenge(
    const std::array<uint8_t, 32>& prev_hash,
    uint32_t height,
    const std::array<uint8_t, 20>& miner_address
);

/**
 * Compare two VDF outputs to determine winner.
 *
 * The miner with the LOWEST output wins the block.
 * This creates a fair lottery where each miner has equal probability.
 *
 * @return -1 if a < b, 0 if a == b, 1 if a > b
 */
int compare_outputs(
    const std::array<uint8_t, 32>& a,
    const std::array<uint8_t, 32>& b
);

/**
 * Benchmark VDF performance on this hardware.
 *
 * Runs a short VDF computation to estimate iterations/second.
 * Used to calibrate target_iterations for ~200s blocks.
 *
 * @param sample_iterations Number of iterations for benchmark (default 1M)
 * @return Estimated iterations per second
 */
uint64_t benchmark(uint64_t sample_iterations = 1'000'000);

/**
 * Calculate recommended iterations for target block time.
 *
 * @param target_seconds Desired VDF computation time
 * @param measured_ips Iterations per second from benchmark()
 * @return Recommended iteration count
 */
uint64_t calculate_iterations(double target_seconds, uint64_t measured_ips);

// Library initialization/cleanup
bool init();
void shutdown();

// Version info
const char* version();

} // namespace vdf

#endif // DILITHION_VDF_H
