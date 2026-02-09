/**
 * VDF Test Tool
 *
 * Tests chiavdf class group VDF computation and Wesolowski verification.
 */

#include "vdf.h"
#include <iostream>
#include <iomanip>
#include <cstring>

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len && i < 16; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    if (len > 16) std::cout << "...";
    std::cout << std::dec;
}

int main(int argc, char* argv[]) {
    // Default: 10,000 iterations (~2-10 seconds for class group squarings)
    uint64_t iterations = 10'000;

    if (argc > 1) {
        iterations = std::stoull(argv[1]);
    }

    std::cout << "Dilithion VDF Test (chiavdf)\n";
    std::cout << "============================\n\n";
    std::cout << "Version: " << vdf::version() << "\n\n";

    // Initialize
    if (!vdf::init()) {
        std::cerr << "Failed to initialize VDF library\n";
        return 1;
    }

    // Benchmark
    std::cout << "=== BENCHMARK ===\n\n";
    std::cout << "Running benchmark (1,000 class group squarings)...\n";

    uint64_t ips = vdf::benchmark(1'000);
    std::cout << "Performance: " << ips << " iterations/sec";
    if (ips > 1'000'000) {
        std::cout << " (" << (ips / 1'000'000.0) << " M/s)";
    } else if (ips > 1'000) {
        std::cout << " (" << (ips / 1'000.0) << " K/s)";
    }
    std::cout << "\n";

    double time_for_200m = 200'000'000.0 / ips;
    std::cout << "Estimated time for 200M iterations: " << std::fixed << std::setprecision(1) << time_for_200m << " seconds\n\n";

    // Compute VDF
    std::cout << "=== VDF COMPUTATION ===\n\n";
    std::cout << "Iterations: " << iterations << "\n";

    std::array<uint8_t, 32> challenge = {};
    for (int i = 0; i < 32; i++) {
        challenge[i] = static_cast<uint8_t>(i * 7 + 13);
    }

    std::cout << "Challenge: ";
    print_hex(challenge.data(), 32);
    std::cout << "\n";

    vdf::VDFConfig config;

    std::cout << "Computing VDF (class group squarings)...\n";
    auto result = vdf::compute(challenge, iterations, config, nullptr);

    if (result.proof.empty()) {
        std::cerr << "ERROR: VDF computation failed!\n";
        return 1;
    }

    std::cout << "Output: ";
    print_hex(result.output.data(), 32);
    std::cout << "\n";
    std::cout << "Duration: " << (result.duration_us / 1000.0) << " ms\n";
    std::cout << "Proof size: " << result.proof.size() << " bytes\n\n";

    // Verify
    std::cout << "=== VERIFICATION ===\n\n";
    std::cout << "Verifying Wesolowski proof...\n";

    auto verify_start = std::chrono::high_resolution_clock::now();
    bool valid = vdf::verify(challenge, result, config);
    auto verify_end = std::chrono::high_resolution_clock::now();
    auto verify_us = std::chrono::duration_cast<std::chrono::microseconds>(verify_end - verify_start).count();

    std::cout << "Valid: " << (valid ? "YES" : "NO") << "\n";
    std::cout << "Verify time: " << (verify_us / 1000.0) << " ms\n\n";

    if (!valid) {
        std::cerr << "ERROR: Proof verification FAILED!\n";
        return 1;
    }

    // Test invalid proof rejection
    std::cout << "=== INVALID PROOF TEST ===\n\n";

    vdf::VDFResult tampered = result;
    tampered.proof[0] ^= 0xFF;  // Flip bits in the proof
    // Recompute output hash from tampered proof to bypass the output check
    tampered.output.fill(0);
    bool tampered_valid = vdf::verify(challenge, tampered, config);
    std::cout << "Tampered proof accepted: " << (tampered_valid ? "YES (BAD!)" : "NO (correct)") << "\n\n";

    if (tampered_valid) {
        std::cerr << "ERROR: Tampered proof was incorrectly accepted!\n";
        return 1;
    }

    // Serialization round-trip
    std::cout << "=== SERIALIZATION TEST ===\n\n";

    auto serialized = result.serialize();
    std::cout << "Serialized size: " << serialized.size() << " bytes\n";

    auto deserialized = vdf::VDFResult::deserialize(serialized);
    if (!deserialized) {
        std::cerr << "ERROR: Deserialization failed!\n";
        return 1;
    }

    bool round_trip_ok = (deserialized->output == result.output &&
                          deserialized->iterations == result.iterations &&
                          deserialized->proof == result.proof);
    std::cout << "Round-trip: " << (round_trip_ok ? "PASS" : "FAIL") << "\n\n";

    if (!round_trip_ok) {
        std::cerr << "ERROR: Serialization round-trip failed!\n";
        return 1;
    }

    // Lottery simulation
    std::cout << "=== LOTTERY SIMULATION ===\n\n";
    std::cout << "Simulating 3 miners competing for a block...\n\n";

    std::array<uint8_t, 32> prev_hash = {};
    prev_hash[0] = 0xAB;
    uint32_t height = 7000;

    struct Miner {
        const char* name;
        std::array<uint8_t, 20> address;
    };

    Miner miners[3] = {
        {"Alice", {}},
        {"Bob", {}},
        {"Carol", {}},
    };

    // Generate unique addresses
    for (int m = 0; m < 3; m++) {
        for (int i = 0; i < 20; i++) {
            miners[m].address[i] = static_cast<uint8_t>(m * 20 + i);
        }
    }

    // Each miner computes their VDF (short for demo)
    uint64_t lottery_iters = std::min(iterations, (uint64_t)1000);
    struct Result {
        const char* name;
        std::array<uint8_t, 32> output;
    };
    Result results[3];

    for (int m = 0; m < 3; m++) {
        auto miner_challenge = vdf::compute_challenge(prev_hash, height, miners[m].address);
        auto vdf_result = vdf::compute(miner_challenge, lottery_iters, config, nullptr);
        results[m].name = miners[m].name;
        results[m].output = vdf_result.output;

        std::cout << miners[m].name << " output: ";
        print_hex(vdf_result.output.data(), 8);
        std::cout << "\n";
    }

    // Find winner (lowest output)
    int winner = 0;
    for (int m = 1; m < 3; m++) {
        if (vdf::compare_outputs(results[m].output, results[winner].output) < 0) {
            winner = m;
        }
    }

    std::cout << "\nWinner: " << results[winner].name << " (lowest VDF output)\n\n";

    std::cout << "=== ALL TESTS PASSED ===\n";

    vdf::shutdown();
    return 0;
}
