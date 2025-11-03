// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Difficulty Adjustment Determinism Test
 *
 * CRITICAL CONSENSUS TEST
 *
 * This test validates that difficulty adjustment calculations produce
 * identical results across all platforms, architectures, and compilers.
 *
 * Purpose: Prevent consensus forks due to platform-specific arithmetic
 * Priority: P0 - CRITICAL (Mainnet blocker)
 * Related: CRITICAL-DIFFICULTY-DETERMINISM-PLAN.md
 * FIXME: src/consensus/pow.cpp:228-230
 */

#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>

// Include the consensus code we're testing
#include <consensus/pow.h>
#include <primitives/block.h>
#include <uint256.h>

// JSON output for cross-platform comparison
struct TestResult {
    std::string test_id;
    std::string input_target_hex;
    uint32_t input_compact;
    int64_t actual_timespan;
    int64_t target_timespan;
    std::string output_target_hex;
    uint32_t output_compact;
    bool passed;
    std::string error_message;
};

/**
 * Convert uint256 to hex string for comparison
 */
std::string uint256_to_hex(const uint256& value) {
    std::stringstream ss;
    for (int i = 31; i >= 0; i--) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << (unsigned int)value.data[i];
    }
    return ss.str();
}

/**
 * Create uint256 from hex string
 */
uint256 hex_to_uint256(const std::string& hex) {
    uint256 result;
    memset(result.data, 0, 32);

    // Parse hex string (expecting 64 hex chars = 32 bytes)
    for (size_t i = 0; i < hex.length() && i < 64; i += 2) {
        std::string byte_str = hex.substr(i, 2);
        unsigned int byte_val = std::stoul(byte_str, nullptr, 16);

        // Store in little-endian order
        result.data[31 - (i / 2)] = static_cast<uint8_t>(byte_val);
    }

    return result;
}

/**
 * Test Case Structure
 */
struct DifficultyTestCase {
    std::string id;
    std::string description;
    uint32_t input_compact;
    int64_t actual_timespan;
    int64_t target_timespan;
    uint32_t expected_compact;
    std::string expected_hex;
};

/**
 * Get platform information for reporting
 */
std::string get_platform_info() {
    std::stringstream info;

    info << "Platform: ";
#if defined(__x86_64__) || defined(_M_X64)
    info << "x86-64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    info << "ARM64";
#elif defined(__riscv)
    info << "RISC-V";
#else
    info << "Unknown";
#endif

    info << ", OS: ";
#if defined(__linux__)
    info << "Linux";
#elif defined(_WIN32)
    info << "Windows";
#elif defined(__APPLE__)
    info << "macOS";
#else
    info << "Unknown";
#endif

    info << ", Compiler: ";
#if defined(__GNUC__) && !defined(__clang__)
    info << "GCC " << __GNUC__ << "." << __GNUC_MINOR__;
#elif defined(__clang__)
    info << "Clang " << __clang_major__ << "." << __clang_minor__;
#elif defined(_MSC_VER)
    info << "MSVC " << _MSC_VER;
#else
    info << "Unknown";
#endif

    return info.str();
}

/**
 * Run a single difficulty test case
 */
TestResult run_test_case(const DifficultyTestCase& test) {
    TestResult result;
    result.test_id = test.id;
    result.input_compact = test.input_compact;
    result.actual_timespan = test.actual_timespan;
    result.target_timespan = test.target_timespan;

    // Convert compact bits to full target
    uint256 input_target = CompactToBig(test.input_compact);
    result.input_target_hex = uint256_to_hex(input_target);

    // CRITICAL: Call the actual difficulty adjustment code
    // This is the function we're validating for cross-platform determinism
    uint32_t calculated_compact = CalculateNextWorkRequired(
        test.input_compact,
        test.actual_timespan,
        test.target_timespan
    );

    result.output_compact = calculated_compact;

    // Convert result back to full target
    uint256 output_target = CompactToBig(calculated_compact);
    result.output_target_hex = uint256_to_hex(output_target);

    // Compare with expected
    if (calculated_compact == test.expected_compact) {
        result.passed = true;
    } else {
        result.passed = false;
        result.error_message = "Compact mismatch: expected 0x" +
            std::to_string(test.expected_compact) + ", got 0x" +
            std::to_string(calculated_compact);
    }

    return result;
}

/**
 * Generate test vectors
 */
std::vector<DifficultyTestCase> generate_test_vectors() {
    std::vector<DifficultyTestCase> tests;

    // Test 1: No change (exact 2 weeks)
    tests.push_back({
        "basic_001_no_change",
        "Exact 2-week timespan, no difficulty change",
        0x1d00ffff,  // Bitcoin genesis difficulty
        1209600,     // 2 weeks
        1209600,     // 2 weeks
        0x1d00ffff,  // No change expected
        "00000000ffff0000000000000000000000000000000000000000000000000000"
    });

    // Test 2: Blocks 2x faster (difficulty should double)
    tests.push_back({
        "basic_002_2x_faster",
        "Blocks came 2x faster, difficulty should double",
        0x1d00ffff,
        604800,      // 1 week (half the target)
        1209600,
        0x1c7fffff,  // Approximately doubled difficulty
        ""           // Will calculate expected
    });

    // Test 3: Blocks 2x slower (difficulty should halve)
    tests.push_back({
        "basic_003_2x_slower",
        "Blocks came 2x slower, difficulty should halve",
        0x1d00ffff,
        2419200,     // 4 weeks (double the target)
        1209600,
        0x1d01ffff,  // Approximately halved difficulty
        ""
    });

    // Test 4: Maximum increase (4x faster, clamped)
    tests.push_back({
        "edge_004_max_increase",
        "Blocks 4x faster, difficulty increases by maximum 4x",
        0x1d00ffff,
        302400,      // 3.5 days (target/4)
        1209600,
        0x1c3fffff,  // 4x difficulty increase (clamped)
        ""
    });

    // Test 5: Maximum decrease (4x slower, clamped)
    tests.push_back({
        "edge_005_max_decrease",
        "Blocks 4x slower, difficulty decreases by maximum 4x",
        0x1d00ffff,
        4838400,     // 8 weeks (target*4)
        1209600,
        0x1d03ffff,  // 4x difficulty decrease (clamped)
        ""
    });

    // Test 6: Even faster (should be clamped to 4x)
    tests.push_back({
        "edge_006_faster_than_4x",
        "Blocks 8x faster, but clamped to 4x increase",
        0x1d00ffff,
        151200,      // 1.75 days (target/8)
        1209600,
        0x1c3fffff,  // Still 4x max (clamped)
        ""
    });

    // Test 7: Even slower (should be clamped to 4x)
    tests.push_back({
        "edge_007_slower_than_4x",
        "Blocks 8x slower, but clamped to 4x decrease",
        0x1d00ffff,
        9676800,     // 16 weeks (target*8)
        1209600,
        0x1d03ffff,  // Still 4x max (clamped)
        ""
    });

    // Test 8: High difficulty target
    tests.push_back({
        "edge_008_high_difficulty",
        "High difficulty, 2x faster",
        0x1b0404cb,  // Bitcoin block ~2000 difficulty
        604800,
        1209600,
        0x1a020265,  // Approximately
        ""
    });

    // Test 9: Low difficulty target
    tests.push_back({
        "edge_009_low_difficulty",
        "Low difficulty (testnet), 2x slower",
        0x1e0fffff,  // Very low difficulty
        2419200,
        1209600,
        0x1e1fffff,  // Approximately
        ""
    });

    // Test 10: Minimum difficulty boundary
    tests.push_back({
        "boundary_010_min_difficulty",
        "At minimum difficulty, cannot decrease further",
        0x1effffff,  // Assume this is min
        4838400,     // 4x slower
        1209600,
        0x1effffff,  // Should not go lower
        ""
    });

    return tests;
}

/**
 * Output results as JSON for cross-platform comparison
 */
void output_json_results(const std::vector<TestResult>& results,
                        const std::string& filename) {
    std::ofstream outfile(filename);

    outfile << "{\n";
    outfile << "  \"platform_info\": \"" << get_platform_info() << "\",\n";
    outfile << "  \"test_count\": " << results.size() << ",\n";
    outfile << "  \"passed_count\": "
            << std::count_if(results.begin(), results.end(),
                           [](const TestResult& r) { return r.passed; })
            << ",\n";
    outfile << "  \"results\": [\n";

    for (size_t i = 0; i < results.size(); i++) {
        const auto& r = results[i];

        outfile << "    {\n";
        outfile << "      \"test_id\": \"" << r.test_id << "\",\n";
        outfile << "      \"input_target_hex\": \"" << r.input_target_hex << "\",\n";
        outfile << "      \"input_compact\": \"0x" << std::hex << r.input_compact << "\",\n";
        outfile << "      \"actual_timespan\": " << std::dec << r.actual_timespan << ",\n";
        outfile << "      \"target_timespan\": " << r.target_timespan << ",\n";
        outfile << "      \"output_target_hex\": \"" << r.output_target_hex << "\",\n";
        outfile << "      \"output_compact\": \"0x" << std::hex << r.output_compact << "\",\n";
        outfile << std::dec;
        outfile << "      \"passed\": " << (r.passed ? "true" : "false");

        if (!r.error_message.empty()) {
            outfile << ",\n      \"error\": \"" << r.error_message << "\"";
        }

        outfile << "\n    }";
        if (i < results.size() - 1) outfile << ",";
        outfile << "\n";
    }

    outfile << "  ]\n";
    outfile << "}\n";

    outfile.close();
}

/**
 * Main test execution
 */
int main() {
    std::cout << "========================================\n";
    std::cout << "DIFFICULTY ADJUSTMENT DETERMINISM TEST\n";
    std::cout << "========================================\n\n";

    std::cout << "Platform: " << get_platform_info() << "\n\n";

    std::cout << "CRITICAL: This test validates cross-platform consensus\n";
    std::cout << "          All platforms MUST produce identical results\n\n";

    // Generate test vectors
    auto test_vectors = generate_test_vectors();

    std::cout << "Running " << test_vectors.size() << " test cases...\n\n";

    // Run all tests
    std::vector<TestResult> results;
    int passed = 0;
    int failed = 0;

    for (const auto& test : test_vectors) {
        std::cout << "Test " << test.id << ": " << test.description << "\n";

        TestResult result = run_test_case(test);
        results.push_back(result);

        if (result.passed) {
            std::cout << "  ✓ PASSED\n";
            std::cout << "  Input:  0x" << std::hex << result.input_compact << std::dec << "\n";
            std::cout << "  Output: 0x" << std::hex << result.output_compact << std::dec << "\n";
            passed++;
        } else {
            std::cout << "  ✗ FAILED: " << result.error_message << "\n";
            failed++;
        }

        std::cout << "\n";
    }

    // Summary
    std::cout << "========================================\n";
    std::cout << "SUMMARY\n";
    std::cout << "========================================\n";
    std::cout << "Total:  " << test_vectors.size() << " tests\n";
    std::cout << "Passed: " << passed << " tests\n";
    std::cout << "Failed: " << failed << " tests\n\n";

    // Output JSON for cross-platform comparison
    std::string json_filename = "difficulty_results.json";
    output_json_results(results, json_filename);
    std::cout << "Results saved to: " << json_filename << "\n";
    std::cout << "Use this file for cross-platform comparison\n\n";

    if (failed > 0) {
        std::cout << "⚠ WARNING: Some tests failed!\n";
        std::cout << "   This indicates a problem with the difficulty calculation.\n";
        return 1;
    }

    std::cout << "✓ All tests passed on this platform\n";
    std::cout << "  Next: Compare with other platforms' results\n";

    return 0;
}
