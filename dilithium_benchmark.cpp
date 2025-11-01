/**
 * Dilithium3 Performance Benchmark Suite
 *
 * Comprehensive performance testing for Dilithium3 post-quantum signatures
 * Tests key generation, signing, verification, and blockchain use cases
 */

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <numeric>

// Dilithium3 external C functions
extern "C" {
    // From depends/dilithium/ref/sign.h
    int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);

    int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *sk);

    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

// Dilithium3 size constants (from params.h with MODE=3)
// K=6, L=5, ETA=4, CTILDEBYTES=48
constexpr size_t DILITHIUM3_PUBLIC_KEY_BYTES = 1952;   // 32 + 6*320
constexpr size_t DILITHIUM3_SECRET_KEY_BYTES = 4032;   // 2*32 + 64 + 5*128 + 6*128 + 6*416
constexpr size_t DILITHIUM3_SIGNATURE_BYTES = 3309;    // 48 + 5*640 + (55+6)

// Test configuration
constexpr int WARMUP_ITERATIONS = 100;
constexpr int TEST_ITERATIONS = 1000;
constexpr int STRESS_TEST_SECONDS = 3600;  // 1 hour

// Statistics helper
struct Stats {
    double mean;
    double median;
    double std_dev;
    double min;
    double max;
    double p95;
    double p99;
};

Stats calculate_stats(std::vector<double>& times) {
    if (times.empty()) return {0, 0, 0, 0, 0, 0, 0};

    std::sort(times.begin(), times.end());

    Stats s;
    s.min = times.front();
    s.max = times.back();
    s.median = times[times.size() / 2];

    double sum = std::accumulate(times.begin(), times.end(), 0.0);
    s.mean = sum / times.size();

    double sq_sum = 0;
    for (double t : times) {
        sq_sum += (t - s.mean) * (t - s.mean);
    }
    s.std_dev = std::sqrt(sq_sum / times.size());

    s.p95 = times[(size_t)(times.size() * 0.95)];
    s.p99 = times[(size_t)(times.size() * 0.99)];

    return s;
}

void print_stats(const std::string& operation, const Stats& s, const std::string& unit = "ms") {
    std::cout << "\n" << operation << " Performance:\n";
    std::cout << "  Mean:   " << std::fixed << std::setprecision(3) << s.mean << " " << unit << "\n";
    std::cout << "  Median: " << s.median << " " << unit << "\n";
    std::cout << "  Std Dev:" << s.std_dev << " " << unit << "\n";
    std::cout << "  Min:    " << s.min << " " << unit << "\n";
    std::cout << "  Max:    " << s.max << " " << unit << "\n";
    std::cout << "  95th %: " << s.p95 << " " << unit << "\n";
    std::cout << "  99th %: " << s.p99 << " " << unit << "\n";

    if (unit == "ms") {
        double ops_per_sec = 1000.0 / s.mean;
        std::cout << "  Throughput: " << std::fixed << std::setprecision(0) << ops_per_sec << " ops/sec\n";
    }
}

// Benchmark key generation
Stats benchmark_keygen() {
    std::cout << "\n=== KEY GENERATION BENCHMARK ===\n";
    std::cout << "Warming up (" << WARMUP_ITERATIONS << " iterations)...\n";

    std::vector<uint8_t> pk(DILITHIUM3_PUBLIC_KEY_BYTES);
    std::vector<uint8_t> sk(DILITHIUM3_SECRET_KEY_BYTES);

    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        pqcrystals_dilithium3_ref_keypair(pk.data(), sk.data());
    }

    std::cout << "Running benchmark (" << TEST_ITERATIONS << " iterations)...\n";

    std::vector<double> times;
    times.reserve(TEST_ITERATIONS);

    for (int i = 0; i < TEST_ITERATIONS; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        pqcrystals_dilithium3_ref_keypair(pk.data(), sk.data());
        auto end = std::chrono::high_resolution_clock::now();

        double duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
        times.push_back(duration_ms);
    }

    return calculate_stats(times);
}

// Benchmark signing
Stats benchmark_signing(const uint8_t* sk) {
    std::cout << "\n=== SIGNATURE GENERATION BENCHMARK ===\n";
    std::cout << "Warming up (" << WARMUP_ITERATIONS << " iterations)...\n";

    std::vector<uint8_t> sig(DILITHIUM3_SIGNATURE_BYTES);
    size_t siglen;

    // 32-byte message (typical transaction hash)
    uint8_t message[32];
    memset(message, 0xAB, 32);

    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        pqcrystals_dilithium3_ref_signature(sig.data(), &siglen, message, 32, nullptr, 0, sk);
    }

    std::cout << "Running benchmark (" << TEST_ITERATIONS << " iterations)...\n";

    std::vector<double> times;
    times.reserve(TEST_ITERATIONS);

    for (int i = 0; i < TEST_ITERATIONS; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        pqcrystals_dilithium3_ref_signature(sig.data(), &siglen, message, 32, nullptr, 0, sk);
        auto end = std::chrono::high_resolution_clock::now();

        double duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
        times.push_back(duration_ms);
    }

    return calculate_stats(times);
}

// Benchmark verification
Stats benchmark_verification(const uint8_t* pk, const uint8_t* sig, size_t siglen) {
    std::cout << "\n=== SIGNATURE VERIFICATION BENCHMARK ===\n";
    std::cout << "Warming up (" << WARMUP_ITERATIONS << " iterations)...\n";

    // 32-byte message (typical transaction hash)
    uint8_t message[32];
    memset(message, 0xAB, 32);

    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        pqcrystals_dilithium3_ref_verify(sig, siglen, message, 32, nullptr, 0, pk);
    }

    std::cout << "Running benchmark (" << TEST_ITERATIONS << " iterations)...\n";

    std::vector<double> times;
    times.reserve(TEST_ITERATIONS);

    for (int i = 0; i < TEST_ITERATIONS; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        int result = pqcrystals_dilithium3_ref_verify(sig, siglen, message, 32, nullptr, 0, pk);
        auto end = std::chrono::high_resolution_clock::now();

        if (result != 0) {
            std::cerr << "Verification failed at iteration " << i << "\n";
        }

        double duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
        times.push_back(duration_ms);
    }

    return calculate_stats(times);
}

// Benchmark transaction signing (multiple inputs)
void benchmark_transaction_signing() {
    std::cout << "\n=== TRANSACTION SIGNING BENCHMARK ===\n";

    // Generate keys
    std::vector<uint8_t> pk(DILITHIUM3_PUBLIC_KEY_BYTES);
    std::vector<uint8_t> sk(DILITHIUM3_SECRET_KEY_BYTES);
    pqcrystals_dilithium3_ref_keypair(pk.data(), sk.data());

    std::vector<int> input_counts = {1, 10, 100};

    for (int num_inputs : input_counts) {
        std::cout << "\nTransaction with " << num_inputs << " inputs:\n";

        std::vector<double> times;
        const int iterations = (num_inputs >= 100) ? 100 : 1000;

        for (int i = 0; i < iterations; i++) {
            auto start = std::chrono::high_resolution_clock::now();

            // Sign each input
            for (int j = 0; j < num_inputs; j++) {
                std::vector<uint8_t> sig(DILITHIUM3_SIGNATURE_BYTES);
                size_t siglen;
                uint8_t tx_hash[32];
                memset(tx_hash, j, 32);

                pqcrystals_dilithium3_ref_signature(sig.data(), &siglen,
                                                    tx_hash, 32, nullptr, 0, sk.data());
            }

            auto end = std::chrono::high_resolution_clock::now();
            double duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            times.push_back(duration_ms);
        }

        Stats s = calculate_stats(times);
        std::cout << "  Mean time: " << std::fixed << std::setprecision(2) << s.mean << " ms\n";
        std::cout << "  Time per signature: " << (s.mean / num_inputs) << " ms\n";
        std::cout << "  Tx/sec: " << (1000.0 / s.mean) << "\n";
    }
}

// Benchmark block verification
void benchmark_block_verification() {
    std::cout << "\n=== BLOCK VERIFICATION BENCHMARK ===\n";

    // Generate keys and signatures
    std::vector<uint8_t> pk(DILITHIUM3_PUBLIC_KEY_BYTES);
    std::vector<uint8_t> sk(DILITHIUM3_SECRET_KEY_BYTES);
    pqcrystals_dilithium3_ref_keypair(pk.data(), sk.data());

    std::vector<int> tx_counts = {10, 100, 1000};

    for (int num_txs : tx_counts) {
        std::cout << "\nBlock with " << num_txs << " transactions (1 sig each):\n";

        // Pre-generate signatures
        std::vector<std::vector<uint8_t>> signatures;
        std::vector<std::vector<uint8_t>> messages;

        for (int i = 0; i < num_txs; i++) {
            std::vector<uint8_t> sig(DILITHIUM3_SIGNATURE_BYTES);
            size_t siglen;
            std::vector<uint8_t> msg(32);
            memset(msg.data(), i % 256, 32);

            pqcrystals_dilithium3_ref_signature(sig.data(), &siglen,
                                                msg.data(), 32, nullptr, 0, sk.data());
            sig.resize(siglen);
            signatures.push_back(sig);
            messages.push_back(msg);
        }

        // Benchmark verification
        std::vector<double> times;
        const int iterations = (num_txs >= 1000) ? 10 : 100;

        for (int i = 0; i < iterations; i++) {
            auto start = std::chrono::high_resolution_clock::now();

            // Verify all signatures in block
            for (size_t j = 0; j < signatures.size(); j++) {
                int result = pqcrystals_dilithium3_ref_verify(
                    signatures[j].data(), signatures[j].size(),
                    messages[j].data(), 32, nullptr, 0, pk.data()
                );

                if (result != 0) {
                    std::cerr << "Verification failed for tx " << j << "\n";
                }
            }

            auto end = std::chrono::high_resolution_clock::now();
            double duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            times.push_back(duration_ms);
        }

        Stats s = calculate_stats(times);
        std::cout << "  Mean time: " << std::fixed << std::setprecision(2) << s.mean << " ms\n";
        std::cout << "  Time per verification: " << (s.mean / num_txs) << " ms\n";
        std::cout << "  Verifications/sec: " << (num_txs * 1000.0 / s.mean) << "\n";

        // Check against 4-minute block time
        double block_time_seconds = 240.0;
        double margin = (block_time_seconds * 1000.0) / s.mean;
        std::cout << "  Margin vs 4-min block time: " << std::fixed << std::setprecision(0)
                  << margin << "x\n";

        if (s.mean < (block_time_seconds * 1000.0)) {
            std::cout << "  Status: PASS (can verify in < 4 minutes)\n";
        } else {
            std::cout << "  Status: FAIL (exceeds 4 minute block time)\n";
        }
    }
}

// Memory footprint analysis
void analyze_memory_footprint() {
    std::cout << "\n=== MEMORY FOOTPRINT ANALYSIS ===\n";

    std::cout << "\nKey Sizes:\n";
    std::cout << "  Public Key:  " << DILITHIUM3_PUBLIC_KEY_BYTES << " bytes (1.91 KB)\n";
    std::cout << "  Private Key: " << DILITHIUM3_SECRET_KEY_BYTES << " bytes (3.94 KB)\n";
    std::cout << "  Signature:   " << DILITHIUM3_SIGNATURE_BYTES << " bytes (3.23 KB)\n";

    std::cout << "\nWallet Memory (1000 keys):\n";
    size_t wallet_mem = 1000 * (DILITHIUM3_PUBLIC_KEY_BYTES + DILITHIUM3_SECRET_KEY_BYTES);
    std::cout << "  Total: " << (wallet_mem / 1024.0 / 1024.0) << " MB\n";

    std::cout << "\nMempool Memory (1000 transactions, avg 2 sigs each):\n";
    size_t mempool_mem = 1000 * 2 * DILITHIUM3_SIGNATURE_BYTES;
    std::cout << "  Signatures: " << (mempool_mem / 1024.0 / 1024.0) << " MB\n";

    std::cout << "\nBlock Size Analysis:\n";
    std::cout << "  Empty block: ~1 KB\n";
    std::cout << "  100 tx block (2 sigs/tx): "
              << ((100 * 2 * DILITHIUM3_SIGNATURE_BYTES) / 1024.0) << " KB\n";
    std::cout << "  1000 tx block (2 sigs/tx): "
              << ((1000 * 2 * DILITHIUM3_SIGNATURE_BYTES) / 1024.0 / 1024.0) << " MB\n";
}

// Stress test - continuous operation
void stress_test(int duration_seconds = 60) {
    std::cout << "\n=== STRESS TEST ===\n";
    std::cout << "Running continuous operations for " << duration_seconds << " seconds...\n";

    std::vector<uint8_t> pk(DILITHIUM3_PUBLIC_KEY_BYTES);
    std::vector<uint8_t> sk(DILITHIUM3_SECRET_KEY_BYTES);
    std::vector<uint8_t> sig(DILITHIUM3_SIGNATURE_BYTES);
    size_t siglen;
    uint8_t message[32];
    memset(message, 0xAB, 32);

    auto start_time = std::chrono::steady_clock::now();
    auto last_report = start_time;

    int keygen_count = 0;
    int sign_count = 0;
    int verify_count = 0;
    int errors = 0;

    while (true) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

        if (elapsed >= duration_seconds) break;

        // Key generation
        if (pqcrystals_dilithium3_ref_keypair(pk.data(), sk.data()) == 0) {
            keygen_count++;
        } else {
            errors++;
        }

        // Signing
        if (pqcrystals_dilithium3_ref_signature(sig.data(), &siglen, message, 32,
                                                nullptr, 0, sk.data()) == 0) {
            sign_count++;
        } else {
            errors++;
        }

        // Verification
        if (pqcrystals_dilithium3_ref_verify(sig.data(), siglen, message, 32,
                                             nullptr, 0, pk.data()) == 0) {
            verify_count++;
        } else {
            errors++;
        }

        // Report every 10 seconds
        auto report_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_report).count();
        if (report_elapsed >= 10) {
            std::cout << "  " << elapsed << "s: "
                      << keygen_count << " keygens, "
                      << sign_count << " signs, "
                      << verify_count << " verifies, "
                      << errors << " errors\n";
            last_report = now;
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    double total_seconds = std::chrono::duration<double>(end_time - start_time).count();

    std::cout << "\nStress Test Results (" << total_seconds << " seconds):\n";
    std::cout << "  Key generations: " << keygen_count << " (" << (keygen_count / total_seconds) << " ops/sec)\n";
    std::cout << "  Signatures:      " << sign_count << " (" << (sign_count / total_seconds) << " ops/sec)\n";
    std::cout << "  Verifications:   " << verify_count << " (" << (verify_count / total_seconds) << " ops/sec)\n";
    std::cout << "  Errors:          " << errors << "\n";

    if (errors == 0) {
        std::cout << "  Status: PASS (no errors detected)\n";
    } else {
        std::cout << "  Status: FAIL (" << errors << " errors detected)\n";
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=================================================\n";
    std::cout << "   Dilithium3 Performance Benchmark Suite\n";
    std::cout << "   Post-Quantum Cryptography Performance Testing\n";
    std::cout << "=================================================\n";

    std::cout << "\nConfiguration:\n";
    std::cout << "  Dilithium Mode: 3 (NIST Level 3 Security)\n";
    std::cout << "  Public Key Size: " << DILITHIUM3_PUBLIC_KEY_BYTES << " bytes\n";
    std::cout << "  Secret Key Size: " << DILITHIUM3_SECRET_KEY_BYTES << " bytes\n";
    std::cout << "  Signature Size: " << DILITHIUM3_SIGNATURE_BYTES << " bytes\n";
    std::cout << "  Warmup Iterations: " << WARMUP_ITERATIONS << "\n";
    std::cout << "  Test Iterations: " << TEST_ITERATIONS << "\n";

    // Generate test keys
    std::vector<uint8_t> pk(DILITHIUM3_PUBLIC_KEY_BYTES);
    std::vector<uint8_t> sk(DILITHIUM3_SECRET_KEY_BYTES);
    std::vector<uint8_t> sig(DILITHIUM3_SIGNATURE_BYTES);
    size_t siglen;

    std::cout << "\nGenerating test keypair...\n";
    pqcrystals_dilithium3_ref_keypair(pk.data(), sk.data());

    // Generate test signature
    uint8_t message[32];
    memset(message, 0xAB, 32);
    pqcrystals_dilithium3_ref_signature(sig.data(), &siglen, message, 32, nullptr, 0, sk.data());

    // Run benchmarks
    Stats keygen_stats = benchmark_keygen();
    print_stats("Key Generation", keygen_stats);

    Stats signing_stats = benchmark_signing(sk.data());
    print_stats("Signature Generation", signing_stats);

    Stats verify_stats = benchmark_verification(pk.data(), sig.data(), siglen);
    print_stats("Signature Verification", verify_stats);

    // Blockchain-specific benchmarks
    benchmark_transaction_signing();
    benchmark_block_verification();

    // Memory analysis
    analyze_memory_footprint();

    // Stress test (reduced from 1 hour to 60 seconds for quick testing)
    // For full 1-hour test, change to: stress_test(3600);
    int stress_duration = 60;
    if (argc > 1 && std::string(argv[1]) == "--full-stress") {
        stress_duration = 3600;  // 1 hour
    }
    stress_test(stress_duration);

    // Final summary
    std::cout << "\n=================================================\n";
    std::cout << "   PERFORMANCE SUMMARY\n";
    std::cout << "=================================================\n";
    std::cout << "\nKey Operations:\n";
    std::cout << "  Key Generation:   " << std::fixed << std::setprecision(2)
              << keygen_stats.mean << " ms (" << (1000.0 / keygen_stats.mean) << " ops/sec)\n";
    std::cout << "  Signing:          " << signing_stats.mean << " ms ("
              << (1000.0 / signing_stats.mean) << " ops/sec)\n";
    std::cout << "  Verification:     " << verify_stats.mean << " ms ("
              << (1000.0 / verify_stats.mean) << " ops/sec)\n";

    std::cout << "\nBlockchain Performance:\n";
    std::cout << "  4-minute block time: 240 seconds\n";
    std::cout << "  Max verifications in block time: " << (240000.0 / verify_stats.mean) << " signatures\n";
    std::cout << "  Margin for 1000-sig block: " << (240000.0 / (1000 * verify_stats.mean)) << "x\n";

    // Overall assessment
    std::cout << "\n=================================================\n";
    std::cout << "   BLOCKCHAIN READINESS ASSESSMENT\n";
    std::cout << "=================================================\n";

    bool acceptable = true;
    char grade = 'A';

    if (verify_stats.mean > 10.0) {
        acceptable = false;
        grade = 'D';
        std::cout << "  Performance: POOR (verification > 10ms)\n";
    } else if (verify_stats.mean > 5.0) {
        grade = 'B';
        std::cout << "  Performance: GOOD (verification < 10ms)\n";
    } else if (verify_stats.mean > 2.0) {
        grade = 'A';
        std::cout << "  Performance: EXCELLENT (verification < 5ms)\n";
    } else {
        grade = 'A';
        std::cout << "  Performance: OUTSTANDING (verification < 2ms)\n";
    }

    // Check if we can handle 1000 signatures in < 240 seconds
    double block_verify_time = 1000 * verify_stats.mean / 1000.0;  // seconds
    if (block_verify_time < 240.0) {
        std::cout << "  Block Verification: PASS (1000 sigs in "
                  << std::fixed << std::setprecision(2) << block_verify_time << "s < 240s)\n";
    } else {
        std::cout << "  Block Verification: FAIL (1000 sigs would take "
                  << block_verify_time << "s > 240s)\n";
        acceptable = false;
        grade = 'F';
    }

    std::cout << "\n  OVERALL GRADE: " << grade << (grade >= 'A' && grade <= 'B' ? "+" : "") << "\n";
    std::cout << "  Production Ready: " << (acceptable ? "YES" : "NO") << "\n";

    std::cout << "\n=================================================\n";

    return acceptable ? 0 : 1;
}
