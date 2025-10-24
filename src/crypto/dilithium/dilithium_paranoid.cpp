// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/dilithium/dilithium_paranoid.h>
#include <crypto/dilithium/dilithium.h>
#include <support/cleanse.h>
#include <random.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

namespace dilithium {
namespace paranoid {

//
// Security Statistics (global state)
//

static SecurityStats g_security_stats = {0};

SecurityStats get_security_stats() {
    return g_security_stats;
}

void reset_security_stats() {
    memset(&g_security_stats, 0, sizeof(g_security_stats));
}

//
// SecureKeyBuffer Implementation
//

SecureKeyBuffer::SecureKeyBuffer() {
    canary_before = CANARY_BEFORE;
    canary_after = CANARY_AFTER;
    memory_cleanse(key_data, DILITHIUM_SECRETKEYBYTES);
}

SecureKeyBuffer::~SecureKeyBuffer() {
    secure_cleanup();
}

bool SecureKeyBuffer::verify_integrity() const {
    return (canary_before == CANARY_BEFORE && canary_after == CANARY_AFTER);
}

void SecureKeyBuffer::secure_cleanup() {
    // Verify canaries before cleanup
    if (!verify_integrity()) {
        // CRITICAL: Memory corruption detected!
        g_security_stats.memory_corruptions++;

        fprintf(stderr, "FATAL: Memory corruption detected in SecureKeyBuffer!\n");
        fprintf(stderr, "Canary before: 0x%016llx (expected: 0x%016llx)\n",
                (unsigned long long)canary_before, (unsigned long long)CANARY_BEFORE);
        fprintf(stderr, "Canary after:  0x%016llx (expected: 0x%016llx)\n",
                (unsigned long long)canary_after, (unsigned long long)CANARY_AFTER);

        // Fail safely - terminate program
        std::terminate();
    }

    // Clear key data
    memory_cleanse(key_data, DILITHIUM_SECRETKEYBYTES);

    // Verify it was actually cleared (prevent compiler optimization)
    for (size_t i = 0; i < DILITHIUM_SECRETKEYBYTES; i++) {
        if (key_data[i] != 0) {
            // CRITICAL: Memory not cleared!
            fprintf(stderr, "FATAL: Secret key data not cleared at byte %zu!\n", i);
            std::terminate();
        }
    }
}

//
// Memory Safety Utilities
//

void secure_cleanse_verify(void* ptr, size_t len) {
    if (!ptr) return;

    // Clear memory
    memory_cleanse(ptr, len);

    // Verify it was actually cleared
    const volatile unsigned char* p = (const volatile unsigned char*)ptr;
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0) {
            // CRITICAL: Memory not cleared!
            fprintf(stderr, "FATAL: Memory not cleared at byte %zu of %zu!\n", i, len);
            std::terminate();
        }
    }
}

bool buffer_is_nonzero(const unsigned char* buffer, size_t len) {
    if (!buffer) return false;

    for (size_t i = 0; i < len; i++) {
        if (buffer[i] != 0) {
            return true;
        }
    }
    return false;
}

//
// Enhanced Entropy Validation
//

/**
 * Chi-squared test for randomness.
 *
 * This tests if the byte distribution in a buffer is uniform.
 * Weak RNGs often produce non-uniform distributions.
 *
 * @param buffer Buffer to test
 * @param len Length of buffer
 * @return true if distribution appears uniform
 */
static bool chi_squared_test(const unsigned char* buffer, size_t len) {
    if (len < 256) return true; // Not enough data

    // Count frequency of each byte value
    int freq[256] = {0};
    for (size_t i = 0; i < len; i++) {
        freq[buffer[i]]++;
    }

    // Expected frequency for uniform distribution
    double expected = (double)len / 256.0;

    // Calculate chi-squared statistic
    double chi_squared = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = freq[i] - expected;
        chi_squared += (diff * diff) / expected;
    }

    // Critical value for 255 degrees of freedom at 95% confidence
    // is approximately 293.25
    // We use a more conservative threshold
    return chi_squared < 350.0;
}

/**
 * Runs test for randomness.
 *
 * This tests if there are too many or too few "runs" (sequences of
 * same bit value) in the data. Weak RNGs often produce too few runs.
 *
 * @param buffer Buffer to test
 * @param len Length of buffer
 * @return true if number of runs appears normal
 */
static bool runs_test(const unsigned char* buffer, size_t len) {
    if (len < 100) return true; // Not enough data

    // Count bit transitions
    int runs = 1;
    bool prev_bit = (buffer[0] & 0x01);

    for (size_t i = 0; i < len; i++) {
        for (int bit = 0; bit < 8; bit++) {
            bool curr_bit = (buffer[i] >> bit) & 0x01;
            if (curr_bit != prev_bit) {
                runs++;
            }
            prev_bit = curr_bit;
        }
    }

    // For random data, expected number of runs is approximately len*8/2
    // We check if we're within reasonable bounds
    int total_bits = len * 8;
    int expected_runs = total_bits / 2;
    int lower_bound = expected_runs - (int)sqrt(expected_runs) * 3;
    int upper_bound = expected_runs + (int)sqrt(expected_runs) * 3;

    return (runs >= lower_bound && runs <= upper_bound);
}

bool validate_entropy_enhanced() {
    g_security_stats.entropy_checks++;

    // Generate test bytes
    unsigned char test_bytes[256];
    GetRandBytes(test_bytes, 256);

    // Basic checks (all zeros, all ones)
    bool all_zero = true;
    bool all_ones = true;
    for (size_t i = 0; i < 256; i++) {
        if (test_bytes[i] != 0) all_zero = false;
        if (test_bytes[i] != 0xFF) all_ones = false;
    }

    if (all_zero || all_ones) {
        g_security_stats.entropy_failures++;
        memory_cleanse(test_bytes, 256);
        return false;
    }

    // Chi-squared test for uniform distribution
    if (!chi_squared_test(test_bytes, 256)) {
        g_security_stats.entropy_failures++;
        memory_cleanse(test_bytes, 256);
        return false;
    }

    // Runs test for independence
    if (!runs_test(test_bytes, 256)) {
        g_security_stats.entropy_failures++;
        memory_cleanse(test_bytes, 256);
        return false;
    }

    // Clean up
    memory_cleanse(test_bytes, 256);
    return true;
}

bool monitor_entropy_continuous() {
    // Perform enhanced entropy check
    // In a production system, this could be rate-limited
    return validate_entropy_enhanced();
}

//
// Enhanced Cryptographic Operations
//

int keypair_paranoid(unsigned char* pk, unsigned char* sk) {
    g_security_stats.keypairs_generated++;

    // Enhanced entropy validation
    if (!validate_entropy_enhanced()) {
        return -2; // Entropy failure
    }

    // Call standard keypair generation with extra validation
    int ret = dilithium::keypair(pk, sk);

    if (ret != 0) {
        return ret; // Propagate error
    }

    // Additional post-generation validation
    // Verify keys are sufficiently random (not low-entropy)
    if (!chi_squared_test(sk, DILITHIUM_SECRETKEYBYTES)) {
        // Key has poor entropy - regenerate
        memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
        memory_cleanse(pk, DILITHIUM_PUBLICKEYBYTES);
        return -3; // Key validation failed
    }

    return 0;
}

int sign_paranoid(unsigned char* sig, size_t* siglen,
                  const unsigned char* msg, size_t msglen,
                  const unsigned char* sk) {
    g_security_stats.signatures_created++;

    // Validate secret key is non-zero
    if (!buffer_is_nonzero(sk, DILITHIUM_SECRETKEYBYTES)) {
        return -1; // Invalid key
    }

    // Call standard sign operation
    int ret = dilithium::sign(sig, siglen, msg, msglen, sk);

    if (ret != 0) {
        return ret; // Propagate error
    }

    // Verify signature was actually created
    if (!buffer_is_nonzero(sig, DILITHIUM_BYTES)) {
        memory_cleanse(sig, DILITHIUM_BYTES);
        return -2; // Signing failed
    }

    return 0;
}

int verify_paranoid(const unsigned char* sig, size_t siglen,
                    const unsigned char* msg, size_t msglen,
                    const unsigned char* pk) {
    g_security_stats.signatures_verified++;

    // First verification
    int result1 = dilithium::verify(sig, siglen, msg, msglen, pk);

    // Second verification (independent)
    int result2 = dilithium::verify(sig, siglen, msg, msglen, pk);

    // Results must agree (fault injection detection)
    if (result1 != result2) {
        // CRITICAL: Fault injection detected!
        g_security_stats.fault_injections++;
        fprintf(stderr, "WARNING: Fault injection detected in verify!\n");
        fprintf(stderr, "First result: %d, Second result: %d\n", result1, result2);
        return -1; // Fail safely - reject signature
    }

    // Third verification for extra paranoia
    int result3 = dilithium::verify(sig, siglen, msg, msglen, pk);

    if (result1 != result3) {
        // CRITICAL: Fault injection detected!
        g_security_stats.fault_injections++;
        fprintf(stderr, "WARNING: Fault injection detected in verify (3rd check)!\n");
        return -1; // Fail safely - reject signature
    }

    if (result1 != 0) {
        g_security_stats.verification_failures++;
    }

    return result1;
}

//
// Runtime Invariant Checking
//

#ifdef ENABLE_CRYPTO_PARANOIA

[[noreturn]] void crypto_assert_fail(const char* file, int line,
                                     const char* condition, const char* msg) {
    fprintf(stderr, "\n");
    fprintf(stderr, "=========================================\n");
    fprintf(stderr, "CRYPTO ASSERTION FAILED\n");
    fprintf(stderr, "=========================================\n");
    fprintf(stderr, "File: %s\n", file);
    fprintf(stderr, "Line: %d\n", line);
    fprintf(stderr, "Condition: %s\n", condition);
    fprintf(stderr, "Message: %s\n", msg);
    fprintf(stderr, "=========================================\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "This is a critical security violation.\n");
    fprintf(stderr, "The program will now terminate.\n");
    fprintf(stderr, "\n");

    std::terminate();
}

#endif

} // namespace paranoid
} // namespace dilithium
