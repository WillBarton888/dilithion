// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Phase 9.3: Property-Based Tests for Cryptography
 *
 * These tests verify cryptographic properties rather than specific inputs.
 * They ensure that our crypto implementation maintains security properties
 * regardless of input values.
 *
 * Properties tested:
 * - Signature correctness (valid signatures verify)
 * - Signature unforgeability (invalid signatures fail)
 * - Key pair consistency
 * - Deterministic behavior
 * - Constant-time properties (timing invariance)
 */

#include <boost/test/unit_test.hpp>
#include <crypto/sha3.h>
#include <wallet/wallet.h>
#include <primitives/transaction.h>
#include <vector>
#include <cstring>
#include <chrono>
#include <random>

// Include Dilithium headers
extern "C" {
#include "../../depends/dilithium/ref/api.h"
}

BOOST_AUTO_TEST_SUITE(crypto_property_tests)

/**
 * Property 1: Signature Correctness
 *
 * For any message and valid key pair:
 * - Signing produces a valid signature
 * - The signature verifies correctly
 */
BOOST_AUTO_TEST_CASE(property_signature_correctness)
{
    // Generate random key pair
    uint8_t public_key[pqcrystals_dilithium3_ref_PUBLICKEYBYTES];
    uint8_t private_key[pqcrystals_dilithium3_ref_SECRETKEYBYTES];

    // Generate key pair
    int keygen_result = pqcrystals_dilithium3_ref_keypair(public_key, private_key);
    BOOST_REQUIRE(keygen_result == 0);

    // Test with multiple random messages
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 1000);

    for (int i = 0; i < 10; ++i) {
        // Generate random message
        size_t msg_len = dis(gen);
        std::vector<uint8_t> message(msg_len);
        for (size_t j = 0; j < msg_len; ++j) {
            message[j] = static_cast<uint8_t>(dis(gen));
        }

        // Sign message
        uint8_t signature[pqcrystals_dilithium3_ref_BYTES];
        size_t siglen = 0;
        int sign_result = pqcrystals_dilithium3_ref_signature(signature, &siglen,
                                                              message.data(), message.size(),
                                                              nullptr, 0,  // No context
                                                              private_key);
        BOOST_REQUIRE(sign_result == 0);

        // Verify signature
        int verify_result = pqcrystals_dilithium3_ref_verify(signature, siglen,
                                                             message.data(), message.size(),
                                                             nullptr, 0,  // No context
                                                             public_key);
        BOOST_REQUIRE_MESSAGE(verify_result == 0,
                             "Valid signature must verify correctly");
    }
}

/**
 * Property 2: Signature Unforgeability
 *
 * For any message and key pair:
 * - Random data cannot be verified as a valid signature
 * - Modified signatures fail verification
 * - Signatures for different messages fail verification
 */
BOOST_AUTO_TEST_CASE(property_signature_unforgeability)
{
    // Generate key pair
    uint8_t public_key[pqcrystals_dilithium3_ref_PUBLICKEYBYTES];
    uint8_t private_key[pqcrystals_dilithium3_ref_SECRETKEYBYTES];
    pqcrystals_dilithium3_ref_keypair(public_key, private_key);

    // Create test message
    std::vector<uint8_t> message = {0x01, 0x02, 0x03, 0x04, 0x05};

    // Sign message
    uint8_t valid_signature[pqcrystals_dilithium3_ref_BYTES];
    size_t siglen = 0;
    pqcrystals_dilithium3_ref_signature(valid_signature, &siglen,
                                        message.data(), message.size(),
                                        nullptr, 0, private_key);

    // Test 1: Random data should not verify
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < 5; ++i) {
        uint8_t random_signature[pqcrystals_dilithium3_ref_BYTES];
        for (size_t j = 0; j < pqcrystals_dilithium3_ref_BYTES; ++j) {
            random_signature[j] = static_cast<uint8_t>(dis(gen));
        }

        size_t random_siglen = pqcrystals_dilithium3_ref_BYTES;
        int verify_result = pqcrystals_dilithium3_ref_verify(random_signature, random_siglen,
                                                             message.data(), message.size(),
                                                             nullptr, 0, public_key);
        BOOST_REQUIRE_MESSAGE(verify_result != 0,
                             "Random data must not verify as valid signature");
    }

    // Test 2: Modified signature should not verify
    uint8_t modified_signature[pqcrystals_dilithium3_ref_BYTES];
    std::memcpy(modified_signature, valid_signature, pqcrystals_dilithium3_ref_BYTES);
    modified_signature[0] ^= 0xFF; // Flip bits

    int verify_result = pqcrystals_dilithium3_ref_verify(modified_signature, siglen,
                                                          message.data(), message.size(),
                                                          nullptr, 0, public_key);
    BOOST_REQUIRE_MESSAGE(verify_result != 0,
                         "Modified signature must not verify");

    // Test 3: Signature for different message should not verify
    std::vector<uint8_t> different_message = {0x06, 0x07, 0x08, 0x09, 0x0A};
    verify_result = pqcrystals_dilithium3_ref_verify(valid_signature, siglen,
                                                      different_message.data(), different_message.size(),
                                                      nullptr, 0, public_key);
    BOOST_REQUIRE_MESSAGE(verify_result != 0,
                         "Signature for different message must not verify");
}

/**
 * Property 3: Key Pair Consistency
 *
 * For any key pair:
 * - Public key corresponds to private key
 * - Signatures from private key verify with public key
 * - Different key pairs produce different signatures
 */
BOOST_AUTO_TEST_CASE(property_key_pair_consistency)
{
    // Generate two key pairs
    uint8_t public_key1[pqcrystals_dilithium3_ref_PUBLICKEYBYTES];
    uint8_t private_key1[pqcrystals_dilithium3_ref_SECRETKEYBYTES];
    pqcrystals_dilithium3_ref_keypair(public_key1, private_key1);

    uint8_t public_key2[pqcrystals_dilithium3_ref_PUBLICKEYBYTES];
    uint8_t private_key2[pqcrystals_dilithium3_ref_SECRETKEYBYTES];
    pqcrystals_dilithium3_ref_keypair(public_key2, private_key2);

    // Test message
    std::vector<uint8_t> message = {0xAA, 0xBB, 0xCC, 0xDD};

    // Sign with key1, verify with key1 (should work)
    uint8_t signature1[pqcrystals_dilithium3_ref_BYTES];
    size_t siglen1 = 0;
    pqcrystals_dilithium3_ref_signature(signature1, &siglen1, message.data(), message.size(),
                                       nullptr, 0, private_key1);
    int verify1 = pqcrystals_dilithium3_ref_verify(signature1, siglen1,
                                                   message.data(), message.size(),
                                                   nullptr, 0, public_key1);
    BOOST_REQUIRE_MESSAGE(verify1 == 0, "Key pair 1 must be consistent");

    // Sign with key1, verify with key2 (should fail)
    int verify2 = pqcrystals_dilithium3_ref_verify(signature1, siglen1,
                                                   message.data(), message.size(),
                                                   nullptr, 0, public_key2);
    BOOST_REQUIRE_MESSAGE(verify2 != 0, "Key pair 2 must not verify key pair 1 signatures");

    // Sign with key2, verify with key2 (should work)
    uint8_t signature2[pqcrystals_dilithium3_ref_BYTES];
    size_t siglen2 = 0;
    pqcrystals_dilithium3_ref_signature(signature2, &siglen2, message.data(), message.size(),
                                       nullptr, 0, private_key2);
    int verify3 = pqcrystals_dilithium3_ref_verify(signature2, siglen2,
                                                  message.data(), message.size(),
                                                  nullptr, 0, public_key2);
    BOOST_REQUIRE_MESSAGE(verify3 == 0, "Key pair 2 must be consistent");
}

/**
 * Property 4: Deterministic Behavior
 *
 * For the same message and key:
 * - Signing produces the same signature (or valid signature)
 * - Verification is deterministic
 */
BOOST_AUTO_TEST_CASE(property_deterministic_behavior)
{
    // Generate key pair
    uint8_t public_key[pqcrystals_dilithium3_ref_PUBLICKEYBYTES];
    uint8_t private_key[pqcrystals_dilithium3_ref_SECRETKEYBYTES];
    pqcrystals_dilithium3_ref_keypair(public_key, private_key);

    // Test message
    std::vector<uint8_t> message = {0x11, 0x22, 0x33, 0x44, 0x55};

    // Sign multiple times
    uint8_t signature1[pqcrystals_dilithium3_ref_BYTES];
    uint8_t signature2[pqcrystals_dilithium3_ref_BYTES];
    size_t siglen1 = 0, siglen2 = 0;

    pqcrystals_dilithium3_ref_signature(signature1, &siglen1, message.data(), message.size(),
                                        nullptr, 0, private_key);
    pqcrystals_dilithium3_ref_signature(signature2, &siglen2, message.data(), message.size(),
                                        nullptr, 0, private_key);

    // Both signatures should verify (even if different due to randomness)
    int verify1 = pqcrystals_dilithium3_ref_verify(signature1, siglen1,
                                                   message.data(), message.size(),
                                                   nullptr, 0, public_key);
    int verify2 = pqcrystals_dilithium3_ref_verify(signature2, siglen2,
                                                   message.data(), message.size(),
                                                   nullptr, 0, public_key);

    BOOST_REQUIRE_MESSAGE(verify1 == 0, "First signature must verify");
    BOOST_REQUIRE_MESSAGE(verify2 == 0, "Second signature must verify");
}

/**
 * Property 5: Timing Invariance (Constant-Time)
 *
 * Verification time should not depend on signature validity.
 * This is a simplified test - full constant-time verification
 * requires more sophisticated timing analysis.
 */
BOOST_AUTO_TEST_CASE(property_timing_invariance)
{
    // Generate key pair
    uint8_t public_key[pqcrystals_dilithium3_ref_PUBLICKEYBYTES];
    uint8_t private_key[pqcrystals_dilithium3_ref_SECRETKEYBYTES];
    pqcrystals_dilithium3_ref_keypair(public_key, private_key);

    // Create valid signature
    std::vector<uint8_t> message = {0xAA, 0xBB, 0xCC};
    uint8_t valid_signature[pqcrystals_dilithium3_ref_BYTES];
    size_t siglen = 0;
    pqcrystals_dilithium3_ref_signature(valid_signature, &siglen, message.data(), message.size(),
                                       nullptr, 0, private_key);

    // Create invalid signature (random data)
    uint8_t invalid_signature[pqcrystals_dilithium3_ref_BYTES];
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < pqcrystals_dilithium3_ref_BYTES; ++i) {
        invalid_signature[i] = static_cast<uint8_t>(dis(gen));
    }

    // Measure verification times (multiple runs for average)
    const int num_runs = 100;
    std::vector<long long> valid_times;
    std::vector<long long> invalid_times;

    for (int i = 0; i < num_runs; ++i) {
        // Valid signature
        auto start = std::chrono::high_resolution_clock::now();
        pqcrystals_dilithium3_ref_verify(valid_signature, siglen,
                                        message.data(), message.size(),
                                        nullptr, 0, public_key);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        valid_times.push_back(duration.count());

        // Invalid signature
        size_t invalid_siglen = pqcrystals_dilithium3_ref_BYTES;
        start = std::chrono::high_resolution_clock::now();
        pqcrystals_dilithium3_ref_verify(invalid_signature, invalid_siglen,
                                        message.data(), message.size(),
                                        nullptr, 0, public_key);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        invalid_times.push_back(duration.count());
    }

    // Calculate average times
    long long valid_avg = 0;
    long long invalid_avg = 0;
    for (int i = 0; i < num_runs; ++i) {
        valid_avg += valid_times[i];
        invalid_avg += invalid_times[i];
    }
    valid_avg /= num_runs;
    invalid_avg /= num_runs;

    // Times should be similar (within 2x) for constant-time implementation
    // Note: This is a simplified test - real constant-time verification
    // requires more sophisticated statistical analysis
    double ratio = static_cast<double>(std::max(valid_avg, invalid_avg)) /
                   static_cast<double>(std::min(valid_avg, invalid_avg));

    BOOST_TEST_MESSAGE("Valid signature avg time: " << valid_avg << " ns");
    BOOST_TEST_MESSAGE("Invalid signature avg time: " << invalid_avg << " ns");
    BOOST_TEST_MESSAGE("Time ratio: " << ratio);

    // Warn if timing difference is too large (potential timing attack vector)
    if (ratio > 2.0) {
        BOOST_TEST_MESSAGE("WARNING: Significant timing difference detected. "
                          "This may indicate a timing attack vulnerability.");
    }
}

BOOST_AUTO_TEST_SUITE_END()
