// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Cryptography Tests
 *
 * Comprehensive tests for Dilithion's post-quantum cryptography:
 * - CRYSTALS-Dilithium3 signatures
 * - SHA-3 hashing
 * - RandomX hashing
 *
 * Following Bitcoin Core testing standards with Boost Test Framework
 */

#include <boost/test/unit_test.hpp>

#include <crypto/sha3.h>
#include <crypto/randomx_hash.h>

// Dilithium3 API from pqcrystals reference implementation
extern "C" {
    #include <sign.h>
    #include <params.h>
}

#include <vector>
#include <cstring>
#include <algorithm>

BOOST_AUTO_TEST_SUITE(crypto_tests)

/**
 * Test Suite 1: SHA-3 Hashing
 */
BOOST_AUTO_TEST_SUITE(sha3_tests)

BOOST_AUTO_TEST_CASE(sha3_256_empty_input) {
    uint8_t hash[32];
    const uint8_t* empty = nullptr;

    // SHA-3-256 of empty string is well-known
    SHA3_256(empty, 0, hash);

    // Expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    const uint8_t expected[32] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    };

    BOOST_CHECK_EQUAL_COLLECTIONS(hash, hash + 32, expected, expected + 32);
}

BOOST_AUTO_TEST_CASE(sha3_256_known_test_vector) {
    // Test vector: "abc"
    const uint8_t input[] = {'a', 'b', 'c'};
    uint8_t hash[32];

    SHA3_256(input, 3, hash);

    // Expected: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
    const uint8_t expected[32] = {
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
    };

    BOOST_CHECK_EQUAL_COLLECTIONS(hash, hash + 32, expected, expected + 32);
}

BOOST_AUTO_TEST_CASE(sha3_256_deterministic) {
    const uint8_t input[] = "Dilithion cryptocurrency";
    uint8_t hash1[32], hash2[32];

    // Same input should produce same output
    SHA3_256(input, sizeof(input) - 1, hash1);
    SHA3_256(input, sizeof(input) - 1, hash2);

    BOOST_CHECK_EQUAL_COLLECTIONS(hash1, hash1 + 32, hash2, hash2 + 32);
}

BOOST_AUTO_TEST_CASE(sha3_256_different_inputs) {
    const uint8_t input1[] = "test1";
    const uint8_t input2[] = "test2";
    uint8_t hash1[32], hash2[32];

    SHA3_256(input1, sizeof(input1) - 1, hash1);
    SHA3_256(input2, sizeof(input2) - 1, hash2);

    // Different inputs should produce different outputs
    BOOST_CHECK(memcmp(hash1, hash2, 32) != 0);
}

BOOST_AUTO_TEST_CASE(sha3_512_known_test_vector) {
    // Test vector: "abc"
    const uint8_t input[] = {'a', 'b', 'c'};
    uint8_t hash[64];

    SHA3_512(input, 3, hash);

    // Expected: first 32 bytes of SHA3-512("abc")
    // b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e
    // 10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0
    const uint8_t expected[64] = {
        0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
        0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
        0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
        0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
        0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
        0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
        0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
        0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0
    };

    BOOST_CHECK_EQUAL_COLLECTIONS(hash, hash + 64, expected, expected + 64);
}

BOOST_AUTO_TEST_SUITE_END() // sha3_tests

/**
 * Test Suite 2: Dilithium3 Signatures
 */
BOOST_AUTO_TEST_SUITE(dilithium_tests)

BOOST_AUTO_TEST_CASE(dilithium_keypair_generation) {
    uint8_t pk[PQCLEAN_DILITHIUM3_REF_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_DILITHIUM3_REF_CRYPTO_SECRETKEYBYTES];

    // Generate keypair
    int result = crypto_sign_keypair(pk, sk);

    BOOST_CHECK_EQUAL(result, 0); // Success

    // Public key should not be all zeros
    bool all_zeros = true;
    for (size_t i = 0; i < sizeof(pk); i++) {
        if (pk[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    BOOST_CHECK(!all_zeros);

    // Secret key should not be all zeros
    all_zeros = true;
    for (size_t i = 0; i < sizeof(sk); i++) {
        if (sk[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    BOOST_CHECK(!all_zeros);
}

BOOST_AUTO_TEST_CASE(dilithium_keypair_uniqueness) {
    uint8_t pk1[PQCLEAN_DILITHIUM3_REF_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk1[PQCLEAN_DILITHIUM3_REF_CRYPTO_SECRETKEYBYTES];
    uint8_t pk2[PQCLEAN_DILITHIUM3_REF_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk2[PQCLEAN_DILITHIUM3_REF_CRYPTO_SECRETKEYBYTES];

    // Generate two keypairs
    BOOST_CHECK_EQUAL(crypto_sign_keypair(pk1, sk1), 0);
    BOOST_CHECK_EQUAL(crypto_sign_keypair(pk2, sk2), 0);

    // Public keys should be different (with overwhelming probability)
    BOOST_CHECK(memcmp(pk1, pk2, sizeof(pk1)) != 0);

    // Secret keys should be different
    BOOST_CHECK(memcmp(sk1, sk2, sizeof(sk1)) != 0);
}

BOOST_AUTO_TEST_CASE(dilithium_sign_and_verify) {
    // Generate keypair
    uint8_t pk[PQCLEAN_DILITHIUM3_REF_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_DILITHIUM3_REF_CRYPTO_SECRETKEYBYTES];
    BOOST_REQUIRE_EQUAL(crypto_sign_keypair(pk, sk), 0);

    // Message to sign
    const uint8_t message[] = "Dilithion transaction";
    const size_t message_len = sizeof(message) - 1;

    // Sign message
    uint8_t sig[PQCLEAN_DILITHIUM3_REF_CRYPTO_BYTES];
    size_t sig_len;
    const uint8_t* ctx = nullptr;  // No context
    size_t ctx_len = 0;

    int sign_result = crypto_sign_signature(sig, &sig_len, message, message_len, ctx, ctx_len, sk);
    BOOST_CHECK_EQUAL(sign_result, 0);
    BOOST_CHECK_EQUAL(sig_len, PQCLEAN_DILITHIUM3_REF_CRYPTO_BYTES);

    // Verify signature
    int verify_result = crypto_sign_verify(sig, sig_len, message, message_len, ctx, ctx_len, pk);
    BOOST_CHECK_EQUAL(verify_result, 0); // Verification should succeed
}

BOOST_AUTO_TEST_CASE(dilithium_verify_wrong_message_fails) {
    // Generate keypair
    uint8_t pk[PQCLEAN_DILITHIUM3_REF_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_DILITHIUM3_REF_CRYPTO_SECRETKEYBYTES];
    BOOST_REQUIRE_EQUAL(crypto_sign_keypair(pk, sk), 0);

    // Original message
    const uint8_t message[] = "Original message";
    const size_t message_len = sizeof(message) - 1;

    // Sign message
    uint8_t sig[PQCLEAN_DILITHIUM3_REF_CRYPTO_BYTES];
    size_t sig_len;
    const uint8_t* ctx = nullptr;
    size_t ctx_len = 0;

    BOOST_REQUIRE_EQUAL(
        crypto_sign_signature(sig, &sig_len, message, message_len, ctx, ctx_len, sk), 0);

    // Try to verify with different message
    const uint8_t wrong_message[] = "Modified message";
    const size_t wrong_len = sizeof(wrong_message) - 1;

    int verify_result = crypto_sign_verify(sig, sig_len, wrong_message, wrong_len, ctx, ctx_len, pk);
    BOOST_CHECK(verify_result != 0); // Verification should FAIL
}

BOOST_AUTO_TEST_CASE(dilithium_verify_wrong_key_fails) {
    // Generate two keypairs
    uint8_t pk1[PQCLEAN_DILITHIUM3_REF_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk1[PQCLEAN_DILITHIUM3_REF_CRYPTO_SECRETKEYBYTES];
    uint8_t pk2[PQCLEAN_DILITHIUM3_REF_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk2[PQCLEAN_DILITHIUM3_REF_CRYPTO_SECRETKEYBYTES];

    BOOST_REQUIRE_EQUAL(crypto_sign_keypair(pk1, sk1), 0);
    BOOST_REQUIRE_EQUAL(crypto_sign_keypair(pk2, sk2), 0);

    // Sign with key 1
    const uint8_t message[] = "Test message";
    const size_t message_len = sizeof(message) - 1;
    uint8_t sig[PQCLEAN_DILITHIUM3_REF_CRYPTO_BYTES];
    size_t sig_len;
    const uint8_t* ctx = nullptr;
    size_t ctx_len = 0;

    BOOST_REQUIRE_EQUAL(
        crypto_sign_signature(sig, &sig_len, message, message_len, ctx, ctx_len, sk1), 0);

    // Try to verify with key 2 (should fail)
    int verify_result = crypto_sign_verify(sig, sig_len, message, message_len, ctx, ctx_len, pk2);
    BOOST_CHECK(verify_result != 0); // Verification should FAIL
}

BOOST_AUTO_TEST_CASE(dilithium_verify_corrupted_signature_fails) {
    // Generate keypair
    uint8_t pk[PQCLEAN_DILITHIUM3_REF_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_DILITHIUM3_REF_CRYPTO_SECRETKEYBYTES];
    BOOST_REQUIRE_EQUAL(crypto_sign_keypair(pk, sk), 0);

    // Sign message
    const uint8_t message[] = "Test message";
    const size_t message_len = sizeof(message) - 1;
    uint8_t sig[PQCLEAN_DILITHIUM3_REF_CRYPTO_BYTES];
    size_t sig_len;
    const uint8_t* ctx = nullptr;
    size_t ctx_len = 0;

    BOOST_REQUIRE_EQUAL(
        crypto_sign_signature(sig, &sig_len, message, message_len, ctx, ctx_len, sk), 0);

    // Corrupt signature by flipping one bit
    sig[100] ^= 0x01;

    // Verify should fail
    int verify_result = crypto_sign_verify(sig, sig_len, message, message_len, ctx, ctx_len, pk);
    BOOST_CHECK(verify_result != 0); // Verification should FAIL
}

BOOST_AUTO_TEST_CASE(dilithium_signature_determinism) {
    // Note: Dilithium3 is randomized by default, so signatures will differ
    // This test verifies that the same (message, key) pair can be signed
    // multiple times and all signatures verify correctly

    uint8_t pk[PQCLEAN_DILITHIUM3_REF_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_DILITHIUM3_REF_CRYPTO_SECRETKEYBYTES];
    BOOST_REQUIRE_EQUAL(crypto_sign_keypair(pk, sk), 0);

    const uint8_t message[] = "Test message";
    const size_t message_len = sizeof(message) - 1;
    const uint8_t* ctx = nullptr;
    size_t ctx_len = 0;

    // Sign same message twice
    uint8_t sig1[PQCLEAN_DILITHIUM3_REF_CRYPTO_BYTES];
    uint8_t sig2[PQCLEAN_DILITHIUM3_REF_CRYPTO_BYTES];
    size_t sig1_len, sig2_len;

    BOOST_REQUIRE_EQUAL(
        crypto_sign_signature(sig1, &sig1_len, message, message_len, ctx, ctx_len, sk), 0);
    BOOST_REQUIRE_EQUAL(
        crypto_sign_signature(sig2, &sig2_len, message, message_len, ctx, ctx_len, sk), 0);

    // Both signatures should verify
    BOOST_CHECK_EQUAL(crypto_sign_verify(sig1, sig1_len, message, message_len, ctx, ctx_len, pk), 0);
    BOOST_CHECK_EQUAL(crypto_sign_verify(sig2, sig2_len, message, message_len, ctx, ctx_len, pk), 0);

    // Note: Signatures may differ due to randomization, which is correct behavior
}

BOOST_AUTO_TEST_SUITE_END() // dilithium_tests

BOOST_AUTO_TEST_SUITE_END() // crypto_tests
