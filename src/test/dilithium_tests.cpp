// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <crypto/dilithium/dilithium.h>
#include <random.h>
#include <support/cleanse.h>

#include <vector>
#include <cstring>

/**
 * Comprehensive test suite for Dilithium wrapper implementation.
 *
 * Test Coverage:
 * - Basic functionality (keypair, sign, verify)
 * - Error handling (invalid parameters, null pointers)
 * - Security properties (invalid signature detection)
 * - Edge cases (empty messages, corrupted data)
 * - Memory safety (proper cleanup)
 * - Multiple operations (stress testing)
 *
 * All tests follow the Crypto Specialist agent directives for
 * security-critical code testing.
 */

BOOST_AUTO_TEST_SUITE(dilithium_tests)

//
// Basic Functionality Tests
//

BOOST_AUTO_TEST_CASE(dilithium_keypair_generation)
{
    // Test basic keypair generation
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];

    // Generate keypair
    int ret = dilithium::keypair(pk, sk);
    BOOST_CHECK_EQUAL(ret, 0);

    // Verify keys are not all zeros (sanity check)
    bool pk_nonzero = false;
    bool sk_nonzero = false;

    for (size_t i = 0; i < DILITHIUM_PUBLICKEYBYTES; i++) {
        if (pk[i] != 0) {
            pk_nonzero = true;
            break;
        }
    }

    for (size_t i = 0; i < DILITHIUM_SECRETKEYBYTES; i++) {
        if (sk[i] != 0) {
            sk_nonzero = true;
            break;
        }
    }

    BOOST_CHECK(pk_nonzero);
    BOOST_CHECK(sk_nonzero);

    // Clean up (security requirement)
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

BOOST_AUTO_TEST_CASE(dilithium_sign_verify_basic)
{
    // Test basic sign and verify operation

    // Generate keypair
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);

    // Create test message
    const char* test_msg = "Hello, quantum-resistant world!";
    const unsigned char* msg = (const unsigned char*)test_msg;
    size_t msglen = strlen(test_msg);

    // Sign message
    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    int sign_ret = dilithium::sign(sig, &siglen, msg, msglen, sk);
    BOOST_CHECK_EQUAL(sign_ret, 0);
    BOOST_CHECK_EQUAL(siglen, DILITHIUM_BYTES);

    // Verify signature
    int verify_ret = dilithium::verify(sig, siglen, msg, msglen, pk);
    BOOST_CHECK_EQUAL(verify_ret, 0); // 0 = valid signature

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

BOOST_AUTO_TEST_CASE(dilithium_sign_verify_random_message)
{
    // Test with random message data

    // Generate keypair
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);

    // Create random message
    unsigned char msg[64];
    GetRandBytes(msg, 64);

    // Sign message
    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg, 64, sk), 0);
    BOOST_CHECK_EQUAL(siglen, DILITHIUM_BYTES);

    // Verify signature
    BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, msg, 64, pk), 0);

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

//
// Security Tests - Invalid Signature Detection
//

BOOST_AUTO_TEST_CASE(dilithium_corrupted_signature)
{
    // Test that corrupted signatures are rejected

    // Generate keypair
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);

    // Create and sign message
    unsigned char msg[32];
    GetRandBytes(msg, 32);

    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg, 32, sk), 0);

    // Verify original signature is valid
    BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, msg, 32, pk), 0);

    // Corrupt the signature (flip one bit)
    sig[0] ^= 0x01;

    // Verify corrupted signature is rejected
    BOOST_CHECK(dilithium::verify(sig, siglen, msg, 32, pk) != 0);

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

BOOST_AUTO_TEST_CASE(dilithium_wrong_message)
{
    // Test that signature fails for different message

    // Generate keypair
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);

    // Create and sign first message
    unsigned char msg1[32];
    GetRandBytes(msg1, 32);

    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg1, 32, sk), 0);

    // Create different message
    unsigned char msg2[32];
    GetRandBytes(msg2, 32);

    // Ensure messages are actually different
    BOOST_CHECK(memcmp(msg1, msg2, 32) != 0);

    // Verify signature with wrong message fails
    BOOST_CHECK(dilithium::verify(sig, siglen, msg2, 32, pk) != 0);

    // Verify signature with correct message succeeds
    BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, msg1, 32, pk), 0);

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

BOOST_AUTO_TEST_CASE(dilithium_wrong_public_key)
{
    // Test that signature fails with wrong public key

    // Generate first keypair
    unsigned char pk1[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk1[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk1, sk1), 0);

    // Generate second keypair
    unsigned char pk2[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk2[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk2, sk2), 0);

    // Create and sign message with first key
    unsigned char msg[32];
    GetRandBytes(msg, 32);

    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg, 32, sk1), 0);

    // Verify with correct public key succeeds
    BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, msg, 32, pk1), 0);

    // Verify with wrong public key fails
    BOOST_CHECK(dilithium::verify(sig, siglen, msg, 32, pk2) != 0);

    // Clean up
    memory_cleanse(sk1, DILITHIUM_SECRETKEYBYTES);
    memory_cleanse(sk2, DILITHIUM_SECRETKEYBYTES);
}

//
// Error Handling Tests
//

BOOST_AUTO_TEST_CASE(dilithium_null_pointer_checks)
{
    // Test that null pointers are properly rejected

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    unsigned char sig[DILITHIUM_BYTES];
    unsigned char msg[32];
    size_t siglen;

    // Null pointer in keypair()
    BOOST_CHECK(dilithium::keypair(nullptr, sk) != 0);
    BOOST_CHECK(dilithium::keypair(pk, nullptr) != 0);
    BOOST_CHECK(dilithium::keypair(nullptr, nullptr) != 0);

    // Generate valid keypair for other tests
    BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);

    // Null pointer in sign()
    BOOST_CHECK(dilithium::sign(nullptr, &siglen, msg, 32, sk) != 0);
    BOOST_CHECK(dilithium::sign(sig, nullptr, msg, 32, sk) != 0);
    BOOST_CHECK(dilithium::sign(sig, &siglen, msg, 32, nullptr) != 0);

    // Null msg is allowed if msglen is 0
    BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, nullptr, 0, sk), 0);

    // But null msg with non-zero msglen should fail
    BOOST_CHECK(dilithium::sign(sig, &siglen, nullptr, 32, sk) != 0);

    // Null pointer in verify()
    BOOST_CHECK(dilithium::verify(nullptr, DILITHIUM_BYTES, msg, 32, pk) != 0);
    BOOST_CHECK(dilithium::verify(sig, DILITHIUM_BYTES, msg, 32, nullptr) != 0);

    // Null msg is allowed if msglen is 0
    BOOST_CHECK(dilithium::verify(sig, DILITHIUM_BYTES, nullptr, 0, pk) != 0); // Should fail because sig is not valid for empty message

    // But null msg with non-zero msglen should fail
    BOOST_CHECK(dilithium::verify(sig, DILITHIUM_BYTES, nullptr, 32, pk) != 0);

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

BOOST_AUTO_TEST_CASE(dilithium_invalid_signature_length)
{
    // Test that wrong signature lengths are rejected

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);

    unsigned char msg[32];
    GetRandBytes(msg, 32);

    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg, 32, sk), 0);

    // Correct length should work
    BOOST_CHECK_EQUAL(dilithium::verify(sig, DILITHIUM_BYTES, msg, 32, pk), 0);

    // Wrong lengths should fail
    BOOST_CHECK(dilithium::verify(sig, DILITHIUM_BYTES - 1, msg, 32, pk) != 0);
    BOOST_CHECK(dilithium::verify(sig, DILITHIUM_BYTES + 1, msg, 32, pk) != 0);
    BOOST_CHECK(dilithium::verify(sig, 0, msg, 32, pk) != 0);

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

//
// Edge Case Tests
//

BOOST_AUTO_TEST_CASE(dilithium_empty_message)
{
    // Test signing and verifying an empty message

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);

    // Sign empty message
    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, nullptr, 0, sk), 0);

    // Verify empty message signature
    BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, nullptr, 0, pk), 0);

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

BOOST_AUTO_TEST_CASE(dilithium_large_message)
{
    // Test with a large message (1 MB)

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);

    // Create 1 MB message
    const size_t large_msglen = 1024 * 1024;
    std::vector<unsigned char> large_msg(large_msglen);
    GetRandBytes(large_msg.data(), large_msglen);

    // Sign large message
    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    int sign_ret = dilithium::sign(sig, &siglen, large_msg.data(), large_msglen, sk);
    BOOST_CHECK_EQUAL(sign_ret, 0);

    // Verify large message signature
    int verify_ret = dilithium::verify(sig, siglen, large_msg.data(), large_msglen, pk);
    BOOST_CHECK_EQUAL(verify_ret, 0);

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

//
// Stress Tests
//

BOOST_AUTO_TEST_CASE(dilithium_multiple_operations)
{
    // Test multiple sign/verify operations with same keypair

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);

    // Perform 100 sign/verify operations
    for (int i = 0; i < 100; i++) {
        unsigned char msg[64];
        GetRandBytes(msg, 64);

        unsigned char sig[DILITHIUM_BYTES];
        size_t siglen;

        // Sign
        BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg, 64, sk), 0);

        // Verify
        BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, msg, 64, pk), 0);
    }

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

BOOST_AUTO_TEST_CASE(dilithium_multiple_keypairs)
{
    // Test generating multiple keypairs

    const int num_keypairs = 10;

    for (int i = 0; i < num_keypairs; i++) {
        unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
        unsigned char sk[DILITHIUM_SECRETKEYBYTES];

        // Generate keypair
        BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);

        // Sign a message
        unsigned char msg[32];
        GetRandBytes(msg, 32);

        unsigned char sig[DILITHIUM_BYTES];
        size_t siglen;
        BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg, 32, sk), 0);

        // Verify signature
        BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, msg, 32, pk), 0);

        // Clean up
        memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
    }
}

BOOST_AUTO_TEST_SUITE_END()
