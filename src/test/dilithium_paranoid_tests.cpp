// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <crypto/dilithium/dilithium_paranoid.h>
#include <random.h>
#include <support/cleanse.h>

/**
 * Test suite for paranoid security layer.
 *
 * This tests the enhanced security features:
 * - Canary-based memory protection
 * - Double-verification pattern
 * - Secure memory clearing verification
 * - Enhanced entropy validation
 * - Runtime invariant checking
 * - Security statistics tracking
 */

BOOST_AUTO_TEST_SUITE(dilithium_paranoid_tests)

//
// SecureKeyBuffer Tests
//

BOOST_AUTO_TEST_CASE(secure_key_buffer_canary_protection)
{
    // Test that SecureKeyBuffer properly maintains canaries

    dilithium::paranoid::SecureKeyBuffer key_storage;

    // Canaries should be initialized correctly
    BOOST_CHECK(key_storage.verify_integrity());

    // Generate keypair into secure storage
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    int ret = dilithium::keypair(pk, key_storage.data());
    BOOST_CHECK_EQUAL(ret, 0);

    // Canaries should still be intact after key generation
    BOOST_CHECK(key_storage.verify_integrity());

    // Use the key to sign something
    unsigned char msg[32];
    GetRandBytes(msg, 32);

    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    ret = dilithium::sign(sig, &siglen, msg, 32, key_storage.data());
    BOOST_CHECK_EQUAL(ret, 0);

    // Canaries should still be intact after signing
    BOOST_CHECK(key_storage.verify_integrity());

    // Verify signature works
    BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, msg, 32, pk), 0);

    // SecureKeyBuffer will automatically clean up on scope exit
}

BOOST_AUTO_TEST_CASE(secure_key_buffer_multiple_operations)
{
    // Test SecureKeyBuffer with multiple sign operations

    dilithium::paranoid::SecureKeyBuffer key_storage;
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];

    BOOST_CHECK_EQUAL(dilithium::keypair(pk, key_storage.data()), 0);
    BOOST_CHECK(key_storage.verify_integrity());

    // Perform 10 signing operations
    for (int i = 0; i < 10; i++) {
        unsigned char msg[64];
        GetRandBytes(msg, 64);

        unsigned char sig[DILITHIUM_BYTES];
        size_t siglen;
        BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg, 64, key_storage.data()), 0);
        BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, msg, 64, pk), 0);

        // Canaries must remain intact after each operation
        BOOST_CHECK(key_storage.verify_integrity());
    }
}

//
// Paranoid Operation Tests
//

BOOST_AUTO_TEST_CASE(keypair_paranoid_basic)
{
    // Test basic paranoid keypair generation

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    dilithium::paranoid::SecureKeyBuffer key_storage;

    int ret = dilithium::paranoid::keypair_paranoid(pk, key_storage.data());
    BOOST_CHECK_EQUAL(ret, 0);

    // Verify keys are non-zero
    BOOST_CHECK(dilithium::paranoid::buffer_is_nonzero(pk, DILITHIUM_PUBLICKEYBYTES));
    BOOST_CHECK(dilithium::paranoid::buffer_is_nonzero(key_storage.data(), DILITHIUM_SECRETKEYBYTES));

    // Verify canaries intact
    BOOST_CHECK(key_storage.verify_integrity());
}

BOOST_AUTO_TEST_CASE(sign_paranoid_basic)
{
    // Test paranoid signing

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    dilithium::paranoid::SecureKeyBuffer key_storage;

    BOOST_CHECK_EQUAL(dilithium::paranoid::keypair_paranoid(pk, key_storage.data()), 0);

    unsigned char msg[32];
    GetRandBytes(msg, 32);

    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    int ret = dilithium::paranoid::sign_paranoid(sig, &siglen, msg, 32, key_storage.data());
    BOOST_CHECK_EQUAL(ret, 0);
    BOOST_CHECK_EQUAL(siglen, DILITHIUM_BYTES);

    // Verify signature
    BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, msg, 32, pk), 0);
}

BOOST_AUTO_TEST_CASE(verify_paranoid_basic)
{
    // Test paranoid verification (double-verification)

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    dilithium::paranoid::SecureKeyBuffer key_storage;

    BOOST_CHECK_EQUAL(dilithium::keypair(pk, key_storage.data()), 0);

    unsigned char msg[32];
    GetRandBytes(msg, 32);

    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg, 32, key_storage.data()), 0);

    // Paranoid verification should succeed for valid signature
    int ret = dilithium::paranoid::verify_paranoid(sig, siglen, msg, 32, pk);
    BOOST_CHECK_EQUAL(ret, 0);

    // Paranoid verification should fail for corrupted signature
    sig[0] ^= 0x01;
    ret = dilithium::paranoid::verify_paranoid(sig, siglen, msg, 32, pk);
    BOOST_CHECK(ret != 0);
}

BOOST_AUTO_TEST_CASE(verify_paranoid_invalid_signature)
{
    // Test that paranoid verification properly rejects invalid signatures

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    dilithium::paranoid::SecureKeyBuffer key_storage;

    BOOST_CHECK_EQUAL(dilithium::keypair(pk, key_storage.data()), 0);

    // Create and sign message
    unsigned char msg1[32];
    GetRandBytes(msg1, 32);

    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg1, 32, key_storage.data()), 0);

    // Verify with correct message (should succeed)
    BOOST_CHECK_EQUAL(dilithium::paranoid::verify_paranoid(sig, siglen, msg1, 32, pk), 0);

    // Verify with wrong message (should fail)
    unsigned char msg2[32];
    GetRandBytes(msg2, 32);
    BOOST_CHECK(dilithium::paranoid::verify_paranoid(sig, siglen, msg2, 32, pk) != 0);
}

//
// Memory Safety Tests
//

BOOST_AUTO_TEST_CASE(secure_cleanse_verify_test)
{
    // Test secure memory clearing with verification

    unsigned char buffer[256];

    // Fill with random data
    GetRandBytes(buffer, 256);

    // Verify buffer contains non-zero data
    BOOST_CHECK(dilithium::paranoid::buffer_is_nonzero(buffer, 256));

    // Securely clear and verify
    dilithium::paranoid::secure_cleanse_verify(buffer, 256);

    // Verify buffer is all zeros
    bool all_zero = true;
    for (size_t i = 0; i < 256; i++) {
        if (buffer[i] != 0) {
            all_zero = false;
            break;
        }
    }
    BOOST_CHECK(all_zero);
}

BOOST_AUTO_TEST_CASE(buffer_is_nonzero_test)
{
    // Test buffer non-zero detection

    unsigned char zero_buffer[64];
    memset(zero_buffer, 0, 64);
    BOOST_CHECK(!dilithium::paranoid::buffer_is_nonzero(zero_buffer, 64));

    unsigned char nonzero_buffer[64];
    memset(nonzero_buffer, 0, 64);
    nonzero_buffer[32] = 0x01; // One non-zero byte
    BOOST_CHECK(dilithium::paranoid::buffer_is_nonzero(nonzero_buffer, 64));

    unsigned char random_buffer[64];
    GetRandBytes(random_buffer, 64);
    BOOST_CHECK(dilithium::paranoid::buffer_is_nonzero(random_buffer, 64));
}

//
// Entropy Validation Tests
//

BOOST_AUTO_TEST_CASE(enhanced_entropy_validation)
{
    // Test enhanced entropy validation

    // Should pass with system RNG (assuming it's healthy)
    bool entropy_ok = dilithium::paranoid::validate_entropy_enhanced();
    BOOST_CHECK(entropy_ok);

    // Test multiple times to ensure consistency
    int passes = 0;
    for (int i = 0; i < 10; i++) {
        if (dilithium::paranoid::validate_entropy_enhanced()) {
            passes++;
        }
    }

    // Most checks should pass (allow for statistical variation)
    BOOST_CHECK(passes >= 8);
}

BOOST_AUTO_TEST_CASE(continuous_entropy_monitoring)
{
    // Test continuous entropy monitoring

    bool entropy_ok = dilithium::paranoid::monitor_entropy_continuous();
    BOOST_CHECK(entropy_ok);
}

//
// Security Statistics Tests
//

BOOST_AUTO_TEST_CASE(security_stats_tracking)
{
    // Test that security statistics are tracked correctly

    // Reset stats
    dilithium::paranoid::reset_security_stats();

    auto stats = dilithium::paranoid::get_security_stats();
    BOOST_CHECK_EQUAL(stats.keypairs_generated, 0ULL);
    BOOST_CHECK_EQUAL(stats.signatures_created, 0ULL);
    BOOST_CHECK_EQUAL(stats.signatures_verified, 0ULL);

    // Generate keypair
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    dilithium::paranoid::SecureKeyBuffer key_storage;
    dilithium::paranoid::keypair_paranoid(pk, key_storage.data());

    stats = dilithium::paranoid::get_security_stats();
    BOOST_CHECK_EQUAL(stats.keypairs_generated, 1ULL);

    // Sign
    unsigned char msg[32];
    GetRandBytes(msg, 32);
    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    dilithium::paranoid::sign_paranoid(sig, &siglen, msg, 32, key_storage.data());

    stats = dilithium::paranoid::get_security_stats();
    BOOST_CHECK_EQUAL(stats.signatures_created, 1ULL);

    // Verify
    dilithium::paranoid::verify_paranoid(sig, siglen, msg, 32, pk);

    stats = dilithium::paranoid::get_security_stats();
    BOOST_CHECK_EQUAL(stats.signatures_verified, 1ULL);
}

BOOST_AUTO_TEST_CASE(security_stats_verification_failures)
{
    // Test that verification failures are tracked

    dilithium::paranoid::reset_security_stats();

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    dilithium::paranoid::SecureKeyBuffer key_storage;
    dilithium::paranoid::keypair_paranoid(pk, key_storage.data());

    // Create and sign message
    unsigned char msg[32];
    GetRandBytes(msg, 32);
    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    dilithium::paranoid::sign_paranoid(sig, &siglen, msg, 32, key_storage.data());

    // Corrupt signature and verify (should fail)
    sig[0] ^= 0x01;
    dilithium::paranoid::verify_paranoid(sig, siglen, msg, 32, pk);

    // Check that failure was tracked
    auto stats = dilithium::paranoid::get_security_stats();
    BOOST_CHECK_EQUAL(stats.verification_failures, 1ULL);
}

//
// Stress Tests for Paranoid Mode
//

BOOST_AUTO_TEST_CASE(paranoid_multiple_operations)
{
    // Test paranoid mode with multiple operations

    dilithium::paranoid::reset_security_stats();

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    dilithium::paranoid::SecureKeyBuffer key_storage;

    BOOST_CHECK_EQUAL(dilithium::paranoid::keypair_paranoid(pk, key_storage.data()), 0);

    // Perform 50 sign/verify operations
    for (int i = 0; i < 50; i++) {
        unsigned char msg[64];
        GetRandBytes(msg, 64);

        unsigned char sig[DILITHIUM_BYTES];
        size_t siglen;

        // Sign with paranoid mode
        BOOST_CHECK_EQUAL(dilithium::paranoid::sign_paranoid(sig, &siglen, msg, 64, key_storage.data()), 0);

        // Verify with paranoid mode
        BOOST_CHECK_EQUAL(dilithium::paranoid::verify_paranoid(sig, siglen, msg, 64, pk), 0);

        // Canaries must remain intact
        BOOST_CHECK(key_storage.verify_integrity());
    }

    // Check statistics
    auto stats = dilithium::paranoid::get_security_stats();
    BOOST_CHECK_EQUAL(stats.keypairs_generated, 1ULL);
    BOOST_CHECK_EQUAL(stats.signatures_created, 50ULL);
    BOOST_CHECK_EQUAL(stats.signatures_verified, 50ULL);
}

BOOST_AUTO_TEST_CASE(paranoid_multiple_keypairs)
{
    // Test generating multiple keypairs with paranoid mode

    dilithium::paranoid::reset_security_stats();

    for (int i = 0; i < 5; i++) {
        unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
        dilithium::paranoid::SecureKeyBuffer key_storage;

        BOOST_CHECK_EQUAL(dilithium::paranoid::keypair_paranoid(pk, key_storage.data()), 0);
        BOOST_CHECK(key_storage.verify_integrity());

        // Sign and verify with each keypair
        unsigned char msg[32];
        GetRandBytes(msg, 32);
        unsigned char sig[DILITHIUM_BYTES];
        size_t siglen;

        BOOST_CHECK_EQUAL(dilithium::paranoid::sign_paranoid(sig, &siglen, msg, 32, key_storage.data()), 0);
        BOOST_CHECK_EQUAL(dilithium::paranoid::verify_paranoid(sig, siglen, msg, 32, pk), 0);
    }

    auto stats = dilithium::paranoid::get_security_stats();
    BOOST_CHECK_EQUAL(stats.keypairs_generated, 5ULL);
    BOOST_CHECK_EQUAL(stats.signatures_created, 5ULL);
    BOOST_CHECK_EQUAL(stats.signatures_verified, 5ULL);
}

BOOST_AUTO_TEST_SUITE_END()
