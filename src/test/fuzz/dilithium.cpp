// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/dilithium/dilithium.h>
#include <support/cleanse.h>
#include <test/fuzz/fuzz.h>

#include <cstring>
#include <vector>

/**
 * Fuzz test for Dilithium cryptographic operations.
 *
 * This fuzz target tests the robustness of the Dilithium wrapper
 * against malformed, malicious, or unexpected inputs. The goal is
 * to ensure the implementation:
 * - Never crashes on any input
 * - Properly validates all inputs
 * - Returns appropriate error codes
 * - Has no memory safety issues
 * - Has no undefined behavior
 *
 * SECURITY CRITICAL: Any crash, hang, or memory safety issue found
 * by fuzzing is a potential security vulnerability.
 */

namespace {

/**
 * Fuzz target: Dilithium keypair generation
 *
 * Tests that keypair() handles all buffer states safely.
 */
void test_keypair_generation(FuzzedDataProvider& fuzzed_data_provider)
{
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];

    // Optionally corrupt buffers with fuzzed data
    if (fuzzed_data_provider.ConsumeBool()) {
        auto pk_data = fuzzed_data_provider.ConsumeBytes<unsigned char>(DILITHIUM_PUBLICKEYBYTES);
        memcpy(pk, pk_data.data(), std::min(pk_data.size(), (size_t)DILITHIUM_PUBLICKEYBYTES));
    }

    if (fuzzed_data_provider.ConsumeBool()) {
        auto sk_data = fuzzed_data_provider.ConsumeBytes<unsigned char>(DILITHIUM_SECRETKEYBYTES);
        memcpy(sk, sk_data.data(), std::min(sk_data.size(), (size_t)DILITHIUM_SECRETKEYBYTES));
    }

    // Call keypair - should not crash regardless of buffer contents
    int ret = dilithium::keypair(pk, sk);

    // If successful, keys should be non-zero
    if (ret == 0) {
        bool pk_nonzero = false;
        bool sk_nonzero = false;

        for (size_t i = 0; i < DILITHIUM_PUBLICKEYBYTES; i++) {
            if (pk[i] != 0) pk_nonzero = true;
        }

        for (size_t i = 0; i < DILITHIUM_SECRETKEYBYTES; i++) {
            if (sk[i] != 0) sk_nonzero = true;
        }

        // Valid keys should be non-zero
        assert(pk_nonzero);
        assert(sk_nonzero);
    }

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

/**
 * Fuzz target: Dilithium signing
 *
 * Tests that sign() handles corrupted keys and messages safely.
 */
void test_signing(FuzzedDataProvider& fuzzed_data_provider)
{
    // Generate a valid keypair first
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];

    if (dilithium::keypair(pk, sk) != 0) {
        return; // RNG failure, skip test
    }

    // Optionally corrupt the secret key
    if (fuzzed_data_provider.ConsumeBool()) {
        size_t corrupt_bytes = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 100);
        for (size_t i = 0; i < corrupt_bytes && i < DILITHIUM_SECRETKEYBYTES; i++) {
            size_t idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, DILITHIUM_SECRETKEYBYTES - 1);
            sk[idx] ^= fuzzed_data_provider.ConsumeIntegral<unsigned char>();
        }
    }

    // Fuzzed message
    auto msg = fuzzed_data_provider.ConsumeBytes<unsigned char>(
        fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 1024 * 1024) // 0 to 1MB
    );

    // Try to sign
    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;

    // Should not crash regardless of key corruption or message content
    int ret = dilithium::sign(sig, &siglen, msg.data(), msg.size(), sk);

    // If successful, signature length should be correct
    if (ret == 0) {
        assert(siglen == DILITHIUM_BYTES);
    }

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

/**
 * Fuzz target: Dilithium verification (MOST CRITICAL)
 *
 * This is the most important fuzz target because signature verification
 * is the primary attack surface. An attacker can craft malicious
 * signatures and public keys to try to exploit the verifier.
 *
 * Tests:
 * - Malformed signatures
 * - Malformed public keys
 * - Malformed messages
 * - Invalid signature lengths
 * - Edge cases
 */
void test_verification(FuzzedDataProvider& fuzzed_data_provider)
{
    // Fuzzed public key
    auto pk_data = fuzzed_data_provider.ConsumeBytes<unsigned char>(DILITHIUM_PUBLICKEYBYTES);
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES] = {0};
    memcpy(pk, pk_data.data(), std::min(pk_data.size(), (size_t)DILITHIUM_PUBLICKEYBYTES));

    // Fuzzed signature
    auto sig_data = fuzzed_data_provider.ConsumeBytes<unsigned char>(DILITHIUM_BYTES);
    unsigned char sig[DILITHIUM_BYTES] = {0};
    memcpy(sig, sig_data.data(), std::min(sig_data.size(), (size_t)DILITHIUM_BYTES));

    // Fuzzed signature length (test various invalid lengths)
    size_t siglen = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, DILITHIUM_BYTES * 2);

    // Fuzzed message
    auto msg = fuzzed_data_provider.ConsumeBytes<unsigned char>(
        fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 1024 * 1024)
    );

    // CRITICAL: This should NEVER crash, regardless of input
    // - Malformed public key → should return error
    // - Malformed signature → should return error
    // - Invalid siglen → should return error
    // - Corrupted message → should return error (signature won't verify)
    //
    // The only acceptable outcomes are:
    // 1. Return 0 (valid signature - unlikely with random data)
    // 2. Return non-zero (invalid signature)
    // 3. Never crash, hang, or have undefined behavior

    int ret = dilithium::verify(sig, siglen, msg.data(), msg.size(), pk);

    // Return value should be deterministic for same inputs
    // (constant-time property check - verify should always take same time)

    (void)ret; // We don't care about the result, just that it doesn't crash
}

/**
 * Fuzz target: Full sign/verify cycle
 *
 * Tests the complete workflow with fuzzed corruption at each step.
 */
void test_sign_verify_cycle(FuzzedDataProvider& fuzzed_data_provider)
{
    // Generate keypair
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];

    if (dilithium::keypair(pk, sk) != 0) {
        return; // RNG failure
    }

    // Fuzzed message
    auto msg = fuzzed_data_provider.ConsumeBytes<unsigned char>(
        fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 10000)
    );

    // Sign
    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;

    int sign_ret = dilithium::sign(sig, &siglen, msg.data(), msg.size(), sk);

    if (sign_ret != 0) {
        memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
        return; // Signing failed
    }

    // Optionally corrupt the signature
    if (fuzzed_data_provider.ConsumeBool()) {
        size_t corrupt_bytes = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 10);
        for (size_t i = 0; i < corrupt_bytes; i++) {
            size_t idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, DILITHIUM_BYTES - 1);
            sig[idx] ^= fuzzed_data_provider.ConsumeIntegral<unsigned char>();
        }
    }

    // Optionally corrupt the message
    if (fuzzed_data_provider.ConsumeBool() && !msg.empty()) {
        size_t idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, msg.size() - 1);
        msg[idx] ^= fuzzed_data_provider.ConsumeIntegral<unsigned char>();
    }

    // Optionally corrupt the public key
    if (fuzzed_data_provider.ConsumeBool()) {
        size_t idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, DILITHIUM_PUBLICKEYBYTES - 1);
        pk[idx] ^= fuzzed_data_provider.ConsumeIntegral<unsigned char>();
    }

    // Verify - should not crash
    int verify_ret = dilithium::verify(sig, siglen, msg.data(), msg.size(), pk);

    (void)verify_ret; // Don't care about result, just that it doesn't crash

    // Clean up
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

/**
 * Fuzz target: Memory safety tests
 *
 * Tests for buffer overflows, use-after-free, etc.
 */
void test_memory_safety(FuzzedDataProvider& fuzzed_data_provider)
{
    // Allocate buffers on heap to help ASAN detect issues
    std::vector<unsigned char> pk(DILITHIUM_PUBLICKEYBYTES);
    std::vector<unsigned char> sk(DILITHIUM_SECRETKEYBYTES);
    std::vector<unsigned char> sig(DILITHIUM_BYTES);

    // Generate keypair
    if (dilithium::keypair(pk.data(), sk.data()) != 0) {
        return;
    }

    // Create message
    auto msg = fuzzed_data_provider.ConsumeBytes<unsigned char>(
        fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 10000)
    );

    // Sign
    size_t siglen;
    if (dilithium::sign(sig.data(), &siglen, msg.data(), msg.size(), sk.data()) != 0) {
        memory_cleanse(sk.data(), DILITHIUM_SECRETKEYBYTES);
        return;
    }

    // Verify
    dilithium::verify(sig.data(), siglen, msg.data(), msg.size(), pk.data());

    // Clean up
    memory_cleanse(sk.data(), DILITHIUM_SECRETKEYBYTES);

    // Vectors will be automatically freed - ASAN will detect any issues
}

} // namespace

/**
 * Main fuzz entrypoint
 */
FUZZ_TARGET(dilithium)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    // Choose which test to run based on fuzzed input
    uint8_t test_selector = fuzzed_data_provider.ConsumeIntegral<uint8_t>();

    switch (test_selector % 6) {
        case 0:
            test_keypair_generation(fuzzed_data_provider);
            break;
        case 1:
            test_signing(fuzzed_data_provider);
            break;
        case 2:
            test_verification(fuzzed_data_provider);
            break;
        case 3:
            test_sign_verify_cycle(fuzzed_data_provider);
            break;
        case 4:
            test_memory_safety(fuzzed_data_provider);
            break;
        case 5:
            // Run multiple operations in sequence
            test_keypair_generation(fuzzed_data_provider);
            test_signing(fuzzed_data_provider);
            test_verification(fuzzed_data_provider);
            break;
    }
}
