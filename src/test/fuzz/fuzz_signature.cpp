// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: Dilithium signature verification
 *
 * Tests Dilithium3 signature verification with malformed signatures,
 * public keys, and messages.
 *
 * Priority: CRITICAL (consensus-critical cryptography)
 */

#include "fuzz.h"
#include "util.h"
extern "C" {
    #include "../../../depends/dilithium/ref/sign.h"
    #include "../../../depends/dilithium/ref/params.h"
}
#include <vector>
#include <cstring>

FUZZ_TARGET(signature_verify)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Fuzz message
        size_t msg_len = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 1024);
        std::vector<uint8_t> msg = fuzzed_data.ConsumeBytes<uint8_t>(msg_len);

        // Fuzz signature (should be CRYPTO_BYTES = 3293 bytes for Dilithium3)
        size_t sig_len = fuzzed_data.ConsumeIntegralInRange<size_t>(0, CRYPTO_BYTES + 100);
        std::vector<uint8_t> sig = fuzzed_data.ConsumeBytes<uint8_t>(sig_len);

        // Fuzz public key (should be CRYPTO_PUBLICKEYBYTES = 1952 bytes)
        size_t pk_len = fuzzed_data.ConsumeIntegralInRange<size_t>(0, CRYPTO_PUBLICKEYBYTES + 100);
        std::vector<uint8_t> pk = fuzzed_data.ConsumeBytes<uint8_t>(pk_len);

        // Pad to correct sizes if needed
        if (sig.size() < CRYPTO_BYTES) {
            sig.resize(CRYPTO_BYTES, 0);
        }
        if (pk.size() < CRYPTO_PUBLICKEYBYTES) {
            pk.resize(CRYPTO_PUBLICKEYBYTES, 0);
        }

        // Attempt signature verification
        // This should handle all malformed inputs gracefully
        // Using crypto_sign_verify with empty context
        int result = crypto_sign_verify(
            sig.data(), sig.size(),
            msg.data(), msg.size(),
            nullptr, 0,  // empty context
            pk.data()
        );

        // Result should be 0 (valid) or -1 (invalid)
        // Most fuzzed inputs will be invalid
        if (result == 0) {
            // Valid signature (very rare with random data)
        } else {
            // Invalid signature (expected)
        }

    } catch (const std::exception& e) {
        return;
    }
}
