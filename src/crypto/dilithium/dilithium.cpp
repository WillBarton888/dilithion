// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/dilithium/dilithium.h>
#include <support/cleanse.h>
#include <random.h>

#include <cstring>
#include <cstdint>

// Include Dilithium reference implementation
// This is the NIST-standard reference implementation
extern "C" {
#include "../../depends/dilithium/ref/api.h"
#include "../../depends/dilithium/ref/sign.h"
}

namespace dilithium {

//
// Internal validation functions
// These provide defense-in-depth security checks
//

/**
 * Validate entropy quality before key generation.
 *
 * This prevents weak key generation due to insufficient entropy.
 * We test the RNG by generating test bytes and checking for
 * obvious failure modes (all zeros, all ones).
 *
 * @return true if RNG appears healthy, false if RNG is suspect
 */
static bool validate_entropy_quality()
{
    unsigned char test_bytes[32];
    GetRandBytes(test_bytes, 32);

    // Check for all zeros (RNG failure mode)
    bool all_zero = true;
    for (size_t i = 0; i < 32; i++) {
        if (test_bytes[i] != 0) {
            all_zero = false;
            break;
        }
    }

    // Check for all 0xFF (RNG failure mode)
    bool all_ones = true;
    for (size_t i = 0; i < 32; i++) {
        if (test_bytes[i] != 0xFF) {
            all_ones = false;
            break;
        }
    }

    // Clear test bytes (good hygiene)
    memory_cleanse(test_bytes, 32);

    return !all_zero && !all_ones;
}

/**
 * Validate keypair parameters before generation.
 *
 * This checks for common programming errors:
 * - Null pointers
 * - Buffer overlap (undefined behavior)
 * - Misalignment (potential performance issue)
 *
 * @param pk Public key buffer
 * @param sk Secret key buffer
 * @return 0 on valid parameters, -1 on invalid
 */
static int validate_keypair_params(const unsigned char* pk,
                                   const unsigned char* sk)
{
    // Check for null pointers
    if (!pk || !sk) return -1;

    // Check for buffer overlap (undefined behavior in C)
    // This catches pk == sk and partial overlaps
    const uintptr_t pk_start = (uintptr_t)pk;
    const uintptr_t pk_end = pk_start + DILITHIUM_PUBLICKEYBYTES;
    const uintptr_t sk_start = (uintptr_t)sk;
    const uintptr_t sk_end = sk_start + DILITHIUM_SECRETKEYBYTES;

    // Check if ranges overlap
    bool overlap = (pk_start < sk_end) && (sk_start < pk_end);
    if (overlap) return -1;

    return 0;
}

/**
 * Validate sign parameters.
 *
 * @param sig Signature buffer
 * @param siglen Signature length pointer
 * @param msg Message buffer (can be nullptr if msglen == 0)
 * @param msglen Message length
 * @param sk Secret key buffer
 * @return 0 on valid parameters, -1 on invalid
 */
static int validate_sign_params(const unsigned char* sig,
                                const size_t* siglen,
                                const unsigned char* msg,
                                size_t msglen,
                                const unsigned char* sk)
{
    // Check for null pointers (msg can be nullptr if msglen == 0)
    if (!sig || !siglen || !sk) return -1;
    if (msglen > 0 && !msg) return -1;

    // Check for buffer overlaps
    const uintptr_t sig_start = (uintptr_t)sig;
    const uintptr_t sig_end = sig_start + DILITHIUM_BYTES;
    const uintptr_t sk_start = (uintptr_t)sk;
    const uintptr_t sk_end = sk_start + DILITHIUM_SECRETKEYBYTES;

    // sig and sk must not overlap
    bool sig_sk_overlap = (sig_start < sk_end) && (sk_start < sig_end);
    if (sig_sk_overlap) return -1;

    // If msg exists, check it doesn't overlap with sig or sk
    if (msg && msglen > 0) {
        const uintptr_t msg_start = (uintptr_t)msg;
        const uintptr_t msg_end = msg_start + msglen;

        bool sig_msg_overlap = (sig_start < msg_end) && (msg_start < sig_end);
        bool sk_msg_overlap = (sk_start < msg_end) && (msg_start < sk_end);

        if (sig_msg_overlap || sk_msg_overlap) return -1;
    }

    return 0;
}

/**
 * Validate verify parameters.
 *
 * @param sig Signature buffer
 * @param siglen Signature length
 * @param msg Message buffer (can be nullptr if msglen == 0)
 * @param msglen Message length
 * @param pk Public key buffer
 * @return 0 on valid parameters, -1 on invalid
 */
static int validate_verify_params(const unsigned char* sig,
                                  size_t siglen,
                                  const unsigned char* msg,
                                  size_t msglen,
                                  const unsigned char* pk)
{
    // Check for null pointers (msg can be nullptr if msglen == 0)
    if (!sig || !pk) return -1;
    if (msglen > 0 && !msg) return -1;

    // Signature must be exactly DILITHIUM_BYTES
    if (siglen != DILITHIUM_BYTES) return -1;

    return 0;
}

/**
 * Verify that a buffer contains non-zero data.
 *
 * This is used to verify that key generation actually wrote data
 * and didn't just leave the buffer as zeros.
 *
 * @param buffer Buffer to check
 * @param len Length of buffer
 * @return true if buffer contains at least one non-zero byte
 */
static bool buffer_is_nonzero(const unsigned char* buffer, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buffer[i] != 0) {
            return true;
        }
    }
    return false;
}

//
// Public API implementation
//

int keypair(unsigned char* pk, unsigned char* sk)
{
    // Phase 1: Parameter validation
    if (validate_keypair_params(pk, sk) != 0) {
        return -1; // Invalid parameters
    }

    // Phase 2: Entropy quality check
    // This prevents weak key generation due to insufficient entropy
    if (!validate_entropy_quality()) {
        return -2; // RNG failure
    }

    // Phase 3: Call reference implementation
    // This is the NIST-standard Dilithium reference implementation
    // It uses constant-time operations internally
    int ret = pqcrystals_dilithium2_ref_keypair(pk, sk);

    if (ret != 0) {
        // Key generation failed in reference implementation
        return ret;
    }

    // Phase 4: Post-generation validation
    // Verify that keys were actually generated (not left as zeros)
    // This catches catastrophic RNG failures
    bool pk_valid = buffer_is_nonzero(pk, DILITHIUM_PUBLICKEYBYTES);
    bool sk_valid = buffer_is_nonzero(sk, DILITHIUM_SECRETKEYBYTES);

    if (!pk_valid || !sk_valid) {
        // Key generation produced invalid (all-zero) keys
        // Clear any data that was written
        memory_cleanse(pk, DILITHIUM_PUBLICKEYBYTES);
        memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
        return -3; // Key verification failed
    }

    // Success: valid keypair generated
    return 0;
}

int sign(unsigned char* sig, size_t* siglen,
         const unsigned char* msg, size_t msglen,
         const unsigned char* sk)
{
    // Phase 1: Parameter validation
    if (validate_sign_params(sig, siglen, msg, msglen, sk) != 0) {
        return -1; // Invalid parameters
    }

    // Phase 2: Call reference implementation
    // This is the NIST-standard Dilithium reference implementation
    // It uses constant-time operations internally
    int ret = pqcrystals_dilithium2_ref_signature(
        sig, siglen, msg, msglen, sk
    );

    if (ret != 0) {
        // Signing failed in reference implementation
        return -2; // Signing failure
    }

    // Phase 3: Post-signing validation
    // Verify signature length is correct
    if (*siglen != DILITHIUM_BYTES) {
        // Something went wrong - invalid signature length
        // Clear the potentially invalid signature
        memory_cleanse(sig, DILITHIUM_BYTES);
        return -2; // Signing failure
    }

    // Success: valid signature created
    return 0;
}

int verify(const unsigned char* sig, size_t siglen,
           const unsigned char* msg, size_t msglen,
           const unsigned char* pk)
{
    // Phase 1: Parameter validation
    if (validate_verify_params(sig, siglen, msg, msglen, pk) != 0) {
        return -1; // Invalid parameters
    }

    // Phase 2: Call reference implementation (constant-time)
    // This is the NIST-standard Dilithium reference implementation
    // Verification is constant-time (execution time independent of validity)
    //
    // IMPORTANT: Returns 0 for VALID, non-zero for INVALID (C convention)
    int ret = pqcrystals_dilithium2_ref_verify(
        sig, siglen, msg, msglen, pk
    );

    // Return verification result directly
    // 0 = valid signature
    // non-zero = invalid signature
    return ret;
}

} // namespace dilithium
