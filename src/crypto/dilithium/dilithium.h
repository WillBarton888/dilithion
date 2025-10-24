// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_DILITHIUM_H
#define BITCOIN_CRYPTO_DILITHIUM_H

#include <cstddef>
#include <cstdint>

/**
 * CRYSTALS-Dilithium Post-Quantum Digital Signature Wrapper
 *
 * This is a C++ wrapper around the NIST-standardized Dilithium reference
 * implementation. Dilithium is a lattice-based digital signature scheme
 * selected by NIST for standardization (FIPS 204).
 *
 * Security Level: We use Dilithium-2 (NIST Security Level 2) which provides
 * 128-bit quantum security, equivalent to AES-128.
 *
 * CRITICAL SECURITY NOTES:
 * - All operations are constant-time (timing-attack resistant)
 * - Secret keys MUST be cleared after use with memory_cleanse()
 * - This is Tier 1 cryptographic code - highest security standards apply
 * - Any modifications require cryptographer review
 *
 * Reference: https://pq-crystals.org/dilithium/
 * NIST FIPS 204: https://csrc.nist.gov/publications/detail/fips/204/final
 */

// Dilithium-2 parameters (NIST Security Level 2)
// These are fixed by the NIST standard and must not be changed
#define DILITHIUM_PUBLICKEYBYTES 1312  // 1.3 KB public key
#define DILITHIUM_SECRETKEYBYTES 2528  // 2.5 KB secret key
#define DILITHIUM_BYTES 2420           // 2.4 KB signature

namespace dilithium {

/**
 * Generate a Dilithium keypair.
 *
 * This function generates a fresh public/secret keypair using
 * cryptographically secure random number generation.
 *
 * SECURITY REQUIREMENTS:
 * - Requires high-quality entropy from system RNG
 * - Output buffers must be at least DILITHIUM_PUBLICKEYBYTES and
 *   DILITHIUM_SECRETKEYBYTES in size
 * - Buffers must not overlap (undefined behavior)
 * - Secret key MUST be cleared with memory_cleanse() after use
 *
 * TIMING: Constant-time operation (no timing side-channels)
 *
 * @param pk Output buffer for public key (DILITHIUM_PUBLICKEYBYTES bytes)
 * @param sk Output buffer for secret key (DILITHIUM_SECRETKEYBYTES bytes)
 *
 * @return 0 on success
 *         -1 on invalid parameters (null pointers, buffer overlap)
 *         -2 on RNG failure (insufficient entropy)
 *         -3 on key generation failure (verification failed)
 *
 * @pre pk != nullptr && sk != nullptr
 * @pre pk != sk (no buffer overlap)
 * @post ret == 0 => public key and secret key are valid and non-zero
 *
 * Example usage:
 * @code
 *   unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
 *   unsigned char sk[DILITHIUM_SECRETKEYBYTES];
 *
 *   if (dilithium::keypair(pk, sk) == 0) {
 *       // Use keys...
 *       memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES); // Always clear!
 *   }
 * @endcode
 */
int keypair(unsigned char* pk, unsigned char* sk)
    __attribute__((warn_unused_result))
    __attribute__((nonnull(1, 2)));

/**
 * Sign a message with Dilithium.
 *
 * This function creates a digital signature over a message using the
 * Dilithium signature algorithm. The signature is deterministic but
 * includes randomness for security.
 *
 * SECURITY REQUIREMENTS:
 * - Secret key must be valid (generated with keypair())
 * - Secret key must be cleared after use
 * - Signature buffer must be at least DILITHIUM_BYTES in size
 * - All buffers must not overlap (undefined behavior)
 *
 * TIMING: Constant-time operation (execution time independent of:
 *         message content, message length, secret key value)
 *
 * @param sig Output buffer for signature (DILITHIUM_BYTES bytes)
 * @param siglen Output: actual signature length (will be DILITHIUM_BYTES)
 * @param msg Input: message to sign (can be any length)
 * @param msglen Input: length of message in bytes
 * @param sk Input: secret key (DILITHIUM_SECRETKEYBYTES bytes)
 *
 * @return 0 on success
 *         -1 on invalid parameters (null pointers, buffer overlap)
 *         -2 on signing failure
 *
 * @pre sig != nullptr && siglen != nullptr && sk != nullptr
 * @pre msg != nullptr || msglen == 0
 * @pre No buffer overlaps between sig, msg, and sk
 * @post ret == 0 => *siglen == DILITHIUM_BYTES
 * @post ret == 0 => signature is valid for (msg, msglen, pk)
 *
 * Example usage:
 * @code
 *   unsigned char sig[DILITHIUM_BYTES];
 *   size_t siglen;
 *   unsigned char msg[] = "Hello, quantum-resistant world!";
 *
 *   if (dilithium::sign(sig, &siglen, msg, sizeof(msg), sk) == 0) {
 *       // Signature created successfully
 *       assert(siglen == DILITHIUM_BYTES);
 *   }
 * @endcode
 */
int sign(unsigned char* sig, size_t* siglen,
         const unsigned char* msg, size_t msglen,
         const unsigned char* sk)
    __attribute__((warn_unused_result))
    __attribute__((nonnull(1, 2, 5)));

/**
 * Verify a Dilithium signature (constant-time).
 *
 * This function verifies that a signature is valid for a given message
 * and public key. Verification is constant-time to prevent timing attacks.
 *
 * SECURITY REQUIREMENTS:
 * - Verification is constant-time (timing independent of validity)
 * - Invalid signatures are rejected safely
 * - Public key must be valid (from a keypair() call)
 * - Signature must be exactly DILITHIUM_BYTES in length
 *
 * TIMING: Constant-time operation (execution time independent of:
 *         signature validity, message content, public key value)
 *
 * IMPORTANT: This function returns 0 for VALID signatures and
 *            non-zero for INVALID signatures (C convention).
 *
 * @param sig Input: signature to verify (DILITHIUM_BYTES bytes)
 * @param siglen Input: signature length (must be DILITHIUM_BYTES)
 * @param msg Input: message that was signed
 * @param msglen Input: length of message in bytes
 * @param pk Input: public key (DILITHIUM_PUBLICKEYBYTES bytes)
 *
 * @return 0 if signature is VALID
 *         non-zero if signature is INVALID or parameters are invalid
 *
 * @pre sig != nullptr && msg != nullptr && pk != nullptr
 * @pre siglen == DILITHIUM_BYTES
 * @pre msg != nullptr || msglen == 0
 *
 * Example usage:
 * @code
 *   if (dilithium::verify(sig, siglen, msg, msglen, pk) == 0) {
 *       // Signature is VALID
 *   } else {
 *       // Signature is INVALID or parameters are bad
 *   }
 * @endcode
 *
 * Note: This follows the C convention where 0 = success. In boolean
 * contexts, remember that verify() == 0 means the signature is valid.
 */
int verify(const unsigned char* sig, size_t siglen,
           const unsigned char* msg, size_t msglen,
           const unsigned char* pk)
    __attribute__((warn_unused_result))
    __attribute__((nonnull(1, 3, 5)));

} // namespace dilithium

#endif // BITCOIN_CRYPTO_DILITHIUM_H
