// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CRYPTO_SHA3_H
#define DILITHION_CRYPTO_SHA3_H

#include <stdint.h>
#include <stdlib.h>

/**
 * SHA-3 (Keccak) hashing - Quantum-resistant hash function
 *
 * Using NIST FIPS 202 standard from Dilithium library
 *
 * SHA-3 is quantum-resistant because:
 * - Grover's algorithm only provides quadratic speedup (not exponential)
 * - 256-bit SHA-3 provides ~128-bit security against quantum attacks
 * - This is considered secure for post-quantum cryptography
 *
 * CRITICAL FIX (SHA3-STREAMING): Removed unimplemented streaming API classes
 * (CSHA3_256/CSHA3_512) which threw runtime_error if called. Use the one-shot
 * functions below which are fully implemented and production-ready.
 */

/**
 * Compute SHA3-256 hash of data (one-shot function)
 *
 * @param data Input data to hash
 * @param len Length of input data in bytes
 * @param hash Output buffer for 32-byte hash
 */
void SHA3_256(const uint8_t* data, size_t len, uint8_t hash[32]);

/**
 * Compute SHA3-512 hash of data (one-shot function)
 *
 * @param data Input data to hash
 * @param len Length of input data in bytes
 * @param hash Output buffer for 64-byte hash
 */
void SHA3_512(const uint8_t* data, size_t len, uint8_t hash[64]);

/**
 * Hash a uint256 value with SHA3-256
 *
 * @param data 32-byte input value
 * @param hash Output buffer for 32-byte hash
 */
inline void SHA3_256_uint256(const uint8_t data[32], uint8_t hash[32]) {
    SHA3_256(data, 32, hash);
}

#endif // DILITHION_CRYPTO_SHA3_H
