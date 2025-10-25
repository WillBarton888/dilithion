// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CRYPTO_SHA3_H
#define DILITHION_CRYPTO_SHA3_H

#include <stdint.h>
#include <stdlib.h>
#include <vector>

/**
 * SHA-3 (Keccak) hashing - Quantum-resistant hash function
 *
 * Using NIST FIPS 202 standard from Dilithium library
 *
 * SHA-3 is quantum-resistant because:
 * - Grover's algorithm only provides quadratic speedup (not exponential)
 * - 256-bit SHA-3 provides ~128-bit security against quantum attacks
 * - This is considered secure for post-quantum cryptography
 */

/** SHA-3-256 hasher class */
class CSHA3_256 {
private:
    void* state;  // keccak_state from fips202.h
    bool finalized;

public:
    static const size_t OUTPUT_SIZE = 32;

    CSHA3_256();
    ~CSHA3_256();

    CSHA3_256& Write(const uint8_t* data, size_t len);
    void Finalize(uint8_t hash[OUTPUT_SIZE]);
    CSHA3_256& Reset();
};

/** SHA-3-512 hasher class */
class CSHA3_512 {
private:
    void* state;  // keccak_state from fips202.h
    bool finalized;

public:
    static const size_t OUTPUT_SIZE = 64;

    CSHA3_512();
    ~CSHA3_512();

    CSHA3_512& Write(const uint8_t* data, size_t len);
    void Finalize(uint8_t hash[OUTPUT_SIZE]);
    CSHA3_512& Reset();
};

/** Convenience function: Compute SHA3-256 hash of data */
void SHA3_256(const uint8_t* data, size_t len, uint8_t hash[32]);

/** Convenience function: Compute SHA3-512 hash of data */
void SHA3_512(const uint8_t* data, size_t len, uint8_t hash[64]);

/** Hash a uint256 value with SHA3-256 */
inline void SHA3_256_uint256(const uint8_t data[32], uint8_t hash[32]) {
    SHA3_256(data, 32, hash);
}

#endif // DILITHION_CRYPTO_SHA3_H
