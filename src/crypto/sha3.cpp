// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <crypto/sha3.h>

// Import SHA-3 from Dilithium's FIPS 202 implementation
extern "C" {
    void pqcrystals_dilithium_fips202_ref_sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
    void pqcrystals_dilithium_fips202_ref_sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);
}

/**
 * SHA-3-256 one-shot hashing function
 *
 * CRITICAL FIX (SHA3-STREAMING): Removed unimplemented CSHA3_256 streaming class
 * which threw runtime_error if Write() or Finalize() were called. This one-shot
 * function is fully implemented using Dilithium's FIPS 202 reference implementation
 * and is production-ready.
 */
void SHA3_256(const uint8_t* data, size_t len, uint8_t hash[32]) {
    pqcrystals_dilithium_fips202_ref_sha3_256(hash, data, len);
}

/**
 * SHA-3-512 one-shot hashing function
 *
 * CRITICAL FIX (SHA3-STREAMING): Removed unimplemented CSHA3_512 streaming class
 * which threw runtime_error if Write() or Finalize() were called. This one-shot
 * function is fully implemented using Dilithium's FIPS 202 reference implementation
 * and is production-ready.
 */
void SHA3_512(const uint8_t* data, size_t len, uint8_t hash[64]) {
    pqcrystals_dilithium_fips202_ref_sha3_512(hash, data, len);
}
