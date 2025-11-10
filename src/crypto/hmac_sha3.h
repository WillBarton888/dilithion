// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CRYPTO_HMAC_SHA3_H
#define DILITHION_CRYPTO_HMAC_SHA3_H

#include <stdint.h>
#include <stdlib.h>
#include <vector>

/**
 * HMAC-SHA3-512 (Keyed-Hash Message Authentication Code using SHA-3-512)
 *
 * HMAC provides message authentication using a cryptographic hash function
 * and a secret key. It's used in HD wallet key derivation.
 *
 * Algorithm (RFC 2104 adapted for SHA-3):
 *   HMAC(K, m) = SHA3-512((K' ⊕ opad) || SHA3-512((K' ⊕ ipad) || m))
 *
 * Where:
 *   K' = K if len(K) <= blocksize, else SHA3-512(K)
 *   opad = 0x5c repeated blocksize times
 *   ipad = 0x36 repeated blocksize times
 *   blocksize = 72 bytes for SHA3-512 (rate = 576 bits = 72 bytes)
 *   Note: SHA3-256 uses 136 bytes (rate = 1088 bits)
 */

/**
 * Compute HMAC-SHA3-512
 *
 * @param key Secret key
 * @param key_len Length of key in bytes
 * @param data Message to authenticate
 * @param data_len Length of message in bytes
 * @param output Output buffer for 64-byte HMAC
 */
void HMAC_SHA3_512(const uint8_t* key, size_t key_len,
                   const uint8_t* data, size_t data_len,
                   uint8_t output[64]);

/**
 * Compute HMAC-SHA3-512 (C++ vector interface)
 *
 * @param key Secret key
 * @param data Message to authenticate
 * @param output Output buffer for 64-byte HMAC
 */
inline void HMAC_SHA3_512(const std::vector<uint8_t>& key,
                          const std::vector<uint8_t>& data,
                          uint8_t output[64]) {
    HMAC_SHA3_512(key.data(), key.size(), data.data(), data.size(), output);
}

#endif // DILITHION_CRYPTO_HMAC_SHA3_H
