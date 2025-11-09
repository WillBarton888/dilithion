// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CRYPTO_PBKDF2_SHA3_H
#define DILITHION_CRYPTO_PBKDF2_SHA3_H

#include <stdint.h>
#include <stdlib.h>
#include <vector>

/**
 * PBKDF2-SHA3-512 (Password-Based Key Derivation Function 2 with SHA-3-512)
 *
 * PBKDF2 derives a cryptographic key from a password using a pseudorandom function.
 * It's used in BIP39 to convert a mnemonic phrase into a seed.
 *
 * Algorithm (RFC 2898 / PKCS #5 v2.0):
 *   DK = T1 || T2 || ... || Tdklen/hlen
 *   Ti = F(Password, Salt, c, i)
 *
 * Where:
 *   F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc
 *   U1 = HMAC-SHA3-512(Password, Salt || INT_32_BE(i))
 *   U2 = HMAC-SHA3-512(Password, U1)
 *   ...
 *   Uc = HMAC-SHA3-512(Password, Uc-1)
 *
 * For BIP39:
 *   - Password: Mnemonic phrase (UTF-8)
 *   - Salt: "dilithion-mnemonic" + optional passphrase (UTF-8)
 *   - Iterations (c): 2048
 *   - Output length: 64 bytes (512 bits)
 */

/**
 * Compute PBKDF2-SHA3-512
 *
 * Derives a cryptographic key from a password using HMAC-SHA3-512 as the PRF.
 *
 * @param password Password/passphrase bytes
 * @param password_len Length of password in bytes
 * @param salt Salt bytes (typically "prefix" + user_salt)
 * @param salt_len Length of salt in bytes
 * @param iterations Number of iterations (c) - must be > 0
 * @param output Output buffer for derived key
 * @param output_len Desired output length in bytes
 *
 * Security notes:
 * - iterations should be >= 2048 for BIP39 (balance security vs performance)
 * - Higher iterations increase resistance to brute-force attacks
 * - output_len can be any length (multiple of 64 bytes is most efficient)
 */
void PBKDF2_SHA3_512(const uint8_t* password, size_t password_len,
                     const uint8_t* salt, size_t salt_len,
                     uint32_t iterations,
                     uint8_t* output, size_t output_len);

/**
 * Compute PBKDF2-SHA3-512 (C++ vector interface)
 *
 * Convenience wrapper for C++ code using std::vector.
 *
 * @param password Password/passphrase
 * @param salt Salt bytes
 * @param iterations Number of iterations
 * @param output Output buffer for derived key
 * @param output_len Desired output length in bytes
 */
inline void PBKDF2_SHA3_512(const std::vector<uint8_t>& password,
                            const std::vector<uint8_t>& salt,
                            uint32_t iterations,
                            uint8_t* output, size_t output_len) {
    PBKDF2_SHA3_512(password.data(), password.size(),
                    salt.data(), salt.size(),
                    iterations, output, output_len);
}

/**
 * BIP39-specific PBKDF2 derivation
 *
 * Convenience function for BIP39 mnemonic → seed conversion.
 * Uses standard BIP39 parameters:
 * - 2048 iterations
 * - 64-byte output
 * - Salt prefix: "dilithion-mnemonic"
 *
 * @param mnemonic_phrase Mnemonic phrase (UTF-8 encoded, space-separated words)
 * @param mnemonic_len Length of mnemonic phrase in bytes
 * @param passphrase Optional passphrase (can be NULL if passphrase_len = 0)
 * @param passphrase_len Length of passphrase in bytes (0 if no passphrase)
 * @param seed_output Output buffer for 64-byte seed
 */
void BIP39_MnemonicToSeed(const char* mnemonic_phrase, size_t mnemonic_len,
                          const char* passphrase, size_t passphrase_len,
                          uint8_t seed_output[64]);

#endif // DILITHION_CRYPTO_PBKDF2_SHA3_H
