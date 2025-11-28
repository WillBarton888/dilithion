// Copyright (c) 2016-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DILITHION_CRYPTO_SIPHASH_H
#define DILITHION_CRYPTO_SIPHASH_H

#include <cstdint>
#include <primitives/block.h>

/**
 * @file siphash.h
 * @brief SipHash-2-4 implementation for compact block short IDs
 *
 * SipHash is a fast, cryptographically secure PRF (pseudorandom function)
 * designed for hash-table security and short message authentication.
 *
 * Used in compact blocks (BIP 152) to generate 6-byte short transaction IDs
 * that are collision-resistant but much smaller than full 32-byte txids.
 *
 * Reference: https://131002.net/siphash/
 */

/**
 * SipHash-2-4 for uint256 values
 *
 * @param k0 First 64-bit key
 * @param k1 Second 64-bit key
 * @param val 256-bit value to hash
 * @return 64-bit SipHash result
 */
uint64_t SipHashUint256(uint64_t k0, uint64_t k1, const uint256& val);

/**
 * SipHash-2-4 for arbitrary data
 *
 * @param k0 First 64-bit key
 * @param k1 Second 64-bit key
 * @param data Pointer to data
 * @param len Length of data in bytes
 * @return 64-bit SipHash result
 */
uint64_t SipHash(uint64_t k0, uint64_t k1, const uint8_t* data, size_t len);

/**
 * Incremental SipHash hasher class
 *
 * For hashing large or variable-length data incrementally.
 */
class CSipHasher {
private:
    uint64_t v[4];
    uint64_t tmp;
    uint8_t count;  // Only counts up to 7 (for final block)

public:
    /**
     * Construct with keys
     *
     * @param k0 First 64-bit key
     * @param k1 Second 64-bit key
     */
    CSipHasher(uint64_t k0, uint64_t k1);

    /**
     * Write data to hasher
     *
     * @param data Pointer to data
     * @param len Length in bytes
     * @return Reference to this hasher
     */
    CSipHasher& Write(const uint8_t* data, size_t len);

    /**
     * Write a 64-bit value
     */
    CSipHasher& Write(uint64_t val);

    /**
     * Finalize and return hash
     *
     * @return 64-bit SipHash result
     */
    uint64_t Finalize() const;
};

#endif // DILITHION_CRYPTO_SIPHASH_H
