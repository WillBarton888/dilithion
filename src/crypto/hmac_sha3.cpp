// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <crypto/hmac_sha3.h>
#include <crypto/sha3.h>
#include <cstring>

// SHA3-512 block size (rate in bytes)
// SHA3-512 has capacity = 1024 bits, rate = 1600 - 1024 = 576 bits = 72 bytes
static const size_t SHA3_512_BLOCKSIZE = 72;

void HMAC_SHA3_512(const uint8_t* key, size_t key_len,
                   const uint8_t* data, size_t data_len,
                   uint8_t output[64]) {
    // Prepare key
    uint8_t key_block[SHA3_512_BLOCKSIZE];
    std::memset(key_block, 0, SHA3_512_BLOCKSIZE);

    if (key_len > SHA3_512_BLOCKSIZE) {
        // If key is longer than block size, hash it first
        uint8_t key_hash[64];
        SHA3_512(key, key_len, key_hash);
        std::memcpy(key_block, key_hash, 64);
    } else {
        // Otherwise use key directly (padded with zeros)
        std::memcpy(key_block, key, key_len);
    }

    // Prepare inner and outer padded keys
    uint8_t ipad_key[SHA3_512_BLOCKSIZE];
    uint8_t opad_key[SHA3_512_BLOCKSIZE];

    for (size_t i = 0; i < SHA3_512_BLOCKSIZE; i++) {
        ipad_key[i] = key_block[i] ^ 0x36;
        opad_key[i] = key_block[i] ^ 0x5c;
    }

    // Inner hash: SHA3-512((K ⊕ ipad) || data)
    uint8_t inner_hash[64];
    {
        // Concatenate ipad_key and data
        size_t inner_len = SHA3_512_BLOCKSIZE + data_len;
        uint8_t* inner_data = new uint8_t[inner_len];
        std::memcpy(inner_data, ipad_key, SHA3_512_BLOCKSIZE);
        std::memcpy(inner_data + SHA3_512_BLOCKSIZE, data, data_len);

        SHA3_512(inner_data, inner_len, inner_hash);

        delete[] inner_data;
    }

    // Outer hash: SHA3-512((K ⊕ opad) || inner_hash)
    {
        size_t outer_len = SHA3_512_BLOCKSIZE + 64;
        uint8_t* outer_data = new uint8_t[outer_len];
        std::memcpy(outer_data, opad_key, SHA3_512_BLOCKSIZE);
        std::memcpy(outer_data + SHA3_512_BLOCKSIZE, inner_hash, 64);

        SHA3_512(outer_data, outer_len, output);

        delete[] outer_data;
    }

    // Wipe sensitive data
    std::memset(key_block, 0, SHA3_512_BLOCKSIZE);
    std::memset(ipad_key, 0, SHA3_512_BLOCKSIZE);
    std::memset(opad_key, 0, SHA3_512_BLOCKSIZE);
    std::memset(inner_hash, 0, 64);
}
