// Copyright (c) 2016-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/siphash.h>
#include <cstring>

/**
 * SipHash-2-4 implementation
 *
 * Based on reference implementation from https://131002.net/siphash/
 * Modified for C++ and Bitcoin/Dilithion use cases.
 */

// Rotate left helper
static inline uint64_t ROTL(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}

// SipHash round
#define SIPROUND do { \
    v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32); \
    v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32); \
} while(0)

CSipHasher::CSipHasher(uint64_t k0, uint64_t k1) {
    v[0] = 0x736f6d6570736575ULL ^ k0;
    v[1] = 0x646f72616e646f6dULL ^ k1;
    v[2] = 0x6c7967656e657261ULL ^ k0;
    v[3] = 0x7465646279746573ULL ^ k1;
    tmp = 0;
    count = 0;
}

CSipHasher& CSipHasher::Write(uint64_t val) {
    uint64_t v0 = this->v[0], v1 = this->v[1], v2 = this->v[2], v3 = this->v[3];

    v3 ^= val;
    SIPROUND;
    SIPROUND;
    v0 ^= val;

    this->v[0] = v0;
    this->v[1] = v1;
    this->v[2] = v2;
    this->v[3] = v3;

    count += 8;
    return *this;
}

CSipHasher& CSipHasher::Write(const uint8_t* data, size_t len) {
    uint64_t v0 = this->v[0], v1 = this->v[1], v2 = this->v[2], v3 = this->v[3];
    uint64_t t = tmp;
    uint8_t c = count;

    while (len--) {
        t |= (static_cast<uint64_t>(*data++)) << (8 * (c % 8));
        c++;
        if ((c & 7) == 0) {
            v3 ^= t;
            SIPROUND;
            SIPROUND;
            v0 ^= t;
            t = 0;
        }
    }

    this->v[0] = v0;
    this->v[1] = v1;
    this->v[2] = v2;
    this->v[3] = v3;
    tmp = t;
    count = c;

    return *this;
}

uint64_t CSipHasher::Finalize() const {
    uint64_t v0 = this->v[0], v1 = this->v[1], v2 = this->v[2], v3 = this->v[3];

    // Add remaining bytes + length
    uint64_t t = tmp | (static_cast<uint64_t>(count) << 56);

    v3 ^= t;
    SIPROUND;
    SIPROUND;
    v0 ^= t;

    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;

    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t SipHash(uint64_t k0, uint64_t k1, const uint8_t* data, size_t len) {
    return CSipHasher(k0, k1).Write(data, len).Finalize();
}

uint64_t SipHashUint256(uint64_t k0, uint64_t k1, const uint256& val) {
    // Hash the uint256 as four 64-bit words
    CSipHasher hasher(k0, k1);

    // Read uint256 as four 64-bit little-endian values
    uint64_t words[4];
    for (int i = 0; i < 4; i++) {
        words[i] = 0;
        for (int j = 0; j < 8; j++) {
            words[i] |= static_cast<uint64_t>(val.data[i * 8 + j]) << (j * 8);
        }
        hasher.Write(words[i]);
    }

    return hasher.Finalize();
}
