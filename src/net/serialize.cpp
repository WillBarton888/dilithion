// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/serialize.h>
#include <crypto/sha3.h>
#include <cstring>

// Checksum calculation using double SHA3-256 (first 4 bytes)
// This matches Bitcoin's double SHA-256 approach but uses SHA3-256 for post-quantum security
uint32_t CDataStream::CalculateChecksum(const std::vector<uint8_t>& data) {
    // First SHA3-256 hash
    uint8_t hash1[32];
    SHA3_256(data.data(), data.size(), hash1);

    // Second SHA3-256 hash (hash of hash)
    uint8_t hash2[32];
    SHA3_256(hash1, 32, hash2);

    // Return first 4 bytes as uint32_t (little-endian)
    uint32_t checksum =
        static_cast<uint32_t>(hash2[0]) |
        (static_cast<uint32_t>(hash2[1]) << 8) |
        (static_cast<uint32_t>(hash2[2]) << 16) |
        (static_cast<uint32_t>(hash2[3]) << 24);

    return checksum;
}
