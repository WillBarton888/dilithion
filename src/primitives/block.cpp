// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <primitives/block.h>
#include <sstream>
#include <iomanip>
#include <cstring>

std::string uint256::GetHex() const {
    std::stringstream ss;
    for (int i = 31; i >= 0; i--) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

void uint256::SetHex(const std::string& str) {
    memset(data, 0, 32);
    // Simple implementation - just set first byte from string
    if (!str.empty()) {
        data[0] = std::stoi(str.substr(0, 2), nullptr, 16);
    }
}

uint256 CBlockHeader::GetHash() const {
    // Serialize header for hashing
    std::vector<uint8_t> data;
    data.reserve(80); // Standard block header size

    // Serialize: version (4) + prevBlock (32) + merkleRoot (32) + time (4) + bits (4) + nonce (4) = 80 bytes
    const uint8_t* versionBytes = reinterpret_cast<const uint8_t*>(&nVersion);
    data.insert(data.end(), versionBytes, versionBytes + 4);
    data.insert(data.end(), hashPrevBlock.begin(), hashPrevBlock.end());
    data.insert(data.end(), hashMerkleRoot.begin(), hashMerkleRoot.end());
    const uint8_t* timeBytes = reinterpret_cast<const uint8_t*>(&nTime);
    data.insert(data.end(), timeBytes, timeBytes + 4);
    const uint8_t* bitsBytes = reinterpret_cast<const uint8_t*>(&nBits);
    data.insert(data.end(), bitsBytes, bitsBytes + 4);
    const uint8_t* nonceBytes = reinterpret_cast<const uint8_t*>(&nNonce);
    data.insert(data.end(), nonceBytes, nonceBytes + 4);

    // SHA-3-256 hash (quantum-resistant)
    uint256 result;
    extern void SHA3_256(const uint8_t* data, size_t len, uint8_t hash[32]);
    SHA3_256(data.data(), data.size(), result.data);

    return result;
}
