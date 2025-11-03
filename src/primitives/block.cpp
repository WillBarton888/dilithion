// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <primitives/block.h>
#include <crypto/randomx_hash.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ostream>

std::string uint256::GetHex() const {
    std::stringstream ss;
    for (int i = 31; i >= 0; i--) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

void uint256::SetHex(const std::string& str) {
    memset(data, 0, 32);

    if (str.empty()) {
        return;
    }

    // Hex string should be 64 characters (32 bytes * 2 hex chars)
    size_t len = str.length();
    if (len > 64) {
        len = 64;
    }

    // Convert hex string to bytes (big-endian format, stored in reverse for little-endian)
    // GetHex() outputs in reverse order (data[31] first), so SetHex() should match
    for (size_t i = 0; i < len / 2; i++) {
        size_t strPos = len - 2 - (i * 2);  // Start from end of string
        std::string byteStr = str.substr(strPos, 2);
        data[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
    }

    // Handle odd-length strings (shouldn't happen, but be safe)
    if (len % 2 == 1) {
        std::string byteStr = "0" + str.substr(0, 1);
        data[len / 2] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
    }
}

// Stream output operator for Boost.Test
std::ostream& operator<<(std::ostream& os, const uint256& h) {
    return os << h.GetHex();
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

    // RandomX hash (CPU-mining resistant, ASIC-resistant)
    uint256 result;
    randomx_hash_fast(data.data(), data.size(), result.data);

    return result;
}
