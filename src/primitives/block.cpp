// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <primitives/block.h>
#include <crypto/randomx_hash.h>
#include <crypto/sha3.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ostream>
#include <iostream>

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
    // IBD OPTIMIZATION: Return cached hash if available
    // This makes subsequent GetHash() calls instant instead of 50-100ms
    if (fHashCached) {
        return cachedHash;
    }

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

    // DEBUG: Log serialized data for height 5547 (nNonce=96937)
    if (nNonce == 96937) {
        std::cerr << "[HASH-DEBUG] nNonce=96937 (height 5547) serialized data first 16 bytes: ";
        for (size_t i = 0; i < 16 && i < data.size(); i++) {
            std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        }
        std::cerr << std::dec << std::endl;
    }

    // RandomX hash (CPU-mining resistant, ASIC-resistant)
    uint256 result;
    randomx_hash_fast(data.data(), data.size(), result.data);

    // DEBUG: Log result for height 5547
    if (nNonce == 96937) {
        std::cerr << "[HASH-DEBUG] nNonce=96937 result=" << result.GetHex().substr(0, 16) << "..." << std::endl;
    }

    // Cache the result
    cachedHash = result;
    fHashCached = true;

    return result;
}

uint256 CBlockHeader::GetFastHash() const {
    // Fast SHA3-256 hash for header identification (NOT for PoW)
    // This is ~10000x faster than RandomX, used for:
    // - Map lookups in headers manager
    // - Duplicate detection
    // - Peer state tracking
    // - Any non-PoW identification

    // Serialize header (same as GetHash)
    std::vector<uint8_t> data;
    data.reserve(80);

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

    // SHA3-256 (fast, quantum-resistant)
    uint256 result;
    SHA3_256(data.data(), data.size(), result.data);

    return result;
}
