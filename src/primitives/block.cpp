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
    uint256 result;
    // Simple hash: combine all header fields
    // In production, this would use SHA256 or RandomX
    result.data[0] = (uint8_t)(nVersion & 0xFF);
    result.data[1] = (uint8_t)(nTime & 0xFF);
    result.data[2] = (uint8_t)(nBits & 0xFF);
    result.data[3] = (uint8_t)(nNonce & 0xFF);
    
    // Mix in prev block hash
    for (int i = 0; i < 8; i++) {
        result.data[i+4] ^= hashPrevBlock.data[i];
    }
    
    return result;
}
