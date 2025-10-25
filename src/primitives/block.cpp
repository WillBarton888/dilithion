// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <primitives/block.h>
#include <crypto/randomx_hash.h>
#include <cstring>
#include <sstream>
#include <iomanip>

std::string uint256::GetHex() const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 31; i >= 0; i--) {
        ss << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

void uint256::SetHex(const std::string& str) {
    memset(data, 0, 32);
    // Simple hex parsing (reverse byte order for little-endian)
    for (size_t i = 0; i < str.length() && i < 64; i += 2) {
        int byte_pos = 31 - (i / 2);
        unsigned int byte_val;
        sscanf(str.substr(i, 2).c_str(), "%x", &byte_val);
        data[byte_pos] = static_cast<uint8_t>(byte_val);
    }
}

uint256 CBlockHeader::GetHash() const
{
    uint256 result;
    
    // Serialize block header for hashing
    std::vector<uint8_t> header_data;
    header_data.resize(80); // 4+32+32+4+4+4 = 80 bytes
    
    uint8_t* ptr = header_data.data();
    
    // nVersion (4 bytes)
    memcpy(ptr, &nVersion, 4);
    ptr += 4;
    
    // hashPrevBlock (32 bytes)
    memcpy(ptr, hashPrevBlock.data, 32);
    ptr += 32;
    
    // hashMerkleRoot (32 bytes)
    memcpy(ptr, hashMerkleRoot.data, 32);
    ptr += 32;
    
    // nTime (4 bytes)
    memcpy(ptr, &nTime, 4);
    ptr += 4;
    
    // nBits (4 bytes)
    memcpy(ptr, &nBits, 4);
    ptr += 4;
    
    // nNonce (4 bytes)
    memcpy(ptr, &nNonce, 4);
    
    // Hash with RandomX
    // For genesis block and initial blocks, use a simple key
    const char* randomx_key = "Dilithion-RandomX-v1";
    randomx_hash(header_data.data(), header_data.size(), 
                 result.data, randomx_key, strlen(randomx_key));
    
    return result;
}
