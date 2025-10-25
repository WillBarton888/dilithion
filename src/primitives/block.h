// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_PRIMITIVES_BLOCK_H
#define DILITHION_PRIMITIVES_BLOCK_H

#include <cstring>
#include <cstdint>
#include <vector>
#include <string>

/** 256-bit hash */
class uint256 {
public:
    uint8_t data[32];
    
    uint256() { memset(data, 0, 32); }
    
    bool IsNull() const {
        for (int i = 0; i < 32; i++)
            if (data[i] != 0) return false;
        return true;
    }
    
    bool operator<(const uint256& other) const {
        return memcmp(data, other.data, 32) < 0;
    }
    
    bool operator==(const uint256& other) const {
        return memcmp(data, other.data, 32) == 0;
    }
    
    uint8_t* begin() { return data; }
    const uint8_t* begin() const { return data; }
    uint8_t* end() { return data + 32; }
    const uint8_t* end() const { return data + 32; }
    
    std::string GetHex() const;
    void SetHex(const std::string& str);
};

class CBlockHeader {
public:
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CBlockHeader() { SetNull(); }

    void SetNull() {
        nVersion = 0;
        hashPrevBlock = uint256();
        hashMerkleRoot = uint256();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const { return (nBits == 0); }
    uint256 GetHash() const;
};

class CBlock : public CBlockHeader {
public:
    std::vector<uint8_t> vtx;

    CBlock() { SetNull(); }
    CBlock(const CBlockHeader &header) {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    void SetNull() {
        CBlockHeader::SetNull();
        vtx.clear();
    }
};

#endif
