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
    
    std::string GetHex() const;
    void SetHex(const std::string& str);
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements. When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain. The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CBlockHeader()
    {
        SetNull();
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock = uint256();
        hashMerkleRoot = uint256();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<uint8_t> vtx; // Placeholder for transactions

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
    }
};

#endif // DILITHION_PRIMITIVES_BLOCK_H
