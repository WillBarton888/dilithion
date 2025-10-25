// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_BLOCK_INDEX_H
#define DILITHION_NODE_BLOCK_INDEX_H

#include <primitives/block.h>
#include <cstdint>
#include <string>

class CBlockIndex
{
public:
    CBlockHeader header;
    CBlockIndex* pprev;
    CBlockIndex* pskip;
    int nHeight;
    int nFile;
    unsigned int nDataPos;
    unsigned int nUndoPos;
    uint256 nChainWork;
    unsigned int nTx;
    uint32_t nStatus;
    uint32_t nSequenceId;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;
    int32_t nVersion;
    mutable uint256 phashBlock;

    CBlockIndex();
    explicit CBlockIndex(const CBlockHeader& block);
    uint256 GetBlockHash() const;
    bool IsValid() const;
    bool HaveData() const;
    std::string ToString() const;

    enum BlockStatus : uint32_t {
        BLOCK_VALID_UNKNOWN      = 0,
        BLOCK_VALID_HEADER       = 1,
        BLOCK_VALID_TREE         = 2,
        BLOCK_VALID_TRANSACTIONS = 3,
        BLOCK_VALID_CHAIN        = 4,
        BLOCK_VALID_SCRIPTS      = 5,
        BLOCK_VALID_MASK         = 31,
        BLOCK_HAVE_DATA          = 8,
        BLOCK_HAVE_UNDO          = 16,
    };
};

#endif
