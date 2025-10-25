// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/block_index.h>
#include <sstream>

CBlockIndex::CBlockIndex() {
    pprev = nullptr;
    pskip = nullptr;
    nHeight = 0;
    nFile = 0;
    nDataPos = 0;
    nUndoPos = 0;
    nChainWork = uint256();
    nTx = 0;
    nStatus = 0;
    nSequenceId = 0;
    nTime = 0;
    nBits = 0;
    nNonce = 0;
    nVersion = 0;
}

CBlockIndex::CBlockIndex(const CBlockHeader& block) {
    pprev = nullptr;
    pskip = nullptr;
    nHeight = 0;
    nFile = 0;
    nDataPos = 0;
    nUndoPos = 0;
    nChainWork = uint256();
    nTx = 0;
    nStatus = 0;
    nSequenceId = 0;
    header = block;
    nTime = block.nTime;
    nBits = block.nBits;
    nNonce = block.nNonce;
    nVersion = block.nVersion;
}

uint256 CBlockIndex::GetBlockHash() const {
    if (phashBlock.IsNull()) {
        phashBlock = header.GetHash();
    }
    return phashBlock;
}

bool CBlockIndex::IsValid() const {
    return (nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_HEADER;
}

bool CBlockIndex::HaveData() const {
    return (nStatus & BLOCK_HAVE_DATA) != 0;
}

std::string CBlockIndex::ToString() const {
    std::stringstream ss;
    ss << "CBlockIndex(hash=" << GetBlockHash().GetHex().substr(0, 20) << "...";
    ss << ", height=" << nHeight << ", nTx=" << nTx << ")";
    return ss.str();
}
