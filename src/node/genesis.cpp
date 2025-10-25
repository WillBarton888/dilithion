// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/genesis.h>
#include <crypto/randomx_hash.h>
#include <crypto/sha3.h>

#include <cstring>
#include <iostream>

namespace Genesis {

const char* COINBASE_MESSAGE =
    "The Guardian 01/Jan/2026: Quantum computing advances threaten cryptocurrency security - "
    "Dilithion launches with post-quantum protection for The People's Coin";

CBlock CreateGenesisBlock() {
    CBlock genesis;

    // Set header fields
    genesis.nVersion = VERSION;
    genesis.hashPrevBlock = uint256();  // All zeros (no previous block)
    genesis.nTime = TIMESTAMP;
    genesis.nBits = NBITS;
    genesis.nNonce = NONCE;

    // Create coinbase message
    // Store the message in the block's transaction data
    const char* msg = COINBASE_MESSAGE;
    size_t msgLen = strlen(msg);
    genesis.vtx.resize(msgLen);
    memcpy(genesis.vtx.data(), msg, msgLen);

    // Calculate merkle root (hash of coinbase message)
    // For simplicity, we just hash the transaction data
    uint8_t hash[32];
    SHA3_256(genesis.vtx.data(), genesis.vtx.size(), hash);
    memcpy(genesis.hashMerkleRoot.data, hash, 32);

    return genesis;
}

uint256 GetGenesisHash() {
    static uint256 hash;
    static bool initialized = false;

    if (!initialized) {
        CBlock genesis = CreateGenesisBlock();
        hash = genesis.GetHash();
        initialized = true;
    }

    return hash;
}

bool IsGenesisBlock(const CBlock& block) {
    // Check all genesis block fields
    if (block.nVersion != VERSION) return false;
    if (!block.hashPrevBlock.IsNull()) return false;
    if (block.nTime != TIMESTAMP) return false;
    if (block.nBits != NBITS) return false;

    // Check merkle root matches expected
    CBlock genesis = CreateGenesisBlock();
    if (!(block.hashMerkleRoot == genesis.hashMerkleRoot)) return false;

    return true;
}

bool MineGenesisBlock(CBlock& block, const uint256& target) {
    std::cout << "Mining genesis block..." << std::endl;
    std::cout << "Target: " << target.GetHex() << std::endl;
    std::cout << "This may take a while..." << std::endl;

    uint64_t nHashesTried = 0;
    const uint64_t REPORT_INTERVAL = 10000;

    // Try different nonces until we find one that meets the target
    for (uint32_t nonce = 0; nonce < 0xFFFFFFFF; ++nonce) {
        block.nNonce = nonce;

        // Calculate hash
        uint256 hash = block.GetHash();

        // Check if hash is less than target
        if (hash < target) {
            std::cout << "\nGenesis block found!" << std::endl;
            std::cout << "Nonce: " << nonce << std::endl;
            std::cout << "Hash: " << hash.GetHex() << std::endl;
            std::cout << "Hashes tried: " << nHashesTried << std::endl;
            return true;
        }

        nHashesTried++;

        // Report progress
        if (nHashesTried % REPORT_INTERVAL == 0) {
            std::cout << "\rHashes: " << nHashesTried << std::flush;
        }
    }

    std::cout << "\nFailed to find valid nonce" << std::endl;
    return false;
}

} // namespace Genesis
