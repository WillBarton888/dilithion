// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <chainparams.h>
#include <consensus/pow.h>
#include <cstring>
#include <ctime>

static CChainParams mainParams;

CBlock CChainParams::CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, 
                                        uint32_t nBits, int32_t nVersion,
                                        const std::string& message) {
    CBlock genesis;
    genesis.nVersion = nVersion;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    
    // For genesis, previous block hash is all zeros
    memset(genesis.hashPrevBlock.data, 0, 32);
    
    // Simple merkle root from message (in production, would be from coinbase tx)
    // For now, just hash the message
    const char* msg = message.c_str();
    for (size_t i = 0; i < 32 && i < message.length(); i++) {
        genesis.hashMerkleRoot.data[i] = msg[i];
    }
    
    return genesis;
}

CChainParams::CChainParams() {
    // Network magic: "d1l1" (dili)
    pchMessageStart[0] = 0x64; // 'd'
    pchMessageStart[1] = 0x31; // '1'
    pchMessageStart[2] = 0x6c; // 'l'
    pchMessageStart[3] = 0x31; // '1'
    
    // Default port
    nDefaultPort = 8444;
    
    // Bech32 address prefix
    bech32_hrp = "dil";
    
    // Total supply: 21 million DIL (like Bitcoin)
    nTotalSupply = 21000000LL * 100000000LL; // 21M * 1 DIL (8 decimals)
    
    // Initial block reward: 50 DIL
    nInitialBlockReward = 50LL * 100000000LL;
    
    // Halving every 210,000 blocks (~4 years at 10 min blocks)
    nHalvingInterval = 210000;
    
    // Target: 10 minutes per block (600 seconds)
    nTargetTimespan = 600;
    
    // Difficulty adjustment: every 2016 blocks (~2 weeks)
    nDifficultyAdjustmentInterval = 2016;
    
    /**
     * Genesis Block
     * 
     * Message: "Quantum computers threaten ECDSA - Oct 2025"
     * Time: January 1, 2026 00:00:00 UTC (1735689600)
     * Nonce: To be mined
     * Difficulty: 0x1d00ffff (minimum)
     */
    genesis = CreateGenesisBlock(
        1735689600,  // Jan 1, 2026 00:00:00 UTC
        0,           // Nonce (to be found by mining)
        0x1d00ffff,  // Difficulty bits (minimum)
        1,           // Version
        "Quantum computers threaten ECDSA - Oct 2025"
    );
}

const CChainParams& Params() {
    return mainParams;
}

void SelectParams() {
    // Initialize main network parameters
    mainParams = CChainParams();
}
