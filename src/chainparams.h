// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CHAINPARAMS_H
#define DILITHION_CHAINPARAMS_H

#include <primitives/block.h>
#include <string>

/**
 * Dilithion Chain Parameters
 * 
 * Network configuration for the quantum-resistant "People's Coin"
 */
class CChainParams {
public:
    /** Network magic bytes */
    uint8_t pchMessageStart[4];
    
    /** Default network port */
    uint16_t nDefaultPort;
    
    /** Address prefix (bech32) */
    std::string bech32_hrp;
    
    /** Genesis block */
    CBlock genesis;
    
    /** Total coin supply (satoshis) */
    int64_t nTotalSupply;
    
    /** Initial block reward (satoshis) */
    int64_t nInitialBlockReward;
    
    /** Blocks per halving */
    int nHalvingInterval;
    
    /** Target block time (seconds) */
    int nTargetTimespan;
    
    /** Difficulty adjustment interval (blocks) */
    int nDifficultyAdjustmentInterval;
    
    CChainParams();
    
    /** Create genesis block */
    static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, 
                                     uint32_t nBits, int32_t nVersion,
                                     const std::string& message);
};

/** Get main network parameters */
const CChainParams& Params();

/** Initialize chain parameters */
void SelectParams();

#endif // DILITHION_CHAINPARAMS_H
