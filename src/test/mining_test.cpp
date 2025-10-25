// Copyright (c) 2025 The Dilithion Core developers
// Simple mining test program

#include <primitives/block.h>
#include <consensus/pow.h>
#include <chainparams.h>
#include <crypto/randomx_hash.h>
#include <iostream>
#include <ctime>

int main() {
    std::cout << "=== Dilithion Mining Test ===" << std::endl;
    std::cout << std::endl;
    
    // Initialize chain parameters
    SelectParams();
    const CChainParams& params = Params();
    
    std::cout << "Network: Dilithion Mainnet" << std::endl;
    std::cout << "Port: " << params.nDefaultPort << std::endl;
    std::cout << "Address prefix: " << params.bech32_hrp << std::endl;
    std::cout << "Total supply: " << params.nTotalSupply / 100000000LL << " DIL" << std::endl;
    std::cout << "Block reward: " << params.nInitialBlockReward / 100000000LL << " DIL" << std::endl;
    std::cout << "Target block time: " << params.nTargetTimespan << " seconds" << std::endl;
    std::cout << std::endl;
    
    // Initialize RandomX
    std::cout << "Initializing RandomX..." << std::endl;
    const char* rx_key = "Dilithion-RandomX-v1";
    randomx_init_cache(rx_key, strlen(rx_key));
    std::cout << "RandomX initialized!" << std::endl;
    std::cout << std::endl;
    
    // Get genesis block
    CBlock genesis = params.genesis;
    
    std::cout << "=== Mining Genesis Block ===" << std::endl;
    std::cout << "Message: Quantum computers threaten ECDSA - Oct 2025" << std::endl;
    std::cout << "Difficulty: 0x" << std::hex << genesis.nBits << std::dec << std::endl;
    std::cout << "Target time: " << genesis.nTime << " (Jan 1, 2026)" << std::endl;
    std::cout << std::endl;
    
    // Mine the genesis block
    std::cout << "Mining..." << std::endl;
    uint64_t nHashesDone = 0;
    time_t start_time = time(nullptr);
    
    for (uint32_t nonce = 0; nonce < UINT32_MAX; nonce++) {
        genesis.nNonce = nonce;
        uint256 hash = genesis.GetHash();
        nHashesDone++;
        
        // Check if we found a valid block
        if (CheckProofOfWork(hash, genesis.nBits)) {
            time_t end_time = time(nullptr);
            double elapsed = difftime(end_time, start_time);
            
            std::cout << std::endl;
            std::cout << "=== BLOCK FOUND! ===" << std::endl;
            std::cout << "Nonce: " << nonce << std::endl;
            std::cout << "Hash: " << hash.GetHex() << std::endl;
            std::cout << "Hashes: " << nHashesDone << std::endl;
            std::cout << "Time: " << elapsed << " seconds" << std::endl;
            std::cout << "Hashrate: " << (nHashesDone / elapsed) << " H/s" << std::endl;
            break;
        }
        
        // Progress update every 10000 hashes
        if (nonce % 10000 == 0 && nonce > 0) {
            time_t current = time(nullptr);
            double elapsed = difftime(current, start_time);
            if (elapsed > 0) {
                std::cout << "  Hashes: " << nHashesDone 
                         << " (" << (nHashesDone / elapsed) << " H/s)" 
                         << "\r" << std::flush;
            }
        }
    }
    
    // Cleanup
    randomx_cleanup();
    
    std::cout << std::endl;
    std::cout << "Mining test complete!" << std::endl;
    return 0;
}
