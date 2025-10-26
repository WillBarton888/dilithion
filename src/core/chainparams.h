#ifndef DILITHION_CHAINPARAMS_H
#define DILITHION_CHAINPARAMS_H

#include <cstdint>
#include <string>

namespace Dilithion {

enum Network {
    MAINNET,
    TESTNET
};

class ChainParams {
public:
    Network network;

    // Network identification
    uint32_t networkMagic;          // Message start bytes for P2P protocol

    // Genesis block parameters
    uint32_t genesisTime;           // Genesis block timestamp
    uint32_t genesisNonce;          // Genesis block nonce (0 = not mined yet)
    uint32_t genesisNBits;          // Genesis block difficulty target
    std::string genesisHash;        // Genesis block hash (empty = not mined yet)
    std::string genesisCoinbaseMsg; // Genesis coinbase message

    // Network ports
    uint16_t p2pPort;               // Peer-to-peer network port
    uint16_t rpcPort;               // RPC server port

    // Data directory
    std::string dataDir;            // Default data directory name

    // Consensus parameters
    uint32_t blockTime;             // Target seconds per block
    uint64_t halvingInterval;       // Blocks between reward halvings
    uint64_t difficultyAdjustment;  // Blocks between difficulty adjustments
    uint32_t maxBlockSize;          // Maximum block size in bytes

    // Mining parameters
    uint64_t initialReward;         // Initial block reward in ions (1 DIL = 100,000,000 ions)

    // Factory methods
    static ChainParams Mainnet();
    static ChainParams Testnet();

    // Helper methods
    const char* GetNetworkName() const {
        return network == MAINNET ? "mainnet" : "testnet";
    }

    bool IsMainnet() const { return network == MAINNET; }
    bool IsTestnet() const { return network == TESTNET; }
};

// Global chain parameters (initialized at startup)
extern ChainParams* g_chainParams;

} // namespace Dilithion

#endif // DILITHION_CHAINPARAMS_H
