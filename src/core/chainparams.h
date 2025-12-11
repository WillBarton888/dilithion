#ifndef DILITHION_CHAINPARAMS_H
#define DILITHION_CHAINPARAMS_H

#include <cstdint>
#include <string>
#include <vector>
#include <uint256.h>

namespace Dilithion {

enum Network {
    MAINNET,
    TESTNET
};

/**
 * MAINNET SECURITY: Blockchain Checkpoint
 *
 * Checkpoints are hardcoded trusted block hashes that:
 * 1. Prevent deep chain reorganizations (51% attack protection)
 * 2. Speed up initial block download (skip signature verification before checkpoint)
 * 3. Protect users - coins received in old blocks are safe from reorgs
 *
 * Testnet: No checkpoints (allows testing reorgs)
 * Mainnet: Populated after launch, updated with each release
 */
struct CCheckpoint {
    int nHeight;
    uint256 hashBlock;

    CCheckpoint(int height, const uint256& hash)
        : nHeight(height), hashBlock(hash) {}
};

class ChainParams {
public:
    Network network;

    // Network identification
    uint32_t networkMagic;          // Message start bytes for P2P protocol
    uint32_t chainID;               // Chain ID for replay protection (included in tx signatures)

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

    // MAINNET SECURITY: Checkpoints to prevent deep reorganizations
    // Testnet: empty (no checkpoint protection, allows testing reorgs)
    // Mainnet: populated after launch, updated with each software release
    std::vector<CCheckpoint> checkpoints;

    // Factory methods
    static ChainParams Mainnet();
    static ChainParams Testnet();

    // Helper methods
    const char* GetNetworkName() const {
        return network == MAINNET ? "mainnet" : "testnet";
    }

    bool IsMainnet() const { return network == MAINNET; }
    bool IsTestnet() const { return network == TESTNET; }

    /**
     * MAINNET SECURITY: Get the last checkpoint at or before given height
     *
     * Used during chain reorganization to reject reorgs that would
     * disconnect blocks before the last checkpoint.
     *
     * @param height Current chain height
     * @return Pointer to last checkpoint before height, or nullptr if none
     */
    const CCheckpoint* GetLastCheckpoint(int height) const {
        // Find highest checkpoint at or below given height
        const CCheckpoint* result = nullptr;
        for (const auto& cp : checkpoints) {
            if (cp.nHeight <= height) {
                if (!result || cp.nHeight > result->nHeight) {
                    result = &cp;
                }
            }
        }
        return result;
    }

    /**
     * Check if a block hash matches a checkpoint at the given height
     *
     * @param height Block height
     * @param hash Block hash
     * @return true if no checkpoint at height, or if hash matches checkpoint
     */
    bool CheckpointCheck(int height, const uint256& hash) const {
        for (const auto& cp : checkpoints) {
            if (cp.nHeight == height) {
                return cp.hashBlock == hash;
            }
        }
        return true;  // No checkpoint at this height
    }

    /**
     * Get the height of the highest checkpoint
     *
     * Used by HeadersManager to skip PoW validation for headers at/before this height.
     * This dramatically speeds up IBD by skipping expensive RandomX validation for
     * headers that are protected by checkpoints.
     *
     * @return Highest checkpoint height, or -1 if no checkpoints
     */
    int GetHighestCheckpointHeight() const {
        int highest = -1;
        for (const auto& cp : checkpoints) {
            if (cp.nHeight > highest) {
                highest = cp.nHeight;
            }
        }
        return highest;
    }
};

// Global chain parameters (initialized at startup)
extern ChainParams* g_chainParams;

} // namespace Dilithion

#endif // DILITHION_CHAINPARAMS_H
