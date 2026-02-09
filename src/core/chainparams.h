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

    // Testnet-only: Allow minimum difficulty blocks if no block for 2x target time
    // SECURITY: Must be FALSE for mainnet (prevents difficulty gaming attacks)
    // When enabled, if a block takes > 2x target time (e.g., 120s for 60s testnet),
    // miners can submit blocks at minimum difficulty. This prevents testnet from
    // getting stuck when miners leave, but would be exploitable on mainnet.
    bool fPowAllowMinDifficultyBlocks;

    // DFMP (Fair Mining Protocol) activation height
    // Before this height: Standard PoW (no identity penalties)
    // After this height: DFMP active (pending + heat penalties apply)
    // Mainnet: Activate from genesis (0) or early block to establish fair mining
    // Testnet: Activate from genesis (0) for testing
    int dfmpActivationHeight;

    // DFMP Assume-Valid Height (IBD optimization)
    // Blocks at or below this height skip DFMP penalty multiplier verification.
    // PoW and MIK signature are STILL verified - only penalty calculation is skipped.
    // This fixes IBD where in-memory state (identity DB, heat tracker) differs from
    // when blocks were originally mined.
    // Updated with each release as chain grows.
    // 0 = validate everything (no optimization)
    int dfmpAssumeValidHeight;

    // DFMP v3.0 Activation Height
    // Before this height: DFMP v2.0 rules (20-block free tier, 3.0x maturity, no payout heat)
    // After this height: DFMP v3.0 rules (5-block free tier, 5.0x maturity, payout heat, dormancy, registration PoW)
    // This is a consensus-critical change - all nodes must upgrade before this height
    int dfmpV3ActivationHeight;

    // VDF Fair Mining parameters
    // vdfActivationHeight: Hybrid period starts (accept both RandomX and VDF blocks)
    // vdfExclusiveHeight:  VDF-only period (reject RandomX blocks after this)
    // vdfIterations:       Target squarings per VDF round
    // 0 = VDF not active (default for both networks until fork is scheduled)
    int vdfActivationHeight;
    int vdfExclusiveHeight;
    uint64_t vdfIterations;

    // MAINNET SECURITY: Checkpoints to prevent deep reorganizations
    // Testnet: empty (no checkpoint protection, allows testing reorgs)
    // Mainnet: populated after launch, updated with each software release
    std::vector<CCheckpoint> checkpoints;

    // ASSUME-VALID: Skip DFMP penalty validation below this block (Bitcoin Core pattern)
    // This is a performance optimization for IBD - blocks still have PoW verified.
    // Set via --assumevalid CLI parameter or use this default.
    // Empty string = validate everything (no assumevalid optimization)
    // Updated with each software release after mainnet has established blocks.
    std::string defaultAssumeValid;

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
