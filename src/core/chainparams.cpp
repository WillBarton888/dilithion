#include "chainparams.h"
#include <util/system.h>

namespace Dilithion {

// Global chain parameters pointer
ChainParams* g_chainParams = nullptr;

ChainParams ChainParams::Mainnet() {
    ChainParams params;
    params.network = MAINNET;

    // Network identification
    // Magic bytes: 0xD1714102 (DIL in hex-ish, plus version)
    // BUGFIX: Was 0xD1711710, but protocol.h had 0xD1714102. Unified to protocol.h value.
    params.networkMagic = 0xD1714102;

    // Chain ID for replay protection (EIP-155 style)
    // Included in transaction signatures to prevent cross-chain replay attacks
    params.chainID = 1;  // Mainnet Chain ID

    // Genesis block parameters
    params.genesisTime = 1736899200;   // January 15, 2026 00:00:00 UTC (v2 genesis)
    params.genesisNonce = 146455;
    params.genesisNBits = 0x1e0fffff;  // Higher difficulty (16x harder) to prevent rapid external mining
    params.genesisHash = "00000b9c54d61c85d570ed7bf97406a3aa40a136c62fa4fa38640d80f4708dfa";
    params.genesisCoinbaseMsg = "Dilithion Mainnet Genesis v2 - 15/Jan/2026 - Post-Quantum Security For The People";

    // Network ports
    params.p2pPort = 8444;             // P2P network port
    params.rpcPort = 8332;             // RPC server port

    // Data directory (use absolute path from utility function)
    params.dataDir = GetDataDir(false);

    // Consensus parameters
    params.blockTime = 240;                // 4 minutes (240 seconds)
    params.halvingInterval = 210000;       // ~1.6 years at 4-minute blocks
    params.difficultyAdjustment = 2016;    // ~5.6 days at 4-minute blocks
    params.maxBlockSize = 4 * 1024 * 1024; // 4 MB (for post-quantum signatures)

    // Mining parameters
    params.initialReward = 50ULL * 100000000ULL; // 50 DIL (in ions: 1 DIL = 100,000,000 ions)

    // MAINNET SECURITY: Never allow minimum difficulty blocks
    // This prevents attackers from gaming timestamps to get easy blocks
    params.fPowAllowMinDifficultyBlocks = false;

    // MAINNET SECURITY: Checkpoints (hardcoded trusted block hashes)
    // These prevent deep chain reorganizations and protect user funds
    //
    // IMPORTANT: After mainnet launch, add checkpoints every ~10,000 blocks:
    //   params.checkpoints.emplace_back(10000, uint256S("0000..."));
    //   params.checkpoints.emplace_back(20000, uint256S("0000..."));
    //
    // For now, only genesis is checkpointed (will be updated after mining)
    // params.checkpoints.emplace_back(0, uint256S(params.genesisHash));

    return params;
}

ChainParams ChainParams::Testnet() {
    ChainParams params;
    params.network = TESTNET;

    // Network identification
    // Different magic bytes to prevent testnet/mainnet cross-contamination
    params.networkMagic = 0xDAB5BFFA;

    // Chain ID for replay protection (EIP-155 style)
    // Different from mainnet to prevent transaction replay between networks
    params.chainID = 1001;  // Testnet Chain ID

    // Genesis block parameters
    // V1.0.14: Increased difficulty 6x (0x1f060000 → 0x1f010000) to match v1.0.13 performance
    // With per-thread RandomX VMs (~600 H/s), this produces ~60 second block times
    params.genesisTime = 1730000000;   // October 27, 2025 (testnet launch)
    params.genesisNonce = 15178;       // Mined on 2025-11-18
    params.genesisNBits = 0x1f010000;  // 6x harder (target=0x010000...)
    params.genesisHash = "0000ee281e9c4a9216ed662146da376ff20fd2b3cc516bc4346cedb2a330e6d3";
    params.genesisCoinbaseMsg = "Dilithion Testnet v1.0.15 - Bug #32 & #33 fixes (mining template + IBD)";

    // Network ports (different from mainnet to allow running both simultaneously)
    params.p2pPort = 18444;            // Testnet P2P port
    params.rpcPort = 18332;            // Testnet RPC port

    // Data directory (use absolute path from utility function - separate from mainnet)
    params.dataDir = GetDataDir(true);

    // Consensus parameters (faster blocks for testnet)
    params.blockTime = 60;                 // 1 minute (4x faster than mainnet for quicker testing)
    params.halvingInterval = 210000;       // Same as mainnet
    params.difficultyAdjustment = 2016;    // Same as mainnet
    params.maxBlockSize = 4 * 1024 * 1024; // 4 MB (same as mainnet)

    // Mining parameters (same as mainnet)
    params.initialReward = 50ULL * 100000000ULL; // 50 DIL (same as mainnet)

    // TESTNET: Allow minimum difficulty blocks for network resilience
    // If no block is found for 2x target time (120s), allow easy difficulty
    // This prevents testnet from getting stuck when miners leave
    // Safe for testnet since coins have no value (would be exploitable on mainnet)
    params.fPowAllowMinDifficultyBlocks = true;

    // TESTNET: Checkpoints for IBD optimization
    // PoW validation is skipped for headers at/before the highest checkpoint
    // This dramatically speeds up Initial Block Download (~100ms -> ~1ms per header)
    // Reorgs can still be tested on blocks AFTER the highest checkpoint
    params.checkpoints.emplace_back(1000, uint256S("0000cb60f4051a278b03a4133a6cefda689a5788a215c6209b160a9be632b5ca"));
    params.checkpoints.emplace_back(2000, uint256S("000099b421f37840b53ec623a201c817a7ea9fcfa48e69e5c3461727fd92282f"));
    params.checkpoints.emplace_back(3000, uint256S("00002c1ca3bbbd9c7dd7b0903873b36724e1ee31c53f70ab7c81123228d9edb4"));

    return params;
}

} // namespace Dilithion
