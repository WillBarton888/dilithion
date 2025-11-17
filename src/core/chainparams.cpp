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
    params.genesisTime = 1767225600;   // January 1, 2026 00:00:00 UTC
    params.genesisNonce = 0;           // TO BE UPDATED after mining
    params.genesisNBits = 0x1e00ffff;  // RandomX-appropriate difficulty (~9 hours solo with good CPU)
    params.genesisHash = "";           // TO BE UPDATED after mining
    params.genesisCoinbaseMsg = "The Guardian 01/Jan/2026: Quantum computing advances threaten cryptocurrency security - Dilithion launches with post-quantum protection for The People's Coin";

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
    params.genesisTime = 1730000000;   // October 27, 2025 (testnet launch)
    params.genesisNonce = 28661;       // Mined with Bug #4 fix (proper tx serialization), FULL RandomX mode
    params.genesisNBits = 0x1f060000;  // TEST: target=0x060000...
    params.genesisHash = "00022c79303274086852c750c509908aa01dfefb810d25b42b7fad720a897f14";
    params.genesisCoinbaseMsg = "Dilithion Testnet Genesis - Testing post-quantum cryptocurrency before mainnet launch";

    // Network ports (different from mainnet to allow running both simultaneously)
    params.p2pPort = 18444;            // Testnet P2P port
    params.rpcPort = 18332;            // Testnet RPC port

    // Data directory (use absolute path from utility function - separate from mainnet)
    params.dataDir = GetDataDir(true);

    // Consensus parameters (same as mainnet for realistic testing)
    params.blockTime = 240;                // 4 minutes (same as mainnet)
    params.halvingInterval = 210000;       // Same as mainnet
    params.difficultyAdjustment = 2016;    // Same as mainnet
    params.maxBlockSize = 4 * 1024 * 1024; // 4 MB (same as mainnet)

    // Mining parameters (same as mainnet)
    params.initialReward = 50ULL * 100000000ULL; // 50 DIL (same as mainnet)

    return params;
}

} // namespace Dilithion
