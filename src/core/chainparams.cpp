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
    // v2.0.0 genesis - complete mainnet reset (January 18, 2026)
    params.genesisTime = 1737158400;   // January 18, 2026 00:00:00 UTC (v2.0.0 genesis)
    params.genesisNonce = 429612875;   // MINED
    params.genesisNBits = 0x1e01fffe;  // 128x harder than original (50% reduction from 0x1e00ffff)
    params.genesisHash = "0000009eaa5e7781ba6d14525c3f75c35444045b21ddafbbea61090db99b0bc3";  // MINED
    params.genesisCoinbaseMsg = "Dilithion Mainnet v2.0.0 - Fair Launch Reset - Quantum-Resistant Digital Gold";

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

    // Emergency Difficulty Adjustment: activate at block 7034
    // Mainnet stuck at 7033 due to hashrate drop - EDA prevents death spiral
    params.edaActivationHeight = 7034;

    // DFMP (Fair Mining Protocol) activation
    // Active from genesis to establish fair mining from the start
    // This prevents early mining dominance before DFMP can take effect
    params.dfmpActivationHeight = 0;

    // DFMP Assume-Valid Height (IBD fix)
    // Skip DFMP penalty validation for blocks at or below this height.
    // PoW and MIK signature verification skipped for historical blocks during IBD.
    // This fixes IBD where identity database is empty/incomplete.
    // NOTE: Chain built with MIK bypassed - cannot be removed, only raised
    params.dfmpAssumeValidHeight = 1000;

    // DFMP v3.0 activation - payout heat tracking, reduced free tier, dormancy decay
    params.dfmpV3ActivationHeight = 7000;

    // DFMP Dynamic Scaling - free tier scales by active miner count
    // Prevents penalty spiral with few miners (e.g., 3 miners sharing 360-block window)
    params.dfmpDynamicScalingHeight = 7100;

    // DFMP v3.1 - emergency parameter softening (network stalling at v3.0 parameters)
    // Reduces: free tier 12→36, growth 1.58x→1.08x, maturity 5.0x→2.0x
    params.dfmpV31ActivationHeight = 7168;

    // DFMP v3.2 - tightened anti-whale (community feedback: whales accumulating 50-60k coins)
    // Returns to v3.0 heat: free tier 36→12, growth 1.08x→1.58x, cliff 1.5x→2.0x
    // Moderate maturity: 2.5x over 500 blocks (softer than v3.0's 5.0x/800)
    params.dfmpV32ActivationHeight = 13250;

    // VDF Fair Mining (not yet scheduled for mainnet)
    params.vdfActivationHeight = 999999999;   // Disabled until fork is scheduled
    params.vdfExclusiveHeight  = 999999999;
    params.vdfIterations       = 200'000'000; // ~200s on reference hardware

    // MAINNET SECURITY: Checkpoints (hardcoded trusted block hashes)
    // These prevent deep chain reorganizations and protect user funds
    //
    // IMPORTANT: After mainnet launch, add checkpoints every ~10,000 blocks:
    //   params.checkpoints.emplace_back(10000, uint256S("0000..."));
    //   params.checkpoints.emplace_back(20000, uint256S("0000..."));
    //
    // Checkpoint at height 1000 - locks in chain before DFMP enforcement
    params.checkpoints.emplace_back(1000, uint256S("000000006c282edbcc0f2eee5b0f8c8feb62c73d3787137037e589db99cab59f"));
    // Checkpoint at height 2000 - locks in chain through difficulty adjustment period
    params.checkpoints.emplace_back(2000, uint256S("0000002c86158454f79a22a31dcabcaca7861f7e95e98275439dd66f4f9e8b4d"));
    // Checkpoint at height 5000 - locks in chain past fork recovery fixes
    params.checkpoints.emplace_back(5000, uint256S("00000152698282228ce368858d4070bc9da937ff2ed5c6276adf45dd9d299ee9"));
    // Checkpoint at height 10000
    params.checkpoints.emplace_back(10000, uint256S("000032dc7d684254b446b7568ec895b3279e1230d5a6b6a42e5552e1d45f8402"));
    // Checkpoint at height 11000
    params.checkpoints.emplace_back(11000, uint256S("000009628d3af9adef443ee681d19e4ff7c9d8f56a0b05acce8f55e43f88a6cf"));

    // ASSUME-VALID: Skip DFMP penalty validation below this block
    // Empty = validate everything (populate after mainnet has established blocks)
    params.defaultAssumeValid = "";

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
    // NOTE: Superseded by EDA which handles this at the consensus level
    params.fPowAllowMinDifficultyBlocks = true;

    // Emergency Difficulty Adjustment: always active on testnet
    params.edaActivationHeight = 0;

    // DFMP (Fair Mining Protocol) activation
    // Active from genesis for testing fair mining protocol
    params.dfmpActivationHeight = 0;

    // DFMP Assume-Valid Height (IBD optimization)
    // Testnet: 0 = validate everything (testnet has different consensus testing needs)
    params.dfmpAssumeValidHeight = 0;

    // DFMP v3.0 activation - set above existing testnet chain height
    // Testnet tip was ~86,829 when v3.0 was implemented
    // Activation at 87,000 gives ~170 blocks buffer for upgrade
    params.dfmpV3ActivationHeight = 87000;

    // DFMP Dynamic Scaling - always active on testnet
    params.dfmpDynamicScalingHeight = 0;

    // DFMP v3.1 - always active on testnet (softened parameters)
    params.dfmpV31ActivationHeight = 0;

    // DFMP v3.2 - always active on testnet (tightened anti-whale)
    params.dfmpV32ActivationHeight = 0;

    // VDF Fair Mining (testnet activation)
    params.vdfActivationHeight = 86850;       // Hybrid period: VDF + RandomX both accepted
    params.vdfExclusiveHeight  = 87500;       // VDF-only after this height
    params.vdfIterations       = 10'000'000;  // ~10s on reference hardware (faster for testing)

    // TESTNET: Checkpoints for IBD optimization
    // PoW validation is skipped for headers at/before the highest checkpoint
    // This dramatically speeds up Initial Block Download (~100ms -> ~1ms per header)
    // Reorgs can still be tested on blocks AFTER the highest checkpoint
    params.checkpoints.emplace_back(1000, uint256S("0000cb60f4051a278b03a4133a6cefda689a5788a215c6209b160a9be632b5ca"));
    params.checkpoints.emplace_back(2000, uint256S("000099b421f37840b53ec623a201c817a7ea9fcfa48e69e5c3461727fd92282f"));
    params.checkpoints.emplace_back(3000, uint256S("00002c1ca3bbbd9c7dd7b0903873b36724e1ee31c53f70ab7c81123228d9edb4"));

    // ASSUME-VALID: Skip DFMP penalty validation below this block
    // Empty = validate everything (populate after testnet has established blocks)
    params.defaultAssumeValid = "";

    return params;
}

} // namespace Dilithion
