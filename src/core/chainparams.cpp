#include "chainparams.h"
#include "../attestation/seed_pubkeys_testnet.h"
#include "../attestation/seed_pubkeys_mainnet.h"
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
    params.difficultyAdjustment = 2016;    // ~5.6 days at 4-minute blocks (pre-fork)
    params.difficultyAdjustmentV2 = 360;   // ~1 day at 4-minute blocks (post-fork)
    params.difficultyForkHeight = 18500;   // Activate v2 difficulty at this height (moved from 20160 to fix sign bit + EDA interaction)
    params.difficultyMaxChange = 2;        // 2x max change per retarget (post-fork, pre-v3)
    params.difficultyV3ForkHeight = 20520; // v3: 4x clamp + 1-hour EDA threshold (15 blocks)
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
    params.dfmpAssumeValidHeight = 18600;  // Covers blocks affected by v3.4.4 memory stomp crash

    // DFMP v3.0 activation - payout heat tracking, reduced free tier, dormancy decay
    params.dfmpV3ActivationHeight = 7000;
    params.registrationPowBits = 28;  // DIL mainnet: original production value (unchanged)

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

    // DFMP v3.3 - remove dynamic scaling, linear+exponential penalty
    // Dynamic scaling was inflating free tier to 72+ blocks with few miners, negating v3.2
    // v3.3: fixed 12-block free tier, linear ramp to 4.0x at 24, then exponential wall
    params.dfmpV33ActivationHeight = 13500;

    // DFMP v3.4: verification-aware free tier (verified=12, unverified=3)
    params.dfmpV34ActivationHeight = 999999999;  // Disabled until DNA verification matures

    // Compact encoding fix: fixes BigToCompact sign bit bug that caused
    // difficulty to be ~5x harder than intended due to EDA + sign bit compounding.
    // Moved from 20160 to 18500 to stop ongoing chain degradation.
    params.compactEncodingFixHeight = 18500;

    // ASERT difficulty algorithm activation
    // Replaces periodic retarget + EDA with per-block exponential adjustment.
    // Anchor block: height 23039 (the block at activationHeight - 1).
    params.asertActivationHeight = 23040;
    params.asertHalflife = 34560;  // 144 blocks * 240s = 9.6 hours

    // Timestamp validation hard fork: enforce CheckBlockTimestamp in block processing,
    // reduce future time limit from 2h to 10min, re-anchor ASERT at this height.
    params.timestampValidationHeight = 24500;

    // VDF Fair Mining (not yet scheduled for mainnet)
    params.vdfActivationHeight = 999999999;   // Disabled until fork is scheduled
    params.vdfExclusiveHeight  = 999999999;
    params.vdfIterations       = 5'000'000;   // ~44s fast, ~110s slow (fairness via minBlockTime)

    // VDF Distribution: "lowest output wins" (disabled until fork is scheduled)
    params.vdfLotteryActivationHeight = 999999999;
    params.vdfLotteryGracePeriod = 60;  // 60 seconds
    params.vdfMinBlockTime = 180;       // 3 minutes: ensures all miners finish VDF
    params.vdfCooldownActiveWindow = 360; // 360 × 240s ≈ 24 hours
    params.dfmpCooldownConsensusHeight = 999999999; // Disabled (VDF not active on mainnet)
    params.stallExemptionV2Height = 999999999;     // Disabled (VDF not active on mainnet)
    params.consecutiveMinerCheckHeight = 999999999; // Disabled (VDF not active on mainnet)
    params.vdfCooldownShortWindow = 0;               // Disabled (VDF not active on mainnet)
    params.stabilizationForkHeight = 999999999;      // Disabled (VDF not active on mainnet)
    params.mikWindowCapWindow = 0;                   // Disabled (VDF not active on mainnet)
    params.mikWindowCapFloor = 0;
    params.livenessTimeoutSec = 0;
    params.minBlockTimestampGap = 0;                 // Disabled (DIL uses RandomX, not VDF pacing)
    params.minBlockTimestampGapHeight = 0;
    params.coinbaseMaturity = 100;        // Standard PoW safety margin

    // Script V2 (HTLC, multisig, etc.): disabled until fork is scheduled
    params.scriptV2ActivationHeight = 999999999;

    params.digitalDnaActivationHeight = 30000;  // DNA collection + P2P exchange (advisory only, no consensus impact)
    params.dnaCommitmentActivationHeight = 40000;  // DNA mandatory in MIK registration from height 40,000
    params.dnaHashEnforcementHeight = 999999999;       // Disabled until calibration complete
    params.trustWeightedNetworkHeight = 999999999;     // Phase 4: trust-weighted P2P (disabled)
    params.dnaRotationActivationHeight = 999999999;   // Phase 5: DNA rotation penalties (disabled)

    // Seed attestation: residential IP verification for MIK registration
    // Activates at height 40,000 (~11 days from v4.0.0 release)
    // After activation, new MIK registrations require 3-of-4 seed attestations
    // confirming the miner connects from a residential (non-datacenter) IP
    params.seedAttestationActivationHeight = 40000;
    // Same seed servers as DilV — same attestation keys
    params.seedAttestationPubkeys = Attestation::GetMainnetSeedPubkeys();
    params.seedAttestationIPs = {
        "138.197.68.128",   // NYC
        "167.172.56.119",   // London
        "165.22.103.114",   // Singapore
        "134.199.159.83"    // Sydney
    };
    params.seedAttestationRPCPort = 8332;  // DIL mainnet RPC port

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
    // Checkpoint at height 13000
    params.checkpoints.emplace_back(13000, uint256S("000001fe5b08776d2f96e3fca8a30ad4113e8e2d998f800e70b06e73454380c7"));
    // Checkpoint at height 16500 - locks in chain through DFMP v3.3 stabilization
    params.checkpoints.emplace_back(16500, uint256S("000000b37d07c641b2b0e18ff7931300ac76ee083eae2522632b343ee221475f"));
    // Checkpoint at height 18500 - post difficulty fork stabilization
    params.checkpoints.emplace_back(18500, uint256S("0000000c9cbfc8c909156c22b37437183ece80257851d5dc324312497d3f2a37"));
    // Checkpoint at height 23000 - pre-ASERT activation (protects all pre-ASERT history)
    params.checkpoints.emplace_back(23000, uint256S("00000a5bbef0e203c6b013976bbe4a3afc401975d5d4405298691d6620f47fa6"));
    // Checkpoint at height 24476 - covers blocks with stale nBits accepted via fork switch path
    params.checkpoints.emplace_back(24476, uint256S("000007289cc3fdbe88a572d84f974a49fb962eda7412312c28930153ae52d611"));
    // Checkpoint at height 30000 - locks in chain through Digital DNA activation
    params.checkpoints.emplace_back(30000, uint256S("0000000f1cadcbc897976ebe04f1171a5d591ebdb580bdd229d2e310f1a09f05"));
    // Checkpoint at height 34000 - post v3.9.0 stabilization
    params.checkpoints.emplace_back(34000, uint256S("00000009b2312644f10b286934ed982520e92aaa54b2736e46f365a77bd92d98"));

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

    // Genesis block parameters — VDF genesis for MVP testing
    params.genesisTime = 1774656000;   // March 25, 2026 12:00:00 UTC (MVP testnet reset)
    params.genesisNonce = 0;           // VDF blocks don't use nonce
    params.genesisNBits = 0x1d00ffff;  // Fixed — VDF uses lowest-output-wins
    params.genesisHash = "";           // COMPUTED AT STARTUP — will be printed on first run
    params.genesisCoinbaseMsg = "Dilithion Testnet MVP - Fair Mining Reset";

    // Network ports (different from mainnet to allow running both simultaneously)
    params.p2pPort = 18444;            // Testnet P2P port
    params.rpcPort = 18332;            // Testnet RPC port

    // Data directory (use absolute path from utility function - separate from mainnet)
    params.dataDir = GetDataDir(true);

    // Consensus parameters (faster blocks for testnet)
    params.blockTime = 60;                 // 1 minute (4x faster than mainnet for quicker testing)
    params.halvingInterval = 210000;       // Same as mainnet
    params.difficultyAdjustment = 2016;    // Pre-fork (same as mainnet)
    params.difficultyAdjustmentV2 = 360;   // Post-fork: ~6 hours at 1-minute blocks
    params.difficultyForkHeight = 0;       // Active from genesis on testnet
    params.difficultyMaxChange = 2;        // 2x max change per retarget (pre-v3)
    params.difficultyV3ForkHeight = 0;     // v3 active from genesis on testnet
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
    // Skip MIK and penalty validation for historical blocks during IBD.
    // Early testnet blocks were mined before MIK was added to coinbase.
    // Must cover all pre-MIK blocks to allow fresh nodes to sync.
    params.dfmpAssumeValidHeight = 86850;

    // DFMP v3.0 activation - set above existing testnet chain height
    // Testnet tip was ~86,829 when v3.0 was implemented
    // Activation at 87,000 gives ~170 blocks buffer for upgrade
    params.dfmpV3ActivationHeight = 87000;
    params.registrationPowBits = 24;  // DIL testnet

    // DFMP Dynamic Scaling - always active on testnet
    params.dfmpDynamicScalingHeight = 0;

    // DFMP v3.1 - always active on testnet (softened parameters)
    params.dfmpV31ActivationHeight = 0;

    // DFMP v3.2 - always active on testnet (tightened anti-whale)
    params.dfmpV32ActivationHeight = 0;

    // DFMP v3.3 - always active on testnet (no dynamic scaling)
    params.dfmpV33ActivationHeight = 0;

    // DFMP v3.4 - disabled on testnet until DNA verification matures
    params.dfmpV34ActivationHeight = 999999999;

    // Compact encoding fix: always active on testnet (no legacy blocks to worry about)
    params.compactEncodingFixHeight = 0;

    // ASERT difficulty algorithm (disabled on testnet for now)
    params.asertActivationHeight = 999999999;
    params.asertHalflife = 8640;  // 144 blocks * 60s = 2.4 hours

    // Timestamp validation: active from genesis on testnet
    params.timestampValidationHeight = 0;

    // VDF Fair Mining — VDF-only from genesis for MVP testing
    params.vdfActivationHeight = 0;
    params.vdfExclusiveHeight  = 0;            // VDF-only from genesis (like DilV)
    params.vdfIterations       = 500000;       // 500K iterations (~4-8s, matches DilV)

    // VDF Distribution: "lowest output wins" — reset MVP testing
    params.vdfLotteryActivationHeight = 0;     // Active from genesis for MVP testing
    params.vdfLotteryGracePeriod = 45;         // 45s grace period (MVP)
    params.vdfMinBlockTime = 0;                // Disabled — grace period controls pacing
    params.vdfCooldownActiveWindow = 1920;     // 1920 × 45s ≈ 24 hours
    params.dfmpCooldownConsensusHeight = 0;    // Consensus-enforced cooldown from genesis
    params.stallExemptionV2Height = 0;         // Tightened stall exemption from genesis
    params.consecutiveMinerCheckHeight = 0;    // Reject >3 consecutive from genesis
    params.vdfCooldownShortWindow = 0;         // Disabled — avoids MIN_COOLDOWN bypass
    params.stabilizationForkHeight = 0;        // Dual-window + time expiry from genesis
    params.mikWindowCapWindow = 480;           // 480 blocks = ~6h at 45s/block (MVP)
    params.mikWindowCapFloor = 24;             // Max 24 blocks per MIK per window (5%)
    params.livenessTimeoutSec = 300;           // 300s liveness escape (MVP)
    params.minBlockTimestampGap = 45;          // Consensus-enforced 45s min gap (MVP)
    params.minBlockTimestampGapHeight = 0;     // Active from genesis on testnet
    params.coinbaseMaturity = 100;        // Standard PoW safety margin

    // Script V2 (HTLC, multisig, etc.): active from genesis on testnet
    params.scriptV2ActivationHeight = 0;

    params.digitalDnaActivationHeight = 1;    // Active from near-genesis for testing
    params.dnaCommitmentActivationHeight = 999999999;  // Disabled until fork is scheduled
    params.dnaHashEnforcementHeight = 999999999;       // Disabled until calibration complete
    params.trustWeightedNetworkHeight = 999999999;     // Phase 4: trust-weighted P2P (disabled)
    params.dnaRotationActivationHeight = 999999999;   // Phase 5: DNA rotation penalties (disabled)

    // Seed attestation: disabled on DIL testnet (DilV-only feature)
    params.seedAttestationActivationHeight = 999999999;
    params.seedAttestationPubkeys = {};
    params.seedAttestationIPs = {};
    params.seedAttestationRPCPort = 0;

    // TESTNET: Checkpoints for IBD optimization
    // PoW validation is skipped for headers at/before the highest checkpoint
    // This dramatically speeds up Initial Block Download (~100ms -> ~1ms per header)
    // Reorgs can still be tested on blocks AFTER the highest checkpoint
    params.checkpoints.emplace_back(1000, uint256S("0000cb60f4051a278b03a4133a6cefda689a5788a215c6209b160a9be632b5ca"));
    params.checkpoints.emplace_back(2000, uint256S("000099b421f37840b53ec623a201c817a7ea9fcfa48e69e5c3461727fd92282f"));
    params.checkpoints.emplace_back(3000, uint256S("00002c1ca3bbbd9c7dd7b0903873b36724e1ee31c53f70ab7c81123228d9edb4"));
    params.checkpoints.emplace_back(5000, uint256S("00000e8e96d5571c22a6dbf934cb50b9c27c513d0bdf86d3539a014b59751643"));
    params.checkpoints.emplace_back(10000, uint256S("0001cb679cfe170ba4893cac1b6a3cb22c69dabe4913927a513761a0ad788e9a"));
    params.checkpoints.emplace_back(20000, uint256S("000adc0c364bed2b4f2247961d852d19d5432b8363e801df24045258a6730b3c"));
    params.checkpoints.emplace_back(40000, uint256S("0007eb5ab7d4a2086d5cc554ce7bbd7866c8ca5791e4ab1cedf631d04803f015"));
    params.checkpoints.emplace_back(60000, uint256S("0003d271d83c1fc66bb2af7cf8f16207034c8f80ec918f119a51ccb4203aadc7"));
    params.checkpoints.emplace_back(80000, uint256S("000a18c94a5bd98403807aff7260c5671079be0d822bdc0815916d8b6fed718e"));
    params.checkpoints.emplace_back(86000, uint256S("00001432d1653a47059b1aa78e71b9cbe69720555cdea55473412d97f74cb3dd"));

    // ASSUME-VALID: Skip DFMP penalty validation below this block
    // Empty = validate everything (populate after testnet has established blocks)
    params.defaultAssumeValid = "";

    return params;
}

ChainParams ChainParams::DilV() {
    ChainParams params;
    params.network = DILV;

    // Network identification
    // Unique magic for DilV chain — prevents cross-chain message contamination
    params.networkMagic = 0xD17FD100;

    // Chain ID for replay protection
    // Different from mainnet (1) and testnet (1001) to prevent cross-chain tx replay
    params.chainID = 2;

    // Genesis block parameters (VDF genesis — pre-computed)
    // Genesis VDF proof computed by dilv-genesis-vdf tool
    params.genesisTime = 1743206400;  // March 29, 2026 00:00:00 UTC (chain reset)
    params.genesisNonce = 0;          // Not used for VDF blocks (nonce is vestigial)
    params.genesisNBits = 0x1d00ffff; // Fixed — VDF uses lowest-output-wins, not hash-under-target
    params.genesisHash = "27b45859879bd329a64dcbe9aa12ac2c0e7b24650955419e6e1192e6111c1464";
    params.genesisCoinbaseMsg = "DilV Reset - Fair Distribution Recovery - March 2026";

    // Network ports (unique to DilV)
    params.p2pPort = 9444;
    params.rpcPort = 9332;

    // Data directory — separate from DIL and testnet
    params.dataDir = GetDataDir(DILV);

    // Consensus parameters
    params.blockTime = 45;                     // ~45-second target block time
    params.halvingInterval = 1050000;          // ~1.5 years at 45s blocks, yields ~210M total supply
    params.difficultyAdjustment = 0;           // Unused — VDF doesn't use difficulty retargeting
    params.difficultyAdjustmentV2 = 0;         // Unused
    params.difficultyForkHeight = 999999999;   // Disabled
    params.difficultyMaxChange = 0;            // Unused
    params.difficultyV3ForkHeight = 999999999; // Disabled
    params.maxBlockSize = 4 * 1024 * 1024;     // 4 MB (same as DIL — room for Dilithium signatures)

    // Mining parameters
    params.initialReward = 100ULL * 100000000ULL; // 100 DilV per block (in volts: 1 DilV = 100,000,000 volts)

    // VDF chain: no RandomX minimum difficulty blocks
    params.fPowAllowMinDifficultyBlocks = false;

    // EDA disabled — not applicable to VDF consensus
    params.edaActivationHeight = -1;

    // DFMP (Fair Mining Protocol) — active from genesis
    // Genesis block itself is exempt (code at chain.cpp:889-890 skips height 0)
    // MIK required from block 1 onward
    params.dfmpActivationHeight = 0;
    params.dfmpAssumeValidHeight = 0;  // Validate everything from start (fresh chain)

    // All DFMP versions active from genesis — use modern rules from day one
    params.dfmpV3ActivationHeight = 0;
    params.registrationPowBits = 28;  // DilV mainnet: ~27 min on consumer hardware (DNA+attestation are primary Sybil defense)
    params.dfmpDynamicScalingHeight = 0;
    params.dfmpV31ActivationHeight = 0;
    params.dfmpV32ActivationHeight = 0;
    params.dfmpV33ActivationHeight = 0;
    params.dfmpV34ActivationHeight = 999999999;  // Disabled until DNA verification matures

    // Compact encoding fix: active from genesis
    params.compactEncodingFixHeight = 0;

    // ASERT: disabled — VDF uses distribution (lowest output wins), not difficulty retargeting
    params.asertActivationHeight = 999999999;
    params.asertHalflife = 0;  // Unused

    // Timestamp validation: active from genesis
    params.timestampValidationHeight = 0;

    // VDF: active from genesis — DilV is a VDF-only chain
    params.vdfActivationHeight = 0;
    params.vdfExclusiveHeight  = 0;            // No RandomX blocks ever accepted
    params.vdfIterations       = 500000;       // 500K iterations (~4-8s compute time)

    // VDF Distribution: active from genesis
    params.vdfLotteryActivationHeight = 0;
    params.vdfLotteryGracePeriod = 45;         // 45 seconds — collection window for all miners' VDF outputs
    params.vdfMinBlockTime = 0;                // Disabled — grace period controls pacing now
    params.vdfCooldownActiveWindow = 1920;     // 1920 × 45s ≈ 24 hours
    params.dfmpCooldownConsensusHeight = 0;    // Consensus-enforced cooldown from genesis
    params.stallExemptionV2Height = 0;         // Tightened stall exemption from genesis
    params.consecutiveMinerCheckHeight = 0;    // Reject >3 consecutive blocks from same miner from genesis
    params.vdfCooldownShortWindow = 0;         // Disabled at genesis — avoids short-window MIN_COOLDOWN bypass
    params.stabilizationForkHeight = 0;        // Dual-window cooldown + time-based expiry from genesis

    // Per-MIK window cap + liveness escape
    params.mikWindowCapWindow = 480;           // 480 blocks = ~6 hours at 45s/block
    params.mikWindowCapFloor = 24;             // Max 24 blocks per MIK per 480-block window (5%)
    params.livenessTimeoutSec = 300;           // 300s = ~6.7× target; suspends cap during stalls

    // Minimum block timestamp gap (consensus-enforced block pacing)
    params.minBlockTimestampGap = 45;          // block.nTime >= prevBlock.nTime + 45
    params.minBlockTimestampGapHeight = 37000; // Activate after existing chain (pre-deploy blocks had <45s gaps)

    params.coinbaseMaturity = 6;               // VDF is sequential/deterministic — reorgs near-impossible

    // Script V2 (HTLC, multisig, etc.): active from genesis on DilV
    params.scriptV2ActivationHeight = 0;

    // Digital DNA: active from genesis
    params.digitalDnaActivationHeight = 0;
    params.dnaCommitmentActivationHeight = 0;           // Active from genesis
    params.dnaHashEnforcementHeight = 999999999;       // Disabled until calibration complete
    params.trustWeightedNetworkHeight = 999999999;     // Phase 4: trust-weighted P2P (disabled)
    params.dnaRotationActivationHeight = 999999999;   // Phase 5: DNA rotation penalties (disabled)

    // Seed-attested MIK registration (Phase 2+3)
    // Disabled until seed nodes generate their keys and pubkeys are hardcoded here.
    // Activation height will be set once all seeds have keys deployed.
    params.seedAttestationActivationHeight = 0;   // Active from genesis — fair mining from block 1

    // Seed attestation public keys (mainnet — extracted from seed nodes)
    params.seedAttestationPubkeys = Attestation::GetMainnetSeedPubkeys();

    // Seed node IPs for attestation requests (DilV mainnet seeds)
    params.seedAttestationIPs = {
        "138.197.68.128",   // NYC
        "167.172.56.119",   // London
        "165.22.103.114",   // Singapore
        "134.199.159.83"    // Sydney
    };
    params.seedAttestationRPCPort = 9332;  // DilV mainnet RPC port

    // DilV Checkpoints (cleared for chain reset)
    // New checkpoints will be added after the reset chain stabilizes.

    // No assume-valid yet
    params.defaultAssumeValid = "";

    // =========================================================================
    // Pre-funded addresses: balance restoration from chain reset
    // Generated by chain_forensics.py at height 36202 (2026-03-27)
    // 146 legitimate addresses + bridge backing for 297,987 wDILV
    // Exploiter addresses (9,389) excluded via transaction graph analysis
    // =========================================================================
    #include "dilv_prefund.inc"

    return params;
}

} // namespace Dilithion
