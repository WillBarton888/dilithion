// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DFMP_H
#define DILITHION_DFMP_H

/**
 * Dilithion Fair Mining Protocol (DFMP) v3.0
 *
 * Creates diminishing returns for concentrated mining power through:
 * 1. Identity-based tracking (derived from coinbase scriptPubKey)
 * 2. First-block grace: New identities get ONE block at 1× to establish identity
 * 3. Pending penalty: After first block, 5× → 1× decay over 500 blocks
 * 4. Heat-based penalty for prolific miners (quadratic scaling)
 *
 * See: docs/specs/DILITHION-FAIR-MINING-PROTOCOL-SPEC.md
 */

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <cstdint>
#include <vector>
#include <deque>
#include <map>
#include <mutex>
#include <string>

namespace DFMP {

// ============================================================================
// PROTOCOL CONSTANTS (v3.0)
// ============================================================================
// v2.0 uses Mining Identity Key (MIK) for persistent identity tracking
// and updated penalty parameters. See mik.h for full v2.0 spec.

/** Number of blocks in the observation window for heat calculation (v2.0: 360 blocks = ~24 hours) */
constexpr int OBSERVATION_WINDOW = 360;

/** Number of free blocks before heat penalty applies (v3.0: 12 blocks ~3.3%) */
constexpr int FREE_TIER_THRESHOLD = 12;

/** Number of blocks for maturity penalty to fully decay (v2.0: 400 blocks) */
constexpr int MATURITY_BLOCKS = 800;

/** Starting maturity penalty multiplier for new identities (v2.0: 3.0x, no first-block grace) */
constexpr double PENDING_PENALTY_START = 5.0;

/** Ending maturity penalty multiplier (mature identity) */
constexpr double PENDING_PENALTY_END = 1.0;

/** v3.0: Cliff penalty at FREE_TIER_THRESHOLD + 1 (2.0x immediate jump) */
constexpr double HEAT_CLIFF_PENALTY = 2.0;

/** v3.0: Exponential growth rate per block above free tier (1.58x per block) */
constexpr double HEAT_GROWTH_RATE = 1.58;

// Legacy v1.3 constants (kept for reference, no longer used)
// constexpr double HEAT_COEFFICIENT = 0.046;
// constexpr double HEAT_EXPONENT = 2.0;

// Fixed-point scale for deterministic integer arithmetic
// All multipliers are stored as (value * FP_SCALE)
constexpr int64_t FP_SCALE = 1000000;

// Fixed-point versions of v2.0 constants
constexpr int64_t FP_PENDING_START = 5000000;   // 5.0 × 1,000,000 (v3.0 maturity start)
constexpr int64_t FP_PENDING_END = 1000000;     // 1.0 × 1,000,000
constexpr int64_t FP_HEAT_CLIFF = 2000000;      // 2.0 × 1,000,000 (cliff at free tier + 1)
constexpr int64_t FP_HEAT_GROWTH = 158;          // 1.58x per block (multiply by 158, divide by 100)

// DFMP v3.0: Dormancy decay constants
constexpr int DORMANCY_THRESHOLD = 720;           // Blocks of inactivity before maturity resets
constexpr int DORMANCY_DECAY_BLOCKS = 400;         // Decay duration after dormancy reset
constexpr int64_t FP_DORMANCY_PENALTY = 2500000;   // 2.5 × 1,000,000 (dormancy reset penalty)

// DFMP v3.0: Registration PoW - computational cost per new MIK identity
constexpr int REGISTRATION_POW_BITS = 28;          // Leading zero bits required (~10-15 min with ref SHA3)

// ============================================================================
// DFMP v3.1 CONSTANTS (softened for small networks)
// ============================================================================
// v3.1 reduces penalty aggressiveness to prevent network stall when
// few miners are active. Same structure as v3.0 (payout heat, dormancy,
// registration PoW) but with gentler parameters.

/** v3.1: Free blocks before heat penalty (raised from 12 to 36) */
constexpr int FREE_TIER_THRESHOLD_V31 = 36;

/** v3.1: Maturity decay duration (reduced from 800 to 400 blocks) */
constexpr int MATURITY_BLOCKS_V31 = 400;

/** v3.1: Starting maturity penalty (reduced from 5.0x to 2.0x) */
constexpr int64_t FP_PENDING_START_V31 = 2000000;   // 2.0 × 1,000,000

/** v3.1: Cliff penalty at free tier + 1 (reduced from 2.0x to 1.5x) */
constexpr int64_t FP_HEAT_CLIFF_V31 = 1500000;      // 1.5 × 1,000,000

/** v3.1: Exponential growth rate per block (reduced from 1.58x to 1.08x) */
constexpr int64_t FP_HEAT_GROWTH_V31 = 108;          // 1.08x per block

// ============================================================================
// DFMP v3.2 CONSTANTS (tightened anti-whale, back to v3.0 heat with softer maturity)
// ============================================================================
// v3.2 returns to v3.0 heat aggressiveness (12-block free tier, 2.0x cliff,
// 1.58x growth) but with a more moderate maturity penalty (2.5x over 500 blocks)
// to avoid the network stall that occurred with v3.0's 5.0x over 800 blocks.

/** v3.2: Free blocks before heat penalty (back to v3.0: 12) */
constexpr int FREE_TIER_THRESHOLD_V32 = 12;

/** v3.2: Maturity decay duration (500 blocks, between v3.0's 800 and v3.1's 400) */
constexpr int MATURITY_BLOCKS_V32 = 500;

/** v3.2: Starting maturity penalty (2.5x, between v3.0's 5.0x and v3.1's 2.0x) */
constexpr int64_t FP_PENDING_START_V32 = 2500000;   // 2.5 × 1,000,000

/** v3.2: Cliff penalty at free tier + 1 (back to v3.0: 2.0x) */
constexpr int64_t FP_HEAT_CLIFF_V32 = 2000000;      // 2.0 × 1,000,000

/** v3.2: Exponential growth rate per block (back to v3.0: 1.58x) */
constexpr int64_t FP_HEAT_GROWTH_V32 = 158;          // 1.58x per block

// ============================================================================
// IDENTITY TYPE (20 bytes)
// ============================================================================

/**
 * Miner identity - 20-byte hash derived from coinbase scriptPubKey
 *
 * Identity = SHA256(coinbase.vout[0].scriptPubKey)[:20]
 */
struct Identity {
    uint8_t data[20];

    /** Construct null identity */
    Identity();

    /** Construct from raw bytes */
    explicit Identity(const uint8_t* bytes);

    /** Check if identity is null (all zeros) */
    bool IsNull() const;

    /** Equality comparison */
    bool operator==(const Identity& other) const;

    /** Inequality comparison */
    bool operator!=(const Identity& other) const;

    /** Less-than comparison (for std::map) */
    bool operator<(const Identity& other) const;

    /** Get hexadecimal string representation (40 chars) */
    std::string GetHex() const;

    /** Set from hexadecimal string */
    bool SetHex(const std::string& hex);
};

// ============================================================================
// IDENTITY DERIVATION
// ============================================================================

/**
 * Derive miner identity from coinbase transaction
 *
 * @param coinbaseTx The coinbase transaction (must have at least one output)
 * @return Identity derived from SHA256(vout[0].scriptPubKey)[:20]
 *         Returns null identity if coinbase has no outputs
 */
Identity DeriveIdentity(const CTransaction& coinbaseTx);

/**
 * Derive identity from raw scriptPubKey bytes
 *
 * @param scriptPubKey The locking script bytes
 * @return Identity derived from SHA256(scriptPubKey)[:20]
 *         Returns null identity if scriptPubKey is empty
 */
Identity DeriveIdentityFromScript(const std::vector<uint8_t>& scriptPubKey);

// ============================================================================
// HEAT TRACKER
// ============================================================================

/**
 * Tracks miner heat (blocks mined in observation window)
 *
 * Maintains a sliding window of recent blocks and their miner identities.
 * Heat for an identity = count of blocks by that identity in the window.
 *
 * Thread-safe: Protected by internal mutex.
 * In-memory: Rebuilt from chain on startup.
 */
class CHeatTracker {
private:
    /** Sliding window of (height, identity) pairs */
    std::deque<std::pair<int, Identity>> m_window;

    /** Cache: identity -> block count in window (O(1) lookup) */
    std::map<Identity, int> m_heatCache;

    /** Mutex for thread safety */
    mutable std::mutex m_mutex;

public:
    CHeatTracker() = default;

    /**
     * Called when a new block is connected to the chain
     *
     * @param height Block height
     * @param identity Miner identity from coinbase
     */
    void OnBlockConnected(int height, const Identity& identity);

    /**
     * Called when a block is disconnected (reorg)
     *
     * @param height Height of disconnected block
     */
    void OnBlockDisconnected(int height);

    /**
     * Get current heat for an identity
     *
     * @param identity Miner identity to query
     * @return Number of blocks by this identity in the observation window
     */
    int GetHeat(const Identity& identity) const;

    /**
     * Get effective heat (heat minus free tier threshold)
     *
     * @param identity Miner identity to query
     * @return max(0, heat - FREE_TIER_THRESHOLD)
     */
    int GetEffectiveHeat(const Identity& identity) const;

    /**
     * Clear all tracking data
     */
    void Clear();

    /**
     * Get current window size (for debugging)
     */
    size_t GetWindowSize() const;

    /**
     * Get number of unique miners in the current observation window
     * Used for dynamic DFMP scaling
     */
    int GetUniqueMinerCount() const;

    /**
     * Get all identities and their block counts in the current window
     * (for distribution analysis)
     */
    std::map<Identity, int> GetAllHeat() const;
};

// ============================================================================
// MULTIPLIER CALCULATION (Fixed-Point)
// ============================================================================

/**
 * Calculate pending penalty multiplier (fixed-point)
 *
 * New identities (firstSeenHeight = -1) get ONE free block at 1× difficulty
 * to establish their identity. After that first block is mined, subsequent
 * blocks face 5× difficulty that decays linearly to 1× over 500 blocks.
 *
 * @param currentHeight Current block height
 * @param firstSeenHeight Height where identity was first seen (-1 for new identity)
 * @return Pending multiplier × FP_SCALE (1000000 for new, up to 5000000 for just-established)
 */
int64_t CalculatePendingPenaltyFP(int currentHeight, int firstSeenHeight);

/**
 * Calculate heat multiplier (fixed-point) with dynamic scaling
 *
 * Free tier scales by active miner count:
 *   effectiveFreeThreshold = max(FREE_TIER_THRESHOLD, OBSERVATION_WINDOW / uniqueMiners)
 *
 * @param heat Block count in observation window
 * @param uniqueMiners Number of unique miners in window (0 = use static threshold)
 * @return Heat multiplier × FP_SCALE (e.g., 1000000 for 1.0×)
 */
int64_t CalculateHeatMultiplierFP(int heat, int uniqueMiners = 0);

/**
 * Calculate total DFMP multiplier (fixed-point)
 *
 * Total = pending_multiplier × heat_multiplier
 *
 * @param currentHeight Current block height
 * @param firstSeenHeight Height where identity was first seen (-1 for new)
 * @param heat Block count in observation window
 * @param uniqueMiners Number of unique miners in window (0 = use static threshold)
 * @return Total multiplier × FP_SCALE
 */
int64_t CalculateTotalMultiplierFP(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners = 0);

/**
 * Calculate effective target (256-bit integer division)
 *
 * effective_target = base_target / multiplier
 *
 * @param baseTarget The unadjusted difficulty target
 * @param multiplierFP Total multiplier × FP_SCALE
 * @return Effective target (never less than 1)
 */
uint256 CalculateEffectiveTarget(const uint256& baseTarget, int64_t multiplierFP);

// ============================================================================
// DFMP v3.1 MULTIPLIER CALCULATION (Fixed-Point)
// ============================================================================

/** v3.1 pending penalty: 2.0x → 1.5x → 1.0x over 400 blocks */
int64_t CalculatePendingPenaltyFP_V31(int currentHeight, int firstSeenHeight);

/** v3.1 heat multiplier: 36-block free tier, 1.5x cliff, 1.08x growth */
int64_t CalculateHeatMultiplierFP_V31(int heat, int uniqueMiners = 0);

/** v3.1 total multiplier: maturity × heat */
int64_t CalculateTotalMultiplierFP_V31(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners = 0);

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/**
 * Get pending penalty as double (for display/logging)
 */
double GetPendingPenalty(int currentHeight, int firstSeenHeight);

/**
 * Get heat multiplier as double (for display/logging)
 */
double GetHeatMultiplier(int heat, int uniqueMiners = 0);

/**
 * Get total multiplier as double (for display/logging)
 */
double GetTotalMultiplier(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners = 0);

/** v3.1 convenience functions for logging */
double GetPendingPenalty_V31(int currentHeight, int firstSeenHeight);
double GetHeatMultiplier_V31(int heat, int uniqueMiners = 0);

// ============================================================================
// DFMP v3.2 MULTIPLIER CALCULATION (Fixed-Point)
// ============================================================================

/** v3.2 pending penalty: 2.5x → 2.0x → 1.5x → 1.25x → 1.0x over 500 blocks */
int64_t CalculatePendingPenaltyFP_V32(int currentHeight, int firstSeenHeight);

/** v3.2 heat multiplier: 12-block free tier, 2.0x cliff, 1.58x growth */
int64_t CalculateHeatMultiplierFP_V32(int heat, int uniqueMiners = 0);

/** v3.2 total multiplier: maturity × heat */
int64_t CalculateTotalMultiplierFP_V32(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners = 0);

/** v3.2 convenience functions for logging */
double GetPendingPenalty_V32(int currentHeight, int firstSeenHeight);
double GetHeatMultiplier_V32(int heat, int uniqueMiners = 0);

// ============================================================================
// GLOBAL STATE
// ============================================================================

// Forward declaration
class CIdentityDB;

/** Global heat tracker instance */
extern CHeatTracker* g_heatTracker;

/** Global payout address heat tracker (v3.0) */
extern CHeatTracker* g_payoutHeatTracker;

/** Global identity database instance */
extern CIdentityDB* g_identityDb;

/**
 * Initialize DFMP subsystem
 *
 * @param dataDir Data directory for identity database
 * @return true if initialization successful
 */
bool InitializeDFMP(const std::string& dataDir);

/**
 * Shutdown DFMP subsystem
 */
void ShutdownDFMP();

/**
 * Check if DFMP is initialized and ready
 */
bool IsDFMPReady();

} // namespace DFMP

#endif // DILITHION_DFMP_H
