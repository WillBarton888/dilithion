// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DFMP_H
#define DILITHION_DFMP_H

/**
 * Dilithion Fair Mining Protocol (DFMP) v1.4
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
// PROTOCOL CONSTANTS (v1.3)
// ============================================================================

/** Number of blocks in the observation window for heat calculation */
constexpr int OBSERVATION_WINDOW = 100;

/** Number of free blocks before heat penalty applies */
constexpr int FREE_TIER_THRESHOLD = 14;

/** Number of blocks for pending penalty to fully decay */
constexpr int MATURITY_BLOCKS = 500;

/** Starting pending penalty multiplier for new identities */
constexpr double PENDING_PENALTY_START = 5.0;

/** Ending pending penalty multiplier (mature identity) */
constexpr double PENDING_PENALTY_END = 1.0;

/** Heat coefficient for quadratic penalty curve */
constexpr double HEAT_COEFFICIENT = 0.046;

/** Heat exponent for penalty curve (quadratic) */
constexpr double HEAT_EXPONENT = 2.0;

// Fixed-point scale for deterministic integer arithmetic
// All multipliers are stored as (value * FP_SCALE)
constexpr int64_t FP_SCALE = 1000000;

// Fixed-point versions of constants
constexpr int64_t FP_PENDING_START = 5000000;   // 5.0 × 1,000,000
constexpr int64_t FP_PENDING_END = 1000000;     // 1.0 × 1,000,000
constexpr int64_t FP_HEAT_COEFF = 46000;        // 0.046 × 1,000,000

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
 * Calculate heat multiplier (fixed-point)
 *
 * Formula: 1 + 0.046 × max(0, heat - 14)²
 *
 * @param heat Block count in observation window
 * @return Heat multiplier × FP_SCALE (e.g., 1000000 for 1.0×)
 */
int64_t CalculateHeatMultiplierFP(int heat);

/**
 * Calculate total DFMP multiplier (fixed-point)
 *
 * Total = pending_multiplier × heat_multiplier
 *
 * @param currentHeight Current block height
 * @param firstSeenHeight Height where identity was first seen (-1 for new)
 * @param heat Block count in observation window
 * @return Total multiplier × FP_SCALE
 */
int64_t CalculateTotalMultiplierFP(int currentHeight, int firstSeenHeight, int heat);

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
// CONVENIENCE FUNCTIONS
// ============================================================================

/**
 * Get pending penalty as double (for display/logging)
 */
double GetPendingPenalty(int currentHeight, int firstSeenHeight);

/**
 * Get heat multiplier as double (for display/logging)
 */
double GetHeatMultiplier(int heat);

/**
 * Get total multiplier as double (for display/logging)
 */
double GetTotalMultiplier(int currentHeight, int firstSeenHeight, int heat);

// ============================================================================
// GLOBAL STATE
// ============================================================================

// Forward declaration
class CIdentityDB;

/** Global heat tracker instance */
extern CHeatTracker* g_heatTracker;

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
