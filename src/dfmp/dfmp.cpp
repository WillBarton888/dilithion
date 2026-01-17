// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <dfmp/dfmp.h>
#include <dfmp/identity_db.h>
#include <crypto/sha3.h>

#include <cstring>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <cmath>

namespace DFMP {

// ============================================================================
// GLOBAL STATE
// ============================================================================

CHeatTracker* g_heatTracker = nullptr;
CIdentityDB* g_identityDb = nullptr;

// ============================================================================
// IDENTITY IMPLEMENTATION
// ============================================================================

Identity::Identity() {
    std::memset(data, 0, sizeof(data));
}

Identity::Identity(const uint8_t* bytes) {
    if (bytes) {
        std::memcpy(data, bytes, sizeof(data));
    } else {
        std::memset(data, 0, sizeof(data));
    }
}

bool Identity::IsNull() const {
    for (size_t i = 0; i < sizeof(data); ++i) {
        if (data[i] != 0) return false;
    }
    return true;
}

bool Identity::operator==(const Identity& other) const {
    return std::memcmp(data, other.data, sizeof(data)) == 0;
}

bool Identity::operator!=(const Identity& other) const {
    return !(*this == other);
}

bool Identity::operator<(const Identity& other) const {
    return std::memcmp(data, other.data, sizeof(data)) < 0;
}

std::string Identity::GetHex() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < sizeof(data); ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

bool Identity::SetHex(const std::string& hex) {
    if (hex.length() != 40) return false;

    for (size_t i = 0; i < 20; ++i) {
        std::string byteStr = hex.substr(i * 2, 2);
        char* end;
        unsigned long val = std::strtoul(byteStr.c_str(), &end, 16);
        if (*end != '\0' || val > 255) return false;
        data[i] = static_cast<uint8_t>(val);
    }
    return true;
}

// ============================================================================
// IDENTITY DERIVATION
// ============================================================================

Identity DeriveIdentity(const CTransaction& coinbaseTx) {
    // Check for at least one output
    if (coinbaseTx.vout.empty()) {
        return Identity();  // Null identity
    }

    // Use first output's scriptPubKey
    return DeriveIdentityFromScript(coinbaseTx.vout[0].scriptPubKey);
}

Identity DeriveIdentityFromScript(const std::vector<uint8_t>& scriptPubKey) {
    if (scriptPubKey.empty()) {
        return Identity();  // Null identity
    }

    // Hash the scriptPubKey with SHA3-256
    uint8_t hash[32];
    SHA3_256(scriptPubKey.data(), scriptPubKey.size(), hash);

    // Take first 20 bytes as identity
    return Identity(hash);
}

// ============================================================================
// HEAT TRACKER IMPLEMENTATION
// ============================================================================

void CHeatTracker::OnBlockConnected(int height, const Identity& identity) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Add new entry
    m_window.push_back({height, identity});
    m_heatCache[identity]++;

    // Remove entries outside the observation window
    while (!m_window.empty() && m_window.front().first <= height - OBSERVATION_WINDOW) {
        const Identity& oldIdentity = m_window.front().second;

        // Decrement heat cache
        auto it = m_heatCache.find(oldIdentity);
        if (it != m_heatCache.end()) {
            it->second--;
            if (it->second <= 0) {
                m_heatCache.erase(it);
            }
        }

        m_window.pop_front();
    }
}

void CHeatTracker::OnBlockDisconnected(int height) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Remove the most recent entry if it matches the height
    while (!m_window.empty() && m_window.back().first >= height) {
        const Identity& removedIdentity = m_window.back().second;

        // Decrement heat cache
        auto it = m_heatCache.find(removedIdentity);
        if (it != m_heatCache.end()) {
            it->second--;
            if (it->second <= 0) {
                m_heatCache.erase(it);
            }
        }

        m_window.pop_back();
    }
}

int CHeatTracker::GetHeat(const Identity& identity) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_heatCache.find(identity);
    if (it != m_heatCache.end()) {
        return it->second;
    }
    return 0;
}

int CHeatTracker::GetEffectiveHeat(const Identity& identity) const {
    int heat = GetHeat(identity);
    return std::max(0, heat - FREE_TIER_THRESHOLD);
}

void CHeatTracker::Clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_window.clear();
    m_heatCache.clear();
}

size_t CHeatTracker::GetWindowSize() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_window.size();
}

// ============================================================================
// MULTIPLIER CALCULATION (Fixed-Point)
// ============================================================================

int64_t CalculatePendingPenaltyFP(int currentHeight, int firstSeenHeight) {
    // New identity (not yet seen) - NO penalty for first block
    // This allows new miners to establish their identity with one "free" block
    // After their first block is mined, the identity is registered and subsequent
    // blocks face the normal 5x→1x decay over MATURITY_BLOCKS (500 blocks)
    if (firstSeenHeight < 0) {
        return FP_PENDING_END;  // 1.0x - no penalty for identity establishment
    }

    int blocksSinceFirst = currentHeight - firstSeenHeight;

    // Mature identity - no penalty
    if (blocksSinceFirst >= MATURITY_BLOCKS) {
        return FP_PENDING_END;
    }

    // Linear decay from 5× to 1× over MATURITY_BLOCKS
    // pending = 5.0 - 4.0 * (blocksSinceFirst / MATURITY_BLOCKS)
    //
    // In fixed-point:
    // pending_fp = 5,000,000 - 4,000,000 * blocksSinceFirst / MATURITY_BLOCKS

    int64_t decayRange = FP_PENDING_START - FP_PENDING_END;  // 4,000,000
    int64_t decay = (decayRange * blocksSinceFirst) / MATURITY_BLOCKS;

    return FP_PENDING_START - decay;
}

int64_t CalculateHeatMultiplierFP(int heat) {
    // Calculate effective heat (heat above free tier)
    int effectiveHeat = std::max(0, heat - FREE_TIER_THRESHOLD);

    // No penalty if within free tier
    if (effectiveHeat <= 0) {
        return FP_SCALE;  // 1.0×
    }

    // heat_multiplier = 1 + 0.046 × effectiveHeat²
    //
    // In fixed-point:
    // multiplier_fp = 1,000,000 + 46,000 × effectiveHeat²
    //
    // But we need to be careful: 46,000 × effectiveHeat² could overflow
    // For effectiveHeat = 86 (heat = 100), 46000 × 86² = 46000 × 7396 = 340,216,000
    // This fits in int64_t easily.

    int64_t heatSquared = static_cast<int64_t>(effectiveHeat) * effectiveHeat;
    int64_t heatTerm = (FP_HEAT_COEFF * heatSquared) / FP_SCALE;

    // The formula is: 1 + coefficient × heat²
    // coefficient = 0.046 = 46000/1000000
    // So: 1,000,000 + (46000 × heat²) / 1000000 × 1000000
    //   = 1,000,000 + 46000 × heat² / 1000000 × 1000000
    // Simplify: 1,000,000 + 46 × heat²

    // Actually let's recalculate properly:
    // multiplier = 1.0 + 0.046 × h²
    // multiplier_fp = FP_SCALE + 0.046 × h² × FP_SCALE
    //               = FP_SCALE + (FP_HEAT_COEFF × h²)

    return FP_SCALE + (FP_HEAT_COEFF * heatSquared) / FP_SCALE;
}

int64_t CalculateTotalMultiplierFP(int currentHeight, int firstSeenHeight, int heat) {
    int64_t pendingFP = CalculatePendingPenaltyFP(currentHeight, firstSeenHeight);
    int64_t heatFP = CalculateHeatMultiplierFP(heat);

    // total = pending × heat
    // In fixed-point: total_fp = (pending_fp × heat_fp) / FP_SCALE
    return (pendingFP * heatFP) / FP_SCALE;
}

uint256 CalculateEffectiveTarget(const uint256& baseTarget, int64_t multiplierFP) {
    // effective_target = baseTarget / multiplier
    // In fixed-point: effective_target = baseTarget × FP_SCALE / multiplierFP

    // Ensure multiplier is at least 1× (shouldn't happen but be safe)
    if (multiplierFP < FP_SCALE) {
        multiplierFP = FP_SCALE;
    }

    // For 256-bit division, we need to:
    // 1. Multiply baseTarget by FP_SCALE (may increase precision)
    // 2. Divide by multiplierFP

    // Since uint256 doesn't have built-in arithmetic operators,
    // we'll do byte-by-byte division for the high bits and use
    // the ratio for the result.

    // Simplified approach: convert to double for calculation, then back
    // This loses some precision but is deterministic enough for mining
    // because the hash comparison has plenty of margin.

    // Better approach: Do proper 256-bit integer division
    // target_new = target × 1,000,000 / multiplier_fp

    // For now, use a simpler approach:
    // Since multiplierFP ranges from 1,000,000 to maybe 50,000,000 (50×),
    // and baseTarget is 256 bits, we can safely divide.

    // Convert baseTarget to bytes for calculation
    uint256 result;
    result = baseTarget;  // Copy

    // We need: result = baseTarget × FP_SCALE / multiplierFP
    // But uint256 doesn't have division. We'll use byte-level ops.

    // Simplest correct approach: treat uint256 as a big integer
    // and perform long division.

    // For determinism, we'll compute: floor(baseTarget / (multiplierFP / FP_SCALE))
    // which is: floor(baseTarget × FP_SCALE / multiplierFP)

    // Implementation: do it bit by bit or use existing utilities

    // The baseTarget bytes are in little-endian order (data[0] is LSB)
    // We can convert to a big integer, divide, and convert back.

    // For simplicity and correctness, let's just do byte-level division
    // by the scalar ratio = multiplierFP / FP_SCALE

    // ratio = multiplierFP / FP_SCALE (this is the actual multiplier as integer part + fraction)
    // We want result = baseTarget / ratio

    // Actually, the cleanest way:
    // result_i = baseTarget_i × FP_SCALE / multiplierFP for each position
    // But that doesn't work for multi-precision.

    // Let's do proper multi-precision division:
    // We have a 256-bit number and want to divide by a 64-bit number.

    // Approach: Process 64 bits at a time from MSB
    uint64_t divisor = static_cast<uint64_t>(multiplierFP);
    if (divisor == 0) divisor = FP_SCALE;  // Safety

    // We want: result = baseTarget × FP_SCALE / divisor
    // First, we multiply baseTarget by FP_SCALE (this may overflow 256 bits slightly
    // but for targets, the upper bits are usually zero, so it's fine).

    // Convert uint256 to array of uint64_t for easier math
    // uint256.data is uint8_t[32] in little-endian

    uint64_t words[4];  // Little-endian (words[0] = LSB)
    std::memcpy(words, baseTarget.data, 32);

    // Multiply by FP_SCALE (1,000,000)
    // We need to handle potential overflow into a 5th word
    __uint128_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        __uint128_t product = static_cast<__uint128_t>(words[i]) * FP_SCALE + carry;
        words[i] = static_cast<uint64_t>(product);
        carry = product >> 64;
    }
    // carry now holds the overflow (words[4] conceptually)

    // Now divide by divisor (long division from MSB)
    // We have 5 words (320 bits) to divide by 64-bit divisor

    uint64_t resultWords[4] = {0, 0, 0, 0};
    __uint128_t remainder = carry;  // Start with the overflow

    // Process from word 3 down to 0
    for (int i = 3; i >= 0; --i) {
        remainder = (remainder << 64) | words[i];
        resultWords[i] = static_cast<uint64_t>(remainder / divisor);
        remainder = remainder % divisor;
    }

    // Copy result back to uint256
    std::memcpy(result.data, resultWords, 32);

    // Ensure result is at least 1 (target can't be zero)
    bool allZero = true;
    for (size_t i = 0; i < 32; ++i) {
        if (result.data[i] != 0) {
            allZero = false;
            break;
        }
    }
    if (allZero) {
        result.data[0] = 1;  // Minimum target
    }

    return result;
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

double GetPendingPenalty(int currentHeight, int firstSeenHeight) {
    return static_cast<double>(CalculatePendingPenaltyFP(currentHeight, firstSeenHeight)) / FP_SCALE;
}

double GetHeatMultiplier(int heat) {
    return static_cast<double>(CalculateHeatMultiplierFP(heat)) / FP_SCALE;
}

double GetTotalMultiplier(int currentHeight, int firstSeenHeight, int heat) {
    return static_cast<double>(CalculateTotalMultiplierFP(currentHeight, firstSeenHeight, heat)) / FP_SCALE;
}

// ============================================================================
// GLOBAL STATE MANAGEMENT
// ============================================================================

bool InitializeDFMP(const std::string& dataDir) {
    // Create heat tracker
    g_heatTracker = new CHeatTracker();

    // Create and open identity database
    g_identityDb = new CIdentityDB();
    if (!g_identityDb->Open(dataDir + "/dfmp_identity")) {
        delete g_identityDb;
        g_identityDb = nullptr;
        delete g_heatTracker;
        g_heatTracker = nullptr;
        return false;
    }

    return true;
}

void ShutdownDFMP() {
    if (g_identityDb) {
        g_identityDb->Close();
        delete g_identityDb;
        g_identityDb = nullptr;
    }

    if (g_heatTracker) {
        delete g_heatTracker;
        g_heatTracker = nullptr;
    }
}

bool IsDFMPReady() {
    return g_heatTracker != nullptr && g_identityDb != nullptr;
}

} // namespace DFMP
