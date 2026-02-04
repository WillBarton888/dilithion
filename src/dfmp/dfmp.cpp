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
CHeatTracker* g_payoutHeatTracker = nullptr;
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

std::map<Identity, int> CHeatTracker::GetAllHeat() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_heatCache;  // Return a copy
}

// ============================================================================
// MULTIPLIER CALCULATION (Fixed-Point) - DFMP v2.0
// ============================================================================

int64_t CalculatePendingPenaltyFP(int currentHeight, int firstSeenHeight) {
    // DFMP v3.0: NO first-block grace - new identities start at 5.0x
    // Step-wise decay: 5.0x → 4.0x → 3.0x → 2.0x → 1.5x → 1.0x in 160-block steps
    // over 800 blocks total (MATURITY_BLOCKS)

    if (firstSeenHeight < 0) {
        return FP_PENDING_START;  // 5.0x for new identity
    }

    int age = currentHeight - firstSeenHeight;

    if (age < 160) return 5000000;   // 5.0x
    if (age < 320) return 4000000;   // 4.0x
    if (age < 480) return 3000000;   // 3.0x
    if (age < 640) return 2000000;   // 2.0x
    if (age < 800) return 1500000;   // 1.5x
    return FP_PENDING_END;           // 1.0x (mature)
}

int64_t CalculateHeatMultiplierFP(int heat) {
    // DFMP v3.0 Heat Penalty:
    // - 0-12 blocks:  Free tier (1.0x)
    // - 13+ blocks:   2.0x cliff, then ×1.58 per additional block
    //                 Block 13 = 2.0x, 14 = 3.16x, 15 = 5.0x, 20 = 49x

    // Free tier: no penalty
    if (heat <= FREE_TIER_THRESHOLD) {  // FREE_TIER_THRESHOLD = 12
        return FP_SCALE;  // 1.0x
    }

    // Cliff + exponential: 13+ blocks
    // penalty = 2.0 × 1.58^(blocks - 13)
    // Using fixed-point: start at 2.0x, multiply by 158/100 per block
    int64_t penalty = FP_HEAT_CLIFF;  // 2.0 × FP_SCALE
    int exponent = heat - FREE_TIER_THRESHOLD - 1;  // blocks over 13

    for (int i = 0; i < exponent; i++) {
        penalty = (penalty * FP_HEAT_GROWTH) / 100;  // × 1.58
    }

    return penalty;
}

int64_t CalculateTotalMultiplierFP(int currentHeight, int firstSeenHeight, int heat) {
    int64_t pendingFP = CalculatePendingPenaltyFP(currentHeight, firstSeenHeight);
    int64_t heatFP = CalculateHeatMultiplierFP(heat);

    // total = maturity × heat
    // In fixed-point: total_fp = (maturity_fp × heat_fp) / FP_SCALE
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
    // Note: multiplierFP is guaranteed >= FP_SCALE (clamped above), so divisor is never 0
    uint64_t divisor = static_cast<uint64_t>(multiplierFP);

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
    g_payoutHeatTracker = new CHeatTracker();

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

    if (g_payoutHeatTracker) {
        delete g_payoutHeatTracker;
        g_payoutHeatTracker = nullptr;
    }

    if (g_heatTracker) {
        delete g_heatTracker;
        g_heatTracker = nullptr;
    }
}

bool IsDFMPReady() {
    return g_heatTracker != nullptr && g_payoutHeatTracker != nullptr && g_identityDb != nullptr;
}

} // namespace DFMP
