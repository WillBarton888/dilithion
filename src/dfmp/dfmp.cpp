// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <dfmp/dfmp.h>
#include <dfmp/identity_db.h>
#include <dfmp/mik.h>
#include <crypto/sha3.h>
#include <node/block_index.h>
#include <node/blockchain_storage.h>
#include <consensus/validation.h>

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
// MULTIPLIER CALCULATION (Fixed-Point) - DFMP v2.0
// ============================================================================

int64_t CalculatePendingPenaltyFP(int currentHeight, int firstSeenHeight) {
    // DFMP v2.0: NO first-block grace - new identities start at 3.0x
    // This prevents the address rotation loophole where miners could
    // always get 1.0x by using a new payout address.
    //
    // Maturity decay: 3.0x → 2.5x → 2.0x → 1.5x → 1.0x in 100-block steps
    // over 400 blocks total (MATURITY_BLOCKS)

    if (firstSeenHeight < 0) {
        return FP_PENDING_START;  // 3.0x for new identity (v2.0: no grace)
    }

    int age = currentHeight - firstSeenHeight;

    // Step-wise decay over MATURITY_BLOCKS (400 blocks)
    // Each 100 blocks reduces by 0.5x
    if (age < 100) return 3000000;   // 3.0x
    if (age < 200) return 2500000;   // 2.5x
    if (age < 300) return 2000000;   // 2.0x
    if (age < 400) return 1500000;   // 1.5x
    return FP_PENDING_END;           // 1.0x (mature)
}

int64_t CalculateHeatMultiplierFP(int heat) {
    // DFMP v2.0 Heat Penalty:
    // - 0-20 blocks:  Free tier (1.0x)
    // - 21-25 blocks: Linear zone (1.0x → 1.5x)
    // - 26+ blocks:   Exponential (1.5 × 1.08^(blocks-25))

    // Free tier: no penalty
    if (heat <= FREE_TIER_THRESHOLD) {  // FREE_TIER_THRESHOLD = 20
        return FP_SCALE;  // 1.0x
    }

    // Linear zone: 21-25 blocks
    // penalty = 1.0 + 0.1 × (blocks - 20)
    if (heat <= LINEAR_ZONE_UPPER) {  // LINEAR_ZONE_UPPER = 25
        int64_t linearPart = FP_LINEAR_INCREMENT * (heat - FREE_TIER_THRESHOLD);
        return FP_SCALE + linearPart;  // 1.0 + 0.1 per block
    }

    // Exponential zone: 26+ blocks
    // penalty = 1.5 × 1.08^(blocks - 25)
    // Using fixed-point: multiply by 108/100 repeatedly
    int64_t penalty = FP_LINEAR_BASE;  // 1.5 × FP_SCALE
    int exponent = heat - LINEAR_ZONE_UPPER;  // blocks over 25

    for (int i = 0; i < exponent; i++) {
        penalty = (penalty * 108) / 100;  // × 1.08
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

// ============================================================================
// DETERMINISTIC CHAIN-BASED VALIDATION (IBD-safe)
// ============================================================================

bool ExtractIdentityFromBlock(const CBlock& block, Identity& identity) {
    // A valid block must have at least one transaction (the coinbase)
    if (block.vtx.empty()) {
        return false;
    }

    // Deserialize block transactions (vtx is raw bytes, need to convert to CTransaction)
    CBlockValidator validator;
    std::vector<CTransactionRef> transactions;
    std::string deserializeError;
    if (!validator.DeserializeBlockTransactions(block, transactions, deserializeError)) {
        return false;
    }

    if (transactions.empty()) {
        return false;
    }

    const CTransaction& coinbase = *transactions[0];

    // Coinbase must have at least one input with scriptSig
    if (coinbase.vin.empty() || coinbase.vin[0].scriptSig.empty()) {
        return false;
    }

    // Try to parse MIK data from coinbase scriptSig (DFMP v2.0)
    CMIKScriptData mikData;
    if (ParseMIKFromScriptSig(coinbase.vin[0].scriptSig, mikData)) {
        if (mikData.IsValid()) {
            identity = mikData.identity;
            return true;
        }
    }

    // Fallback: Derive identity from coinbase output scriptPubKey (v1.x compatibility)
    if (!coinbase.vout.empty()) {
        identity = DeriveIdentityFromScript(coinbase.vout[0].scriptPubKey);
        return !identity.IsNull();
    }

    return false;
}

void BuildIdentityCache(CDFMPValidationContext& ctx) {
    if (ctx.cacheBuilt) {
        return;  // Already built
    }

    ctx.firstSeenCache.clear();
    ctx.heatCache.clear();

    if (ctx.pindexPrev == nullptr || ctx.pdb == nullptr) {
        ctx.cacheBuilt = true;
        return;
    }

    // Scan range: need to go back far enough to find first-seen for any identity
    // and to count blocks in the observation window.
    // Total range = MATURITY_BLOCKS + OBSERVATION_WINDOW = 400 + 360 = 760 blocks
    const int scanDepth = MATURITY_BLOCKS + OBSERVATION_WINDOW;
    const int currentHeight = ctx.pindexPrev->nHeight + 1;  // The block being validated
    const int windowStart = currentHeight - OBSERVATION_WINDOW;

    // Walk backwards through the chain
    CBlockIndex* pindex = const_cast<CBlockIndex*>(ctx.pindexPrev);
    int blocksScanned = 0;

    while (pindex != nullptr && blocksScanned < scanDepth) {
        // Load block from database
        CBlock block;
        uint256 blockHash = pindex->GetBlockHash();

        if (ctx.pdb->ReadBlock(blockHash, block)) {
            Identity blockIdentity;
            if (ExtractIdentityFromBlock(block, blockIdentity)) {
                // Track first-seen height.
                // We're walking backwards (high->low height), so the last value we
                // write for each identity is the earliest (lowest) height = first-seen.
                ctx.firstSeenCache[blockIdentity] = pindex->nHeight;

                // Count blocks in observation window (for heat calculation)
                if (pindex->nHeight >= windowStart) {
                    ctx.heatCache[blockIdentity]++;
                }
            }
        }

        pindex = pindex->pprev;
        blocksScanned++;
    }

    ctx.cacheBuilt = true;
}

int ScanChainForFirstSeen(CDFMPValidationContext& ctx, const Identity& identity) {
    // Build cache if not already done
    if (!ctx.cacheBuilt) {
        BuildIdentityCache(ctx);
    }

    // Look up in cache
    auto it = ctx.firstSeenCache.find(identity);
    if (it != ctx.firstSeenCache.end()) {
        return it->second;
    }

    // Not found in scanned range - this is a new identity
    return -1;
}

int CountBlocksInWindow(CDFMPValidationContext& ctx, const Identity& identity) {
    // Build cache if not already done
    if (!ctx.cacheBuilt) {
        BuildIdentityCache(ctx);
    }

    // Look up in cache
    auto it = ctx.heatCache.find(identity);
    if (it != ctx.heatCache.end()) {
        return it->second;
    }

    // Not found - no blocks by this identity in the window
    return 0;
}

bool ScanChainForMIKPubKey(CDFMPValidationContext& ctx, const Identity& identity, std::vector<uint8_t>& pubkey) {
    // Check cache first
    auto cacheIt = ctx.mikPubkeyCache.find(identity);
    if (cacheIt != ctx.mikPubkeyCache.end()) {
        pubkey = cacheIt->second;
        return true;
    }

    if (ctx.pindexPrev == nullptr || ctx.pdb == nullptr) {
        return false;
    }

    // Scan backwards through the chain to find the registration block
    // Registration blocks embed the full pubkey, so we need to find where
    // this identity first appeared with isRegistration=true
    //
    // We scan up to MATURITY_BLOCKS + OBSERVATION_WINDOW blocks back,
    // which should cover any identity that could affect the current block.
    const int scanDepth = MATURITY_BLOCKS + OBSERVATION_WINDOW;
    CBlockIndex* pindex = const_cast<CBlockIndex*>(ctx.pindexPrev);
    int blocksScanned = 0;

    while (pindex != nullptr && blocksScanned < scanDepth) {
        // Load block from database
        CBlock block;
        uint256 blockHash = pindex->GetBlockHash();

        if (ctx.pdb->ReadBlock(blockHash, block)) {
            // Deserialize block transactions
            CBlockValidator validator;
            std::vector<CTransactionRef> transactions;
            std::string deserializeError;

            if (validator.DeserializeBlockTransactions(block, transactions, deserializeError) &&
                !transactions.empty()) {

                const CTransaction& coinbase = *transactions[0];

                // Check if coinbase has MIK data
                if (!coinbase.vin.empty() && !coinbase.vin[0].scriptSig.empty()) {
                    CMIKScriptData mikData;
                    if (ParseMIKFromScriptSig(coinbase.vin[0].scriptSig, mikData)) {
                        // Found MIK data - check if it's a registration for our identity
                        if (mikData.isRegistration && mikData.identity == identity) {
                            // Found the registration block - extract pubkey
                            pubkey = mikData.pubkey;

                            // Cache for future lookups
                            ctx.mikPubkeyCache[identity] = pubkey;

                            return true;
                        }

                        // Also cache any registrations we encounter for other identities
                        // This helps if we need to validate multiple reference blocks
                        if (mikData.isRegistration &&
                            ctx.mikPubkeyCache.find(mikData.identity) == ctx.mikPubkeyCache.end()) {
                            ctx.mikPubkeyCache[mikData.identity] = mikData.pubkey;
                        }
                    }
                }
            }
        }

        pindex = pindex->pprev;
        blocksScanned++;
    }

    // Registration not found in scanned range
    return false;
}

} // namespace DFMP
