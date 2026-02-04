// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DFMP_MIK_H
#define DILITHION_DFMP_MIK_H

/**
 * Mining Identity Key (MIK) - DFMP v2.0
 *
 * A dedicated Dilithium3 keypair for miner identity that is separate from
 * payout addresses. This closes the address rotation loophole where miners
 * could bypass DFMP penalties by using a new payout address for each block.
 *
 * MIK is mandatory in every block starting from DFMP v2.0 activation.
 *
 * Key Sizes (Dilithium3):
 * - Public key:  1,952 bytes
 * - Private key: 4,032 bytes
 * - Signature:   3,309 bytes
 *
 * Identity derivation: SHA3-256(pubkey)[:20 bytes]
 *
 * Signature message (avoids circular dependency with block hash):
 *   message = SHA3-256(prevBlockHash || height || timestamp || mikIdentity)
 *
 * Coinbase scriptSig format:
 *   [height: 4 bytes] [msg: ~20 bytes] [MIK_MARKER: 1 byte] [MIK_DATA: variable]
 *
 *   MIK_MARKER = 0xDF
 *
 *   MIK_DATA for registration (first block with this MIK):
 *     [0x01] [pubkey: 1952 bytes] [signature: 3309 bytes]
 *
 *   MIK_DATA for reference (subsequent blocks):
 *     [0x02] [identity: 20 bytes] [signature: 3309 bytes]
 *
 * See: docs/specs/DFMP-V2-SPEC.md
 */

#include <dfmp/dfmp.h>
#include <uint256.h>
#include <util/secure_allocator.h>

#include <cstdint>
#include <vector>
#include <string>

namespace DFMP {

// ============================================================================
// MIK CONSTANTS
// ============================================================================

/** Dilithium3 public key size */
constexpr size_t MIK_PUBKEY_SIZE = 1952;

/** Dilithium3 private key size */
constexpr size_t MIK_PRIVKEY_SIZE = 4032;

/** Dilithium3 signature size */
constexpr size_t MIK_SIGNATURE_SIZE = 3309;

/** MIK identity size (SHA3-256 truncated to 20 bytes) */
constexpr size_t MIK_IDENTITY_SIZE = 20;

/** Marker byte in coinbase scriptSig indicating MIK data follows */
constexpr uint8_t MIK_MARKER = 0xDF;

/** MIK type: Registration (includes full public key) */
constexpr uint8_t MIK_TYPE_REGISTRATION = 0x01;

/** MIK type: Reference (includes only identity hash) */
constexpr uint8_t MIK_TYPE_REFERENCE = 0x02;

/** Minimum size for MIK reference: marker(1) + type(1) + identity(20) + sig(3309) */
constexpr size_t MIK_REFERENCE_MIN_SIZE = 1 + 1 + 20 + 3309;

/** Size for MIK registration (v2.0, no nonce): marker(1) + type(1) + pubkey(1952) + sig(3309) */
constexpr size_t MIK_REGISTRATION_SIZE_V2 = 1 + 1 + 1952 + 3309;

/** Size for MIK registration: marker(1) + type(1) + pubkey(1952) + sig(3309) + nonce(8) [v3.0] */
constexpr size_t MIK_REGISTRATION_SIZE = 1 + 1 + 1952 + 3309 + 8;

// ============================================================================
// MINING IDENTITY KEY
// ============================================================================

/**
 * Mining Identity Key - Dilithium3 keypair for miner identification
 *
 * The private key uses SecureAllocator to prevent swapping to disk.
 */
struct CMiningIdentityKey {
    /** Public key (1,952 bytes) */
    std::vector<uint8_t> pubkey;

    /** Private key (4,032 bytes) - secured memory */
    std::vector<uint8_t, SecureAllocator<uint8_t>> privkey;

    /** Identity derived from public key (20 bytes) */
    Identity identity;

    /** Default constructor - creates empty/invalid MIK */
    CMiningIdentityKey();

    /** Destructor - securely wipes private key */
    ~CMiningIdentityKey();

    // Prevent copying (contains secure data)
    CMiningIdentityKey(const CMiningIdentityKey&) = delete;
    CMiningIdentityKey& operator=(const CMiningIdentityKey&) = delete;

    // Allow moving
    CMiningIdentityKey(CMiningIdentityKey&& other) noexcept;
    CMiningIdentityKey& operator=(CMiningIdentityKey&& other) noexcept;

    /**
     * Check if MIK is valid (has correct key sizes)
     */
    bool IsValid() const;

    /**
     * Check if MIK has a private key (can sign)
     */
    bool HasPrivateKey() const;

    /**
     * Generate a new MIK keypair
     *
     * @return true if generation successful
     */
    bool Generate();

    /**
     * Sign a block commitment message
     *
     * Message format: SHA3-256(prevBlockHash || height || timestamp || identity)
     *
     * @param prevHash Previous block hash (32 bytes)
     * @param height Block height being mined
     * @param timestamp Block timestamp
     * @param[out] signature Output signature (3,309 bytes)
     * @return true if signing successful
     */
    bool Sign(const uint256& prevHash, int height, uint32_t timestamp,
              std::vector<uint8_t>& signature) const;

    /**
     * Clear the MIK (secure wipe of private key)
     */
    void Clear();

    /**
     * Get identity as hex string
     */
    std::string GetIdentityHex() const;

    /**
     * Serialize public key and identity for storage
     *
     * @param[out] data Output buffer for serialized data
     */
    void SerializePublic(std::vector<uint8_t>& data) const;

    /**
     * Deserialize public key and derive identity (for validation)
     *
     * @param data Serialized public data
     * @return true if deserialization successful
     */
    bool DeserializePublic(const std::vector<uint8_t>& data);
};

// ============================================================================
// SIGNATURE VERIFICATION (Static - no private key needed)
// ============================================================================

/**
 * Build the message to sign for MIK authentication
 *
 * @param prevHash Previous block hash
 * @param height Block height
 * @param timestamp Block timestamp
 * @param identity MIK identity (20 bytes)
 * @return 32-byte message hash
 */
std::vector<uint8_t> BuildMIKSignatureMessage(
    const uint256& prevHash,
    int height,
    uint32_t timestamp,
    const Identity& identity);

/**
 * Verify a MIK signature
 *
 * @param pubkey Public key (1,952 bytes)
 * @param signature Signature to verify (3,309 bytes)
 * @param prevHash Previous block hash
 * @param height Block height
 * @param timestamp Block timestamp
 * @param identity Expected identity (must match SHA3-256(pubkey)[:20])
 * @return true if signature is valid
 */
bool VerifyMIKSignature(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    const uint256& prevHash,
    int height,
    uint32_t timestamp,
    const Identity& identity);

/**
 * Derive identity from MIK public key
 *
 * @param pubkey Public key (1,952 bytes)
 * @return Identity (20 bytes), or null identity if pubkey invalid
 */
Identity DeriveIdentityFromMIK(const std::vector<uint8_t>& pubkey);

// ============================================================================
// SCRIPTSIG PARSING
// ============================================================================

/**
 * Parsed MIK data from coinbase scriptSig
 */
struct CMIKScriptData {
    /** True if this is a registration (includes full pubkey) */
    bool isRegistration;

    /** MIK identity (20 bytes) */
    Identity identity;

    /** Public key (only set for registration, 1952 bytes) */
    std::vector<uint8_t> pubkey;

    /** Signature (3,309 bytes) */
    std::vector<uint8_t> signature;

    /** v3.0: PoW nonce for registration */
    uint64_t registrationNonce = 0;

    CMIKScriptData() : isRegistration(false), registrationNonce(0) {}

    bool IsValid() const {
        return !identity.IsNull() && signature.size() == MIK_SIGNATURE_SIZE;
    }
};

/**
 * Parse MIK data from coinbase scriptSig
 *
 * Looks for MIK_MARKER (0xDF) and extracts:
 * - Type (registration or reference)
 * - Identity (from pubkey for registration, direct for reference)
 * - Public key (registration only)
 * - Signature
 *
 * @param scriptSig The coinbase input scriptSig
 * @param[out] mikData Parsed MIK data
 * @return true if MIK data found and parsed successfully, false otherwise
 */
bool ParseMIKFromScriptSig(
    const std::vector<uint8_t>& scriptSig,
    CMIKScriptData& mikData);

/**
 * Build MIK scriptSig data for registration (first block)
 *
 * Format: [MIK_MARKER] [MIK_TYPE_REGISTRATION] [pubkey: 1952] [signature: 3309]
 *
 * @param pubkey Public key
 * @param signature Signature
 * @param[out] data Output buffer
 * @return true if successful
 */
bool BuildMIKScriptSigRegistration(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    std::vector<uint8_t>& data);

/**
 * Build MIK scriptSig data for reference (subsequent blocks)
 *
 * Format: [MIK_MARKER] [MIK_TYPE_REFERENCE] [identity: 20] [signature: 3309]
 *
 * @param identity MIK identity
 * @param signature Signature
 * @param[out] data Output buffer
 * @return true if successful
 */
bool BuildMIKScriptSigReference(
    const Identity& identity,
    const std::vector<uint8_t>& signature,
    std::vector<uint8_t>& data);

/**
 * Build MIK scriptSig data for registration with PoW nonce (DFMP v3.0)
 *
 * Format: [MIK_MARKER] [MIK_TYPE_REGISTRATION] [pubkey: 1952] [signature: 3309] [nonce: 8]
 *
 * @param pubkey Public key
 * @param signature Signature
 * @param registrationNonce PoW nonce
 * @param[out] data Output buffer
 * @return true if successful
 */
bool BuildMIKScriptSigRegistration(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    uint64_t registrationNonce,
    std::vector<uint8_t>& data);

/**
 * Verify registration proof-of-work (DFMP v3.0)
 *
 * Registration PoW prevents mass MIK identity generation.
 * SHA3-256(pubkey || nonce) must have >= requiredBits leading zero bits.
 *
 * @param pubkey MIK public key (1,952 bytes)
 * @param nonce Registration nonce
 * @param requiredBits Number of leading zero bits required (default: REGISTRATION_POW_BITS = 28)
 * @return true if PoW is valid
 */
bool VerifyRegistrationPoW(const std::vector<uint8_t>& pubkey, uint64_t nonce, int requiredBits);

/**
 * Mine registration proof-of-work nonce (DFMP v3.0)
 *
 * Finds a nonce such that SHA3-256(pubkey || nonce) has >= requiredBits leading zero bits.
 * This is computationally expensive (~5 seconds for 28 bits).
 *
 * @param pubkey MIK public key (1,952 bytes)
 * @param requiredBits Number of leading zero bits required
 * @param[out] nonce Output nonce that satisfies the PoW requirement
 * @return true if nonce found
 */
bool MineRegistrationPoW(const std::vector<uint8_t>& pubkey, int requiredBits, uint64_t& nonce);

// ============================================================================
// DFMP V2.0 CONSTANTS
// ============================================================================

/** DFMP v2.0: Observation window (360 blocks = 24 hours at 4 min/block) */
constexpr int OBSERVATION_WINDOW_V2 = 360;

/** DFMP v2.0: Free tier threshold (20 blocks per window) */
constexpr int FREE_TIER_THRESHOLD_V2 = 20;

/** DFMP v2.0: Linear zone upper bound (blocks 21-25) */
constexpr int LINEAR_ZONE_UPPER_V2 = 25;

/** DFMP v2.0: Exponential growth rate (1.08 per block over linear zone) */
constexpr double HEAT_GROWTH_RATE_V2 = 1.08;

/** DFMP v2.0: Maturity blocks (400 blocks for full penalty decay) */
constexpr int MATURITY_BLOCKS_V2 = 400;

/** DFMP v2.0: Maturity step size (penalty drops every 100 blocks) */
constexpr int MATURITY_STEP_V2 = 100;

/** DFMP v2.0: Starting maturity penalty for new MIK */
constexpr double MATURITY_PENALTY_START_V2 = 3.0;

// Fixed-point versions for deterministic calculation
// Note: FP_SCALE is defined in dfmp.h
constexpr int64_t FP_LINEAR_INCREMENT_V2 = 100000;    // 0.1 × FP_SCALE (v2.0 linear zone step)
constexpr int64_t FP_LINEAR_BASE_V2 = 1500000;        // 1.5 × FP_SCALE (v2.0 exponential zone start)
constexpr int64_t FP_MATURITY_START_V2 = 3000000;     // 3.0 × FP_SCALE
constexpr int64_t FP_MATURITY_STEP_25 = 2500000;      // 2.5 × FP_SCALE
constexpr int64_t FP_MATURITY_STEP_20 = 2000000;      // 2.0 × FP_SCALE
constexpr int64_t FP_MATURITY_STEP_15 = 1500000;      // 1.5 × FP_SCALE

// ============================================================================
// DFMP V2.0 PENALTY CALCULATIONS
// ============================================================================

/**
 * Calculate maturity penalty (v2.0) - fixed-point
 *
 * NO first-block grace - new MIKs start at 3.0x
 * Step-wise decay: 3.0x → 2.5x → 2.0x → 1.5x → 1.0x over 400 blocks
 *
 * @param currentHeight Current block height
 * @param firstSeenHeight Height where MIK was first seen (-1 for new)
 * @return Maturity penalty × FP_SCALE
 */
int64_t CalculateMaturityPenaltyFP_V2(int currentHeight, int firstSeenHeight);

/**
 * Calculate heat penalty (v2.0) - fixed-point
 *
 * Uses 360-block observation window:
 * - 0-20 blocks: Free tier (1.0x)
 * - 21-25 blocks: Linear zone (1.0x → 1.5x)
 * - 26+ blocks: Exponential (1.5 × 1.08^(blocks-25))
 *
 * @param blocksInWindow Number of blocks by this identity in the window
 * @return Heat penalty × FP_SCALE
 */
int64_t CalculateHeatPenaltyFP_V2(int blocksInWindow);

/**
 * Calculate total DFMP v2.0 multiplier - fixed-point
 *
 * Total = maturity_penalty × heat_penalty
 *
 * @param currentHeight Current block height
 * @param firstSeenHeight Height where MIK was first seen (-1 for new)
 * @param blocksInWindow Number of blocks by this MIK in observation window
 * @return Total multiplier × FP_SCALE
 */
int64_t CalculateTotalMultiplierFP_V2(int currentHeight, int firstSeenHeight, int blocksInWindow);

/**
 * Get maturity penalty as double (for display/logging)
 */
double GetMaturityPenalty_V2(int currentHeight, int firstSeenHeight);

/**
 * Get heat penalty as double (for display/logging)
 */
double GetHeatPenalty_V2(int blocksInWindow);

/**
 * Get total multiplier as double (for display/logging)
 */
double GetTotalMultiplier_V2(int currentHeight, int firstSeenHeight, int blocksInWindow);

} // namespace DFMP

#endif // DILITHION_DFMP_MIK_H
