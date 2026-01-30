// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <dfmp/mik.h>
#include <crypto/sha3.h>
#include <wallet/crypter.h>  // For memory_cleanse()

#include <cstring>
#include <algorithm>
#include <iostream>

// Dilithium3 reference implementation
extern "C" {
    int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
    int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *sk);
    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

namespace DFMP {

// ============================================================================
// CMiningIdentityKey IMPLEMENTATION
// ============================================================================

CMiningIdentityKey::CMiningIdentityKey() {
    // Default constructor - creates empty/invalid MIK
}

CMiningIdentityKey::~CMiningIdentityKey() {
    Clear();
}

CMiningIdentityKey::CMiningIdentityKey(CMiningIdentityKey&& other) noexcept
    : pubkey(std::move(other.pubkey)),
      privkey(std::move(other.privkey)),
      identity(other.identity) {
    // Clear the moved-from identity
    std::memset(other.identity.data, 0, sizeof(other.identity.data));
}

CMiningIdentityKey& CMiningIdentityKey::operator=(CMiningIdentityKey&& other) noexcept {
    if (this != &other) {
        // Clear current data
        Clear();

        // Move data from other
        pubkey = std::move(other.pubkey);
        privkey = std::move(other.privkey);
        identity = other.identity;

        // Clear the moved-from identity
        std::memset(other.identity.data, 0, sizeof(other.identity.data));
    }
    return *this;
}

bool CMiningIdentityKey::IsValid() const {
    return pubkey.size() == MIK_PUBKEY_SIZE && !identity.IsNull();
}

bool CMiningIdentityKey::HasPrivateKey() const {
    return privkey.size() == MIK_PRIVKEY_SIZE;
}

bool CMiningIdentityKey::Generate() {
    // Allocate space for keys
    pubkey.resize(MIK_PUBKEY_SIZE);
    privkey.resize(MIK_PRIVKEY_SIZE);

    // Generate Dilithium3 keypair
    int result = pqcrystals_dilithium3_ref_keypair(pubkey.data(), privkey.data());
    if (result != 0) {
        Clear();
        return false;
    }

    // Derive identity from public key
    identity = DeriveIdentityFromMIK(pubkey);
    if (identity.IsNull()) {
        Clear();
        return false;
    }

    return true;
}

bool CMiningIdentityKey::Sign(const uint256& prevHash, int height, uint32_t timestamp,
                               std::vector<uint8_t>& signature) const {
    if (!HasPrivateKey()) {
        return false;
    }

    // Build the message to sign
    std::vector<uint8_t> message = BuildMIKSignatureMessage(prevHash, height, timestamp, identity);

    // Allocate signature buffer
    signature.resize(MIK_SIGNATURE_SIZE);
    size_t siglen = 0;

    // Sign with Dilithium3
    // Context is empty for MIK signatures
    int result = pqcrystals_dilithium3_ref_signature(
        signature.data(), &siglen,
        message.data(), message.size(),
        nullptr, 0,  // No context
        privkey.data()
    );

    if (result != 0 || siglen != MIK_SIGNATURE_SIZE) {
        signature.clear();
        return false;
    }

    return true;
}

void CMiningIdentityKey::Clear() {
    // Securely wipe private key
    if (!privkey.empty()) {
        memory_cleanse(privkey.data(), privkey.size());
    }
    privkey.clear();

    // Clear public key (not sensitive, but for completeness)
    pubkey.clear();

    // Clear identity
    std::memset(identity.data, 0, sizeof(identity.data));
}

std::string CMiningIdentityKey::GetIdentityHex() const {
    return identity.GetHex();
}

void CMiningIdentityKey::SerializePublic(std::vector<uint8_t>& data) const {
    // Format: [pubkey: 1952 bytes]
    data = pubkey;
}

bool CMiningIdentityKey::DeserializePublic(const std::vector<uint8_t>& data) {
    if (data.size() != MIK_PUBKEY_SIZE) {
        return false;
    }

    pubkey = data;
    identity = DeriveIdentityFromMIK(pubkey);
    privkey.clear();  // Public-only deserialization

    return !identity.IsNull();
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

std::vector<uint8_t> BuildMIKSignatureMessage(
    const uint256& prevHash,
    int height,
    uint32_t timestamp,
    const Identity& identity) {
    // Message format: SHA3-256(prevBlockHash || height || timestamp || identity)
    // This commits to the chain position without requiring the block hash
    // (which would create a circular dependency)

    // Build the preimage
    // prevHash: 32 bytes
    // height: 4 bytes (little-endian)
    // timestamp: 4 bytes (little-endian)
    // identity: 20 bytes
    // Total: 60 bytes

    std::vector<uint8_t> preimage;
    preimage.reserve(60);

    // Previous block hash (32 bytes)
    preimage.insert(preimage.end(), prevHash.data, prevHash.data + 32);

    // Height (4 bytes, little-endian)
    uint32_t h = static_cast<uint32_t>(height);
    preimage.push_back(static_cast<uint8_t>(h & 0xFF));
    preimage.push_back(static_cast<uint8_t>((h >> 8) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((h >> 16) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((h >> 24) & 0xFF));

    // Timestamp (4 bytes, little-endian)
    preimage.push_back(static_cast<uint8_t>(timestamp & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 8) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 16) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 24) & 0xFF));

    // Identity (20 bytes)
    preimage.insert(preimage.end(), identity.data, identity.data + 20);

    // Hash the preimage
    std::vector<uint8_t> message(32);
    SHA3_256(preimage.data(), preimage.size(), message.data());

    return message;
}

bool VerifyMIKSignature(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    const uint256& prevHash,
    int height,
    uint32_t timestamp,
    const Identity& identity) {
    // Validate input sizes
    if (pubkey.size() != MIK_PUBKEY_SIZE) {
        return false;
    }
    if (signature.size() != MIK_SIGNATURE_SIZE) {
        return false;
    }

    // Verify identity matches pubkey
    Identity derivedIdentity = DeriveIdentityFromMIK(pubkey);
    if (derivedIdentity != identity) {
        std::cerr << "[MIK-DEBUG] Identity mismatch: derived=" << derivedIdentity.GetHex()
                  << " claimed=" << identity.GetHex() << std::endl;
        return false;
    }

    // Build the message
    std::vector<uint8_t> message = BuildMIKSignatureMessage(prevHash, height, timestamp, identity);

    // Verify signature
    int result = pqcrystals_dilithium3_ref_verify(
        signature.data(), signature.size(),
        message.data(), message.size(),
        nullptr, 0,  // No context
        pubkey.data()
    );

    if (result != 0) {
        std::cerr << "[MIK-DEBUG] Crypto verify failed: result=" << result
                  << " prevHash=" << prevHash.GetHex().substr(0, 16) << "..."
                  << " height=" << height << " timestamp=" << timestamp << std::endl;
    }

    return result == 0;
}

Identity DeriveIdentityFromMIK(const std::vector<uint8_t>& pubkey) {
    if (pubkey.size() != MIK_PUBKEY_SIZE) {
        return Identity();  // Null identity
    }

    // Hash the public key with SHA3-256
    uint8_t hash[32];
    SHA3_256(pubkey.data(), pubkey.size(), hash);

    // Take first 20 bytes as identity
    return Identity(hash);
}

// ============================================================================
// SCRIPTSIG PARSING
// ============================================================================

bool ParseMIKFromScriptSig(
    const std::vector<uint8_t>& scriptSig,
    CMIKScriptData& mikData) {
    // Look for MIK_MARKER (0xDF) in the scriptSig
    // Typically after the height encoding and any extra nonce

    // Minimum size check: marker(1) + type(1) + identity(20) + sig(3309) = 3331
    if (scriptSig.size() < MIK_REFERENCE_MIN_SIZE) {
        return false;
    }

    // Search for MIK_MARKER
    // It should appear after the height (BIP 34) which is typically 1-4 bytes
    // We'll search from the beginning but skip obvious height encoding
    size_t pos = 0;

    // Skip height encoding (1 byte length + up to 4 bytes data)
    if (scriptSig.size() > 0) {
        uint8_t heightLen = scriptSig[0];
        if (heightLen >= 1 && heightLen <= 4 && scriptSig.size() > heightLen) {
            pos = 1 + heightLen;
        }
    }

    // Search for MIK_MARKER from current position
    while (pos < scriptSig.size()) {
        if (scriptSig[pos] == MIK_MARKER) {
            // Found marker, parse MIK data
            pos++;
            if (pos >= scriptSig.size()) {
                return false;  // No type byte
            }

            uint8_t mikType = scriptSig[pos];
            pos++;

            if (mikType == MIK_TYPE_REGISTRATION) {
                // Registration: pubkey(1952) + signature(3309)
                size_t requiredSize = MIK_PUBKEY_SIZE + MIK_SIGNATURE_SIZE;
                if (pos + requiredSize > scriptSig.size()) {
                    return false;  // Not enough data
                }

                mikData.isRegistration = true;

                // Extract public key
                mikData.pubkey.assign(
                    scriptSig.begin() + pos,
                    scriptSig.begin() + pos + MIK_PUBKEY_SIZE
                );
                pos += MIK_PUBKEY_SIZE;

                // Derive identity from pubkey
                mikData.identity = DeriveIdentityFromMIK(mikData.pubkey);
                if (mikData.identity.IsNull()) {
                    return false;
                }

                // Extract signature
                mikData.signature.assign(
                    scriptSig.begin() + pos,
                    scriptSig.begin() + pos + MIK_SIGNATURE_SIZE
                );

                return true;

            } else if (mikType == MIK_TYPE_REFERENCE) {
                // Reference: identity(20) + signature(3309)
                size_t requiredSize = MIK_IDENTITY_SIZE + MIK_SIGNATURE_SIZE;
                if (pos + requiredSize > scriptSig.size()) {
                    return false;  // Not enough data
                }

                mikData.isRegistration = false;

                // Extract identity
                mikData.identity = Identity(scriptSig.data() + pos);
                pos += MIK_IDENTITY_SIZE;

                // No pubkey for reference (must be looked up)
                mikData.pubkey.clear();

                // Extract signature
                mikData.signature.assign(
                    scriptSig.begin() + pos,
                    scriptSig.begin() + pos + MIK_SIGNATURE_SIZE
                );

                return true;

            } else {
                // Unknown MIK type, continue searching
                continue;
            }
        }
        pos++;
    }

    return false;  // No MIK data found
}

bool BuildMIKScriptSigRegistration(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    std::vector<uint8_t>& data) {
    if (pubkey.size() != MIK_PUBKEY_SIZE) {
        return false;
    }
    if (signature.size() != MIK_SIGNATURE_SIZE) {
        return false;
    }

    // Format: [MIK_MARKER] [MIK_TYPE_REGISTRATION] [pubkey] [signature]
    data.clear();
    data.reserve(1 + 1 + MIK_PUBKEY_SIZE + MIK_SIGNATURE_SIZE);

    data.push_back(MIK_MARKER);
    data.push_back(MIK_TYPE_REGISTRATION);
    data.insert(data.end(), pubkey.begin(), pubkey.end());
    data.insert(data.end(), signature.begin(), signature.end());

    return true;
}

bool BuildMIKScriptSigReference(
    const Identity& identity,
    const std::vector<uint8_t>& signature,
    std::vector<uint8_t>& data) {
    if (identity.IsNull()) {
        return false;
    }
    if (signature.size() != MIK_SIGNATURE_SIZE) {
        return false;
    }

    // Format: [MIK_MARKER] [MIK_TYPE_REFERENCE] [identity] [signature]
    data.clear();
    data.reserve(1 + 1 + MIK_IDENTITY_SIZE + MIK_SIGNATURE_SIZE);

    data.push_back(MIK_MARKER);
    data.push_back(MIK_TYPE_REFERENCE);
    data.insert(data.end(), identity.data, identity.data + MIK_IDENTITY_SIZE);
    data.insert(data.end(), signature.begin(), signature.end());

    return true;
}

// ============================================================================
// DFMP V2.0 PENALTY CALCULATIONS
// ============================================================================

int64_t CalculateMaturityPenaltyFP_V2(int currentHeight, int firstSeenHeight) {
    // v2.0: NO first-block grace - new MIKs start at 3.0x
    if (firstSeenHeight < 0) {
        return FP_MATURITY_START_V2;  // 3.0x for new MIK
    }

    int age = currentHeight - firstSeenHeight;

    // Step-wise decay over 400 blocks (100 block steps)
    if (age < 100) {
        return FP_MATURITY_START_V2;   // 3.0x (blocks 0-99)
    }
    if (age < 200) {
        return FP_MATURITY_STEP_25;    // 2.5x (blocks 100-199)
    }
    if (age < 300) {
        return FP_MATURITY_STEP_20;    // 2.0x (blocks 200-299)
    }
    if (age < 400) {
        return FP_MATURITY_STEP_15;    // 1.5x (blocks 300-399)
    }

    return FP_SCALE;  // 1.0x (mature, 400+ blocks)
}

int64_t CalculateHeatPenaltyFP_V2(int blocksInWindow) {
    // Free tier: 0-20 blocks → 1.0x
    if (blocksInWindow <= FREE_TIER_THRESHOLD_V2) {
        return FP_SCALE;  // 1.0x
    }

    // Linear zone: 21-25 blocks → 1.0x to 1.5x
    // Formula: 1.0 + 0.1 × (blocks - 20)
    if (blocksInWindow <= LINEAR_ZONE_UPPER_V2) {
        int64_t linearPart = FP_LINEAR_INCREMENT * (blocksInWindow - FREE_TIER_THRESHOLD_V2);
        return FP_SCALE + linearPart;  // 1.1x to 1.5x
    }

    // Exponential zone: 26+ blocks → 1.5 × 1.08^(blocks - 25)
    // Start at 1.5x and multiply by 1.08 for each block over 25
    int64_t penalty = FP_MATURITY_STEP_15;  // 1.5 × FP_SCALE = 1,500,000
    int exponent = blocksInWindow - LINEAR_ZONE_UPPER_V2;

    // Multiply by 1.08 for each block over 25
    // Using fixed-point: × 1.08 = × 108 / 100
    for (int i = 0; i < exponent; i++) {
        penalty = (penalty * 108) / 100;
    }

    return penalty;
}

int64_t CalculateTotalMultiplierFP_V2(int currentHeight, int firstSeenHeight, int blocksInWindow) {
    int64_t maturityFP = CalculateMaturityPenaltyFP_V2(currentHeight, firstSeenHeight);
    int64_t heatFP = CalculateHeatPenaltyFP_V2(blocksInWindow);

    // total = maturity × heat
    // In fixed-point: total_fp = (maturity_fp × heat_fp) / FP_SCALE
    return (maturityFP * heatFP) / FP_SCALE;
}

double GetMaturityPenalty_V2(int currentHeight, int firstSeenHeight) {
    return static_cast<double>(CalculateMaturityPenaltyFP_V2(currentHeight, firstSeenHeight)) / FP_SCALE;
}

double GetHeatPenalty_V2(int blocksInWindow) {
    return static_cast<double>(CalculateHeatPenaltyFP_V2(blocksInWindow)) / FP_SCALE;
}

double GetTotalMultiplier_V2(int currentHeight, int firstSeenHeight, int blocksInWindow) {
    return static_cast<double>(CalculateTotalMultiplierFP_V2(currentHeight, firstSeenHeight, blocksInWindow)) / FP_SCALE;
}

} // namespace DFMP
