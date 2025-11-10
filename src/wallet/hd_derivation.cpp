// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/hd_derivation.h>
#include <crypto/hmac_sha3.h>
#include <crypto/sha3.h>
#include <cstring>
#include <sstream>
#include <algorithm>

// Dilithium API
extern "C" {
    #include <api.h>
}

// ============================================================================
// CHDExtendedKey Implementation
// ============================================================================

CHDExtendedKey::CHDExtendedKey() {
    std::memset(seed, 0, 32);
    std::memset(chaincode, 0, 32);
    depth = 0;
    fingerprint = 0;
    child_index = 0;
}

void CHDExtendedKey::Wipe() {
    std::memset(seed, 0, 32);
    std::memset(chaincode, 0, 32);
    depth = 0;
    fingerprint = 0;
    child_index = 0;
}

uint32_t CHDExtendedKey::GetFingerprint() const {
    // WL-013 FIX: Detailed documentation for fingerprint calculation edge cases

    // FINGERPRINT CALCULATION PROCESS:
    // 1. Generate Dilithium3 keypair from extended key's seed (deterministic)
    // 2. Hash public key with SHA3-256
    // 3. Take first 4 bytes of hash as fingerprint (big-endian uint32)
    //
    // EDGE CASE: Dilithium rejection sampling failure
    // - Dilithium3 uses rejection sampling for key generation
    // - In rare cases (<0.1%), sampling may fail and require retry
    // - If pqcrystals_dilithium3_ref_keypair_from_seed returns non-zero:
    //   * Buffers are wiped for security
    //   * Return fingerprint of 0 to indicate error
    //   * Calling code should treat 0 as invalid fingerprint
    // - Master keys have fingerprint 0 by convention (no parent)
    //
    // EDGE CASE: Fingerprint collision
    // - 32-bit fingerprint → 2^32 possible values
    // - Birthday paradox: ~50% collision chance after 2^16 (65,536) keys
    // - Fingerprints are for quick lookups only, NOT security-critical identifiers
    // - Always verify full public key for security-critical operations

    // Generate public key from this extended key's seed
    uint8_t pk[pqcrystals_dilithium3_ref_PUBLICKEYBYTES];
    uint8_t sk[pqcrystals_dilithium3_ref_SECRETKEYBYTES];

    // WL-008 FIX: Check return value from Dilithium keygen
    int result = pqcrystals_dilithium3_ref_keypair_from_seed(pk, sk, seed);
    if (result != 0) {
        // Key generation failed - wipe buffers and return zero fingerprint
        std::memset(pk, 0, sizeof(pk));
        std::memset(sk, 0, sizeof(sk));
        return 0;  // Zero fingerprint indicates error (also used for master key)
    }

    // Compute fingerprint
    uint32_t fp = ComputeFingerprint(pk);

    // Wipe secret key
    std::memset(sk, 0, sizeof(sk));

    return fp;
}

// ============================================================================
// CHDKeyPath Implementation
// ============================================================================

CHDKeyPath::CHDKeyPath(const std::string& path) {
    Parse(path);
}

bool CHDKeyPath::Parse(const std::string& path) {
    indices.clear();

    // Must start with "m" or "m/"
    if (path.empty() || path[0] != 'm') {
        return false;
    }

    size_t pos = 1;
    if (pos < path.length() && path[pos] == '/') {
        pos++;
    } else if (pos < path.length()) {
        return false;  // Must be "m" or "m/..."
    }

    // Parse each level
    while (pos < path.length()) {
        // Find next slash or end
        size_t slash_pos = path.find('/', pos);
        if (slash_pos == std::string::npos) {
            slash_pos = path.length();
        }

        std::string level_str = path.substr(pos, slash_pos - pos);
        if (level_str.empty()) {
            return false;
        }

        // Check for hardened marker (')
        bool hardened = false;
        if (level_str.back() == '\'') {
            hardened = true;
            level_str = level_str.substr(0, level_str.length() - 1);
        }

        // Parse index
        uint32_t index = 0;
        try {
            // Use stoul for unsigned conversion
            unsigned long val = std::stoul(level_str);
            if (val >= HD_HARDENED_BIT) {
                return false;  // Index too large
            }
            index = static_cast<uint32_t>(val);
        } catch (...) {
            return false;  // Invalid number
        }

        // Add hardened bit if necessary
        if (hardened) {
            index |= HD_HARDENED_BIT;
        }

        indices.push_back(index);

        // Move to next level
        pos = slash_pos + 1;
    }

    return true;
}

std::string CHDKeyPath::ToString() const {
    std::ostringstream oss;
    oss << "m";

    for (uint32_t index : indices) {
        oss << "/";

        bool hardened = (index >= HD_HARDENED_BIT);
        if (hardened) {
            index &= ~HD_HARDENED_BIT;  // Remove hardened bit
        }

        oss << index;
        if (hardened) {
            oss << "'";
        }
    }

    return oss.str();
}

bool CHDKeyPath::IsValid() const {
    // Must have exactly 5 levels (purpose, coin_type, account, change, address_index)
    if (indices.size() != 5) {
        return false;
    }

    // Level 0: purpose must be 44'
    if (indices[0] != (44 | HD_HARDENED_BIT)) {
        return false;
    }

    // Level 1: coin_type must be 573' (Dilithion)
    if (indices[1] != (573 | HD_HARDENED_BIT)) {
        return false;
    }

    // Level 2: account must be hardened
    if (!IsHardened(indices[2])) {
        return false;
    }

    // Level 3: change must be 0 or 1 (receive or change chain)
    // For Dilithium security, we require hardened derivation at all levels
    if (!IsHardened(indices[3])) {
        return false;
    }
    uint32_t change = indices[3] & ~HD_HARDENED_BIT;
    if (change != 0 && change != 1) {
        return false;
    }

    // Level 4: address_index (for Dilithium, require hardened)
    if (!IsHardened(indices[4])) {
        return false;
    }

    return true;
}

CHDKeyPath CHDKeyPath::ReceiveAddress(uint32_t account, uint32_t index) {
    CHDKeyPath path;
    path.indices = {
        44 | HD_HARDENED_BIT,      // purpose
        573 | HD_HARDENED_BIT,     // coin_type (Dilithion)
        account | HD_HARDENED_BIT, // account
        0 | HD_HARDENED_BIT,       // change (0 = receive)
        index | HD_HARDENED_BIT    // address_index
    };
    return path;
}

CHDKeyPath CHDKeyPath::ChangeAddress(uint32_t account, uint32_t index) {
    CHDKeyPath path;
    path.indices = {
        44 | HD_HARDENED_BIT,      // purpose
        573 | HD_HARDENED_BIT,     // coin_type (Dilithion)
        account | HD_HARDENED_BIT, // account
        1 | HD_HARDENED_BIT,       // change (1 = change)
        index | HD_HARDENED_BIT    // address_index
    };
    return path;
}

// ============================================================================
// HD Derivation Functions
// ============================================================================

void DeriveMaster(const uint8_t seed[64], CHDExtendedKey& master_key) {
    // Use HMAC-SHA3-512 with key "Dilithion seed"
    const char* hmac_key = HD_MASTER_KEY;
    uint8_t output[64];

    HMAC_SHA3_512(reinterpret_cast<const uint8_t*>(hmac_key), std::strlen(hmac_key),
                  seed, 64, output);

    // Split output: first 32 bytes = seed, last 32 bytes = chaincode
    std::memcpy(master_key.seed, output, 32);
    std::memcpy(master_key.chaincode, output + 32, 32);

    // Set master key metadata
    master_key.depth = 0;
    master_key.fingerprint = 0;  // Master has no parent
    master_key.child_index = 0;

    // Wipe output
    std::memset(output, 0, 64);
}

bool DeriveChild(const CHDExtendedKey& parent, uint32_t index, CHDExtendedKey& child) {
    // WL-013 FIX: Detailed documentation for edge case handling

    // HARDENED VS NON-HARDENED DERIVATION:
    // - Non-hardened (index < 2^31): Would allow public key derivation without private key
    //   SECURITY RISK for Dilithium: Quantum computers could break non-hardened derivation
    // - Hardened (index >= 2^31): Requires private key, quantum-resistant
    // - For Dilithium security, we ONLY support hardened derivation (index >= HD_HARDENED_BIT)
    // - This prevents any public key derivation attacks from quantum adversaries

    // DERIVATION INDEX OVERFLOW HANDLING:
    // - Valid indices: 0 to 2^32-1
    // - Hardened indices: 2^31 to 2^32-1 (represented with ' notation, e.g., 0' = 2^31)
    // - If index < HD_HARDENED_BIT (2^31), derivation is rejected
    // - Maximum derivation index: 2^32-1 (hardened index 2^31-1, shown as 2147483647')
    // - Attempting to derive with index >= 2^32 would require using a different child path level
    //   (e.g., increment account level and reset address_index to 0')

    if (index < HD_HARDENED_BIT) {
        return false;  // Reject non-hardened derivation for quantum security
    }

    // Prepare HMAC input: parent_seed || index (big-endian)
    uint8_t hmac_data[32 + 4];
    std::memcpy(hmac_data, parent.seed, 32);
    hmac_data[32] = (index >> 24) & 0xFF;
    hmac_data[33] = (index >> 16) & 0xFF;
    hmac_data[34] = (index >> 8) & 0xFF;
    hmac_data[35] = index & 0xFF;

    // HMAC-SHA3-512(parent_chaincode, parent_seed || index)
    uint8_t output[64];
    HMAC_SHA3_512(parent.chaincode, 32, hmac_data, 36, output);

    // Split output: first 32 bytes = child seed, last 32 bytes = child chaincode
    std::memcpy(child.seed, output, 32);
    std::memcpy(child.chaincode, output + 32, 32);

    // Set child metadata
    child.depth = parent.depth + 1;
    child.fingerprint = parent.GetFingerprint();
    child.child_index = index;

    // Wipe sensitive data
    std::memset(hmac_data, 0, 36);
    std::memset(output, 0, 64);

    return true;
}

bool DerivePath(const CHDExtendedKey& master, const std::string& path, CHDExtendedKey& derived) {
    CHDKeyPath parsed_path(path);
    return DerivePath(master, parsed_path, derived);
}

bool DerivePath(const CHDExtendedKey& master, const CHDKeyPath& path, CHDExtendedKey& derived) {
    // Validate path
    if (!path.IsValid()) {
        return false;
    }

    // Start with master key
    derived = master;

    // Derive through each level
    for (uint32_t index : path.indices) {
        CHDExtendedKey child;
        if (!DeriveChild(derived, index, child)) {
            derived.Wipe();
            return false;
        }
        derived = child;
    }

    return true;
}

bool GenerateDilithiumKey(const CHDExtendedKey& ext_key,
                          uint8_t* public_key, uint8_t* secret_key) {
    // Generate keypair from extended key's seed using deterministic function
    int result = pqcrystals_dilithium3_ref_keypair_from_seed(public_key, secret_key, ext_key.seed);
    return (result == 0);
}

uint32_t ComputeFingerprint(const uint8_t* public_key) {
    // Hash public key with SHA3-256
    uint8_t hash[32];
    SHA3_256(public_key, pqcrystals_dilithium3_ref_PUBLICKEYBYTES, hash);

    // Return first 4 bytes as fingerprint (big-endian)
    uint32_t fingerprint = (static_cast<uint32_t>(hash[0]) << 24) |
                           (static_cast<uint32_t>(hash[1]) << 16) |
                           (static_cast<uint32_t>(hash[2]) << 8) |
                           static_cast<uint32_t>(hash[3]);

    return fingerprint;
}
