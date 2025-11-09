// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_WALLET_HD_DERIVATION_H
#define DILITHION_WALLET_HD_DERIVATION_H

#include <stdint.h>
#include <string>
#include <vector>

/**
 * HD Wallet Key Derivation for Dilithium (BIP32/BIP44 adapted for post-quantum)
 *
 * Unlike ECDSA-based HD wallets that use elliptic curve point multiplication,
 * Dilithium HD derivation uses HMAC-SHA3-512 as a KDF to derive child seeds.
 *
 * BIP44 Path Structure: m / purpose' / coin_type' / account' / change / address_index
 * Dilithion: m / 44' / 573' / account' / change / address_index
 *
 * Hardened derivation (') is used for levels 0-2 (purpose, coin_type, account)
 * Normal derivation is used for levels 3-4 (change, address_index)
 *
 * Security Note: For Dilithium, we only support hardened derivation at all levels
 * to prevent public key-based attacks.
 */

// Hardened index threshold
#define HD_HARDENED_BIT 0x80000000

// Master seed derivation key
#define HD_MASTER_KEY "Dilithion seed"

/**
 * CHDExtendedKey - Extended key structure for HD derivation
 *
 * An extended key consists of:
 * - seed (32 bytes): Used to generate Dilithium keypair
 * - chaincode (32 bytes): Used for child key derivation
 * - metadata: depth, fingerprint, child_index for tracking
 */
class CHDExtendedKey {
public:
    uint8_t seed[32];          // 32-byte seed for key generation
    uint8_t chaincode[32];     // 32-byte chain code for derivation
    uint32_t depth;            // Depth in the derivation tree (0 = master)
    uint32_t fingerprint;      // Parent key fingerprint (first 4 bytes of parent pubkey hash)
    uint32_t child_index;      // Index of this child

    CHDExtendedKey();

    /**
     * Wipe sensitive data from memory
     */
    void Wipe();

    /**
     * Check if this is a master key (depth = 0)
     */
    bool IsMaster() const { return depth == 0; }

    /**
     * Get fingerprint of this key (for child derivation)
     */
    uint32_t GetFingerprint() const;
};

/**
 * CHDKeyPath - BIP44 hierarchical deterministic key path
 *
 * Parses and validates BIP44 paths like:
 * - m/44'/573'/0'/0/0  (first receive address)
 * - m/44'/573'/0'/1/0  (first change address)
 * - m/44'/573'/2'/0/5  (6th receive address of account 2)
 */
class CHDKeyPath {
public:
    std::vector<uint32_t> indices;  // Path indices (with hardened bit if applicable)

    CHDKeyPath() {}
    CHDKeyPath(const std::string& path);

    /**
     * Parse BIP44 path string
     *
     * @param path Path string (e.g., "m/44'/573'/0'/0/0")
     * @return true if valid, false otherwise
     */
    bool Parse(const std::string& path);

    /**
     * Convert back to string
     */
    std::string ToString() const;

    /**
     * Validate BIP44 path for Dilithion
     *
     * Checks:
     * - Exactly 5 levels (purpose, coin_type, account, change, index)
     * - purpose = 44'
     * - coin_type = 573'
     * - account is hardened
     * - change is 0 or 1
     * - index < gap limit
     */
    bool IsValid() const;

    /**
     * Check if index is hardened
     */
    static bool IsHardened(uint32_t index) { return index >= HD_HARDENED_BIT; }

    /**
     * Create standard receive address path
     */
    static CHDKeyPath ReceiveAddress(uint32_t account, uint32_t index);

    /**
     * Create standard change address path
     */
    static CHDKeyPath ChangeAddress(uint32_t account, uint32_t index);

    /**
     * Comparison operators for use in maps
     */
    bool operator==(const CHDKeyPath& other) const {
        return indices == other.indices;
    }

    bool operator<(const CHDKeyPath& other) const {
        return indices < other.indices;
    }
};

/**
 * Derive master extended key from BIP39 seed
 *
 * Uses HMAC-SHA3-512 with key "Dilithion seed" to derive master extended key.
 *
 * @param seed 64-byte BIP39 seed (from mnemonic + passphrase)
 * @param master_key Output master extended key
 */
void DeriveMaster(const uint8_t seed[64], CHDExtendedKey& master_key);

/**
 * Derive child extended key from parent extended key
 *
 * Uses HMAC-SHA3-512(parent_chaincode, parent_seed || index) to derive child.
 * For security, only hardened derivation is supported for Dilithium.
 *
 * @param parent Parent extended key
 * @param index Child index (must be hardened: >= 0x80000000)
 * @param child Output child extended key
 * @return true on success, false if index is not hardened
 */
bool DeriveChild(const CHDExtendedKey& parent, uint32_t index, CHDExtendedKey& child);

/**
 * Derive extended key at specific BIP44 path
 *
 * Starts from master key and derives through the full path.
 *
 * @param master Master extended key
 * @param path BIP44 path (e.g., "m/44'/573'/0'/0/0")
 * @param derived Output extended key at path
 * @return true on success, false on invalid path
 */
bool DerivePath(const CHDExtendedKey& master, const std::string& path, CHDExtendedKey& derived);

/**
 * Derive extended key at specific BIP44 path (vector form)
 *
 * @param master Master extended key
 * @param path Parsed BIP44 path indices
 * @param derived Output extended key at path
 * @return true on success, false on invalid path
 */
bool DerivePath(const CHDExtendedKey& master, const CHDKeyPath& path, CHDExtendedKey& derived);

/**
 * Generate Dilithium keypair from extended key
 *
 * Uses the extended key's seed to generate a deterministic Dilithium keypair.
 *
 * @param ext_key Extended key
 * @param public_key Output buffer for public key (1952 bytes)
 * @param secret_key Output buffer for secret key (4000 bytes)
 * @return true on success
 */
bool GenerateDilithiumKey(const CHDExtendedKey& ext_key,
                          uint8_t* public_key, uint8_t* secret_key);

/**
 * Compute key fingerprint (first 4 bytes of SHA3-256(public_key))
 *
 * Used for tracking parent-child relationships.
 *
 * @param public_key Dilithium public key (1952 bytes)
 * @return 32-bit fingerprint
 */
uint32_t ComputeFingerprint(const uint8_t* public_key);

#endif // DILITHION_WALLET_HD_DERIVATION_H
