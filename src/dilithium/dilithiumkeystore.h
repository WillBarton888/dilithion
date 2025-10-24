// Copyright (c) 2025 The Dilithion Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DILITHIUM_DILITHIUMKEYSTORE_H
#define BITCOIN_DILITHIUM_DILITHIUMKEYSTORE_H

#include <dilithium/dilithiumkey.h>
#include <dilithium/dilithiumpubkey.h>
#include <uint256.h>

#include <map>
#include <string>
#include <vector>

/**
 * Metadata for a stored Dilithium key
 */
struct DilithiumKeyMetadata {
    std::string keyid;          // Unique identifier (hash of pubkey)
    std::string label;          // User-provided label
    int64_t created_time;       // Unix timestamp when key was added
    int64_t last_used_time;     // Unix timestamp of last use
    uint64_t usage_count;       // Number of times key was used for signing

    DilithiumKeyMetadata()
        : created_time(0), last_used_time(0), usage_count(0) {}
};

/**
 * Information about a stored key (for RPC responses)
 */
struct DilithiumKeyInfo {
    std::string keyid;
    DilithiumPubKey pubkey;
    std::string label;
    int64_t created_time;
    int64_t last_used_time;
    uint64_t usage_count;
};

/**
 * In-memory keystore for Dilithium keys
 *
 * This class provides storage and management for Dilithium private keys.
 * Keys are stored in memory only (not persisted to disk in this version).
 *
 * Thread Safety: Not thread-safe. Callers must provide external synchronization
 *                if accessing from multiple threads.
 *
 * Key IDs: Deterministically generated as the first 16 hex characters of
 *          SHA256(pubkey). This ensures the same key always gets the same ID.
 */
class DilithiumKeyStore
{
private:
    // Map from keyid to private key
    std::map<std::string, DilithiumKey> keys;

    // Map from keyid to metadata
    std::map<std::string, DilithiumKeyMetadata> metadata;

    // Map from pubkey hex to keyid (for reverse lookup)
    std::map<std::string, std::string> pubkey_to_keyid;

public:
    DilithiumKeyStore() = default;
    ~DilithiumKeyStore() = default;

    /**
     * Add a key to the store
     *
     * @param key The Dilithium private key to store
     * @param label User-provided label for the key
     * @param[out] keyid The generated key ID
     * @return true if key was added, false if key already exists
     */
    bool AddKey(const DilithiumKey& key, const std::string& label, std::string& keyid);

    /**
     * Get a key by its ID
     *
     * @param keyid The key identifier
     * @param[out] key The retrieved key
     * @return true if key was found, false otherwise
     */
    bool GetKey(const std::string& keyid, DilithiumKey& key) const;

    /**
     * Get a key by its public key
     *
     * @param pubkey The public key
     * @param[out] key The retrieved private key
     * @return true if key was found, false otherwise
     */
    bool GetKeyByPubKey(const DilithiumPubKey& pubkey, DilithiumKey& key) const;

    /**
     * Get metadata for a key
     *
     * @param keyid The key identifier
     * @param[out] meta The metadata
     * @return true if metadata was found, false otherwise
     */
    bool GetMetadata(const std::string& keyid, DilithiumKeyMetadata& meta) const;

    /**
     * Update usage statistics for a key
     *
     * @param keyid The key identifier
     */
    void UpdateUsage(const std::string& keyid);

    /**
     * List all stored keys
     *
     * @return Vector of key information structs
     */
    std::vector<DilithiumKeyInfo> ListKeys() const;

    /**
     * Check if a key exists
     *
     * @param keyid The key identifier
     * @return true if key exists, false otherwise
     */
    bool HaveKey(const std::string& keyid) const;

    /**
     * Remove a key from the store
     *
     * @param keyid The key identifier
     * @return true if key was removed, false if not found
     */
    bool RemoveKey(const std::string& keyid);

    /**
     * Get the number of keys in the store
     *
     * @return Number of stored keys
     */
    size_t KeyCount() const { return keys.size(); }

    /**
     * Clear all keys from the store
     */
    void Clear();

private:
    /**
     * Generate a deterministic key ID from a public key
     *
     * @param pubkey The public key
     * @return 16-character hex key ID
     */
    static std::string GenerateKeyID(const DilithiumPubKey& pubkey);
};

// Global keystore instance (for RPC commands)
extern DilithiumKeyStore g_dilithium_keystore;

#endif // BITCOIN_DILITHIUM_DILITHIUMKEYSTORE_H
