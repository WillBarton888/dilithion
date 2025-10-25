// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_WALLET_WALLET_H
#define DILITHION_WALLET_WALLET_H

#include <primitives/block.h>
#include <uint256.h>

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>

// Dilithium3 parameters (balanced security/performance)
static const size_t DILITHIUM_PUBLICKEY_SIZE = 1952;
static const size_t DILITHIUM_SECRETKEY_SIZE = 4032;
static const size_t DILITHIUM_SIGNATURE_SIZE = 3309;

/**
 * Dilithium key pair
 */
struct CKey {
    std::vector<uint8_t> vchPubKey;  // Public key (1952 bytes)
    std::vector<uint8_t> vchPrivKey; // Secret key (4032 bytes)

    CKey() {}

    bool IsValid() const {
        return vchPubKey.size() == DILITHIUM_PUBLICKEY_SIZE &&
               vchPrivKey.size() == DILITHIUM_SECRETKEY_SIZE;
    }

    void Clear() {
        vchPubKey.clear();
        vchPrivKey.clear();
    }
};

/**
 * Dilithium address - Base58 encoded hash of public key
 */
class CAddress {
private:
    std::vector<uint8_t> vchData; // 20-byte hash + 4-byte checksum

public:
    CAddress() {}
    explicit CAddress(const std::vector<uint8_t>& pubkey);

    std::string ToString() const;
    bool SetString(const std::string& str);

    bool IsValid() const { return vchData.size() == 21; } // 1 version byte + 20 hash bytes

    const std::vector<uint8_t>& GetData() const { return vchData; }

    bool operator==(const CAddress& other) const {
        return vchData == other.vchData;
    }

    bool operator<(const CAddress& other) const {
        return vchData < other.vchData;
    }
};

/**
 * Wallet transaction output
 */
struct CWalletTx {
    uint256 txid;
    uint32_t vout;
    int64_t nValue;
    CAddress address;
    bool fSpent;
    uint32_t nHeight;

    CWalletTx() : vout(0), nValue(0), fSpent(false), nHeight(0) {}
};

/**
 * Wallet - manages keys, addresses, and transactions
 *
 * Features:
 * - CRYSTALS-Dilithium key pair generation
 * - Address generation and validation
 * - Transaction signing
 * - UTXO tracking
 * - Balance calculation
 *
 * Usage:
 *   CWallet wallet;
 *   wallet.GenerateNewKey();
 *   CAddress addr = wallet.GetNewAddress();
 *   int64_t balance = wallet.GetBalance();
 */
class CWallet {
private:
    // Key storage
    std::map<CAddress, CKey> mapKeys;
    std::vector<CAddress> vchAddresses;

    // Transaction tracking
    std::map<uint256, CWalletTx> mapWalletTx;

    // Thread safety
    mutable std::mutex cs_wallet;

    // Default address
    CAddress defaultAddress;

public:
    CWallet();
    ~CWallet();

    // Prevent copying
    CWallet(const CWallet&) = delete;
    CWallet& operator=(const CWallet&) = delete;

    /**
     * Generate a new Dilithium key pair
     * @return true if successful
     */
    bool GenerateNewKey();

    /**
     * Get the default receiving address
     * @return address or empty if no keys
     */
    CAddress GetNewAddress();

    /**
     * Get all addresses in wallet
     */
    std::vector<CAddress> GetAddresses() const;

    /**
     * Check if wallet has a key for this address
     */
    bool HasKey(const CAddress& address) const;

    /**
     * Get the key for an address
     * @param address Address to look up
     * @param keyOut Output key
     * @return true if key found
     */
    bool GetKey(const CAddress& address, CKey& keyOut) const;

    /**
     * Sign a message hash with address's private key
     * @param address Address whose key to use
     * @param hash Message hash to sign
     * @param signature Output signature
     * @return true if successful
     */
    bool SignHash(const CAddress& address, const uint256& hash,
                  std::vector<uint8_t>& signature);

    /**
     * Add a transaction output to the wallet
     */
    bool AddTxOut(const uint256& txid, uint32_t vout, int64_t nValue,
                  const CAddress& address, uint32_t nHeight);

    /**
     * Mark a transaction output as spent
     */
    bool MarkSpent(const uint256& txid, uint32_t vout);

    /**
     * Get wallet balance (sum of unspent outputs)
     */
    int64_t GetBalance() const;

    /**
     * Get unspent transaction outputs
     */
    std::vector<CWalletTx> GetUnspentTxOuts() const;

    /**
     * Get number of keys in wallet
     */
    size_t GetKeyPoolSize() const;

    /**
     * Load wallet from file
     * @param filename Path to wallet file
     * @return true if successful
     */
    bool Load(const std::string& filename);

    /**
     * Save wallet to file
     * @param filename Path to wallet file
     * @return true if successful
     */
    bool Save(const std::string& filename) const;

    /**
     * Clear all wallet data
     */
    void Clear();
};

/**
 * Crypto utility functions
 */
namespace WalletCrypto {
    /**
     * Generate a new Dilithium3 key pair
     */
    bool GenerateKeyPair(CKey& key);

    /**
     * Sign data with Dilithium3
     */
    bool Sign(const CKey& key, const uint8_t* data, size_t dataLen,
              std::vector<uint8_t>& signature);

    /**
     * Verify Dilithium3 signature
     */
    bool Verify(const std::vector<uint8_t>& pubkey, const uint8_t* data,
                size_t dataLen, const std::vector<uint8_t>& signature);

    /**
     * Hash public key to create address
     */
    std::vector<uint8_t> HashPubKey(const std::vector<uint8_t>& pubkey);

    /**
     * Base58 encode with checksum
     */
    std::string EncodeBase58Check(const std::vector<uint8_t>& data);

    /**
     * Base58 decode and verify checksum
     */
    bool DecodeBase58Check(const std::string& str, std::vector<uint8_t>& data);
}

#endif // DILITHION_WALLET_WALLET_H
