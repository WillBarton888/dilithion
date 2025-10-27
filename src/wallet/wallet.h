// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_WALLET_WALLET_H
#define DILITHION_WALLET_WALLET_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <amount.h>
#include <uint256.h>
#include <wallet/crypter.h>

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <chrono>

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
 * Encrypted key data
 */
struct CEncryptedKey {
    std::vector<uint8_t> vchCryptedKey;  // Encrypted private key
    std::vector<uint8_t> vchIV;          // Initialization vector
    std::vector<uint8_t> vchPubKey;      // Public key (unencrypted)

    CEncryptedKey() {}

    bool IsValid() const {
        return !vchCryptedKey.empty() &&
               vchIV.size() == WALLET_CRYPTO_IV_SIZE &&
               vchPubKey.size() == DILITHIUM_PUBLICKEY_SIZE;
    }
};

/**
 * Master key - encrypted with user passphrase
 */
struct CMasterKey {
    std::vector<uint8_t> vchCryptedKey;  // Encrypted master key
    std::vector<uint8_t> vchSalt;        // PBKDF2 salt
    std::vector<uint8_t> vchIV;          // Initialization vector
    unsigned int nDerivationMethod;       // 0 = PBKDF2-SHA3
    unsigned int nDeriveIterations;       // Number of iterations (default: 100,000)

    CMasterKey() : nDerivationMethod(0), nDeriveIterations(WALLET_CRYPTO_PBKDF2_ROUNDS) {}

    bool IsValid() const {
        return !vchCryptedKey.empty() &&
               vchSalt.size() == WALLET_CRYPTO_SALT_SIZE &&
               vchIV.size() == WALLET_CRYPTO_IV_SIZE;
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
    std::map<CAddress, CKey> mapKeys;              // Unencrypted keys (when wallet not encrypted)
    std::map<CAddress, CEncryptedKey> mapCryptedKeys;  // Encrypted keys
    std::vector<CAddress> vchAddresses;

    // Transaction tracking
    std::map<uint256, CWalletTx> mapWalletTx;

    // Encryption
    CMasterKey masterKey;                           // Master key (encrypted with passphrase)
    CKeyingMaterial vMasterKey;                     // Decrypted master key (only when unlocked)
    bool fWalletUnlocked;                           // Is wallet currently unlocked?
    bool fWalletUnlockForStakingOnly;              // Unlock for staking only (future use)
    std::chrono::time_point<std::chrono::steady_clock> nUnlockTime;  // Auto-lock time

    // Thread safety
    mutable std::mutex cs_wallet;

    // Default address
    CAddress defaultAddress;

    // Persistence
    std::string m_walletFile;  // Current wallet file path
    bool m_autoSave;           // Auto-save after changes

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

    // ============================================================================
    // Wallet Encryption
    // ============================================================================

    /**
     * Encrypt the wallet with a passphrase
     *
     * This encrypts all existing private keys and sets up the master key.
     * Once encrypted, the wallet must be unlocked with the passphrase to:
     * - Generate new keys
     * - Sign transactions
     * - Export private keys
     *
     * @param passphrase User's wallet passphrase
     * @return true if successful, false if already encrypted or error
     */
    bool EncryptWallet(const std::string& passphrase);

    /**
     * Unlock the wallet for a specified time
     *
     * Decrypts the master key and keeps it in memory for the timeout period.
     * During this time, the wallet can sign transactions and generate keys.
     *
     * @param passphrase User's wallet passphrase
     * @param timeout Seconds to keep wallet unlocked (0 = forever)
     * @return true if successful, false if wrong passphrase or not encrypted
     */
    bool Unlock(const std::string& passphrase, int64_t timeout = 0);

    /**
     * Lock the wallet
     *
     * Clears the master key from memory. After locking, signing operations
     * will fail until the wallet is unlocked again.
     *
     * @return true if successful
     */
    bool Lock();

    /**
     * Check if wallet is locked
     *
     * @return true if wallet is encrypted and currently locked
     */
    bool IsLocked() const;

    /**
     * Check if wallet is encrypted
     *
     * @return true if wallet has been encrypted
     */
    bool IsCrypted() const;

    /**
     * Change wallet passphrase
     *
     * Re-encrypts the master key with a new passphrase.
     * Wallet must be unlocked or old passphrase must be provided.
     *
     * @param passphraseOld Current passphrase
     * @param passphraseNew New passphrase
     * @return true if successful, false if wrong old passphrase or not encrypted
     */
    bool ChangePassphrase(const std::string& passphraseOld,
                          const std::string& passphraseNew);

    /**
     * Check if unlock timeout has expired and auto-lock if needed
     *
     * Called periodically to enforce timeout-based locking.
     */
    void CheckUnlockTimeout();

    // ============================================================================
    // Persistence
    // ============================================================================

    /**
     * Load wallet from file
     * @param filename Path to wallet file
     * @return true if successful
     */
    bool Load(const std::string& filename);

    /**
     * Save wallet to file
     * @param filename Path to wallet file (optional, uses current file if empty)
     * @return true if successful
     */
    bool Save(const std::string& filename = "") const;

    /**
     * Set wallet file path and enable auto-save
     * @param filename Path to wallet file
     */
    void SetWalletFile(const std::string& filename);

    /**
     * Get current wallet file path
     */
    std::string GetWalletFile() const { return m_walletFile; }

    /**
     * Enable/disable auto-save
     */
    void SetAutoSave(bool enabled) { m_autoSave = enabled; }

    /**
     * Clear all wallet data
     */
    void Clear();

    // ============================================================================
    // Phase 5.2: UTXO Management & Transaction Creation
    // ============================================================================

    /**
     * Scan the global UTXO set and identify all UTXOs belonging to this wallet
     *
     * This function iterates through the global UTXO set and finds all outputs
     * that are spendable by this wallet's keys. Used for wallet synchronization.
     *
     * @param global_utxo_set The global UTXO set to scan
     * @return true if scan completed successfully
     */
    bool ScanUTXOs(class CUTXOSet& global_utxo_set);

    /**
     * Get wallet's spendable balance
     *
     * Calculates total balance from unspent outputs, excluding immature coinbase.
     * Thread-safe.
     *
     * @param utxo_set UTXO set to query
     * @param current_height Current blockchain height (for maturity checks)
     * @return Total spendable balance in ions (1 DIL = 100,000,000 ions)
     */
    CAmount GetAvailableBalance(class CUTXOSet& utxo_set, unsigned int current_height) const;

    /**
     * List all unspent transaction outputs for this wallet
     *
     * Returns only mature, spendable UTXOs (filters out immature coinbase).
     *
     * @param utxo_set UTXO set to query
     * @param current_height Current blockchain height
     * @return Vector of wallet transaction outputs
     */
    std::vector<CWalletTx> ListUnspentOutputs(class CUTXOSet& utxo_set, unsigned int current_height) const;

    /**
     * Select coins to fund a transaction (coin selection algorithm)
     *
     * Uses simple greedy algorithm: selects largest UTXOs first until target is reached.
     * Future versions can implement more sophisticated algorithms (knapsack, branch & bound).
     *
     * @param target_value Amount needed (including fee)
     * @param selected_coins Output vector of selected UTXOs
     * @param total_value Output parameter for total value of selected coins
     * @param utxo_set UTXO set to query
     * @param current_height Current blockchain height
     * @param error Error message if selection fails
     * @return true if sufficient coins selected, false if insufficient balance
     */
    bool SelectCoins(CAmount target_value,
                    std::vector<CWalletTx>& selected_coins,
                    CAmount& total_value,
                    class CUTXOSet& utxo_set,
                    unsigned int current_height,
                    std::string& error) const;

    /**
     * Create a new transaction
     *
     * Complete transaction creation pipeline:
     * 1. Select coins to cover amount + fee
     * 2. Create inputs from selected coins
     * 3. Create output for recipient
     * 4. Create change output if needed
     * 5. Sign all inputs
     * 6. Validate transaction
     *
     * @param recipient_address Recipient's wallet address
     * @param amount Amount to send (in ions)
     * @param fee Transaction fee (in ions)
     * @param utxo_set UTXO set for coin selection and validation
     * @param current_height Current blockchain height
     * @param tx_out Output parameter for created transaction
     * @param error Error message if creation fails
     * @return true if transaction created successfully
     */
    bool CreateTransaction(const CAddress& recipient_address,
                          CAmount amount,
                          CAmount fee,
                          class CUTXOSet& utxo_set,
                          unsigned int current_height,
                          CTransactionRef& tx_out,
                          std::string& error);

    /**
     * Sign all inputs of a transaction
     *
     * For each input:
     * 1. Lookup the UTXO being spent
     * 2. Extract the public key hash from scriptPubKey
     * 3. Find corresponding wallet key
     * 4. Create signature message (tx hash + input index)
     * 5. Sign with Dilithium
     * 6. Build scriptSig with signature and public key
     *
     * @param tx Transaction to sign (modified in place)
     * @param utxo_set UTXO set to lookup previous outputs
     * @param error Error message if signing fails
     * @return true if all inputs signed successfully
     */
    bool SignTransaction(CTransaction& tx, class CUTXOSet& utxo_set, std::string& error);

    /**
     * Broadcast a transaction to the network
     *
     * Steps:
     * 1. Validate transaction against consensus rules
     * 2. Add to mempool
     * 3. (Future) Relay to P2P network
     *
     * @param tx Transaction to send
     * @param mempool Mempool to add transaction to
     * @param utxo_set UTXO set for validation
     * @param current_height Current blockchain height
     * @param error Error message if broadcast fails
     * @return true if transaction accepted to mempool
     */
    bool SendTransaction(const CTransactionRef& tx,
                        class CTxMemPool& mempool,
                        class CUTXOSet& utxo_set,
                        unsigned int current_height,
                        std::string& error);

    /**
     * Estimate transaction fee (v1.0: fixed fee)
     *
     * Returns fixed fee for v1.0. Future versions will implement:
     * - Size-based fees
     * - Priority-based fees
     * - Dynamic fee estimation based on mempool
     *
     * @return Estimated fee in ions
     */
    static CAmount EstimateFee() { return DEFAULT_TRANSACTION_FEE; }

    /**
     * Default transaction fee (0.00001000 DLT = 1000 ions)
     */
    static const CAmount DEFAULT_TRANSACTION_FEE = 1000;

    /**
     * Get this wallet's public key hash (for receiving payments)
     *
     * @return SHA3-256 hash of default address's public key (32 bytes)
     */
    std::vector<uint8_t> GetPubKeyHash() const;

    /**
     * Get this wallet's public key
     *
     * @return Public key of default address (~1952 bytes for Dilithium3)
     */
    std::vector<uint8_t> GetPublicKey() const;

    /**
     * Get public key hash from an address
     *
     * @param address Address to extract hash from
     * @return Public key hash (20 bytes) or empty vector if invalid
     */
    static std::vector<uint8_t> GetPubKeyHashFromAddress(const CAddress& address);
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

    /**
     * Create scriptPubKey from public key hash (P2PKH-like)
     *
     * Format: [hash_size(1)] [pubkey_hash(32)] [OP_CHECKSIG(1)]
     *
     * @param pubkey_hash Public key hash (32 bytes from SHA3-256)
     * @return scriptPubKey bytes
     */
    std::vector<uint8_t> CreateScriptPubKey(const std::vector<uint8_t>& pubkey_hash);

    /**
     * Create scriptSig from signature and public key
     *
     * Format: [sig_size(2)] [signature] [pubkey_size(2)] [pubkey]
     * Sizes are little-endian 16-bit integers
     *
     * @param signature Dilithium signature (~3293 bytes)
     * @param pubkey Dilithium public key (~1952 bytes)
     * @return scriptSig bytes
     */
    std::vector<uint8_t> CreateScriptSig(const std::vector<uint8_t>& signature,
                                         const std::vector<uint8_t>& pubkey);

    /**
     * Extract public key hash from scriptPubKey
     *
     * Parses P2PKH-like scriptPubKey to extract the hash.
     *
     * @param scriptPubKey Script to parse
     * @return Public key hash (32 bytes) or empty if invalid
     */
    std::vector<uint8_t> ExtractPubKeyHash(const std::vector<uint8_t>& scriptPubKey);
}

#endif // DILITHION_WALLET_WALLET_H
