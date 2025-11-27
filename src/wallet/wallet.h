// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_WALLET_WALLET_H
#define DILITHION_WALLET_WALLET_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <amount.h>
#include <uint256.h>
#include <wallet/crypter.h>
#include <wallet/hd_derivation.h>
#include <wallet/mnemonic.h>

#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <memory>
#include <chrono>

// Forward declarations for PERSIST-008 FIX (WAL)
class CWalletWAL;

// Dilithium3 parameters (balanced security/performance)
static const size_t DILITHIUM_PUBLICKEY_SIZE = 1952;
static const size_t DILITHIUM_SECRETKEY_SIZE = 4032;
static const size_t DILITHIUM_SIGNATURE_SIZE = 3309;

// FIX-011 (PERSIST-001): Wallet File Format v3 with Integrity Protection
// File format: [Magic][Version][Flags][HMAC][Salt][Data...]
static const char WALLET_FILE_MAGIC_V3[] = "DILWLT03";
static const uint32_t WALLET_FILE_VERSION_3 = 3;
static const size_t WALLET_FILE_HMAC_SIZE = 32;    // HMAC-SHA3-256 output
static const size_t WALLET_FILE_SALT_SIZE = 32;    // Salt for HMAC
static const size_t WALLET_FILE_HEADER_SIZE = 8 + 4 + 4 + 32 + 32;  // Magic + Version + Flags + HMAC + Salt = 80 bytes

/**
 * Dilithium key pair
 * WS-001: Secure memory wiping for private keys
 * FIX-009 (CRYPT-004): Use SecureAllocator to prevent private key swapping
 */
struct CKey {
    std::vector<uint8_t> vchPubKey;  // Public key (1952 bytes) - can be public
    // FIX-009: Use SecureAllocator for private key to prevent swapping to disk
    std::vector<uint8_t, SecureAllocator<uint8_t>> vchPrivKey; // Secret key (4032 bytes)

    CKey() {}

    // WS-001: Destructor securely wipes private key from memory
    ~CKey() {
        Clear();
    }

    bool IsValid() const {
        return vchPubKey.size() == DILITHIUM_PUBLICKEY_SIZE &&
               vchPrivKey.size() == DILITHIUM_SECRETKEY_SIZE;
    }

    // WS-001: Clear with secure memory wiping
    void Clear() {
        // Securely wipe private key before clearing
        if (!vchPrivKey.empty()) {
            memory_cleanse(vchPrivKey.data(), vchPrivKey.size());
        }
        vchPrivKey.clear();

        // Public key doesn't need secure wiping (it's public)
        vchPubKey.clear();
    }
};

/**
 * Encrypted key data
 * FIX-008 (CRYPT-007): Added HMAC for authenticated encryption (prevents padding oracle attacks)
 */
struct CEncryptedKey {
    std::vector<uint8_t> vchCryptedKey;  // Encrypted private key
    std::vector<uint8_t> vchIV;          // Initialization vector
    std::vector<uint8_t> vchPubKey;      // Public key (unencrypted)
    std::vector<uint8_t> vchMAC;         // FIX-008: HMAC-SHA3-512 of (IV || ciphertext)

    CEncryptedKey() {}

    bool IsValid() const {
        return !vchCryptedKey.empty() &&
               vchIV.size() == WALLET_CRYPTO_IV_SIZE &&
               vchPubKey.size() == DILITHIUM_PUBLICKEY_SIZE &&
               vchMAC.size() == 64;  // FIX-008: HMAC-SHA3-512 is 64 bytes
    }

    // FIX-008: Check if this is a legacy key (no MAC)
    bool IsLegacy() const {
        return !vchCryptedKey.empty() &&
               vchIV.size() == WALLET_CRYPTO_IV_SIZE &&
               vchPubKey.size() == DILITHIUM_PUBLICKEY_SIZE &&
               vchMAC.empty();
    }
};

/**
 * Master key - encrypted with user passphrase
 * FIX-008 (CRYPT-007): Added HMAC for authenticated encryption
 */
struct CMasterKey {
    std::vector<uint8_t> vchCryptedKey;  // Encrypted master key
    std::vector<uint8_t> vchSalt;        // PBKDF2 salt
    std::vector<uint8_t> vchIV;          // Initialization vector
    std::vector<uint8_t> vchMAC;         // FIX-008: HMAC-SHA3-512 of (IV || ciphertext)
    unsigned int nDerivationMethod;       // 0 = PBKDF2-SHA3
    unsigned int nDeriveIterations;       // Number of iterations (default: 100,000)

    CMasterKey() : nDerivationMethod(0), nDeriveIterations(WALLET_CRYPTO_PBKDF2_ROUNDS) {}

    bool IsValid() const {
        return !vchCryptedKey.empty() &&
               vchSalt.size() == WALLET_CRYPTO_SALT_SIZE &&
               vchIV.size() == WALLET_CRYPTO_IV_SIZE &&
               vchMAC.size() == 64;  // FIX-008: HMAC-SHA3-512 is 64 bytes
    }

    // FIX-008: Check if this is a legacy key (no MAC)
    bool IsLegacy() const {
        return !vchCryptedKey.empty() &&
               vchSalt.size() == WALLET_CRYPTO_SALT_SIZE &&
               vchIV.size() == WALLET_CRYPTO_IV_SIZE &&
               vchMAC.empty();
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

    // Constructor from raw address data (for loading from wallet file)
    static CAddress FromData(const std::vector<uint8_t>& data) {
        CAddress addr;
        addr.vchData = data;
        return addr;
    }

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

    // FIX-005 (WALLET-001): Transaction tracking with composite key
    // Changed from std::map<uint256, CWalletTx> to prevent key collision
    // When a transaction has multiple outputs to wallet, old code overwrote entries
    // New code uses COutPoint(txid, vout) as key to store each output separately
    std::map<COutPoint, CWalletTx> mapWalletTx;

    // Encryption
    CMasterKey masterKey;                           // Master key (encrypted with passphrase)
    CKeyingMaterial vMasterKey;                     // Decrypted master key (only when unlocked)
    bool fWalletUnlocked;                           // Is wallet currently unlocked?
    bool fWalletUnlockForStakingOnly;              // Unlock for staking only (future use)
    std::chrono::time_point<std::chrono::steady_clock> nUnlockTime;  // Auto-lock time
    // WL-011 FIX: Rate limiting with exponential backoff
    uint32_t nUnlockFailedAttempts;                // Consecutive failed unlock attempts
    std::chrono::time_point<std::chrono::steady_clock> nLastFailedUnlock;  // Time of last failed attempt

    // FIX-010 (CRYPT-002): IV Reuse Detection
    // Track all IVs used in this wallet to prevent reuse (which would break AES-CBC security)
    std::set<std::vector<uint8_t>> usedIVs;        // Set of all IVs used for encryption

    // Internal helper: Generate unique IV (assumes caller holds cs_wallet lock)
    template<typename Alloc>
    bool GenerateUniqueIV_Locked(std::vector<uint8_t, Alloc>& iv);

    // Thread safety
    mutable std::mutex cs_wallet;

    // Default address
    CAddress defaultAddress;

    // Persistence
    std::string m_walletFile;  // Current wallet file path
    bool m_autoSave;           // Auto-save after changes

    // ============================================================================
    // BUG #56 FIX: Best Block Tracking (Bitcoin Core Pattern - PR #30221)
    // ============================================================================
    // Tracks the last block the wallet was synced to, enabling:
    // - Incremental rescans on startup (not full UTXO scan)
    // - Proper crash recovery (resume from last persisted block)
    // - Correct reorg handling (blockDisconnected updates this)
    uint256 m_bestBlockHash;      // Hash of last block wallet was synced to
    int32_t m_bestBlockHeight;    // Height of last block (-1 = not initialized)

    // PERSIST-008 FIX: Write-Ahead Log for atomic multi-step operations
    std::unique_ptr<CWalletWAL> m_wal;  // WAL instance (nullptr if not initialized)

    // WALLET-006 FIX: UTXO locking mechanism to prevent concurrent transaction conflicts
    std::set<COutPoint> setLockedCoins;  // UTXOs locked for transaction creation (protected by cs_wallet)

    // ============================================================================
    // HD Wallet (Hierarchical Deterministic) - BIP32/BIP44
    // ============================================================================

    bool fIsHDWallet;                          // Is this an HD wallet?
    std::vector<uint8_t> vchEncryptedMnemonic; // Encrypted BIP39 mnemonic (already encrypted, can use normal allocator)
    // FIX-009: Use SecureAllocator for IVs to prevent leakage
    std::vector<uint8_t, SecureAllocator<uint8_t>> vchMnemonicIV;        // IV for mnemonic encryption
    CHDExtendedKey hdMasterKey;                // Master extended key (encrypted in memory)
    bool fHDMasterKeyEncrypted;                // Is master key encrypted?
    // FIX-009: Use SecureAllocator for IVs to prevent leakage
    std::vector<uint8_t, SecureAllocator<uint8_t>> vchHDMasterKeyIV;     // IV for master key encryption
    // WL-010 FIX: Cache decrypted HD master key when wallet unlocked for performance
    CHDExtendedKey hdMasterKeyDecrypted;       // Cached decrypted HD master (only valid when unlocked)
    bool fHDMasterKeyCached;                   // Is cached key valid?

    // HD chain state (BIP44: m/44'/573'/account'/change'/index')
    uint32_t nHDAccountIndex;                  // Current account (default: 0)
    uint32_t nHDExternalChainIndex;            // Next receive address index
    uint32_t nHDInternalChainIndex;            // Next change address index

    // HD address mappings
    std::map<CAddress, CHDKeyPath> mapAddressToPath;  // Address -> derivation path
    std::map<CHDKeyPath, CAddress> mapPathToAddress;  // Derivation path -> address

    static const uint32_t HD_GAP_LIMIT = 20;   // BIP44 gap limit

    // Private helper methods - assume caller already holds cs_wallet lock
    bool SaveUnlocked(const std::string& filename = "") const;
    std::vector<uint8_t> GetPubKeyHashUnlocked() const;
    std::vector<uint8_t> GetPublicKeyUnlocked() const;
    bool GetKeyUnlocked(const CAddress& address, CKey& keyOut) const;
    bool IsUnlockValid() const;  // VULN-002 FIX: Check if unlock hasn't expired
    bool IsCryptedUnlocked() const;  // BUG #56 FIX: Check encryption without lock (avoids deadlock in ValidateConsistency)
    // FIX-006 (WALLET-002): Internal helper to add UTXO without acquiring lock (avoids deadlock in ScanUTXOs)
    bool AddTxOutUnlocked(const uint256& txid, uint32_t vout, int64_t nValue,
                          const CAddress& address, uint32_t nHeight);

    // HD wallet private helpers - assume caller already holds cs_wallet lock
    bool DeriveAndCacheHDAddress(const CHDKeyPath& path);
    bool EncryptHDMasterKey();
    bool DecryptHDMasterKey(CHDExtendedKey& decrypted) const;
    bool EncryptMnemonic(const std::string& mnemonic);
    bool DecryptMnemonic(std::string& mnemonic) const;

    // ============================================================================
    // BUG #56 FIX: Block processing helpers (Bitcoin Core pattern)
    // ============================================================================

    /**
     * Process all transactions in a block for wallet relevance
     * Called by blockConnected/blockDisconnected
     *
     * @param block The block to process
     * @param height Block height
     * @param connecting True if block is being connected, false if disconnecting
     * @note Assumes caller holds cs_wallet lock
     */
    void ProcessBlockTransactionsUnlocked(const class CBlock& block, int height, bool connecting);

    /**
     * Update best block pointer and persist to disk (Bitcoin Core: SetLastBlockProcessed)
     * This is the atomic update that ensures crash recovery works correctly
     *
     * @param hash Block hash
     * @param height Block height
     * @note Assumes caller holds cs_wallet lock
     */
    void SetLastBlockProcessedUnlocked(const uint256& hash, int height);

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
     * WALLET-008 FIX: Clean up stale UTXOs after blockchain reorganization
     *
     * After a blockchain reorg, some UTXOs in the wallet may no longer exist in the
     * current chain. This function checks all wallet UTXOs against the current UTXO set
     * and removes those that are no longer valid.
     *
     * Should be called:
     * - After detecting a blockchain reorganization
     * - Periodically during wallet rescan
     * - On wallet startup (to recover from interrupted reorg handling)
     *
     * @param utxo_set Current UTXO set from blockchain
     * @return Number of stale UTXOs removed
     * Thread-safe: Acquires cs_wallet lock
     */
    size_t CleanupStaleUTXOs(class CUTXOSet& utxo_set);

    // ============================================================================
    // BUG #56 FIX: Chain Notifications (Bitcoin Core Pattern - PR #30221)
    // ============================================================================
    // These callbacks are invoked by CChainState when blocks are connected/disconnected
    // Following Bitcoin Core's interfaces::Chain::Notifications pattern

    /**
     * Called when a new block is connected to the main chain
     *
     * Processes all transactions in the block:
     * - Adds outputs belonging to wallet addresses
     * - Marks wallet inputs as spent
     * - Updates best block pointer (persists to disk)
     *
     * @param block The connected block
     * @param height Block height
     * Thread-safe: Acquires cs_wallet lock
     */
    void blockConnected(const class CBlock& block, int height);

    /**
     * Called when a block is disconnected from the main chain (reorg)
     *
     * Reverses the effects of blockConnected:
     * - Removes outputs added by this block
     * - Marks wallet inputs as unspent
     * - Updates best block pointer to previous block
     *
     * @param block The disconnected block
     * @param height Block height being disconnected
     * Thread-safe: Acquires cs_wallet lock
     */
    void blockDisconnected(const class CBlock& block, int height);

    /**
     * Get the best block hash the wallet is synced to
     * @return Block hash, or null hash if not initialized
     */
    uint256 GetBestBlockHash() const;

    /**
     * Get the best block height the wallet is synced to
     * @return Block height, or -1 if not initialized
     */
    int32_t GetBestBlockHeight() const;

    /**
     * Rescan blocks in a height range for wallet transactions
     *
     * True incremental scanning: loads each block and processes transactions
     * instead of scanning entire UTXO set. Updates best block after each block.
     *
     * @param chainstate Chain state for block index lookups
     * @param blockchain Database to read block data from
     * @param startHeight First block height to scan (inclusive)
     * @param endHeight Last block height to scan (inclusive)
     * @return true if rescan completed successfully
     * Thread-safe: Acquires cs_wallet lock per block
     */
    bool RescanFromHeight(class CChainState& chainstate, class CBlockchainDB& blockchain,
                          int startHeight, int endHeight);

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
     * WL-015 FIX: Complete parameter documentation
     *
     * Decrypts the master key using PBKDF2-SHA3-256 key derivation (500,000 rounds)
     * and keeps it in memory for the timeout period. During this time, the wallet
     * can sign transactions, generate keys, and perform HD derivation.
     *
     * Rate Limiting: Failed unlock attempts trigger exponential backoff (2^n seconds,
     * max 1 hour). Prevents online brute force attacks.
     *
     * @param passphrase User's wallet passphrase. Must meet strength requirements:
     *                   - Minimum 16 characters
     *                   - Password complexity score >= 60
     *                   - See CPassphraseValidator for full requirements
     * @param timeout    Auto-lock timeout in seconds. Wallet automatically locks after
     *                   this duration. Special values:
     *                   - 0 = Never auto-lock (remains unlocked indefinitely)
     *                   - >0 = Lock after N seconds of being unlocked
     *                   Default: 0 (no auto-lock)
     * @return true on success, false if:
     *         - Wallet is not encrypted
     *         - Passphrase is incorrect (increments failed attempt counter)
     *         - Rate limited (too many recent failed attempts)
     *         - PBKDF2 key derivation fails
     * @see Lock(), IsLocked(), EncryptWallet()
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
     * WL-015 FIX: Complete parameter documentation
     *
     * Re-encrypts the wallet master key with a new passphrase. This operation:
     * 1. Verifies old passphrase and decrypts current master key
     * 2. Validates new passphrase meets strength requirements
     * 3. Re-encrypts master key with new passphrase using fresh PBKDF2 derivation
     * 4. Updates wallet file with new encrypted master key
     *
     * @param passphraseOld Current wallet passphrase. Must be correct to proceed.
     *                      Subject to same rate limiting as Unlock().
     * @param passphraseNew New wallet passphrase. Must meet strength requirements:
     *                      - Minimum 16 characters
     *                      - Password complexity score >= 60
     *                      - Different from old passphrase
     *                      Validated using CPassphraseValidator before accepting.
     * @return true if successful, false if:
     *         - Wallet is not encrypted
     *         - Old passphrase is incorrect
     *         - New passphrase fails strength validation
     *         - Rate limited from recent failed attempts
     *         - File write operation fails
     * @see Unlock(), EncryptWallet(), CPassphraseValidator
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
    // FIX-010 (CRYPT-002): IV Reuse Detection
    // ============================================================================

    /**
     * Generate a unique IV that hasn't been used before
     *
     * Generates a cryptographically random IV and ensures it hasn't been used
     * in this wallet. If collision detected, retries up to 10 times.
     *
     * IV reuse with the same key breaks AES-CBC security - if two plaintexts
     * are encrypted with the same IV and key, an attacker can XOR the
     * ciphertexts to get the XOR of plaintexts, potentially recovering keys.
     *
     * @param iv Output buffer for generated IV (will be resized to 16 bytes)
     * @return true on success, false if collision persists after 10 attempts
     * @note Thread-safe (acquires cs_wallet lock internally)
     */
    bool GenerateUniqueIV(std::vector<uint8_t, SecureAllocator<uint8_t>>& iv);

    /**
     * Register an IV as used (for loading existing wallet IVs)
     *
     * Called when loading encrypted keys from file to populate usedIVs set.
     *
     * @param iv IV to register (must be 16 bytes)
     * @note Thread-safe (acquires cs_wallet lock internally)
     */
    void RegisterIV(const std::vector<uint8_t>& iv);

    /**
     * Check if an IV has been used before
     *
     * @param iv IV to check (must be 16 bytes)
     * @return true if IV exists in usedIVs, false otherwise
     * @note Thread-safe (acquires cs_wallet lock internally)
     */
    bool IsIVUsed(const std::vector<uint8_t>& iv) const;

    /**
     * Get count of tracked IVs
     *
     * @return Number of IVs in usedIVs set
     * @note Thread-safe (acquires cs_wallet lock internally)
     */
    size_t GetIVCount() const;

    // ============================================================================
    // HD Wallet (Hierarchical Deterministic Wallet) - BIP32/BIP44
    // ============================================================================

    /**
     * Initialize HD wallet from BIP39 mnemonic
     *
     * Creates a new HD wallet from a mnemonic phrase. The wallet will be marked
     * as an HD wallet and subsequent address generation will use HD derivation.
     *
     * BIP44 path: m/44'/573'/0'/0'/0' (Dilithion coin type = 573)
     *
     * @param mnemonic BIP39 mnemonic phrase (12-24 words)
     * @param passphrase Optional BIP39 passphrase (empty string if none)
     * @return true if successful, false if wallet already initialized or invalid mnemonic
     */
    bool InitializeHDWallet(const std::string& mnemonic, const std::string& passphrase = "");

    /**
     * Generate new HD wallet with random mnemonic
     *
     * Creates new BIP39 mnemonic (24 words) and initializes HD wallet.
     *
     * @param mnemonic_out Output parameter for generated mnemonic (24 words)
     * @param passphrase Optional BIP39 passphrase
     * @return true if successful
     */
    bool GenerateHDWallet(std::string& mnemonic_out, const std::string& passphrase = "");

    /**
     * Restore HD wallet from mnemonic and scan for existing addresses
     *
     * Similar to InitializeHDWallet but also scans blockchain for existing
     * addresses up to gap limit.
     *
     * @param mnemonic BIP39 mnemonic phrase
     * @param passphrase Optional BIP39 passphrase
     * @return true if successful
     */
    bool RestoreHDWallet(const std::string& mnemonic, const std::string& passphrase = "");

    /**
     * Get new HD receiving address
     *
     * Derives next address on external chain (m/44'/573'/account'/0'/index').
     * Increments external chain index counter.
     *
     * @return New receiving address, or empty if not HD wallet or locked
     */
    CAddress GetNewHDAddress();

    /**
     * Get change address for HD wallet
     *
     * Derives address on internal chain (m/44'/573'/account'/1'/index').
     * Used for sending change back to own wallet.
     *
     * @return Change address, or empty if not HD wallet or locked
     */
    CAddress GetChangeAddress();

    /**
     * Derive address at specific BIP44 path
     *
     * Advanced function for deriving addresses at custom paths.
     * Normal users should use GetNewHDAddress() instead.
     *
     * @param path BIP44 path (e.g., "m/44'/573'/0'/0'/5'")
     * @return Derived address, or empty if invalid path or locked
     */
    CAddress DeriveAddress(const std::string& path);

    /**
     * Export BIP39 mnemonic phrase
     *
     * Returns the wallet's mnemonic phrase. Wallet must be unlocked.
     * Use with extreme caution - mnemonic provides full access to all funds.
     *
     * @param mnemonic_out Output parameter for mnemonic phrase
     * @return true if successful, false if not HD wallet or wallet locked
     */
    bool ExportMnemonic(std::string& mnemonic_out) const;

    /**
     * Get HD wallet information
     *
     * @param account Output: current account index
     * @param external_index Output: next receive address index
     * @param internal_index Output: next change address index
     * @return true if HD wallet, false otherwise
     */
    bool GetHDWalletInfo(uint32_t& account, uint32_t& external_index,
                         uint32_t& internal_index) const;

    /**
     * Scan HD address chains for existing addresses
     *
     * Scans both receive and change chains up to gap limit (20 unused addresses).
     * Used during wallet restoration to find all previously used addresses.
     *
     * @param utxo_set UTXO set to check for address usage
     * @return Number of addresses found and added to wallet
     */
    size_t ScanHDChains(class CUTXOSet& utxo_set);

    /**
     * Check if this is an HD wallet
     */
    bool IsHDWallet() const { return fIsHDWallet; }

    /**
     * Check if wallet is empty (has no keys/addresses)
     * @return true if wallet has no keys
     */
    bool IsEmpty() const { return vchAddresses.empty(); }

    /**
     * Get derivation path for an address
     *
     * @param address Address to look up
     * @param path_out Output parameter for path
     * @return true if address found and is HD-derived
     */
    bool GetAddressPath(const CAddress& address, CHDKeyPath& path_out) const;

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

    /**
     * PERSIST-008 FIX: Initialize Write-Ahead Log for atomic operations
     *
     * Must be called before using AtomicOperation(). Sets up WAL file path
     * and prepares wallet for multi-step atomic operations.
     *
     * @param wallet_path Path to wallet.dat file
     * @return true if WAL initialized successfully, false on error
     */
    bool InitializeWAL(const std::string& wallet_path);

    /**
     * PERSIST-008 FIX: Check for incomplete WAL operations and recover
     *
     * Called on wallet startup to detect crashes during previous operations.
     * If incomplete operations found, executes recovery (rollback or complete).
     *
     * @return true if recovery successful or no recovery needed, false on error
     */
    bool RecoverFromWAL();

    /**
     * PERSIST-008 FIX: Get WAL instance (for advanced operations)
     *
     * @return Pointer to WAL instance, or nullptr if not initialized
     */
    CWalletWAL* GetWAL() const { return m_wal.get(); }

    /**
     * FIX-012 (WALLET-002): Validate wallet structural consistency
     *
     * Performs comprehensive validation of wallet data structures to detect:
     * - Address reconstruction mismatches (public key → address)
     * - HD wallet path gaps (missing derivation indices)
     * - Transaction addresses not belonging to wallet
     * - Encrypted/unencrypted key count mismatches
     * - HD path bidirectional mapping inconsistencies
     *
     * This method performs 5 critical checks:
     *
     * 1. Address Reconstruction: Verifies all addresses match their public keys
     *    - Prevents address<→>key mismatch from file corruption
     *    - Detects tampering with address bytes
     *
     * 2. HD Path Gap Detection: Ensures no missing indices in derivation chains
     *    - External chain: [0, nHDExternalChainIndex)
     *    - Internal chain: [0, nHDInternalChainIndex)
     *    - Detects missing HD addresses in sequential range
     *
     * 3. Transaction Address Validation: All tx addresses belong to wallet
     *    - Prevents orphaned transactions referencing foreign addresses
     *
     * 4. Encrypted Key Count: Encrypted wallets have matching key/address counts
     *    - Detects incomplete encryption or decryption
     *
     * 5. HD Bidirectional Mapping: mapAddressToPath ↔ mapPathToAddress consistency
     *    - Prevents one-way mapping corruption
     *
     * Called automatically during Load() to fail-fast on corruption.
     *
     * @param error_out Output parameter for detailed error description
     * @return true if wallet passes all consistency checks, false if corruption detected
     * @note Thread-safe (acquires cs_wallet lock internally)
     */
    bool ValidateConsistency(std::string& error_out) const;

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
     * @param min_confirmations Minimum confirmations required (default 1) - WALLET-003 FIX
     * @return Vector of wallet transaction outputs
     */
    std::vector<CWalletTx> ListUnspentOutputs(class CUTXOSet& utxo_set, unsigned int current_height, unsigned int min_confirmations = 1) const;

    // ========================================================================
    // WALLET-006 FIX: UTXO Locking Mechanism
    // ========================================================================

    /**
     * Lock a UTXO to prevent it from being selected in concurrent transactions
     *
     * @param outpoint The UTXO to lock (txid + vout)
     * Thread-safe: Acquires cs_wallet lock
     */
    void LockCoin(const COutPoint& outpoint);

    /**
     * Unlock a previously locked UTXO
     *
     * @param outpoint The UTXO to unlock
     * Thread-safe: Acquires cs_wallet lock
     */
    void UnlockCoin(const COutPoint& outpoint);

    /**
     * Check if a UTXO is currently locked
     *
     * @param outpoint The UTXO to check
     * @return true if locked, false otherwise
     * Thread-safe: Acquires cs_wallet lock
     */
    bool IsLocked(const COutPoint& outpoint) const;

    /**
     * Get list of all locked UTXOs
     *
     * @return Vector of locked COutPoints
     * Thread-safe: Acquires cs_wallet lock
     */
    std::vector<COutPoint> ListLockedCoins() const;

    /**
     * Unlock all locked UTXOs
     *
     * Useful for recovery or manual intervention
     * Thread-safe: Acquires cs_wallet lock
     */
    void UnlockAllCoins();

    // ========================================================================

    /**
     * Select coins to fund a transaction (coin selection algorithm)
     *
     * Uses simple greedy algorithm: selects largest UTXOs first until target is reached.
     * Future versions can implement more sophisticated algorithms (knapsack, branch & bound).
     *
     * WALLET-006 FIX: Now skips locked UTXOs to prevent concurrent transaction conflicts
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
     * Default transaction fee (0.00185000 DLT = 185000 ions)
     * Updated for P2PKH script format (larger than simplified script)
     */
    static const CAmount DEFAULT_TRANSACTION_FEE = 185000;

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
