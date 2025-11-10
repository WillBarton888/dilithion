// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/wallet.h>
#include <wallet/passphrase_validator.h>
#include <crypto/sha3.h>
#include <crypto/hmac_sha3.h>  // FIX-011: For file integrity HMAC
#include <rpc/auth.h>  // FIX-011/FIX-012: For SecureCompare
#include <util/base58.h>
#include <node/utxo_set.h>
#include <node/mempool.h>
#include <consensus/tx_validation.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>

// FIX-002 (PERSIST-003): File permissions
// FIX-004 (PERSIST-002): fsync for atomic writes
#ifndef _WIN32
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

// Dilithium3 API
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

namespace WalletCrypto {

bool GenerateKeyPair(CKey& key) {
    key.vchPubKey.resize(DILITHIUM_PUBLICKEY_SIZE);
    key.vchPrivKey.resize(DILITHIUM_SECRETKEY_SIZE);

    int result = pqcrystals_dilithium3_ref_keypair(
        key.vchPubKey.data(),
        key.vchPrivKey.data()
    );

    if (result != 0) {
        key.Clear();
        return false;
    }

    return true;
}

bool Sign(const CKey& key, const uint8_t* data, size_t dataLen,
          std::vector<uint8_t>& signature) {
    if (!key.IsValid()) {
        return false;
    }

    signature.resize(DILITHIUM_SIGNATURE_SIZE);
    size_t siglen = 0;

    int result = pqcrystals_dilithium3_ref_signature(
        signature.data(), &siglen,
        data, dataLen,
        nullptr, 0,  // No context
        key.vchPrivKey.data()
    );

    if (result != 0) {
        signature.clear();
        return false;
    }

    signature.resize(siglen);
    return true;
}

bool Verify(const std::vector<uint8_t>& pubkey, const uint8_t* data,
            size_t dataLen, const std::vector<uint8_t>& signature) {
    if (pubkey.size() != DILITHIUM_PUBLICKEY_SIZE) {
        return false;
    }

    int result = pqcrystals_dilithium3_ref_verify(
        signature.data(), signature.size(),
        data, dataLen,
        nullptr, 0,  // No context
        pubkey.data()
    );

    return result == 0;
}

std::vector<uint8_t> HashPubKey(const std::vector<uint8_t>& pubkey) {
    // SHA3-256 the public key (quantum-resistant)
    uint8_t hash1[32];
    SHA3_256(pubkey.data(), pubkey.size(), hash1);

    // SHA3-256 again for double hashing
    uint8_t hash2[32];
    SHA3_256(hash1, 32, hash2);

    // Take first 20 bytes
    return std::vector<uint8_t>(hash2, hash2 + 20);
}

} // namespace WalletCrypto

// CAddress implementation

CAddress::CAddress(const std::vector<uint8_t>& pubkey) {
    std::vector<uint8_t> hash = WalletCrypto::HashPubKey(pubkey);

    // Create address data: version byte (0x1E) + hash (20 bytes)
    vchData.push_back(0x1E);
    vchData.insert(vchData.end(), hash.begin(), hash.end());

    // vchData is now 21 bytes (1 + 20)
}

std::string CAddress::ToString() const {
    if (!IsValid()) {
        return "";
    }
    return ::EncodeBase58Check(vchData);
}

bool CAddress::SetString(const std::string& str) {
    if (!::DecodeBase58Check(str, vchData)) {
        vchData.clear();
        return false;
    }

    // Verify version byte
    if (vchData.empty() || vchData[0] != 0x1E) {
        vchData.clear();
        return false;
    }

    // Should be 1 version byte + 20 hash bytes
    if (vchData.size() != 21) {
        vchData.clear();
        return false;
    }

    return true;
}

// CWallet implementation

CWallet::CWallet()
    : fWalletUnlocked(false),
      fWalletUnlockForStakingOnly(false),
      nUnlockTime(std::chrono::steady_clock::time_point::max()),
      nUnlockFailedAttempts(0),  // WL-011: Initialize rate limiting
      nLastFailedUnlock(std::chrono::steady_clock::time_point::min()),
      m_autoSave(false),
      fIsHDWallet(false),
      fHDMasterKeyEncrypted(false),
      fHDMasterKeyCached(false),  // WL-010: Initialize cache flag
      nHDAccountIndex(0),
      nHDExternalChainIndex(0),
      nHDInternalChainIndex(0)
{
    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
}

CWallet::~CWallet() {
    Clear();
}

bool CWallet::GenerateNewKey() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Check if wallet is locked (don't call IsLocked() - we already have the mutex)
    if (masterKey.IsValid() && !fWalletUnlocked) {
        return false;  // Cannot generate keys when locked
    }

    CKey key;
    if (!WalletCrypto::GenerateKeyPair(key)) {
        return false;
    }

    CAddress address(key.vchPubKey);

    // If wallet is encrypted, encrypt the key (don't call IsCrypted() - we already have the mutex)
    if (masterKey.IsValid()) {
        CEncryptedKey encKey;
        encKey.vchPubKey = key.vchPubKey;

        // FIX-010: Generate unique IV
        if (!GenerateUniqueIV_Locked(encKey.vchIV)) {
            return false;
        }

        // Encrypt private key with master key
        CCrypter crypter;
        std::vector<uint8_t> masterKeyVec(vMasterKey.data_ptr(),
                                          vMasterKey.data_ptr() + vMasterKey.size());
        if (!crypter.SetKey(masterKeyVec, encKey.vchIV)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            return false;
        }

        if (!crypter.Encrypt(key.vchPrivKey, encKey.vchCryptedKey)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            return false;
        }

        mapCryptedKeys[address] = encKey;
        memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
    } else {
        // Wallet not encrypted, store key as-is
        mapKeys[address] = key;
    }

    vchAddresses.push_back(address);

    // Set as default if first key
    if (vchAddresses.size() == 1) {
        defaultAddress = address;
    }

    // Auto-save wallet if enabled (we already hold the lock)
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    return true;
}

CAddress CWallet::GetNewAddress() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (vchAddresses.empty()) {
        return CAddress();
    }

    return defaultAddress;
}

std::vector<CAddress> CWallet::GetAddresses() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return vchAddresses;
}

bool CWallet::HasKey(const CAddress& address) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Check both encrypted and unencrypted key stores
    if (mapKeys.find(address) != mapKeys.end()) {
        return true;
    }

    return mapCryptedKeys.find(address) != mapCryptedKeys.end();
}

// Public GetKey - acquires lock
bool CWallet::GetKey(const CAddress& address, CKey& keyOut) const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return GetKeyUnlocked(address, keyOut);
}

// Private GetKeyUnlocked - assumes caller holds lock
bool CWallet::GetKeyUnlocked(const CAddress& address, CKey& keyOut) const {
    // First check unencrypted keys
    auto it = mapKeys.find(address);
    if (it != mapKeys.end()) {
        keyOut = it->second;
        return true;
    }

    // Then check encrypted keys
    auto itCrypted = mapCryptedKeys.find(address);
    if (itCrypted == mapCryptedKeys.end()) {
        return false;  // Key not found
    }

    // Wallet is encrypted - check if unlocked
    if (!fWalletUnlocked) {
        return false;  // Wallet is locked, cannot decrypt
    }

    const CEncryptedKey& encKey = itCrypted->second;

    // Decrypt private key
    CCrypter crypter;
    std::vector<uint8_t> masterKeyVec(vMasterKey.data_ptr(),
                                      vMasterKey.data_ptr() + vMasterKey.size());
    if (!crypter.SetKey(masterKeyVec, encKey.vchIV)) {
        memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
        return false;
    }

    // FIX-008 (CRYPT-007): Verify MAC before decryption (prevents padding oracle)
    // For legacy keys without MAC, skip verification
    if (!encKey.IsLegacy()) {
        if (!crypter.VerifyMAC(encKey.vchCryptedKey, encKey.vchMAC)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            return false;  // MAC verification failed - corrupted or tampered key
        }
    }

    std::vector<uint8_t> decryptedPrivKey;
    if (!crypter.Decrypt(encKey.vchCryptedKey, decryptedPrivKey)) {
        memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
        return false;
    }

    // Construct decrypted key
    keyOut.vchPubKey = encKey.vchPubKey;
    // FIX-009: Use assign() to copy from regular vector to SecureAllocator vector
    keyOut.vchPrivKey.assign(decryptedPrivKey.begin(), decryptedPrivKey.end());

    // Wipe sensitive data
    memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
    memory_cleanse(decryptedPrivKey.data(), decryptedPrivKey.size());

    return true;
}

bool CWallet::SignHash(const CAddress& address, const uint256& hash,
                       std::vector<uint8_t>& signature) {
    CKey key;
    if (!GetKey(address, key)) {
        return false;
    }

    return WalletCrypto::Sign(key, hash.begin(), 32, signature);
}

// FIX-006 (WALLET-002): Internal helper that assumes lock is already held
// Used by ScanUTXOs to avoid deadlock
bool CWallet::AddTxOutUnlocked(const uint256& txid, uint32_t vout, int64_t nValue,
                                const CAddress& address, uint32_t nHeight) {
    // REQUIRES: cs_wallet must be held by caller

    CWalletTx wtx;
    wtx.txid = txid;
    wtx.vout = vout;
    wtx.nValue = nValue;
    wtx.address = address;
    wtx.fSpent = false;
    wtx.nHeight = nHeight;

    // FIX-005 (WALLET-001): Use COutPoint as key to prevent collision
    // Old bug: mapWalletTx[txid] overwrites when same tx has multiple outputs
    COutPoint outpoint(txid, vout);
    mapWalletTx[outpoint] = wtx;
    return true;
}

bool CWallet::AddTxOut(const uint256& txid, uint32_t vout, int64_t nValue,
                       const CAddress& address, uint32_t nHeight) {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return AddTxOutUnlocked(txid, vout, nValue, address, nHeight);
}

bool CWallet::MarkSpent(const uint256& txid, uint32_t vout) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // FIX-005 (WALLET-001): Use COutPoint to find exact output
    COutPoint outpoint(txid, vout);
    auto it = mapWalletTx.find(outpoint);
    if (it == mapWalletTx.end()) {
        return false;
    }

    // No need to check vout - COutPoint key already identifies exact output

    it->second.fSpent = true;
    return true;
}

int64_t CWallet::GetBalance() const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    int64_t balance = 0;
    for (const auto& pair : mapWalletTx) {
        const CWalletTx& wtx = pair.second;
        if (!wtx.fSpent) {
            // VULN-001 FIX: Protect against integer overflow
            if (balance > std::numeric_limits<int64_t>::max() - wtx.nValue) {
                // Overflow would occur - this indicates corrupted wallet or attack
                std::cerr << "[Wallet] ERROR: Balance overflow detected - wallet may be corrupted" << std::endl;
                return std::numeric_limits<int64_t>::max();  // Return max value instead of wrapping
            }
            balance += wtx.nValue;
        }
    }

    return balance;
}

std::vector<CWalletTx> CWallet::GetUnspentTxOuts() const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    std::vector<CWalletTx> vUnspent;
    for (const auto& pair : mapWalletTx) {
        if (!pair.second.fSpent) {
            vUnspent.push_back(pair.second);
        }
    }

    return vUnspent;
}

size_t CWallet::GetKeyPoolSize() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    // Return total number of keys (encrypted + unencrypted)
    return mapKeys.size() + mapCryptedKeys.size();
}

// ============================================================================
// Wallet Encryption Implementation
// ============================================================================

bool CWallet::IsCrypted() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    // Wallet is encrypted if master key has been set up
    return masterKey.IsValid();
}

bool CWallet::IsLocked() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    // Don't call IsCrypted() here to avoid deadlock (it also acquires mutex)
    return masterKey.IsValid() && !fWalletUnlocked;
}

// VULN-002 FIX: Helper to check if unlock is still valid (not expired)
// Assumes caller holds cs_wallet lock
bool CWallet::IsUnlockValid() const {
    // WL-005 FIX: Add mutex protection to prevent race condition
    // Without this lock, concurrent calls to CheckUnlockTimeout() or Lock()
    // could modify fWalletUnlocked/nUnlockTime while we're reading them,
    // leading to inconsistent state and potential security issues
    std::lock_guard<std::mutex> lock(cs_wallet);

    // If wallet is not encrypted, it doesn't need to be unlocked
    if (!masterKey.IsValid()) {
        return true;  // Unencrypted wallet is always "unlocked"
    }

    // Wallet is encrypted - check if unlocked
    if (!fWalletUnlocked) {
        return false;  // Wallet is locked
    }

    // If no timeout set, unlock is always valid
    if (nUnlockTime == std::chrono::steady_clock::time_point::max()) {
        return true;
    }

    // Check if timeout has expired
    return std::chrono::steady_clock::now() < nUnlockTime;
}

void CWallet::CheckUnlockTimeout() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fWalletUnlocked) {
        return;  // Already locked
    }

    if (nUnlockTime == std::chrono::steady_clock::time_point::max()) {
        return;  // No timeout (unlocked forever)
    }

    if (std::chrono::steady_clock::now() >= nUnlockTime) {
        // Timeout expired, lock wallet
        fWalletUnlocked = false;
        // Clear master key from memory
        if (!vMasterKey.empty()) {
            memory_cleanse(vMasterKey.data_ptr(), vMasterKey.size());
        }
        // WL-010 FIX: Clear cached decrypted HD master key
        if (fHDMasterKeyCached) {
            memory_cleanse(hdMasterKeyDecrypted.seed, 32);
            memory_cleanse(hdMasterKeyDecrypted.chaincode, 32);
            fHDMasterKeyCached = false;
        }
    }
}

// ============================================================================
// FIX-010 (CRYPT-002): IV Reuse Detection
// ============================================================================

// Internal helper: Generate unique IV (assumes caller holds cs_wallet lock)
template<typename Alloc>
bool CWallet::GenerateUniqueIV_Locked(std::vector<uint8_t, Alloc>& iv) {
    // Try up to 10 times to generate a unique IV
    // If we hit a collision after 10 attempts, the RNG is broken
    for (int attempts = 0; attempts < 10; attempts++) {
        // Generate random IV
        if (!GenerateIV(iv)) {
            return false;  // RNG failure
        }

        // Convert to std::vector for set lookup
        std::vector<uint8_t> iv_std(iv.begin(), iv.end());

        // Check if this IV has been used before
        if (usedIVs.find(iv_std) == usedIVs.end()) {
            // Unique IV found, register it
            usedIVs.insert(iv_std);
            return true;
        }

        // Collision detected, retry
        // Note: With a good RNG, probability of collision is ~2^-128 for 16-byte IVs
        // If we see collisions here, it indicates RNG failure
    }

    // Failed to generate unique IV after 10 attempts
    // This should NEVER happen with a properly functioning RNG
    return false;
}

bool CWallet::GenerateUniqueIV(std::vector<uint8_t, SecureAllocator<uint8_t>>& iv) {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return GenerateUniqueIV_Locked(iv);
}

void CWallet::RegisterIV(const std::vector<uint8_t>& iv) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Only register if IV is correct size (16 bytes for AES)
    if (iv.size() == WALLET_CRYPTO_IV_SIZE) {
        usedIVs.insert(iv);
    }
}

bool CWallet::IsIVUsed(const std::vector<uint8_t>& iv) const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return usedIVs.find(iv) != usedIVs.end();
}

size_t CWallet::GetIVCount() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return usedIVs.size();
}

bool CWallet::Lock() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!masterKey.IsValid()) {
        return false;  // Can't lock unencrypted wallet
    }

    fWalletUnlocked = false;
    nUnlockTime = std::chrono::steady_clock::time_point::max();

    // Clear master key from memory
    if (!vMasterKey.empty()) {
        memory_cleanse(vMasterKey.data_ptr(), vMasterKey.size());
    }

    // WL-010 FIX: Clear cached decrypted HD master key
    if (fHDMasterKeyCached) {
        memory_cleanse(hdMasterKeyDecrypted.seed, 32);
        memory_cleanse(hdMasterKeyDecrypted.chaincode, 32);
        fHDMasterKeyCached = false;
    }

    return true;
}

bool CWallet::Unlock(const std::string& passphrase, int64_t timeout) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!masterKey.IsValid()) {
        return false;  // Wallet not encrypted
    }

    if (passphrase.empty()) {
        return false;
    }

    // WL-011 FIX: Rate limiting with exponential backoff
    // Delay = 2^(attempts-1) seconds, capped at 1 hour
    // Attempts:  1→0s, 2→1s, 3→2s, 4→4s, 5→8s, 10→512s, 15+→3600s
    if (nUnlockFailedAttempts > 0) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - nLastFailedUnlock).count();

        // Calculate required delay: 2^(attempts-1) seconds, max 3600s (1 hour)
        int64_t required_delay = 1LL << (nUnlockFailedAttempts - 1);
        if (required_delay > 3600) required_delay = 3600;

        if (elapsed < required_delay) {
            std::cerr << "[Wallet] Rate limit: " << (required_delay - elapsed)
                     << " seconds remaining (attempt " << (nUnlockFailedAttempts + 1)
                     << ")" << std::endl;
            return false;
        }
    }

    // Derive key from passphrase
    std::vector<uint8_t> derivedKey;
    if (!DeriveKey(passphrase, masterKey.vchSalt, masterKey.nDeriveIterations, derivedKey)) {
        return false;
    }

    // Decrypt master key
    CCrypter crypter;
    if (!crypter.SetKey(derivedKey, masterKey.vchIV)) {
        return false;
    }

    // FIX-008 (CRYPT-007): Verify MAC before decryption (prevents padding oracle)
    // For legacy keys without MAC, skip verification
    if (!masterKey.IsLegacy()) {
        if (!crypter.VerifyMAC(masterKey.vchCryptedKey, masterKey.vchMAC)) {
            // WL-011 FIX: Track failed unlock attempt
            nUnlockFailedAttempts++;
            nLastFailedUnlock = std::chrono::steady_clock::now();
            return false;  // MAC verification failed - wrong passphrase or tampered data
        }
    }

    std::vector<uint8_t> decryptedKey;
    if (!crypter.Decrypt(masterKey.vchCryptedKey, decryptedKey)) {
        // WL-011 FIX: Track failed unlock attempt
        nUnlockFailedAttempts++;
        nLastFailedUnlock = std::chrono::steady_clock::now();
        return false;  // Wrong passphrase
    }

    if (decryptedKey.size() != WALLET_CRYPTO_KEY_SIZE) {
        return false;  // Invalid key size
    }

    // Store decrypted master key in memory
    memcpy(vMasterKey.data_ptr(), decryptedKey.data(), WALLET_CRYPTO_KEY_SIZE);

    fWalletUnlocked = true;

    // WL-011 FIX: Reset failed attempt counter on successful unlock
    nUnlockFailedAttempts = 0;

    // WL-010 FIX: Decrypt and cache HD master key for performance
    if (fIsHDWallet && fHDMasterKeyEncrypted) {
        // Decrypt HD master key into cache
        if (DecryptHDMasterKey(hdMasterKeyDecrypted)) {
            fHDMasterKeyCached = true;
        }
        // Note: If decryption fails, cache remains invalid (fHDMasterKeyCached = false)
        // This is acceptable - DecryptHDMasterKey will decrypt on-demand if cache invalid
    }

    // Set unlock timeout
    if (timeout > 0) {
        nUnlockTime = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
    } else {
        nUnlockTime = std::chrono::steady_clock::time_point::max();  // No timeout
    }

    // Wipe derived key
    memory_cleanse(derivedKey.data(), derivedKey.size());
    memory_cleanse(decryptedKey.data(), decryptedKey.size());

    return true;
}

bool CWallet::EncryptWallet(const std::string& passphrase) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (masterKey.IsValid()) {
        return false;  // Already encrypted
    }

    if (passphrase.empty()) {
        return false;
    }

    // Validate passphrase strength
    PassphraseValidator validator;
    PassphraseValidationResult validation = validator.Validate(passphrase);

    if (!validation.is_valid) {
        std::cerr << "[Wallet] Passphrase validation failed: "
                  << validation.error_message << std::endl;
        return false;
    }

    // Log passphrase strength
    std::cout << "[Wallet] Passphrase strength: "
              << PassphraseValidator::GetStrengthDescription(validation.strength_score)
              << " (" << validation.strength_score << "/100)" << std::endl;

    // Display any warnings
    for (const auto& warning : validation.warnings) {
        std::cout << "[Wallet] Warning: " << warning << std::endl;
    }

    // Allow encrypting empty wallet - keys will be encrypted as they're generated

    // Generate random master key
    std::vector<uint8_t> vMasterKeyPlain(WALLET_CRYPTO_KEY_SIZE);
    if (!GetStrongRandBytes(vMasterKeyPlain.data(), WALLET_CRYPTO_KEY_SIZE)) {
        return false;
    }

    // Generate salt for PBKDF2
    if (!GenerateSalt(masterKey.vchSalt)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // Derive key from passphrase
    std::vector<uint8_t> derivedKey;
    if (!DeriveKey(passphrase, masterKey.vchSalt, WALLET_CRYPTO_PBKDF2_ROUNDS, derivedKey)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // FIX-010: Generate unique IV for master key encryption
    if (!GenerateUniqueIV_Locked(masterKey.vchIV)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        memory_cleanse(derivedKey.data(), derivedKey.size());
        return false;
    }

    // Encrypt master key with passphrase-derived key
    CCrypter masterCrypter;
    if (!masterCrypter.SetKey(derivedKey, masterKey.vchIV)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        memory_cleanse(derivedKey.data(), derivedKey.size());
        return false;
    }

    if (!masterCrypter.Encrypt(vMasterKeyPlain, masterKey.vchCryptedKey)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        memory_cleanse(derivedKey.data(), derivedKey.size());
        return false;
    }

    // FIX-008 (CRYPT-007): Compute MAC for authenticated encryption
    if (!masterCrypter.ComputeMAC(masterKey.vchCryptedKey, masterKey.vchMAC)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        memory_cleanse(derivedKey.data(), derivedKey.size());
        return false;
    }

    masterKey.nDerivationMethod = 0;  // PBKDF2-SHA3
    masterKey.nDeriveIterations = WALLET_CRYPTO_PBKDF2_ROUNDS;

    // Now encrypt all existing keys with the master key
    for (const auto& pair : mapKeys) {
        const CAddress& address = pair.first;
        const CKey& key = pair.second;

        CEncryptedKey encKey;
        encKey.vchPubKey = key.vchPubKey;  // Public key stays unencrypted

        // FIX-010: Generate unique IV for this key
        if (!GenerateUniqueIV_Locked(encKey.vchIV)) {
            memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
            memory_cleanse(derivedKey.data(), derivedKey.size());
            return false;
        }

        // Encrypt private key with master key
        CCrypter keyCrypter;
        if (!keyCrypter.SetKey(vMasterKeyPlain, encKey.vchIV)) {
            memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
            memory_cleanse(derivedKey.data(), derivedKey.size());
            return false;
        }

        if (!keyCrypter.Encrypt(key.vchPrivKey, encKey.vchCryptedKey)) {
            memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
            memory_cleanse(derivedKey.data(), derivedKey.size());
            return false;
        }

        // FIX-008 (CRYPT-007): Compute MAC for authenticated encryption
        if (!keyCrypter.ComputeMAC(encKey.vchCryptedKey, encKey.vchMAC)) {
            memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
            memory_cleanse(derivedKey.data(), derivedKey.size());
            return false;
        }

        mapCryptedKeys[address] = encKey;
    }

    // Clear unencrypted keys
    mapKeys.clear();

    // Keep wallet unlocked after encryption
    memcpy(vMasterKey.data_ptr(), vMasterKeyPlain.data(), WALLET_CRYPTO_KEY_SIZE);
    fWalletUnlocked = true;
    nUnlockTime = std::chrono::steady_clock::time_point::max();

    // Wipe sensitive data
    memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
    memory_cleanse(derivedKey.data(), derivedKey.size());

    // Auto-save wallet if enabled (we already hold the lock)
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    return true;
}

bool CWallet::ChangePassphrase(const std::string& passphraseOld,
                                const std::string& passphraseNew) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!masterKey.IsValid()) {
        return false;  // Wallet not encrypted
    }

    if (passphraseNew.empty()) {
        return false;
    }

    // Validate new passphrase strength
    PassphraseValidator validator;
    PassphraseValidationResult validation = validator.Validate(passphraseNew);

    if (!validation.is_valid) {
        std::cerr << "[Wallet] New passphrase validation failed: "
                  << validation.error_message << std::endl;
        return false;
    }

    // Log passphrase strength
    std::cout << "[Wallet] New passphrase strength: "
              << PassphraseValidator::GetStrengthDescription(validation.strength_score)
              << " (" << validation.strength_score << "/100)" << std::endl;

    // Display any warnings
    for (const auto& warning : validation.warnings) {
        std::cout << "[Wallet] Warning: " << warning << std::endl;
    }

    // Derive old key
    std::vector<uint8_t> derivedKeyOld;
    if (!DeriveKey(passphraseOld, masterKey.vchSalt, masterKey.nDeriveIterations, derivedKeyOld)) {
        return false;
    }

    // Decrypt current master key
    CCrypter crypterOld;
    if (!crypterOld.SetKey(derivedKeyOld, masterKey.vchIV)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        return false;
    }

    // FIX-008 (CRYPT-007): Verify MAC before decryption (prevents padding oracle)
    // For legacy keys without MAC, skip verification
    if (!masterKey.IsLegacy()) {
        if (!crypterOld.VerifyMAC(masterKey.vchCryptedKey, masterKey.vchMAC)) {
            memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
            return false;  // MAC verification failed - wrong passphrase or tampered data
        }
    }

    std::vector<uint8_t> vMasterKeyPlain;
    if (!crypterOld.Decrypt(masterKey.vchCryptedKey, vMasterKeyPlain)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        return false;  // Wrong old passphrase
    }

    // Generate new salt
    std::vector<uint8_t> newSalt;
    if (!GenerateSalt(newSalt)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // Derive new key
    std::vector<uint8_t> derivedKeyNew;
    if (!DeriveKey(passphraseNew, newSalt, WALLET_CRYPTO_PBKDF2_ROUNDS, derivedKeyNew)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // FIX-010: Generate unique IV for re-encryption
    std::vector<uint8_t> newIV;
    if (!GenerateUniqueIV_Locked(newIV)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(derivedKeyNew.data(), derivedKeyNew.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // Re-encrypt master key with new passphrase
    CCrypter crypterNew;
    if (!crypterNew.SetKey(derivedKeyNew, newIV)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(derivedKeyNew.data(), derivedKeyNew.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    std::vector<uint8_t> newCryptedKey;
    if (!crypterNew.Encrypt(vMasterKeyPlain, newCryptedKey)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(derivedKeyNew.data(), derivedKeyNew.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // FIX-008 (CRYPT-007): Compute MAC for authenticated encryption
    std::vector<uint8_t> newMAC;
    if (!crypterNew.ComputeMAC(newCryptedKey, newMAC)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(derivedKeyNew.data(), derivedKeyNew.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // Update master key
    masterKey.vchCryptedKey = newCryptedKey;
    masterKey.vchSalt = newSalt;
    masterKey.vchMAC = newMAC;  // FIX-008: Store MAC
    masterKey.vchIV = newIV;

    // Wipe sensitive data
    memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
    memory_cleanse(derivedKeyNew.data(), derivedKeyNew.size());
    memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());

    // Auto-save wallet if enabled (we already hold the lock)
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    return true;
}

// ============================================================================
// Persistence
// ============================================================================

bool CWallet::Load(const std::string& filename) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;  // File doesn't exist or can't be opened
    }

    // SEC-001 FIX: Load into temporary variables first (atomic load pattern)
    // Only clear existing wallet if load succeeds completely
    std::map<CAddress, CKey> temp_mapKeys;
    std::map<CAddress, CEncryptedKey> temp_mapCryptedKeys;
    std::vector<CAddress> temp_vchAddresses;
    // FIX-005 (WALLET-001): Changed to COutPoint key for v3 format
    std::map<COutPoint, CWalletTx> temp_mapWalletTx;
    CAddress temp_defaultAddress;
    CMasterKey temp_masterKey;
    bool temp_fWalletUnlocked = true;

    // Read header
    char magic[8];
    file.read(magic, 8);
    if (!file.good()) return false;  // SEC-001: Check I/O error

    std::string magic_str(magic, 8);
    // FIX-011 (PERSIST-001): Support DILWLT03 format with file integrity HMAC
    if (magic_str != "DILWLT01" && magic_str != "DILWLT02" && magic_str != "DILWLT03") {
        return false;  // Invalid file format
    }

    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (!file.good()) return false;  // SEC-001: Check I/O error
    if (version != 1 && version != 2 && version != 3) {
        return false;  // Unsupported version
    }

    uint32_t flags;
    file.read(reinterpret_cast<char*>(&flags), sizeof(flags));
    if (!file.good()) return false;  // SEC-001: Check I/O error

    bool is_hd_wallet = (flags & 0x02) != 0;

    // FIX-011 (PERSIST-001): Read HMAC and salt for v3 format
    std::vector<uint8_t> stored_hmac;
    std::vector<uint8_t> hmac_salt;
    std::streampos data_start_pos;  // Position where HMAC-protected data starts (salt position)

    if (version == 3) {
        // v3 format: [Magic][Version][Flags][HMAC][Salt][Data...]
        // Read stored HMAC
        stored_hmac.resize(WALLET_FILE_HMAC_SIZE);
        file.read(reinterpret_cast<char*>(stored_hmac.data()), WALLET_FILE_HMAC_SIZE);
        if (!file.good()) return false;

        // Remember position where HMAC-protected data starts (before reading salt)
        // HMAC covers [Salt][Data...], not [HMAC][Salt][Data...]
        data_start_pos = file.tellg();

        // Read HMAC salt
        hmac_salt.resize(WALLET_FILE_SALT_SIZE);
        file.read(reinterpret_cast<char*>(hmac_salt.data()), WALLET_FILE_SALT_SIZE);
        if (!file.good()) return false;
    } else {
        // v1/v2 format: Skip reserved bytes (no HMAC)
        uint8_t reserved[16];
        file.read(reinterpret_cast<char*>(reserved), 16);
        if (!file.good()) return false;  // SEC-001: Check I/O error
    }

    // Read master key if encrypted
    bool isEncrypted = (flags & 0x01) != 0;
    if (isEncrypted) {
        uint32_t cryptedKeyLen;
        file.read(reinterpret_cast<char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // SEC-001 FIX: Validate cryptedKeyLen to prevent memory exhaustion
        const uint32_t MAX_ENCRYPTED_KEY_SIZE = 8192;  // Reasonable upper bound
        if (cryptedKeyLen > MAX_ENCRYPTED_KEY_SIZE) {
            return false;  // Reject malicious sizes
        }

        temp_masterKey.vchCryptedKey.resize(cryptedKeyLen);
        file.read(reinterpret_cast<char*>(temp_masterKey.vchCryptedKey.data()), cryptedKeyLen);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        temp_masterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
        file.read(reinterpret_cast<char*>(temp_masterKey.vchSalt.data()), WALLET_CRYPTO_SALT_SIZE);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        temp_masterKey.vchIV.resize(WALLET_CRYPTO_IV_SIZE);
        file.read(reinterpret_cast<char*>(temp_masterKey.vchIV.data()), WALLET_CRYPTO_IV_SIZE);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // FIX-010: Register master key IV to prevent reuse
        usedIVs.insert(temp_masterKey.vchIV);

        file.read(reinterpret_cast<char*>(&temp_masterKey.nDerivationMethod), sizeof(temp_masterKey.nDerivationMethod));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.read(reinterpret_cast<char*>(&temp_masterKey.nDeriveIterations), sizeof(temp_masterKey.nDeriveIterations));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // FIX-008 (CRYPT-007): Load MAC for authenticated encryption
        // For legacy wallets (v2 without MAC), this field won't exist
        // Check if there's more data to read
        uint32_t macLen = 0;
        std::streampos pos_before = file.tellg();
        file.read(reinterpret_cast<char*>(&macLen), sizeof(macLen));
        if (file.good() && macLen > 0 && macLen <= 64) {  // HMAC-SHA3-512 is 64 bytes
            temp_masterKey.vchMAC.resize(macLen);
            file.read(reinterpret_cast<char*>(temp_masterKey.vchMAC.data()), macLen);
            if (!file.good()) {
                // Failed to read MAC - might be EOF, treat as legacy wallet
                file.clear();  // Clear error state
                file.seekg(pos_before);  // Restore position
                temp_masterKey.vchMAC.clear();
            }
        } else {
            // No MAC or invalid length - legacy wallet
            file.clear();  // Clear error state if EOF
            file.seekg(pos_before);  // Restore position
            temp_masterKey.vchMAC.clear();
        }

        // Wallet starts locked (encryption status determined by masterKey.IsValid())
        temp_fWalletUnlocked = false;
    }

    // Read HD wallet data (v2 only)
    bool temp_fIsHDWallet = false;
    std::vector<uint8_t> temp_vchEncryptedMnemonic;
    std::vector<uint8_t> temp_vchMnemonicIV;
    CHDExtendedKey temp_hdMasterKey;
    bool temp_fHDMasterKeyEncrypted = false;
    std::vector<uint8_t> temp_vchHDMasterKeyIV;
    uint32_t temp_nHDAccountIndex = 0;
    uint32_t temp_nHDExternalChainIndex = 0;
    uint32_t temp_nHDInternalChainIndex = 0;
    std::map<CAddress, CHDKeyPath> temp_mapAddressToPath;
    std::map<CHDKeyPath, CAddress> temp_mapPathToAddress;

    if (is_hd_wallet) {
        temp_fIsHDWallet = true;

        // Read encrypted mnemonic
        uint32_t mnemonicLen;
        file.read(reinterpret_cast<char*>(&mnemonicLen), sizeof(mnemonicLen));
        if (!file.good()) return false;

        // Validate mnemonic length
        const uint32_t MAX_MNEMONIC_SIZE = 1024;  // Reasonable upper bound
        if (mnemonicLen > MAX_MNEMONIC_SIZE) {
            return false;
        }

        if (mnemonicLen > 0) {
            temp_vchEncryptedMnemonic.resize(mnemonicLen);
            file.read(reinterpret_cast<char*>(temp_vchEncryptedMnemonic.data()), mnemonicLen);
            if (!file.good()) return false;

            temp_vchMnemonicIV.resize(WALLET_CRYPTO_IV_SIZE);
            file.read(reinterpret_cast<char*>(temp_vchMnemonicIV.data()), WALLET_CRYPTO_IV_SIZE);
            if (!file.good()) return false;

            // FIX-010: Register mnemonic IV to prevent reuse
            usedIVs.insert(temp_vchMnemonicIV);
        }

        // Read HD master key
        file.read(reinterpret_cast<char*>(temp_hdMasterKey.seed), 32);
        if (!file.good()) return false;
        file.read(reinterpret_cast<char*>(temp_hdMasterKey.chaincode), 32);
        if (!file.good()) return false;
        file.read(reinterpret_cast<char*>(&temp_hdMasterKey.depth), sizeof(temp_hdMasterKey.depth));
        if (!file.good()) return false;
        file.read(reinterpret_cast<char*>(&temp_hdMasterKey.fingerprint), sizeof(temp_hdMasterKey.fingerprint));
        if (!file.good()) return false;
        file.read(reinterpret_cast<char*>(&temp_hdMasterKey.child_index), sizeof(temp_hdMasterKey.child_index));
        if (!file.good()) return false;

        // Read HD master key encryption flag
        uint8_t encrypted_flag;
        file.read(reinterpret_cast<char*>(&encrypted_flag), 1);
        if (!file.good()) return false;
        temp_fHDMasterKeyEncrypted = (encrypted_flag != 0);

        if (temp_fHDMasterKeyEncrypted) {
            temp_vchHDMasterKeyIV.resize(WALLET_CRYPTO_IV_SIZE);
            file.read(reinterpret_cast<char*>(temp_vchHDMasterKeyIV.data()), WALLET_CRYPTO_IV_SIZE);
            if (!file.good()) return false;

            // FIX-010: Register HD master key IV to prevent reuse
            usedIVs.insert(temp_vchHDMasterKeyIV);
        }

        // Read HD chain state
        file.read(reinterpret_cast<char*>(&temp_nHDAccountIndex), sizeof(temp_nHDAccountIndex));
        if (!file.good()) return false;
        file.read(reinterpret_cast<char*>(&temp_nHDExternalChainIndex), sizeof(temp_nHDExternalChainIndex));
        if (!file.good()) return false;
        file.read(reinterpret_cast<char*>(&temp_nHDInternalChainIndex), sizeof(temp_nHDInternalChainIndex));
        if (!file.good()) return false;

        // Read HD path mappings
        uint32_t numPaths;
        file.read(reinterpret_cast<char*>(&numPaths), sizeof(numPaths));
        if (!file.good()) return false;

        // Validate numPaths
        const uint32_t MAX_HD_PATHS = 100000;  // Reasonable upper bound
        if (numPaths > MAX_HD_PATHS) {
            return false;
        }

        for (uint32_t i = 0; i < numPaths; i++) {
            // Read path indices count
            uint32_t numIndices;
            file.read(reinterpret_cast<char*>(&numIndices), sizeof(numIndices));
            if (!file.good()) return false;

            // Validate numIndices (BIP44 has 5 levels)
            const uint32_t MAX_PATH_DEPTH = 10;
            if (numIndices > MAX_PATH_DEPTH) {
                return false;
            }

            // Read indices
            CHDKeyPath path;
            path.indices.resize(numIndices);
            for (uint32_t j = 0; j < numIndices; j++) {
                file.read(reinterpret_cast<char*>(&path.indices[j]), sizeof(uint32_t));
                if (!file.good()) return false;
            }

            // Read address
            std::vector<uint8_t> addrData(21);
            file.read(reinterpret_cast<char*>(addrData.data()), 21);
            if (!file.good()) return false;

            // Reconstruct address from raw data
            CAddress address = CAddress::FromData(addrData);

            // Store path mappings
            temp_mapPathToAddress[path] = address;
            temp_mapAddressToPath[address] = path;
        }
    }

    // Read keys
    uint32_t numKeys;
    file.read(reinterpret_cast<char*>(&numKeys), sizeof(numKeys));
    if (!file.good()) return false;  // SEC-001: Check I/O error

    // SEC-001 FIX: Validate numKeys to prevent iteration bomb / DoS
    const uint32_t MAX_WALLET_KEYS = 1000000;  // 1M keys is already excessive
    if (numKeys > MAX_WALLET_KEYS) {
        return false;  // Reject malicious loop counts
    }

    for (uint32_t i = 0; i < numKeys; i++) {
        // Read address
        std::vector<uint8_t> addrData(21);
        file.read(reinterpret_cast<char*>(addrData.data()), 21);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        CAddress addr;
        if (!addr.SetString(::EncodeBase58Check(addrData))) {
            // Fallback: construct address directly from data
            // This is needed because SetString expects Base58-encoded string
            // but we have raw bytes. We'll need a different approach.
            // For now, skip validation and construct manually
        }

        if (isEncrypted) {
            // Read encrypted key
            CEncryptedKey encKey;

            encKey.vchPubKey.resize(DILITHIUM_PUBLICKEY_SIZE);
            file.read(reinterpret_cast<char*>(encKey.vchPubKey.data()), DILITHIUM_PUBLICKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            uint32_t cryptedKeyLen;
            file.read(reinterpret_cast<char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // SEC-001 FIX: Validate cryptedKeyLen (same check as master key)
            const uint32_t MAX_ENCRYPTED_KEY_SIZE = 8192;
            if (cryptedKeyLen > MAX_ENCRYPTED_KEY_SIZE) {
                return false;  // Reject malicious sizes
            }

            encKey.vchCryptedKey.resize(cryptedKeyLen);
            file.read(reinterpret_cast<char*>(encKey.vchCryptedKey.data()), cryptedKeyLen);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            encKey.vchIV.resize(16);
            file.read(reinterpret_cast<char*>(encKey.vchIV.data()), 16);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // FIX-010: Register encrypted key IV to prevent reuse
            usedIVs.insert(encKey.vchIV);

            // FIX-008 (CRYPT-007): Load MAC for authenticated encryption
            // For legacy wallets (v2 without MAC), this field won't exist
            uint32_t macLen = 0;
            std::streampos pos_before = file.tellg();
            file.read(reinterpret_cast<char*>(&macLen), sizeof(macLen));
            if (file.good() && macLen > 0 && macLen <= 64) {  // HMAC-SHA3-512 is 64 bytes
                encKey.vchMAC.resize(macLen);
                file.read(reinterpret_cast<char*>(encKey.vchMAC.data()), macLen);
                if (!file.good()) {
                    // Failed to read MAC - might be EOF, treat as legacy wallet
                    file.clear();  // Clear error state
                    file.seekg(pos_before);  // Restore position
                    encKey.vchMAC.clear();
                }
            } else {
                // No MAC or invalid length - legacy wallet
                file.clear();  // Clear error state if EOF
                file.seekg(pos_before);  // Restore position
                encKey.vchMAC.clear();
            }

            // Create address from public key
            CAddress keyAddr(encKey.vchPubKey);
            temp_mapCryptedKeys[keyAddr] = encKey;
            temp_vchAddresses.push_back(keyAddr);
        } else {
            // Read unencrypted key
            CKey key;

            key.vchPubKey.resize(DILITHIUM_PUBLICKEY_SIZE);
            file.read(reinterpret_cast<char*>(key.vchPubKey.data()), DILITHIUM_PUBLICKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            key.vchPrivKey.resize(DILITHIUM_SECRETKEY_SIZE);
            file.read(reinterpret_cast<char*>(key.vchPrivKey.data()), DILITHIUM_SECRETKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Create address from public key
            CAddress keyAddr(key.vchPubKey);
            temp_mapKeys[keyAddr] = key;
            temp_vchAddresses.push_back(keyAddr);
        }
    }

    // Read default address
    uint8_t hasDefault;
    file.read(reinterpret_cast<char*>(&hasDefault), 1);
    if (!file.good()) return false;  // SEC-001: Check I/O error
    if (hasDefault) {
        std::vector<uint8_t> addrData(21);
        file.read(reinterpret_cast<char*>(addrData.data()), 21);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // Find matching address in temp_vchAddresses
        for (const auto& addr : temp_vchAddresses) {
            if (addr.GetData() == addrData) {
                temp_defaultAddress = addr;
                break;
            }
        }
    }

    // Read transactions
    uint32_t numTxs;
    file.read(reinterpret_cast<char*>(&numTxs), sizeof(numTxs));
    if (!file.good()) return false;  // SEC-001: Check I/O error

    // SEC-001 FIX: Validate numTxs to prevent iteration bomb / DoS
    const uint32_t MAX_WALLET_TXS = 10000000;  // 10M transactions is excessive
    if (numTxs > MAX_WALLET_TXS) {
        return false;  // Reject malicious loop counts
    }

    for (uint32_t i = 0; i < numTxs; i++) {
        CWalletTx wtx;

        file.read(reinterpret_cast<char*>(wtx.txid.begin()), 32);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.read(reinterpret_cast<char*>(&wtx.vout), sizeof(wtx.vout));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.read(reinterpret_cast<char*>(&wtx.nValue), sizeof(wtx.nValue));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        std::vector<uint8_t> addrData(21);
        file.read(reinterpret_cast<char*>(addrData.data()), 21);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // Find matching address in temp_vchAddresses
        for (const auto& addr : temp_vchAddresses) {
            if (addr.GetData() == addrData) {
                wtx.address = addr;
                break;
            }
        }

        uint8_t fSpent;
        file.read(reinterpret_cast<char*>(&fSpent), 1);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        wtx.fSpent = (fSpent != 0);

        file.read(reinterpret_cast<char*>(&wtx.nHeight), sizeof(wtx.nHeight));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // FIX-005 (WALLET-001): Use COutPoint as composite key to prevent collision
        // When a transaction has multiple outputs to wallet, using only txid causes overwrites
        COutPoint outpoint(wtx.txid, wtx.vout);
        temp_mapWalletTx[outpoint] = wtx;
    }

    // SEC-001 FIX: Only if ALL data loaded successfully, swap into wallet
    // This ensures atomic load - either everything loads or nothing changes
    if (!file.good()) {
        return false;  // File error occurred, temp data discarded
    }

    // FIX-011 (PERSIST-001): Verify HMAC for v3 format
    if (version == 3) {
        // Remember current position (end of data)
        std::streampos end_pos = file.tellg();

        // Seek back to start of HMAC-protected data (salt position)
        file.seekg(data_start_pos);

        // Read all data from salt to end
        size_t data_size = static_cast<size_t>(end_pos - data_start_pos);
        std::vector<uint8_t> file_data(data_size);
        file.read(reinterpret_cast<char*>(file_data.data()), data_size);
        if (!file.good()) {
            return false;  // Failed to read data for HMAC verification
        }

        // Derive HMAC key (same strategy as SaveUnlocked)
        std::vector<uint8_t> hmac_key(32);
        if (temp_masterKey.IsValid()) {
            // Use first 32 bytes of master key salt as HMAC key (available without passphrase)
            memcpy(hmac_key.data(), temp_masterKey.vchSalt.data(),
                   std::min(hmac_key.size(), temp_masterKey.vchSalt.size()));
        } else {
            // For unencrypted wallets, derive HMAC key from wallet content (deterministic)
            // Use SHA3-256 of (first address + default address) as key
            std::vector<uint8_t> key_material;
            if (!temp_vchAddresses.empty()) {
                std::vector<uint8_t> addr_data = temp_vchAddresses[0].GetData();
                key_material.insert(key_material.end(), addr_data.begin(), addr_data.end());
            }
            std::vector<uint8_t> default_data = temp_defaultAddress.GetData();
            key_material.insert(key_material.end(), default_data.begin(), default_data.end());

            SHA3_256(key_material.data(), key_material.size(), hmac_key.data());
        }

        // Compute HMAC-SHA3-256 over the data
        std::vector<uint8_t> computed_hmac(32);
        HMAC_SHA3_256(hmac_key.data(), hmac_key.size(),
                      file_data.data(), file_data.size(),
                      computed_hmac.data());

        // Constant-time comparison to prevent timing attacks (FIX-001)
        if (!RPCAuth::SecureCompare(stored_hmac.data(), computed_hmac.data(), WALLET_FILE_HMAC_SIZE)) {
            return false;  // HMAC verification failed - file has been tampered with!
        }

        // HMAC verification passed - file integrity confirmed
    }

    // FIX-012 (WALLET-002): Validate wallet consistency before committing
    // This detects corruption/tampering beyond just HMAC failures
    // Create temporary wallet to test consistency before modifying this wallet
    CWallet temp_wallet_for_validation;
    temp_wallet_for_validation.mapKeys = temp_mapKeys;
    temp_wallet_for_validation.mapCryptedKeys = temp_mapCryptedKeys;
    temp_wallet_for_validation.vchAddresses = temp_vchAddresses;
    temp_wallet_for_validation.mapWalletTx = temp_mapWalletTx;
    temp_wallet_for_validation.fIsHDWallet = temp_fIsHDWallet;
    temp_wallet_for_validation.mapAddressToPath = temp_mapAddressToPath;
    temp_wallet_for_validation.mapPathToAddress = temp_mapPathToAddress;
    temp_wallet_for_validation.nHDExternalChainIndex = temp_nHDExternalChainIndex;
    temp_wallet_for_validation.nHDInternalChainIndex = temp_nHDInternalChainIndex;
    temp_wallet_for_validation.nHDAccountIndex = temp_nHDAccountIndex;
    temp_wallet_for_validation.masterKey = temp_masterKey;

    std::string consistency_error;
    if (!temp_wallet_for_validation.ValidateConsistency(consistency_error)) {
        // Consistency check failed - wallet is corrupted
        std::cerr << "ERROR: Wallet consistency validation failed: "
                  << consistency_error << std::endl;
        return false;  // Reject corrupted wallet
    }

    // All data loaded successfully - now atomically replace wallet contents
    mapKeys = std::move(temp_mapKeys);
    mapCryptedKeys = std::move(temp_mapCryptedKeys);
    vchAddresses = std::move(temp_vchAddresses);
    mapWalletTx = std::move(temp_mapWalletTx);
    defaultAddress = temp_defaultAddress;
    masterKey = temp_masterKey;
    fWalletUnlocked = temp_fWalletUnlocked;

    // HD wallet data
    fIsHDWallet = temp_fIsHDWallet;
    vchEncryptedMnemonic = std::move(temp_vchEncryptedMnemonic);
    // FIX-009: Use assign() for SecureAllocator vectors
    vchMnemonicIV.assign(temp_vchMnemonicIV.begin(), temp_vchMnemonicIV.end());
    hdMasterKey = temp_hdMasterKey;
    fHDMasterKeyEncrypted = temp_fHDMasterKeyEncrypted;
    // FIX-009: Use assign() for SecureAllocator vectors
    vchHDMasterKeyIV.assign(temp_vchHDMasterKeyIV.begin(), temp_vchHDMasterKeyIV.end());
    nHDAccountIndex = temp_nHDAccountIndex;
    nHDExternalChainIndex = temp_nHDExternalChainIndex;
    nHDInternalChainIndex = temp_nHDInternalChainIndex;
    mapAddressToPath = std::move(temp_mapAddressToPath);
    mapPathToAddress = std::move(temp_mapPathToAddress);

    m_walletFile = filename;  // Set wallet file path only on successful load

    return true;
}

// Public Save() method - acquires lock and calls SaveUnlocked()
bool CWallet::Save(const std::string& filename) const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return SaveUnlocked(filename);
}

// Private SaveUnlocked() method - assumes caller already holds cs_wallet lock
bool CWallet::SaveUnlocked(const std::string& filename) const {
    // Use current wallet file if no filename specified
    std::string saveFile = filename.empty() ? m_walletFile : filename;
    if (saveFile.empty()) {
        return false;  // No wallet file specified
    }

    // SEC-001 FIX: Atomic file write pattern
    // Write to temporary file first, then atomically rename on success
    // This prevents corruption if write fails mid-operation
    std::string tempFile = saveFile + ".tmp";

    // FIX-002 (PERSIST-003): Set secure file permissions before creating file
    // Only owner can read/write (0600), prevents other users from reading private keys
    #ifndef _WIN32
        mode_t old_umask = umask(0077);  // Remove all group/other permissions
    #endif

    std::ofstream file(tempFile, std::ios::binary);

    #ifndef _WIN32
        umask(old_umask);  // Restore original umask
        // Double-check permissions were applied correctly
        if (file.is_open()) {
            chmod(tempFile.c_str(), S_IRUSR | S_IWUSR);  // 0600: owner read/write only
        }
    #endif

    if (!file.is_open()) {
        return false;
    }

    // FIX-011 (PERSIST-001): Write header with file integrity HMAC (v3 format)
    // Format: [Magic][Version][Flags][HMAC-placeholder][Salt][Data...]
    file.write(WALLET_FILE_MAGIC_V3, 8);  // "DILWLT03"
    if (!file.good()) return false;

    uint32_t version = WALLET_FILE_VERSION_3;
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));
    if (!file.good()) return false;

    // Flags: bit 0 = encrypted, bit 1 = is HD wallet
    uint32_t flags = 0;
    if (masterKey.IsValid()) flags |= 0x01;
    if (fIsHDWallet) flags |= 0x02;
    file.write(reinterpret_cast<const char*>(&flags), sizeof(flags));
    if (!file.good()) return false;

    // FIX-011: Remember position for HMAC (will write real HMAC later)
    std::streampos hmac_pos = file.tellp();

    // Write placeholder HMAC (zeros for now, will compute and write later)
    std::vector<uint8_t> placeholder_hmac(WALLET_FILE_HMAC_SIZE, 0);
    file.write(reinterpret_cast<const char*>(placeholder_hmac.data()), WALLET_FILE_HMAC_SIZE);
    if (!file.good()) return false;

    // FIX-011: Generate random salt for HMAC
    std::vector<uint8_t> hmac_salt(WALLET_FILE_SALT_SIZE);
    if (!GenerateIV(hmac_salt)) {
        return false;
    }
    // FIX-011: Remember position before writing salt (HMAC covers [Salt][Data...])
    std::streampos data_start_pos = file.tellp();
    file.write(reinterpret_cast<const char*>(hmac_salt.data()), WALLET_FILE_SALT_SIZE);
    if (!file.good()) return false;

    // Write master key if encrypted
    if (masterKey.IsValid()) {
        uint32_t cryptedKeyLen = static_cast<uint32_t>(masterKey.vchCryptedKey.size());
        file.write(reinterpret_cast<const char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(masterKey.vchCryptedKey.data()), cryptedKeyLen);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        file.write(reinterpret_cast<const char*>(masterKey.vchSalt.data()), WALLET_CRYPTO_SALT_SIZE);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(masterKey.vchIV.data()), WALLET_CRYPTO_IV_SIZE);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(&masterKey.nDerivationMethod), sizeof(masterKey.nDerivationMethod));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(&masterKey.nDeriveIterations), sizeof(masterKey.nDeriveIterations));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // FIX-008 (CRYPT-007): Save MAC for authenticated encryption
        uint32_t macLen = static_cast<uint32_t>(masterKey.vchMAC.size());
        file.write(reinterpret_cast<const char*>(&macLen), sizeof(macLen));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        if (macLen > 0) {
            file.write(reinterpret_cast<const char*>(masterKey.vchMAC.data()), macLen);
            if (!file.good()) return false;  // SEC-001: Check I/O error
        }
    }

    // Write HD wallet data (v2 only)
    if (fIsHDWallet) {
        // Write encrypted mnemonic
        uint32_t mnemonicLen = static_cast<uint32_t>(vchEncryptedMnemonic.size());
        file.write(reinterpret_cast<const char*>(&mnemonicLen), sizeof(mnemonicLen));
        if (!file.good()) return false;
        if (mnemonicLen > 0) {
            file.write(reinterpret_cast<const char*>(vchEncryptedMnemonic.data()), mnemonicLen);
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(vchMnemonicIV.data()), WALLET_CRYPTO_IV_SIZE);
            if (!file.good()) return false;
        }

        // Write HD master key (seed + chaincode = 64 bytes)
        file.write(reinterpret_cast<const char*>(hdMasterKey.seed), 32);
        if (!file.good()) return false;
        file.write(reinterpret_cast<const char*>(hdMasterKey.chaincode), 32);
        if (!file.good()) return false;
        file.write(reinterpret_cast<const char*>(&hdMasterKey.depth), sizeof(hdMasterKey.depth));
        if (!file.good()) return false;
        file.write(reinterpret_cast<const char*>(&hdMasterKey.fingerprint), sizeof(hdMasterKey.fingerprint));
        if (!file.good()) return false;
        file.write(reinterpret_cast<const char*>(&hdMasterKey.child_index), sizeof(hdMasterKey.child_index));
        if (!file.good()) return false;

        // Write HD master key encryption flag and IV
        uint8_t encrypted_flag = fHDMasterKeyEncrypted ? 1 : 0;
        file.write(reinterpret_cast<const char*>(&encrypted_flag), 1);
        if (!file.good()) return false;
        if (fHDMasterKeyEncrypted) {
            file.write(reinterpret_cast<const char*>(vchHDMasterKeyIV.data()), WALLET_CRYPTO_IV_SIZE);
            if (!file.good()) return false;
        }

        // Write HD chain state
        file.write(reinterpret_cast<const char*>(&nHDAccountIndex), sizeof(nHDAccountIndex));
        if (!file.good()) return false;
        file.write(reinterpret_cast<const char*>(&nHDExternalChainIndex), sizeof(nHDExternalChainIndex));
        if (!file.good()) return false;
        file.write(reinterpret_cast<const char*>(&nHDInternalChainIndex), sizeof(nHDInternalChainIndex));
        if (!file.good()) return false;

        // Write HD path mappings
        uint32_t numPaths = static_cast<uint32_t>(mapPathToAddress.size());
        file.write(reinterpret_cast<const char*>(&numPaths), sizeof(numPaths));
        if (!file.good()) return false;

        for (const auto& pair : mapPathToAddress) {
            const CHDKeyPath& path = pair.first;
            const CAddress& address = pair.second;

            // Write path indices count
            uint32_t numIndices = static_cast<uint32_t>(path.indices.size());
            file.write(reinterpret_cast<const char*>(&numIndices), sizeof(numIndices));
            if (!file.good()) return false;

            // Write indices
            for (uint32_t index : path.indices) {
                file.write(reinterpret_cast<const char*>(&index), sizeof(index));
                if (!file.good()) return false;
            }

            // Write address
            file.write(reinterpret_cast<const char*>(address.GetData().data()), 21);
            if (!file.good()) return false;
        }
    }

    // Write keys
    if (masterKey.IsValid()) {
        // Encrypted wallet - write encrypted keys
        uint32_t numKeys = static_cast<uint32_t>(mapCryptedKeys.size());
        file.write(reinterpret_cast<const char*>(&numKeys), sizeof(numKeys));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        for (const auto& pair : mapCryptedKeys) {
            const CAddress& addr = pair.first;
            const CEncryptedKey& encKey = pair.second;

            // Write address
            file.write(reinterpret_cast<const char*>(addr.GetData().data()), 21);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Write public key
            file.write(reinterpret_cast<const char*>(encKey.vchPubKey.data()), DILITHIUM_PUBLICKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Write encrypted private key
            uint32_t cryptedKeyLen = static_cast<uint32_t>(encKey.vchCryptedKey.size());
            file.write(reinterpret_cast<const char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));
            if (!file.good()) return false;  // SEC-001: Check I/O error
            file.write(reinterpret_cast<const char*>(encKey.vchCryptedKey.data()), cryptedKeyLen);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Write IV
            file.write(reinterpret_cast<const char*>(encKey.vchIV.data()), 16);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // FIX-008 (CRYPT-007): Save MAC for authenticated encryption
            uint32_t macLen = static_cast<uint32_t>(encKey.vchMAC.size());
            file.write(reinterpret_cast<const char*>(&macLen), sizeof(macLen));
            if (!file.good()) return false;  // SEC-001: Check I/O error
            if (macLen > 0) {
                file.write(reinterpret_cast<const char*>(encKey.vchMAC.data()), macLen);
                if (!file.good()) return false;  // SEC-001: Check I/O error
            }
        }
    } else {
        // Unencrypted wallet - write unencrypted keys
        uint32_t numKeys = static_cast<uint32_t>(mapKeys.size());
        file.write(reinterpret_cast<const char*>(&numKeys), sizeof(numKeys));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        for (const auto& pair : mapKeys) {
            const CAddress& addr = pair.first;
            const CKey& key = pair.second;

            // Write address
            file.write(reinterpret_cast<const char*>(addr.GetData().data()), 21);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Write public key
            file.write(reinterpret_cast<const char*>(key.vchPubKey.data()), DILITHIUM_PUBLICKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Write private key
            file.write(reinterpret_cast<const char*>(key.vchPrivKey.data()), DILITHIUM_SECRETKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error
        }
    }

    // Write default address
    uint8_t hasDefault = defaultAddress.IsValid() ? 1 : 0;
    file.write(reinterpret_cast<const char*>(&hasDefault), 1);
    if (!file.good()) return false;  // SEC-001: Check I/O error
    if (hasDefault) {
        file.write(reinterpret_cast<const char*>(defaultAddress.GetData().data()), 21);
        if (!file.good()) return false;  // SEC-001: Check I/O error
    }

    // Write transactions
    uint32_t numTxs = static_cast<uint32_t>(mapWalletTx.size());
    file.write(reinterpret_cast<const char*>(&numTxs), sizeof(numTxs));
    if (!file.good()) return false;  // SEC-001: Check I/O error

    for (const auto& pair : mapWalletTx) {
        const CWalletTx& wtx = pair.second;

        file.write(reinterpret_cast<const char*>(wtx.txid.begin()), 32);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(&wtx.vout), sizeof(wtx.vout));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(&wtx.nValue), sizeof(wtx.nValue));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(wtx.address.GetData().data()), 21);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        uint8_t fSpent = wtx.fSpent ? 1 : 0;
        file.write(reinterpret_cast<const char*>(&fSpent), 1);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(&wtx.nHeight), sizeof(wtx.nHeight));
        if (!file.good()) return false;  // SEC-001: Check I/O error
    }

    // FIX-011 (PERSIST-001): Compute and write file integrity HMAC
    // HMAC covers all data from HMAC field onwards (includes salt and all wallet data)
    std::streampos end_pos = file.tellp();

    // FIX-004 (PERSIST-002): Flush data before reopening for read
    file.flush();
    file.close();

    // Reopen file for reading to compute HMAC
    std::ifstream read_file(tempFile, std::ios::binary);
    if (!read_file.is_open()) {
        std::remove(tempFile.c_str());
        return false;
    }

    // Seek to start of HMAC-protected data
    read_file.seekg(data_start_pos);
    if (!read_file.good()) {
        read_file.close();
        std::remove(tempFile.c_str());
        return false;
    }

    // Read all data from salt position to end
    size_t data_size = static_cast<size_t>(end_pos - data_start_pos);
    std::vector<uint8_t> file_data(data_size);
    read_file.read(reinterpret_cast<char*>(file_data.data()), data_size);
    if (!read_file.good()) {
        read_file.close();
        std::remove(tempFile.c_str());
        return false;
    }
    read_file.close();

    // Compute HMAC-SHA3-256 over the data
    // Using masterKey as HMAC key if encrypted, or derive from wallet content if not
    std::vector<uint8_t> hmac_key(32);
    if (masterKey.IsValid()) {
        // Use first 32 bytes of master key salt as HMAC key (available without passphrase)
        memcpy(hmac_key.data(), masterKey.vchSalt.data(), std::min(hmac_key.size(), masterKey.vchSalt.size()));
    } else {
        // For unencrypted wallets, derive HMAC key from wallet content (deterministic)
        // Use SHA3-256 of (first address + default address) as key
        std::vector<uint8_t> key_material;
        if (!vchAddresses.empty()) {
            std::vector<uint8_t> addr_data = vchAddresses[0].GetData();
            key_material.insert(key_material.end(), addr_data.begin(), addr_data.end());
        }
        std::vector<uint8_t> default_data = defaultAddress.GetData();
        key_material.insert(key_material.end(), default_data.begin(), default_data.end());

        SHA3_256(key_material.data(), key_material.size(), hmac_key.data());
    }

    // Compute HMAC-SHA3-256
    std::vector<uint8_t> computed_hmac(32);
    HMAC_SHA3_256(hmac_key.data(), hmac_key.size(),
                  file_data.data(), file_data.size(),
                  computed_hmac.data());

    // Reopen file in update mode to write HMAC
    std::fstream update_file(tempFile, std::ios::binary | std::ios::in | std::ios::out);
    if (!update_file.is_open()) {
        std::remove(tempFile.c_str());
        return false;
    }

    // Write the computed HMAC
    update_file.seekp(hmac_pos);
    update_file.write(reinterpret_cast<const char*>(computed_hmac.data()), WALLET_FILE_HMAC_SIZE);
    if (!update_file.good()) {
        update_file.close();
        std::remove(tempFile.c_str());
        return false;
    }

    // FIX-004 (PERSIST-002): Flush and sync data before closing
    update_file.flush();
    update_file.close();

    // FIX-004 (PERSIST-002): Force data to disk before atomic rename
    // This prevents data loss if power failure occurs between close() and rename()
    #ifndef _WIN32
        // Linux/Unix: fsync() ensures data written to physical disk
        int fd = open(tempFile.c_str(), O_RDONLY);
        if (fd >= 0) {
            fsync(fd);  // Sync file data and metadata to disk
            close(fd);
        }

        // Also sync parent directory to persist rename operation metadata
        size_t last_slash = saveFile.find_last_of("/\\");
        if (last_slash != std::string::npos) {
            std::string parent_dir = saveFile.substr(0, last_slash);
            if (parent_dir.empty()) parent_dir = ".";
            int dirfd = open(parent_dir.c_str(), O_RDONLY);
            if (dirfd >= 0) {
                fsync(dirfd);
                close(dirfd);
            }
        }
    #endif
    // Windows already uses MOVEFILE_WRITE_THROUGH (ensures disk write)

    // WL-012 FIX: Atomically replace old file with new file
    // On Unix, rename() is atomic
    // On Windows, use MoveFileEx with MOVEFILE_REPLACE_EXISTING for atomic replace
    #ifdef _WIN32
        // Windows: Use MoveFileExW for atomic file replacement
        // This is ATOMIC - either fully succeeds or fully fails (no partial writes)
        std::wstring wTempFile(tempFile.begin(), tempFile.end());
        std::wstring wSaveFile(saveFile.begin(), saveFile.end());

        // MOVEFILE_REPLACE_EXISTING: Replace existing file atomically
        // MOVEFILE_WRITE_THROUGH: Ensure data written to disk before returning
        if (!MoveFileExW(wTempFile.c_str(), wSaveFile.c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            // Move failed - clean up temp file
            std::remove(tempFile.c_str());
            return false;
        }
    #else
        // Unix/Linux: std::rename() is already atomic
        if (std::rename(tempFile.c_str(), saveFile.c_str()) != 0) {
            // Rename failed - clean up temp file
            std::remove(tempFile.c_str());
            return false;
        }
    #endif

    return true;
}

void CWallet::SetWalletFile(const std::string& filename) {
    std::lock_guard<std::mutex> lock(cs_wallet);
    m_walletFile = filename;
    m_autoSave = true;  // Enable auto-save when wallet file is set
}

void CWallet::Clear() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    mapKeys.clear();
    mapCryptedKeys.clear();
    vchAddresses.clear();
    mapWalletTx.clear();
    defaultAddress = CAddress();

    // Clear encryption state
    fWalletUnlocked = false;
    nUnlockTime = std::chrono::steady_clock::time_point::max();

    // Wipe master key from memory
    if (!vMasterKey.empty()) {
        memory_cleanse(vMasterKey.data_ptr(), vMasterKey.size());
    }

    // Clear master key data
    masterKey = CMasterKey();

    // Clear HD wallet data (securely wipe sensitive data)
    fIsHDWallet = false;
    fHDMasterKeyEncrypted = false;

    // Wipe encrypted mnemonic
    if (!vchEncryptedMnemonic.empty()) {
        memory_cleanse(vchEncryptedMnemonic.data(), vchEncryptedMnemonic.size());
    }
    vchEncryptedMnemonic.clear();
    vchMnemonicIV.clear();

    // Wipe HD master key
    hdMasterKey.Wipe();
    vchHDMasterKeyIV.clear();

    // Clear HD chain state
    nHDAccountIndex = 0;
    nHDExternalChainIndex = 0;
    nHDInternalChainIndex = 0;

    // Clear HD mappings
    mapAddressToPath.clear();
    mapPathToAddress.clear();
}

// FIX-012 (WALLET-002): Wallet Consistency Validation
bool CWallet::ValidateConsistency(std::string& error_out) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // ========================================================================
    // Check #1: Address Reconstruction Verification
    // ========================================================================
    // Verify that all addresses can be correctly reconstructed from their public keys

    // Check unencrypted keys
    for (const auto& pair : mapKeys) {
        const CAddress& address = pair.first;
        const CKey& key = pair.second;
        CAddress reconstructed(key.vchPubKey);
        if (!(reconstructed == address)) {
            error_out = "[ADDRESS_RECONSTRUCTION] Mismatch for unencrypted key: expected " +
                       reconstructed.ToString() + ", got " + address.ToString();
            return false;
        }
    }

    // Check encrypted keys (public key is not encrypted, so we can reconstruct)
    for (const auto& pair : mapCryptedKeys) {
        const CAddress& address = pair.first;
        const CEncryptedKey& encKey = pair.second;
        CAddress reconstructed(encKey.vchPubKey);
        if (!(reconstructed == address)) {
            error_out = "[ADDRESS_RECONSTRUCTION] Mismatch for encrypted key: expected " +
                       reconstructed.ToString() + ", got " + address.ToString();
            return false;
        }
    }

    // ========================================================================
    // Check #3: Transaction Address Validation
    // ========================================================================
    // Verify all transaction addresses belong to wallet
    // (Check #3 is simpler than #2, so we do it before the complex HD check)

    // Optimization: Convert vchAddresses to set for O(log n) lookup
    std::set<CAddress> address_set(vchAddresses.begin(), vchAddresses.end());

    for (const auto& pair : mapWalletTx) {
        const COutPoint& outpoint = pair.first;
        const CWalletTx& wtx = pair.second;
        if (address_set.find(wtx.address) == address_set.end()) {
            error_out = "[TX_ADDRESS_VALIDATION] Transaction (" +
                       outpoint.hash.GetHex() + ":" + std::to_string(outpoint.n) +
                       ") references unknown address " + wtx.address.ToString();
            return false;
        }
    }

    // ========================================================================
    // Check #4: Encrypted Key Count Consistency
    // ========================================================================
    // When encrypted, verify key/address counts match

    if (IsCrypted()) {
        // Encrypted wallet should have no unencrypted keys
        if (!mapKeys.empty()) {
            error_out = "[KEY_COUNT] Encrypted wallet has " +
                       std::to_string(mapKeys.size()) + " unencrypted keys (should be 0)";
            return false;
        }

        // Count of encrypted keys should match address count
        if (mapCryptedKeys.size() != vchAddresses.size()) {
            error_out = "[KEY_COUNT] Address count (" +
                       std::to_string(vchAddresses.size()) +
                       ") != encrypted key count (" +
                       std::to_string(mapCryptedKeys.size()) + ")";
            return false;
        }
    }

    // ========================================================================
    // Check #2: HD Path Gap Detection
    // ========================================================================
    // Detect gaps in HD derivation paths (missing indices)

    if (fIsHDWallet) {
        // External chain: Check indices [0, nHDExternalChainIndex)
        for (uint32_t i = 0; i < nHDExternalChainIndex; i++) {
            // Construct expected path: m/44'/573'/account'/0/i
            CHDKeyPath expected;
            expected.indices.push_back(44 | 0x80000000);  // BIP44 purpose (hardened)
            expected.indices.push_back(573 | 0x80000000); // Dilithion coin type (hardened)
            expected.indices.push_back(nHDAccountIndex | 0x80000000); // Account (hardened)
            expected.indices.push_back(0);  // External chain (not hardened)
            expected.indices.push_back(i);  // Address index (not hardened)

            if (mapPathToAddress.find(expected) == mapPathToAddress.end()) {
                error_out = "[HD_PATH_GAPS] Missing external chain address at index " +
                           std::to_string(i) + " (path: m/44'/573'/" +
                           std::to_string(nHDAccountIndex) + "'/0/" + std::to_string(i) + ")";
                return false;
            }
        }

        // Internal chain: Check indices [0, nHDInternalChainIndex)
        for (uint32_t i = 0; i < nHDInternalChainIndex; i++) {
            // Construct expected path: m/44'/573'/account'/1/i
            CHDKeyPath expected;
            expected.indices.push_back(44 | 0x80000000);  // BIP44 purpose (hardened)
            expected.indices.push_back(573 | 0x80000000); // Dilithion coin type (hardened)
            expected.indices.push_back(nHDAccountIndex | 0x80000000); // Account (hardened)
            expected.indices.push_back(1);  // Internal chain (change addresses, not hardened)
            expected.indices.push_back(i);  // Address index (not hardened)

            if (mapPathToAddress.find(expected) == mapPathToAddress.end()) {
                error_out = "[HD_PATH_GAPS] Missing internal chain address at index " +
                           std::to_string(i) + " (path: m/44'/573'/" +
                           std::to_string(nHDAccountIndex) + "'/1/" + std::to_string(i) + ")";
                return false;
            }
        }
    }

    // ========================================================================
    // Check #5: HD Path Bidirectional Mapping Verification
    // ========================================================================
    // Ensure mapAddressToPath and mapPathToAddress are consistent

    if (fIsHDWallet) {
        // Check Address→Path mapping completeness
        for (const auto& pair : mapAddressToPath) {
            const CAddress& addr = pair.first;
            const CHDKeyPath& path = pair.second;
            auto it = mapPathToAddress.find(path);
            if (it == mapPathToAddress.end()) {
                error_out = "[HD_BIDIRECTIONAL] Address→Path exists for " +
                           addr.ToString() + " but Path→Address mapping is missing";
                return false;
            }
            if (!(it->second == addr)) {
                error_out = std::string("[HD_BIDIRECTIONAL] Path→Address maps to different address: ") +
                           "expected " + addr.ToString() + ", got " + it->second.ToString();
                return false;
            }
        }

        // Check Path→Address mapping completeness
        for (const auto& pair : mapPathToAddress) {
            const CHDKeyPath& path = pair.first;
            const CAddress& addr = pair.second;
            auto it = mapAddressToPath.find(addr);
            if (it == mapAddressToPath.end()) {
                error_out = "[HD_BIDIRECTIONAL] Path→Address exists for address " +
                           addr.ToString() + " but Address→Path mapping is missing";
                return false;
            }
            if (!(it->second == path)) {
                error_out = "[HD_BIDIRECTIONAL] Address→Path maps to different path than expected";
                return false;
            }
        }
    }

    // All checks passed
    error_out = "";
    return true;
}

// ============================================================================
// Phase 5.2: Transaction Creation Helper Functions
// ============================================================================

namespace WalletCrypto {

std::vector<uint8_t> CreateScriptPubKey(const std::vector<uint8_t>& pubkey_hash) {
    std::vector<uint8_t> script;

    // P2PKH scriptPubKey format: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    // This creates a standard P2PKH script (25 bytes for 20-byte hash)

    // OP_DUP (0x76) - Duplicates top stack item
    script.push_back(0x76);

    // OP_HASH160 (0xA9) - Hash top stack item with RIPEMD160(SHA256())
    script.push_back(0xA9);

    // Push pubkey hash length (should be 20 bytes)
    script.push_back(static_cast<uint8_t>(pubkey_hash.size()));

    // Push pubkey hash data
    script.insert(script.end(), pubkey_hash.begin(), pubkey_hash.end());

    // OP_EQUALVERIFY (0x88) - Verify top two items are equal
    script.push_back(0x88);

    // OP_CHECKSIG (0xAC) - Verify signature
    script.push_back(0xAC);

    return script;
}

std::vector<uint8_t> CreateScriptSig(const std::vector<uint8_t>& signature,
                                     const std::vector<uint8_t>& pubkey) {
    std::vector<uint8_t> script;

    // Push signature size (2 bytes, little-endian)
    uint16_t sig_size = static_cast<uint16_t>(signature.size());
    script.push_back(static_cast<uint8_t>(sig_size & 0xFF));
    script.push_back(static_cast<uint8_t>((sig_size >> 8) & 0xFF));

    // Push signature data
    script.insert(script.end(), signature.begin(), signature.end());

    // Push pubkey size (2 bytes, little-endian)
    uint16_t pk_size = static_cast<uint16_t>(pubkey.size());
    script.push_back(static_cast<uint8_t>(pk_size & 0xFF));
    script.push_back(static_cast<uint8_t>((pk_size >> 8) & 0xFF));

    // Push pubkey data
    script.insert(script.end(), pubkey.begin(), pubkey.end());

    return script;
}

std::vector<uint8_t> ExtractPubKeyHash(const std::vector<uint8_t>& scriptPubKey) {
    // P2PKH scriptPubKey format: OP_DUP OP_HASH160 <hash_size> <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    // Expected size: 25 bytes (1+1+1+20+1+1) for 20-byte hash
    //           or: 37 bytes (1+1+1+32+1+1) for 32-byte hash

    // Minimum size: 25 bytes for P2PKH
    if (scriptPubKey.size() < 25) {
        return std::vector<uint8_t>();
    }

    // Verify P2PKH opcodes
    if (scriptPubKey[0] != 0x76) {  // OP_DUP
        return std::vector<uint8_t>();
    }
    if (scriptPubKey[1] != 0xA9) {  // OP_HASH160
        return std::vector<uint8_t>();
    }

    // SEC-002: Validate hash_size before using it in calculations
    uint8_t hash_size = scriptPubKey[2];

    // Only accept standard hash sizes: 20 (RIPEMD160) or 32 (SHA3-256)
    // This prevents potential overflow and malformed scripts
    if (hash_size != 20 && hash_size != 32) {
        return std::vector<uint8_t>();
    }

    // Verify script size matches P2PKH format: 3 (opcodes) + hash_size + 2 (opcodes)
    // Now safe because hash_size is validated to be 20 or 32
    size_t expected_size = 3 + static_cast<size_t>(hash_size) + 2;
    if (scriptPubKey.size() != expected_size) {
        return std::vector<uint8_t>();
    }

    // Verify OP_EQUALVERIFY and OP_CHECKSIG at the end
    // Safe to access because size was validated above
    if (scriptPubKey[3 + hash_size] != 0x88) {  // OP_EQUALVERIFY
        return std::vector<uint8_t>();
    }
    if (scriptPubKey[4 + hash_size] != 0xAC) {  // OP_CHECKSIG
        return std::vector<uint8_t>();
    }

    // Extract hash (skip OP_DUP, OP_HASH160, hash_size)
    return std::vector<uint8_t>(scriptPubKey.begin() + 3, scriptPubKey.begin() + 3 + hash_size);
}

} // namespace WalletCrypto

// ============================================================================
// Phase 5.2: UTXO Management & Transaction Creation Implementation
// ============================================================================

// Helper: Get public key hash (20 bytes) from CAddress
std::vector<uint8_t> CWallet::GetPubKeyHashFromAddress(const CAddress& address) {
    if (!address.IsValid()) {
        return std::vector<uint8_t>();
    }

    const std::vector<uint8_t>& addrData = address.GetData();

    // Address format: [version(1)] [hash(20)]
    if (addrData.size() != 21) {
        return std::vector<uint8_t>();
    }

    // Extract hash (skip version byte)
    return std::vector<uint8_t>(addrData.begin() + 1, addrData.end());
}

// Public methods - acquire lock and call unlocked versions
std::vector<uint8_t> CWallet::GetPubKeyHash() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return GetPubKeyHashUnlocked();
}

std::vector<uint8_t> CWallet::GetPublicKey() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return GetPublicKeyUnlocked();
}

// Private unlocked methods - assume caller already holds lock
std::vector<uint8_t> CWallet::GetPubKeyHashUnlocked() const {
    if (!defaultAddress.IsValid()) {
        return std::vector<uint8_t>();
    }

    return GetPubKeyHashFromAddress(defaultAddress);
}

std::vector<uint8_t> CWallet::GetPublicKeyUnlocked() const {
    if (!defaultAddress.IsValid()) {
        return std::vector<uint8_t>();
    }

    // Get key for default address (we already hold the lock)
    CKey key;
    if (GetKeyUnlocked(defaultAddress, key)) {
        return key.vchPubKey;
    }

    return std::vector<uint8_t>();
}

bool CWallet::ScanUTXOs(CUTXOSet& global_utxo_set) {
    // FIX-006 (WALLET-002): Hold wallet lock for entire scan operation
    // Prevents TOCTOU race: GetAddresses() → AddTxOut() gap where wallet could be modified
    std::lock_guard<std::mutex> lock(cs_wallet);

    std::cout << "[Wallet] Scanning UTXO set for wallet outputs..." << std::endl;

    // Step 1: Get all wallet addresses and their pubkey hashes
    // FIX-006: Access vchAddresses directly since we hold lock (avoid deadlock with GetAddresses())
    const std::vector<CAddress>& addresses = vchAddresses;
    if (addresses.empty()) {
        std::cout << "[Wallet] No addresses in wallet - nothing to scan" << std::endl;
        return true;
    }

    // Build set of pubkey hashes for fast lookup
    std::set<std::vector<uint8_t>> walletPubKeyHashes;
    for (const auto& addr : addresses) {
        std::vector<uint8_t> pkh = GetPubKeyHashFromAddress(addr);
        if (!pkh.empty()) {
            walletPubKeyHashes.insert(pkh);
        }
    }

    std::cout << "[Wallet] Scanning for " << walletPubKeyHashes.size() << " address(es)" << std::endl;

    // Step 2: Track found UTXOs
    size_t utxosScanned = 0;
    size_t utxosFound = 0;

    // Step 3: Scan all UTXOs using ForEach iterator
    global_utxo_set.ForEach([&](const COutPoint& outpoint, const CUTXOEntry& entry) {
        utxosScanned++;

        // Extract pubkey hash from scriptPubKey
        std::vector<uint8_t> scriptPubKeyHash = WalletCrypto::ExtractPubKeyHash(entry.out.scriptPubKey);

        // Check if this UTXO belongs to our wallet
        if (!scriptPubKeyHash.empty() && walletPubKeyHashes.count(scriptPubKeyHash) > 0) {
            // Find which address this belongs to
            for (const auto& addr : addresses) {
                std::vector<uint8_t> addrHash = GetPubKeyHashFromAddress(addr);
                if (addrHash == scriptPubKeyHash) {
                    // FIX-006 (WALLET-002): Use unlocked version since we hold lock
                    AddTxOutUnlocked(outpoint.hash, outpoint.n, entry.out.nValue, addr, entry.nHeight);
                    utxosFound++;

                    std::cout << "[Wallet] Found UTXO: " << outpoint.hash.GetHex().substr(0, 16)
                              << ":" << outpoint.n << " (" << entry.out.nValue << " ions)" << std::endl;
                    break;
                }
            }
        }

        // Progress update every 10000 UTXOs
        if (utxosScanned % 10000 == 0) {
            std::cout << "[Wallet] Scanned " << utxosScanned << " UTXOs..." << std::endl;
        }

        return true; // Continue iteration
    });

    std::cout << "[Wallet] Scan complete: Found " << utxosFound << " wallet UTXO(s) out of "
              << utxosScanned << " total" << std::endl;

    return true;
}

CAmount CWallet::GetAvailableBalance(CUTXOSet& utxo_set, unsigned int current_height) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    CAmount balance = 0;

    // Coinbase maturity requirement
    const unsigned int COINBASE_MATURITY = 100;

    for (const auto& pair : mapWalletTx) {
        const CWalletTx& wtx = pair.second;

        // Skip spent outputs
        if (wtx.fSpent) {
            continue;
        }

        // Verify UTXO still exists in global set
        COutPoint outpoint(wtx.txid, wtx.vout);
        CUTXOEntry entry;
        if (!utxo_set.GetUTXO(outpoint, entry)) {
            continue;  // UTXO was spent elsewhere
        }

        // Check coinbase maturity
        if (entry.fCoinBase) {
            if (current_height < entry.nHeight + COINBASE_MATURITY) {
                continue;  // Immature coinbase
            }
        }

        // Add to balance (with overflow protection)
        if (balance > std::numeric_limits<CAmount>::max() - wtx.nValue) {
            // Overflow would occur - this should never happen in practice
            continue;
        }

        balance += wtx.nValue;
    }

    return balance;
}

std::vector<CWalletTx> CWallet::ListUnspentOutputs(CUTXOSet& utxo_set, unsigned int current_height) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    std::vector<CWalletTx> unspent;
    const unsigned int COINBASE_MATURITY = 100;

    for (const auto& pair : mapWalletTx) {
        const CWalletTx& wtx = pair.second;

        // Skip spent outputs
        if (wtx.fSpent) {
            continue;
        }

        // Verify UTXO still exists
        COutPoint outpoint(wtx.txid, wtx.vout);
        CUTXOEntry entry;
        if (!utxo_set.GetUTXO(outpoint, entry)) {
            continue;
        }

        // Check coinbase maturity
        if (entry.fCoinBase) {
            if (current_height < entry.nHeight + COINBASE_MATURITY) {
                continue;  // Immature coinbase
            }
        }

        unspent.push_back(wtx);
    }

    return unspent;
}

bool CWallet::SelectCoins(CAmount target_value,
                          std::vector<CWalletTx>& selected_coins,
                          CAmount& total_value,
                          CUTXOSet& utxo_set,
                          unsigned int current_height,
                          std::string& error) const {
    selected_coins.clear();
    total_value = 0;

    // Get all spendable UTXOs
    std::vector<CWalletTx> unspent = ListUnspentOutputs(utxo_set, current_height);

    if (unspent.empty()) {
        error = "No spendable outputs available";
        return false;
    }

    // Simple greedy algorithm: Select largest UTXOs first
    // Sort by value (descending)
    std::sort(unspent.begin(), unspent.end(),
              [](const CWalletTx& a, const CWalletTx& b) {
                  return a.nValue > b.nValue;
              });

    // Select coins until we reach target
    for (const CWalletTx& wtx : unspent) {
        selected_coins.push_back(wtx);
        total_value += wtx.nValue;

        if (total_value >= target_value) {
            return true;  // Success - we have enough
        }
    }

    // Insufficient funds
    error = "Insufficient balance (need " + std::to_string(target_value) +
            " but only have " + std::to_string(total_value) + ")";
    selected_coins.clear();
    total_value = 0;
    return false;
}

bool CWallet::CreateTransaction(const CAddress& recipient_address,
                                CAmount amount,
                                CAmount fee,
                                CUTXOSet& utxo_set,
                                unsigned int current_height,
                                CTransactionRef& tx_out,
                                std::string& error) {
    // Input validation
    if (!recipient_address.IsValid()) {
        error = "Invalid recipient address";
        return false;
    }

    if (amount <= 0) {
        error = "Invalid amount (must be positive)";
        return false;
    }

    if (fee < 0) {
        error = "Invalid fee (cannot be negative)";
        return false;
    }

    // Calculate total needed
    CAmount total_needed = amount + fee;
    if (total_needed < amount) {  // Overflow check
        error = "Amount + fee overflow";
        return false;
    }

    // Select coins
    std::vector<CWalletTx> selected_coins;
    CAmount total_selected = 0;

    if (!SelectCoins(total_needed, selected_coins, total_selected, utxo_set, current_height, error)) {
        return false;
    }

    // Create transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    // Create inputs from selected coins
    for (const CWalletTx& wtx : selected_coins) {
        COutPoint outpoint(wtx.txid, wtx.vout);
        CTxIn txin(outpoint);
        tx.vin.push_back(txin);
    }

    // Create output for recipient
    std::vector<uint8_t> recipient_hash = GetPubKeyHashFromAddress(recipient_address);
    if (recipient_hash.empty()) {
        error = "Failed to extract recipient public key hash";
        return false;
    }

    std::vector<uint8_t> scriptPubKey = WalletCrypto::CreateScriptPubKey(recipient_hash);
    CTxOut txout_recipient(amount, scriptPubKey);
    tx.vout.push_back(txout_recipient);

    // Create change output if needed
    CAmount change = total_selected - total_needed;
    if (change > 0) {
        std::vector<uint8_t> change_hash = GetPubKeyHash();
        if (change_hash.empty()) {
            error = "Failed to get wallet public key hash for change";
            return false;
        }

        std::vector<uint8_t> change_scriptPubKey = WalletCrypto::CreateScriptPubKey(change_hash);
        CTxOut txout_change(change, change_scriptPubKey);
        tx.vout.push_back(txout_change);
    }

    // Sign transaction
    if (!SignTransaction(tx, utxo_set, error)) {
        return false;
    }

    // Validate transaction
    CTransactionValidator validator;
    CAmount calculated_fee = 0;
    std::string validation_error;

    if (!validator.CheckTransaction(tx, utxo_set, current_height, calculated_fee, validation_error)) {
        error = "Transaction validation failed: " + validation_error;
        return false;
    }

    // Create transaction reference
    tx_out = MakeTransactionRef(std::move(tx));

    return true;
}

bool CWallet::SignTransaction(CTransaction& tx, CUTXOSet& utxo_set, std::string& error) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // VULN-002 FIX: Check if unlock is still valid (not expired) before signing
    if (!IsUnlockValid()) {
        error = "Wallet is locked or unlock timeout has expired";
        return false;
    }

    // Get wallet's public key (we already hold the lock)
    std::vector<uint8_t> wallet_pubkey = GetPublicKeyUnlocked();
    if (wallet_pubkey.empty()) {
        error = "Failed to get wallet public key";
        return false;
    }

    // Get transaction hash for signing
    uint256 tx_hash = tx.GetHash();

    // Sign each input
    for (size_t i = 0; i < tx.vin.size(); i++) {
        CTxIn& txin = tx.vin[i];

        // Lookup the UTXO being spent
        CUTXOEntry utxo_entry;
        if (!utxo_set.GetUTXO(txin.prevout, utxo_entry)) {
            error = "UTXO not found for input " + std::to_string(i);
            return false;
        }

        // Extract public key hash from scriptPubKey
        std::vector<uint8_t> required_hash = WalletCrypto::ExtractPubKeyHash(utxo_entry.out.scriptPubKey);
        if (required_hash.empty()) {
            error = "Failed to extract public key hash from scriptPubKey for input " + std::to_string(i);
            return false;
        }

        // Compute hash of our public key
        std::vector<uint8_t> our_hash = WalletCrypto::HashPubKey(wallet_pubkey);

        // Verify we can spend this output
        if (our_hash != required_hash) {
            error = "Cannot spend input " + std::to_string(i) + " - public key mismatch";
            return false;
        }

        // VULN-003 FIX: Create signature message with version (must match validation)
        // signature message: tx_hash + input_index + tx_version
        std::vector<uint8_t> sig_message;
        sig_message.reserve(32 + 4 + 4);  // hash + index + version
        sig_message.insert(sig_message.end(), tx_hash.begin(), tx_hash.end());

        // Add input index (4 bytes, little-endian)
        uint32_t input_idx = static_cast<uint32_t>(i);
        sig_message.push_back(static_cast<uint8_t>(input_idx & 0xFF));
        sig_message.push_back(static_cast<uint8_t>((input_idx >> 8) & 0xFF));
        sig_message.push_back(static_cast<uint8_t>((input_idx >> 16) & 0xFF));
        sig_message.push_back(static_cast<uint8_t>((input_idx >> 24) & 0xFF));

        // VULN-003 FIX: Add transaction version to prevent signature replay
        uint32_t version = tx.nVersion;
        sig_message.push_back(static_cast<uint8_t>(version & 0xFF));
        sig_message.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
        sig_message.push_back(static_cast<uint8_t>((version >> 16) & 0xFF));
        sig_message.push_back(static_cast<uint8_t>((version >> 24) & 0xFF));

        // Hash the signature message
        uint8_t sig_hash[32];
        SHA3_256(sig_message.data(), sig_message.size(), sig_hash);

        // Find the key for this address
        CKey signing_key;
        bool found_key = false;

        // Check all wallet addresses to find the matching key (we already hold the lock)
        for (const auto& addr : vchAddresses) {
            CKey key;
            if (GetKeyUnlocked(addr, key)) {
                std::vector<uint8_t> key_hash = WalletCrypto::HashPubKey(key.vchPubKey);
                if (key_hash == required_hash) {
                    signing_key = key;
                    found_key = true;
                    break;
                }
            }
        }

        if (!found_key) {
            error = "Wallet does not have key to sign input " + std::to_string(i);
            return false;
        }

        // Sign with Dilithium
        std::vector<uint8_t> signature;
        if (!WalletCrypto::Sign(signing_key, sig_hash, 32, signature)) {
            error = "Failed to sign input " + std::to_string(i);
            return false;
        }

        // Create scriptSig
        std::vector<uint8_t> scriptSig = WalletCrypto::CreateScriptSig(signature, signing_key.vchPubKey);

        // Set scriptSig on input
        txin.scriptSig = scriptSig;
    }

    return true;
}

bool CWallet::SendTransaction(const CTransactionRef& tx,
                              CTxMemPool& mempool,
                              CUTXOSet& utxo_set,
                              unsigned int current_height,
                              std::string& error) {
    if (!tx) {
        error = "Null transaction pointer";
        return false;
    }

    // Validate transaction one more time
    CTransactionValidator validator;
    CAmount fee = 0;
    std::string validation_error;

    if (!validator.CheckTransaction(*tx, utxo_set, current_height, fee, validation_error)) {
        error = "Transaction validation failed: " + validation_error;
        return false;
    }

    // Add to mempool
    int64_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    std::string mempool_error;
    if (!mempool.AddTx(tx, fee, current_time, current_height, &mempool_error)) {
        error = "Failed to add transaction to mempool: " + mempool_error;
        return false;
    }

    // Phase 5.3: Announce transaction to P2P network
    const uint256 txid = tx->GetHash();

    // Forward declaration from net/net.h
    extern void AnnounceTransactionToPeers(const uint256& txid, int64_t exclude_peer);

    // Announce to all peers (-1 = no excluding peer)
    AnnounceTransactionToPeers(txid, -1);

    return true;
}

// ============================================================================
// HD Wallet (Hierarchical Deterministic) Implementation
// ============================================================================

extern "C" {
    int pqcrystals_dilithium3_ref_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]);
}

bool CWallet::InitializeHDWallet(const std::string& mnemonic, const std::string& passphrase) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Check if wallet already initialized
    if (fIsHDWallet || !mapKeys.empty() || !mapCryptedKeys.empty()) {
        return false;
    }

    // Validate mnemonic
    if (!CMnemonic::Validate(mnemonic)) {
        return false;
    }

    // WL-002 FIX: Use RAII for BIP39 seed to prevent memory leak on exception
    //
    // CRITICAL: If DeriveMaster() throws an exception or crashes, the seed
    // must still be wiped from memory. Using CKeyingMaterial ensures the
    // destructor wipes memory even on abnormal exit paths.
    //
    // This prevents seed extraction from core dumps if the node crashes.
    //
    CKeyingMaterial bip39_seed(64);  // RAII: auto-wipes on scope exit
    if (!CMnemonic::ToSeed(mnemonic, passphrase, bip39_seed.data_ptr())) {
        return false;  // RAII automatically wipes seed
    }

    // Derive master HD key (if this throws, RAII still wipes seed)
    DeriveMaster(bip39_seed.data_ptr(), hdMasterKey);

    // Seed will be automatically wiped when bip39_seed goes out of scope
    // (no explicit memory_cleanse needed)

    // Encrypt mnemonic if wallet is encrypted
    if (masterKey.IsValid()) {
        if (!EncryptMnemonic(mnemonic)) {
            hdMasterKey.Wipe();
            return false;
        }

        if (!EncryptHDMasterKey()) {
            hdMasterKey.Wipe();
            memory_cleanse(vchEncryptedMnemonic.data(), vchEncryptedMnemonic.size());
            vchEncryptedMnemonic.clear();
            vchMnemonicIV.clear();
            return false;
        }
    } else {
        // Store encrypted mnemonic directly (no wallet encryption yet)
        if (!EncryptMnemonic(mnemonic)) {
            hdMasterKey.Wipe();
            return false;
        }
        fHDMasterKeyEncrypted = false;
    }

    // Initialize HD wallet state
    fIsHDWallet = true;
    nHDAccountIndex = 0;
    nHDExternalChainIndex = 0;
    nHDInternalChainIndex = 0;

    // Derive first receiving address
    CHDKeyPath firstPath = CHDKeyPath::ReceiveAddress(0, 0);
    if (!DeriveAndCacheHDAddress(firstPath)) {
        // Rollback on failure
        fIsHDWallet = false;
        hdMasterKey.Wipe();
        memory_cleanse(vchEncryptedMnemonic.data(), vchEncryptedMnemonic.size());
        vchEncryptedMnemonic.clear();
        vchMnemonicIV.clear();
        return false;
    }

    nHDExternalChainIndex = 1;  // Next address index

    // Auto-save if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    return true;
}

bool CWallet::GenerateHDWallet(std::string& mnemonic_out, const std::string& passphrase) {
    // Generate 256-bit (24-word) mnemonic
    if (!CMnemonic::Generate(256, mnemonic_out)) {
        return false;
    }

    // Initialize wallet with generated mnemonic
    if (!InitializeHDWallet(mnemonic_out, passphrase)) {
        memory_cleanse(&mnemonic_out[0], mnemonic_out.size());
        mnemonic_out.clear();
        return false;
    }

    return true;
}

bool CWallet::RestoreHDWallet(const std::string& mnemonic, const std::string& passphrase) {
    // Initialize HD wallet
    if (!InitializeHDWallet(mnemonic, passphrase)) {
        return false;
    }

    // Note: Actual blockchain scanning would require UTXO set
    // For now, just initialize with first address
    // User can call ScanHDChains() separately after loading blockchain

    return true;
}

CAddress CWallet::GetNewHDAddress() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return CAddress();  // Empty address
    }

    // Check if wallet is locked and encrypted
    if (fHDMasterKeyEncrypted && !fWalletUnlocked) {
        return CAddress();
    }

    // Derive next address on external chain (receive)
    CHDKeyPath path = CHDKeyPath::ReceiveAddress(nHDAccountIndex, nHDExternalChainIndex);

    if (!DeriveAndCacheHDAddress(path)) {
        return CAddress();
    }

    // Increment external chain index
    nHDExternalChainIndex++;

    // Auto-save if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    // Return the address we just derived
    auto it = mapPathToAddress.find(path);
    if (it != mapPathToAddress.end()) {
        return it->second;
    }

    return CAddress();
}

CAddress CWallet::GetChangeAddress() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return CAddress();
    }

    // Check if wallet is locked and encrypted
    if (fHDMasterKeyEncrypted && !fWalletUnlocked) {
        return CAddress();
    }

    // Derive next address on internal chain (change)
    CHDKeyPath path = CHDKeyPath::ChangeAddress(nHDAccountIndex, nHDInternalChainIndex);

    if (!DeriveAndCacheHDAddress(path)) {
        return CAddress();
    }

    // Increment internal chain index
    nHDInternalChainIndex++;

    // Auto-save if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    // Return the address we just derived
    auto it = mapPathToAddress.find(path);
    if (it != mapPathToAddress.end()) {
        return it->second;
    }

    return CAddress();
}

CAddress CWallet::DeriveAddress(const std::string& path_str) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return CAddress();
    }

    // Check if wallet is locked and encrypted
    if (fHDMasterKeyEncrypted && !fWalletUnlocked) {
        return CAddress();
    }

    // Parse path
    CHDKeyPath path;
    if (!path.Parse(path_str) || !path.IsValid()) {
        return CAddress();
    }

    // Check if already cached
    auto it = mapPathToAddress.find(path);
    if (it != mapPathToAddress.end()) {
        return it->second;
    }

    // Derive and cache new address
    if (!DeriveAndCacheHDAddress(path)) {
        return CAddress();
    }

    // Auto-save if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    // Return the address we just derived
    it = mapPathToAddress.find(path);
    if (it != mapPathToAddress.end()) {
        return it->second;
    }

    return CAddress();
}

bool CWallet::ExportMnemonic(std::string& mnemonic_out) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return false;
    }

    // Check if wallet is locked
    if (masterKey.IsValid() && !fWalletUnlocked) {
        return false;
    }

    // Decrypt mnemonic
    return DecryptMnemonic(mnemonic_out);
}

bool CWallet::GetHDWalletInfo(uint32_t& account, uint32_t& external_index,
                              uint32_t& internal_index) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return false;
    }

    account = nHDAccountIndex;
    external_index = nHDExternalChainIndex;
    internal_index = nHDInternalChainIndex;

    return true;
}

bool CWallet::GetAddressPath(const CAddress& address, CHDKeyPath& path_out) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return false;
    }

    auto it = mapAddressToPath.find(address);
    if (it == mapAddressToPath.end()) {
        return false;
    }

    path_out = it->second;
    return true;
}

size_t CWallet::ScanHDChains(CUTXOSet& utxo_set) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return 0;
    }

    // Check if wallet is locked
    if (fHDMasterKeyEncrypted && !fWalletUnlocked) {
        return 0;
    }

    size_t found_count = 0;
    uint32_t gap_counter_external = 0;
    uint32_t gap_counter_internal = 0;

    // Scan external chain (receive addresses)
    for (uint32_t i = nHDExternalChainIndex; gap_counter_external < HD_GAP_LIMIT; i++) {
        CHDKeyPath path = CHDKeyPath::ReceiveAddress(nHDAccountIndex, i);

        if (!DeriveAndCacheHDAddress(path)) {
            break;  // Error deriving address
        }

        auto it = mapPathToAddress.find(path);
        if (it == mapPathToAddress.end()) {
            break;
        }

        // Check if this address has any UTXOs
        bool has_utxos = false;
        // Note: Actual UTXO checking would require iterating utxo_set
        // For now, placeholder logic
        // has_utxos = utxo_set.HasAddressOutputs(it->second);

        if (has_utxos) {
            found_count++;
            gap_counter_external = 0;  // Reset gap counter
            nHDExternalChainIndex = i + 1;  // Update index
        } else {
            gap_counter_external++;
        }
    }

    // Scan internal chain (change addresses)
    for (uint32_t i = nHDInternalChainIndex; gap_counter_internal < HD_GAP_LIMIT; i++) {
        CHDKeyPath path = CHDKeyPath::ChangeAddress(nHDAccountIndex, i);

        if (!DeriveAndCacheHDAddress(path)) {
            break;
        }

        auto it = mapPathToAddress.find(path);
        if (it == mapPathToAddress.end()) {
            break;
        }

        bool has_utxos = false;
        // has_utxos = utxo_set.HasAddressOutputs(it->second);

        if (has_utxos) {
            found_count++;
            gap_counter_internal = 0;
            nHDInternalChainIndex = i + 1;
        } else {
            gap_counter_internal++;
        }
    }

    // Auto-save if we found any addresses
    if (found_count > 0 && m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    return found_count;
}

// ============================================================================
// HD Wallet Private Helper Functions
// ============================================================================

bool CWallet::DeriveAndCacheHDAddress(const CHDKeyPath& path) {
    // Assumes caller holds cs_wallet lock

    // Check if already cached
    if (mapPathToAddress.find(path) != mapPathToAddress.end()) {
        return true;  // Already have this address
    }

    // Decrypt HD master key if encrypted
    CHDExtendedKey master_copy;
    if (fHDMasterKeyEncrypted) {
        if (!DecryptHDMasterKey(master_copy)) {
            return false;
        }
    } else {
        master_copy = hdMasterKey;
    }

    // Derive extended key at path
    CHDExtendedKey derived;
    if (!DerivePath(master_copy, path, derived)) {
        master_copy.Wipe();
        return false;
    }

    // Generate Dilithium keypair
    uint8_t pk[DILITHIUM_PUBLICKEY_SIZE];
    uint8_t sk[DILITHIUM_SECRETKEY_SIZE];

    if (!GenerateDilithiumKey(derived, pk, sk)) {
        derived.Wipe();
        master_copy.Wipe();
        memory_cleanse(sk, DILITHIUM_SECRETKEY_SIZE);
        return false;
    }

    // Create address from public key
    CAddress address(std::vector<uint8_t>(pk, pk + DILITHIUM_PUBLICKEY_SIZE));

    // Create CKey structure
    CKey key;
    key.vchPubKey = std::vector<uint8_t>(pk, pk + DILITHIUM_PUBLICKEY_SIZE);
    // FIX-009: Use assign() for SecureAllocator vector
    key.vchPrivKey.assign(sk, sk + DILITHIUM_SECRETKEY_SIZE);

    // Store in wallet (encrypt if necessary)
    if (masterKey.IsValid()) {
        // Wallet is encrypted - encrypt the private key
        CEncryptedKey encKey;
        encKey.vchPubKey = key.vchPubKey;

        // FIX-010: Generate unique IV
        if (!GenerateUniqueIV_Locked(encKey.vchIV)) {
            key.Clear();
            derived.Wipe();
            master_copy.Wipe();
            return false;
        }

        // Encrypt with master key
        CCrypter crypter;
        std::vector<uint8_t> masterKeyVec(vMasterKey.data_ptr(),
                                          vMasterKey.data_ptr() + vMasterKey.size());
        if (!crypter.SetKey(masterKeyVec, encKey.vchIV)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            key.Clear();
            derived.Wipe();
            master_copy.Wipe();
            return false;
        }

        if (!crypter.Encrypt(key.vchPrivKey, encKey.vchCryptedKey)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            key.Clear();
            derived.Wipe();
            master_copy.Wipe();
            return false;
        }

        memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
        mapCryptedKeys[address] = encKey;
    } else {
        // Wallet not encrypted - store key directly
        mapKeys[address] = key;
    }

    // Cache HD path mappings
    mapPathToAddress[path] = address;
    mapAddressToPath[address] = path;

    // Add to address list
    vchAddresses.push_back(address);

    // Wipe sensitive data
    key.Clear();  // This will securely wipe private key
    derived.Wipe();
    master_copy.Wipe();

    return true;
}

bool CWallet::EncryptHDMasterKey() {
    // Assumes caller holds cs_wallet lock

    if (!masterKey.IsValid()) {
        return false;  // Wallet not encrypted
    }

    // FIX-010: Generate unique IV for HD master key
    if (!GenerateUniqueIV_Locked(vchHDMasterKeyIV)) {
        return false;
    }

    // Prepare master key seed + chaincode (64 bytes total)
    std::vector<uint8_t> masterKeyData(64);
    std::memcpy(masterKeyData.data(), hdMasterKey.seed, 32);
    std::memcpy(masterKeyData.data() + 32, hdMasterKey.chaincode, 32);

    // Encrypt with wallet master key
    CCrypter crypter;
    std::vector<uint8_t> vMasterKeyVec(vMasterKey.data_ptr(),
                                       vMasterKey.data_ptr() + vMasterKey.size());

    if (!crypter.SetKey(vMasterKeyVec, vchHDMasterKeyIV)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(masterKeyData.data(), masterKeyData.size());
        return false;
    }

    // Store encrypted data back in hdMasterKey structure
    // We'll reuse the seed/chaincode fields to store encrypted data
    std::vector<uint8_t> encrypted;
    if (!crypter.Encrypt(masterKeyData, encrypted)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(masterKeyData.data(), masterKeyData.size());
        return false;
    }

    // Copy encrypted data to hdMasterKey (first 32 bytes in seed, rest in chaincode)
    if (encrypted.size() != 64) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(masterKeyData.data(), masterKeyData.size());
        memory_cleanse(encrypted.data(), encrypted.size());
        return false;
    }

    std::memcpy(hdMasterKey.seed, encrypted.data(), 32);
    std::memcpy(hdMasterKey.chaincode, encrypted.data() + 32, 32);

    fHDMasterKeyEncrypted = true;

    // Wipe sensitive data
    memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
    memory_cleanse(masterKeyData.data(), masterKeyData.size());
    memory_cleanse(encrypted.data(), encrypted.size());

    return true;
}

bool CWallet::DecryptHDMasterKey(CHDExtendedKey& decrypted) const {
    // Assumes caller holds cs_wallet lock

    if (!fHDMasterKeyEncrypted) {
        // Not encrypted, just copy
        decrypted = hdMasterKey;
        return true;
    }

    if (!fWalletUnlocked) {
        return false;  // Wallet locked
    }

    // WL-010 FIX: Use cached decrypted key if available
    if (fHDMasterKeyCached) {
        decrypted = hdMasterKeyDecrypted;
        return true;
    }

    // Cache miss - decrypt HD master key
    CCrypter crypter;
    std::vector<uint8_t> vMasterKeyVec(vMasterKey.data_ptr(),
                                       vMasterKey.data_ptr() + vMasterKey.size());

    if (!crypter.SetKey(vMasterKeyVec, vchHDMasterKeyIV)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        return false;
    }

    // Prepare encrypted data (64 bytes from seed + chaincode)
    std::vector<uint8_t> encrypted(64);
    std::memcpy(encrypted.data(), hdMasterKey.seed, 32);
    std::memcpy(encrypted.data() + 32, hdMasterKey.chaincode, 32);

    std::vector<uint8_t> decrypted_data;
    if (!crypter.Decrypt(encrypted, decrypted_data)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(encrypted.data(), encrypted.size());
        return false;
    }

    if (decrypted_data.size() != 64) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(encrypted.data(), encrypted.size());
        memory_cleanse(decrypted_data.data(), decrypted_data.size());
        return false;
    }

    // Copy decrypted data to output
    std::memcpy(decrypted.seed, decrypted_data.data(), 32);
    std::memcpy(decrypted.chaincode, decrypted_data.data() + 32, 32);
    decrypted.depth = hdMasterKey.depth;
    decrypted.fingerprint = hdMasterKey.fingerprint;
    decrypted.child_index = hdMasterKey.child_index;

    // Wipe sensitive data
    memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
    memory_cleanse(encrypted.data(), encrypted.size());
    memory_cleanse(decrypted_data.data(), decrypted_data.size());

    return true;
}

bool CWallet::EncryptMnemonic(const std::string& mnemonic) {
    // Assumes caller holds cs_wallet lock

    // FIX-010: Generate unique IV
    if (!GenerateUniqueIV_Locked(vchMnemonicIV)) {
        return false;
    }

    std::vector<uint8_t> mnemonicBytes(mnemonic.begin(), mnemonic.end());

    if (masterKey.IsValid()) {
        // Wallet encrypted - use master key
        CCrypter crypter;
        std::vector<uint8_t> vMasterKeyVec(vMasterKey.data_ptr(),
                                           vMasterKey.data_ptr() + vMasterKey.size());

        if (!crypter.SetKey(vMasterKeyVec, vchMnemonicIV)) {
            memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
            memory_cleanse(mnemonicBytes.data(), mnemonicBytes.size());
            return false;
        }

        if (!crypter.Encrypt(mnemonicBytes, vchEncryptedMnemonic)) {
            memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
            memory_cleanse(mnemonicBytes.data(), mnemonicBytes.size());
            return false;
        }

        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
    } else {
        // WL-003 FIX: Wallet not encrypted - derive obfuscation key from wallet-unique data
        //
        // CRITICAL SECURITY FIX: Old code used fixed key (0x42...) = trivially decryptable
        //
        // New approach: Derive obfuscation key from HD master key fingerprint
        // This creates a unique key per wallet that's not easily guessable.
        //
        // Security properties:
        // - Unique per wallet (derived from HD master key)
        // - Not plaintext or fixed key
        // - Attacker needs both wallet file AND swap/memory dump
        // - Still weaker than passphrase encryption (user should encrypt wallet!)
        //
        // WL-007 FIX: Use HKDF for proper key derivation with domain separation
        // Derive obfuscation key from HD master key using HKDF-SHA3-256
        std::vector<uint8_t> tempKey(WALLET_CRYPTO_KEY_SIZE);
        std::vector<uint8_t> hdSeed(hdMasterKey.seed,
                                    hdMasterKey.seed + 32);

        // Derive encryption key using HKDF with "mnemonic" context
        // This provides cryptographic domain separation from other derived keys
        DeriveEncryptionKey(hdSeed, "mnemonic", tempKey);

        // Wipe temporary HD seed copy
        memory_cleanse(hdSeed.data(), hdSeed.size());

        CCrypter crypter;
        if (!crypter.SetKey(tempKey, vchMnemonicIV)) {
            memory_cleanse(tempKey.data(), tempKey.size());
            memory_cleanse(mnemonicBytes.data(), mnemonicBytes.size());
            return false;
        }

        if (!crypter.Encrypt(mnemonicBytes, vchEncryptedMnemonic)) {
            memory_cleanse(tempKey.data(), tempKey.size());
            memory_cleanse(mnemonicBytes.data(), mnemonicBytes.size());
            return false;
        }

        memory_cleanse(tempKey.data(), tempKey.size());
    }

    memory_cleanse(mnemonicBytes.data(), mnemonicBytes.size());
    return true;
}

bool CWallet::DecryptMnemonic(std::string& mnemonic) const {
    // Assumes caller holds cs_wallet lock

    if (vchEncryptedMnemonic.empty()) {
        return false;
    }

    std::vector<uint8_t> decrypted;

    if (masterKey.IsValid()) {
        // Wallet encrypted - decrypt with master key
        if (!fWalletUnlocked) {
            return false;  // Wallet locked
        }

        CCrypter crypter;
        std::vector<uint8_t> vMasterKeyVec(vMasterKey.data_ptr(),
                                           vMasterKey.data_ptr() + vMasterKey.size());

        if (!crypter.SetKey(vMasterKeyVec, vchMnemonicIV)) {
            memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
            return false;
        }

        if (!crypter.Decrypt(vchEncryptedMnemonic, decrypted)) {
            memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
            return false;
        }

        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
    } else {
        // WL-003 FIX: Wallet not encrypted - derive same obfuscation key as EncryptMnemonic
        // WL-007 FIX: Use HKDF (must match EncryptMnemonic key derivation)
        std::vector<uint8_t> tempKey(WALLET_CRYPTO_KEY_SIZE);
        std::vector<uint8_t> hdSeed(hdMasterKey.seed,
                                    hdMasterKey.seed + 32);

        DeriveEncryptionKey(hdSeed, "mnemonic", tempKey);
        memory_cleanse(hdSeed.data(), hdSeed.size());

        CCrypter crypter;
        if (!crypter.SetKey(tempKey, vchMnemonicIV)) {
            memory_cleanse(tempKey.data(), tempKey.size());
            return false;
        }

        if (!crypter.Decrypt(vchEncryptedMnemonic, decrypted)) {
            memory_cleanse(tempKey.data(), tempKey.size());
            return false;
        }

        memory_cleanse(tempKey.data(), tempKey.size());
    }

    mnemonic = std::string(decrypted.begin(), decrypted.end());
    memory_cleanse(decrypted.data(), decrypted.size());

    return true;
}
