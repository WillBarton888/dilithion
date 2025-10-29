// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/wallet.h>
#include <wallet/passphrase_validator.h>
#include <crypto/sha3.h>
#include <node/utxo_set.h>
#include <node/mempool.h>
#include <consensus/tx_validation.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>

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

// Base58 alphabet
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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

std::string EncodeBase58Check(const std::vector<uint8_t>& data) {
    // Add checksum (double SHA3-256 of data, first 4 bytes)
    std::vector<uint8_t> vchChecksum(32);
    SHA3_256(data.data(), data.size(), vchChecksum.data());
    SHA3_256(vchChecksum.data(), 32, vchChecksum.data());

    // Combine data + checksum
    std::vector<uint8_t> vch = data;
    vch.insert(vch.end(), vchChecksum.begin(), vchChecksum.begin() + 4);

    // Convert to base58
    // Skip leading zeroes
    size_t zeroes = 0;
    while (zeroes < vch.size() && vch[zeroes] == 0) {
        zeroes++;
    }

    // Allocate enough space in base58
    std::vector<uint8_t> b58((vch.size() - zeroes) * 138 / 100 + 1);
    size_t length = 0;

    for (size_t i = zeroes; i < vch.size(); ++i) {
        int carry = vch[i];
        for (size_t j = 0; j < length; ++j) {
            carry += 256 * b58[j];
            b58[j] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            b58[length++] = carry % 58;
            carry /= 58;
        }
    }

    // Convert to string
    std::string str;
    str.reserve(zeroes + length);
    for (size_t i = 0; i < zeroes; ++i) {
        str += pszBase58[0];
    }
    for (size_t i = 0; i < length; ++i) {
        str += pszBase58[b58[length - 1 - i]];
    }

    return str;
}

bool DecodeBase58Check(const std::string& str, std::vector<uint8_t>& data) {
    // VULN-006 FIX: Prevent DoS via excessively long Base58 strings
    static const size_t MAX_BASE58_LEN = 1024;  // Reasonable limit for addresses
    if (str.size() > MAX_BASE58_LEN) {
        return false;  // Reject maliciously long input
    }

    // Simple implementation - convert from base58
    std::vector<uint8_t> vch;
    vch.reserve(str.size() * 138 / 100 + 1);

    // Skip leading '1's
    size_t zeroes = 0;
    while (zeroes < str.size() && str[zeroes] == pszBase58[0]) {
        zeroes++;
    }

    // Decode base58
    for (size_t i = zeroes; i < str.size(); ++i) {
        const char* p = strchr(pszBase58, str[i]);
        if (p == nullptr) {
            return false;
        }
        int carry = p - pszBase58;
        for (size_t j = 0; j < vch.size(); ++j) {
            carry += 58 * vch[j];
            vch[j] = carry % 256;
            carry /= 256;
        }
        while (carry > 0) {
            vch.push_back(carry % 256);
            carry /= 256;
        }
    }

    // Add leading zeros
    data.assign(zeroes, 0);
    data.insert(data.end(), vch.rbegin(), vch.rend());

    if (data.size() < 4) {
        return false;
    }

    // Verify checksum
    std::vector<uint8_t> payload(data.begin(), data.end() - 4);
    std::vector<uint8_t> checksum(data.end() - 4, data.end());

    uint8_t hash[32];
    SHA3_256(payload.data(), payload.size(), hash);
    SHA3_256(hash, 32, hash);

    if (memcmp(checksum.data(), hash, 4) != 0) {
        return false;
    }

    data = payload;
    return true;
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
    return WalletCrypto::EncodeBase58Check(vchData);
}

bool CAddress::SetString(const std::string& str) {
    if (!WalletCrypto::DecodeBase58Check(str, vchData)) {
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
      m_autoSave(false)
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

        // Generate unique IV
        if (!GenerateIV(encKey.vchIV)) {
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

    std::vector<uint8_t> decryptedPrivKey;
    if (!crypter.Decrypt(encKey.vchCryptedKey, decryptedPrivKey)) {
        memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
        return false;
    }

    // Construct decrypted key
    keyOut.vchPubKey = encKey.vchPubKey;
    keyOut.vchPrivKey = decryptedPrivKey;

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

bool CWallet::AddTxOut(const uint256& txid, uint32_t vout, int64_t nValue,
                       const CAddress& address, uint32_t nHeight) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Note: Caller should verify address ownership before calling
    // We don't check HasKey() here to avoid nested locking

    CWalletTx wtx;
    wtx.txid = txid;
    wtx.vout = vout;
    wtx.nValue = nValue;
    wtx.address = address;
    wtx.fSpent = false;
    wtx.nHeight = nHeight;

    mapWalletTx[txid] = wtx;
    return true;
}

bool CWallet::MarkSpent(const uint256& txid, uint32_t vout) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    auto it = mapWalletTx.find(txid);
    if (it == mapWalletTx.end()) {
        return false;
    }

    if (it->second.vout != vout) {
        return false;
    }

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
    }
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

    std::vector<uint8_t> decryptedKey;
    if (!crypter.Decrypt(masterKey.vchCryptedKey, decryptedKey)) {
        return false;  // Wrong passphrase
    }

    if (decryptedKey.size() != WALLET_CRYPTO_KEY_SIZE) {
        return false;  // Invalid key size
    }

    // Store decrypted master key in memory
    memcpy(vMasterKey.data_ptr(), decryptedKey.data(), WALLET_CRYPTO_KEY_SIZE);

    fWalletUnlocked = true;

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

    // Generate IV for master key encryption
    if (!GenerateIV(masterKey.vchIV)) {
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

    masterKey.nDerivationMethod = 0;  // PBKDF2-SHA3
    masterKey.nDeriveIterations = WALLET_CRYPTO_PBKDF2_ROUNDS;

    // Now encrypt all existing keys with the master key
    for (const auto& pair : mapKeys) {
        const CAddress& address = pair.first;
        const CKey& key = pair.second;

        CEncryptedKey encKey;
        encKey.vchPubKey = key.vchPubKey;  // Public key stays unencrypted

        // Generate unique IV for this key
        if (!GenerateIV(encKey.vchIV)) {
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

    // Generate new IV
    std::vector<uint8_t> newIV;
    if (!GenerateIV(newIV)) {
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

    // Update master key
    masterKey.vchCryptedKey = newCryptedKey;
    masterKey.vchSalt = newSalt;
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
    std::map<uint256, CWalletTx> temp_mapWalletTx;
    CAddress temp_defaultAddress;
    CMasterKey temp_masterKey;
    bool temp_fWalletUnlocked = true;

    // Read header
    char magic[8];
    file.read(magic, 8);
    if (!file.good()) return false;  // SEC-001: Check I/O error
    if (std::string(magic, 8) != "DILWLT01") {
        return false;  // Invalid file format
    }

    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (!file.good()) return false;  // SEC-001: Check I/O error
    if (version != 1) {
        return false;  // Unsupported version
    }

    uint32_t flags;
    file.read(reinterpret_cast<char*>(&flags), sizeof(flags));
    if (!file.good()) return false;  // SEC-001: Check I/O error

    // Skip reserved bytes
    uint8_t reserved[16];
    file.read(reinterpret_cast<char*>(reserved), 16);
    if (!file.good()) return false;  // SEC-001: Check I/O error

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

        file.read(reinterpret_cast<char*>(&temp_masterKey.nDerivationMethod), sizeof(temp_masterKey.nDerivationMethod));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.read(reinterpret_cast<char*>(&temp_masterKey.nDeriveIterations), sizeof(temp_masterKey.nDeriveIterations));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // Wallet starts locked (encryption status determined by masterKey.IsValid())
        temp_fWalletUnlocked = false;
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
        if (!addr.SetString(WalletCrypto::EncodeBase58Check(addrData))) {
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

        temp_mapWalletTx[wtx.txid] = wtx;
    }

    // SEC-001 FIX: Only if ALL data loaded successfully, swap into wallet
    // This ensures atomic load - either everything loads or nothing changes
    if (!file.good()) {
        return false;  // File error occurred, temp data discarded
    }

    // All data loaded successfully - now atomically replace wallet contents
    mapKeys = std::move(temp_mapKeys);
    mapCryptedKeys = std::move(temp_mapCryptedKeys);
    vchAddresses = std::move(temp_vchAddresses);
    mapWalletTx = std::move(temp_mapWalletTx);
    defaultAddress = temp_defaultAddress;
    masterKey = temp_masterKey;
    fWalletUnlocked = temp_fWalletUnlocked;
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

    std::ofstream file(tempFile, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // Write header
    const char magic[9] = "DILWLT01";
    file.write(magic, 8);  // Write 8 bytes (without null terminator)
    if (!file.good()) return false;  // SEC-001: Check I/O error

    uint32_t version = 1;
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));
    if (!file.good()) return false;  // SEC-001: Check I/O error

    uint32_t flags = masterKey.IsValid() ? 0x01 : 0x00;  // Bit 0 = encrypted
    file.write(reinterpret_cast<const char*>(&flags), sizeof(flags));
    if (!file.good()) return false;  // SEC-001: Check I/O error

    // Reserved bytes
    uint8_t reserved[16] = {0};
    file.write(reinterpret_cast<const char*>(reserved), 16);
    if (!file.good()) return false;  // SEC-001: Check I/O error

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

    file.close();

    // SEC-001 FIX: Check if write was successful before committing
    if (!file.good()) {
        // Write failed - clean up temp file and return error
        std::remove(tempFile.c_str());
        return false;
    }

    // SEC-001 FIX: Atomically replace old file with new file
    // On most OS, rename() is atomic - either fully succeeds or fully fails
    // This ensures we never have a half-written wallet file
    #ifdef _WIN32
    // On Windows, need to remove target file first
    std::remove(saveFile.c_str());
    #endif

    if (std::rename(tempFile.c_str(), saveFile.c_str()) != 0) {
        // Rename failed - clean up temp file
        std::remove(tempFile.c_str());
        return false;
    }

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
    std::cout << "[Wallet] Scanning UTXO set for wallet outputs..." << std::endl;

    // Step 1: Get all wallet addresses and their pubkey hashes
    std::vector<CAddress> addresses = GetAddresses();
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
                    // Add to wallet (this acquires lock internally)
                    AddTxOut(outpoint.hash, outpoint.n, entry.out.nValue, addr, entry.nHeight);
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
