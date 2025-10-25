// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/wallet.h>
#include <crypto/sha3.h>

#include <algorithm>
#include <cstring>
#include <fstream>

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
            memset(masterKeyVec.data(), 0, masterKeyVec.size());
            return false;
        }

        if (!crypter.Encrypt(key.vchPrivKey, encKey.vchCryptedKey)) {
            memset(masterKeyVec.data(), 0, masterKeyVec.size());
            return false;
        }

        mapCryptedKeys[address] = encKey;
        memset(masterKeyVec.data(), 0, masterKeyVec.size());
    } else {
        // Wallet not encrypted, store key as-is
        mapKeys[address] = key;
    }

    vchAddresses.push_back(address);

    // Set as default if first key
    if (vchAddresses.size() == 1) {
        defaultAddress = address;
    }

    // Auto-save wallet if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        Save();
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

bool CWallet::GetKey(const CAddress& address, CKey& keyOut) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

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
        memset(masterKeyVec.data(), 0, masterKeyVec.size());
        return false;
    }

    std::vector<uint8_t> decryptedPrivKey;
    if (!crypter.Decrypt(encKey.vchCryptedKey, decryptedPrivKey)) {
        memset(masterKeyVec.data(), 0, masterKeyVec.size());
        return false;
    }

    // Construct decrypted key
    keyOut.vchPubKey = encKey.vchPubKey;
    keyOut.vchPrivKey = decryptedPrivKey;

    // Wipe sensitive data
    memset(masterKeyVec.data(), 0, masterKeyVec.size());
    memset(decryptedPrivKey.data(), 0, decryptedPrivKey.size());

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

    // Check if we own this address
    if (!HasKey(address)) {
        return false;
    }

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
            memset(vMasterKey.data_ptr(), 0, vMasterKey.size());
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
        memset(vMasterKey.data_ptr(), 0, vMasterKey.size());
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
    memset(derivedKey.data(), 0, derivedKey.size());
    memset(decryptedKey.data(), 0, decryptedKey.size());

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

    // Allow encrypting empty wallet - keys will be encrypted as they're generated

    // Generate random master key
    std::vector<uint8_t> vMasterKeyPlain(WALLET_CRYPTO_KEY_SIZE);
    if (!GetStrongRandBytes(vMasterKeyPlain.data(), WALLET_CRYPTO_KEY_SIZE)) {
        return false;
    }

    // Generate salt for PBKDF2
    if (!GenerateSalt(masterKey.vchSalt)) {
        memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
        return false;
    }

    // Derive key from passphrase
    std::vector<uint8_t> derivedKey;
    if (!DeriveKey(passphrase, masterKey.vchSalt, WALLET_CRYPTO_PBKDF2_ROUNDS, derivedKey)) {
        memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
        return false;
    }

    // Generate IV for master key encryption
    if (!GenerateIV(masterKey.vchIV)) {
        memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
        memset(derivedKey.data(), 0, derivedKey.size());
        return false;
    }

    // Encrypt master key with passphrase-derived key
    CCrypter masterCrypter;
    if (!masterCrypter.SetKey(derivedKey, masterKey.vchIV)) {
        memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
        memset(derivedKey.data(), 0, derivedKey.size());
        return false;
    }

    if (!masterCrypter.Encrypt(vMasterKeyPlain, masterKey.vchCryptedKey)) {
        memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
        memset(derivedKey.data(), 0, derivedKey.size());
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
            memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
            memset(derivedKey.data(), 0, derivedKey.size());
            return false;
        }

        // Encrypt private key with master key
        CCrypter keyCrypter;
        if (!keyCrypter.SetKey(vMasterKeyPlain, encKey.vchIV)) {
            memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
            memset(derivedKey.data(), 0, derivedKey.size());
            return false;
        }

        if (!keyCrypter.Encrypt(key.vchPrivKey, encKey.vchCryptedKey)) {
            memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
            memset(derivedKey.data(), 0, derivedKey.size());
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
    memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
    memset(derivedKey.data(), 0, derivedKey.size());

    // Auto-save wallet if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        Save();
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

    // Derive old key
    std::vector<uint8_t> derivedKeyOld;
    if (!DeriveKey(passphraseOld, masterKey.vchSalt, masterKey.nDeriveIterations, derivedKeyOld)) {
        return false;
    }

    // Decrypt current master key
    CCrypter crypterOld;
    if (!crypterOld.SetKey(derivedKeyOld, masterKey.vchIV)) {
        memset(derivedKeyOld.data(), 0, derivedKeyOld.size());
        return false;
    }

    std::vector<uint8_t> vMasterKeyPlain;
    if (!crypterOld.Decrypt(masterKey.vchCryptedKey, vMasterKeyPlain)) {
        memset(derivedKeyOld.data(), 0, derivedKeyOld.size());
        return false;  // Wrong old passphrase
    }

    // Generate new salt
    std::vector<uint8_t> newSalt;
    if (!GenerateSalt(newSalt)) {
        memset(derivedKeyOld.data(), 0, derivedKeyOld.size());
        memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
        return false;
    }

    // Derive new key
    std::vector<uint8_t> derivedKeyNew;
    if (!DeriveKey(passphraseNew, newSalt, WALLET_CRYPTO_PBKDF2_ROUNDS, derivedKeyNew)) {
        memset(derivedKeyOld.data(), 0, derivedKeyOld.size());
        memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
        return false;
    }

    // Generate new IV
    std::vector<uint8_t> newIV;
    if (!GenerateIV(newIV)) {
        memset(derivedKeyOld.data(), 0, derivedKeyOld.size());
        memset(derivedKeyNew.data(), 0, derivedKeyNew.size());
        memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
        return false;
    }

    // Re-encrypt master key with new passphrase
    CCrypter crypterNew;
    if (!crypterNew.SetKey(derivedKeyNew, newIV)) {
        memset(derivedKeyOld.data(), 0, derivedKeyOld.size());
        memset(derivedKeyNew.data(), 0, derivedKeyNew.size());
        memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
        return false;
    }

    std::vector<uint8_t> newCryptedKey;
    if (!crypterNew.Encrypt(vMasterKeyPlain, newCryptedKey)) {
        memset(derivedKeyOld.data(), 0, derivedKeyOld.size());
        memset(derivedKeyNew.data(), 0, derivedKeyNew.size());
        memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());
        return false;
    }

    // Update master key
    masterKey.vchCryptedKey = newCryptedKey;
    masterKey.vchSalt = newSalt;
    masterKey.vchIV = newIV;

    // Wipe sensitive data
    memset(derivedKeyOld.data(), 0, derivedKeyOld.size());
    memset(derivedKeyNew.data(), 0, derivedKeyNew.size());
    memset(vMasterKeyPlain.data(), 0, vMasterKeyPlain.size());

    // Auto-save wallet if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        Save();
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

    // Set wallet file path on successful load
    m_walletFile = filename;

    // Clear existing wallet data
    mapKeys.clear();
    mapCryptedKeys.clear();
    vchAddresses.clear();
    mapWalletTx.clear();
    defaultAddress = CAddress();

    // Read header
    char magic[8];
    file.read(magic, 8);
    if (std::string(magic, 8) != "DILWLT01") {
        return false;  // Invalid file format
    }

    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 1) {
        return false;  // Unsupported version
    }

    uint32_t flags;
    file.read(reinterpret_cast<char*>(&flags), sizeof(flags));

    // Skip reserved bytes
    uint8_t reserved[16];
    file.read(reinterpret_cast<char*>(reserved), 16);

    // Read master key if encrypted
    bool isEncrypted = (flags & 0x01) != 0;
    if (isEncrypted) {
        uint32_t cryptedKeyLen;
        file.read(reinterpret_cast<char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));

        masterKey.vchCryptedKey.resize(cryptedKeyLen);
        file.read(reinterpret_cast<char*>(masterKey.vchCryptedKey.data()), cryptedKeyLen);

        masterKey.vchSalt.resize(32);
        file.read(reinterpret_cast<char*>(masterKey.vchSalt.data()), 32);

        masterKey.vchIV.resize(16);
        file.read(reinterpret_cast<char*>(masterKey.vchIV.data()), 16);

        file.read(reinterpret_cast<char*>(&masterKey.nDerivationMethod), sizeof(masterKey.nDerivationMethod));
        file.read(reinterpret_cast<char*>(&masterKey.nDeriveIterations), sizeof(masterKey.nDeriveIterations));

        // Wallet starts locked
        fWalletUnlocked = false;
    }

    // Read keys
    uint32_t numKeys;
    file.read(reinterpret_cast<char*>(&numKeys), sizeof(numKeys));

    for (uint32_t i = 0; i < numKeys; i++) {
        // Read address
        std::vector<uint8_t> addrData(21);
        file.read(reinterpret_cast<char*>(addrData.data()), 21);

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

            uint32_t cryptedKeyLen;
            file.read(reinterpret_cast<char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));

            encKey.vchCryptedKey.resize(cryptedKeyLen);
            file.read(reinterpret_cast<char*>(encKey.vchCryptedKey.data()), cryptedKeyLen);

            encKey.vchIV.resize(16);
            file.read(reinterpret_cast<char*>(encKey.vchIV.data()), 16);

            // Create address from public key
            CAddress keyAddr(encKey.vchPubKey);
            mapCryptedKeys[keyAddr] = encKey;
            vchAddresses.push_back(keyAddr);
        } else {
            // Read unencrypted key
            CKey key;

            key.vchPubKey.resize(DILITHIUM_PUBLICKEY_SIZE);
            file.read(reinterpret_cast<char*>(key.vchPubKey.data()), DILITHIUM_PUBLICKEY_SIZE);

            key.vchPrivKey.resize(DILITHIUM_SECRETKEY_SIZE);
            file.read(reinterpret_cast<char*>(key.vchPrivKey.data()), DILITHIUM_SECRETKEY_SIZE);

            // Create address from public key
            CAddress keyAddr(key.vchPubKey);
            mapKeys[keyAddr] = key;
            vchAddresses.push_back(keyAddr);
        }
    }

    // Read default address
    uint8_t hasDefault;
    file.read(reinterpret_cast<char*>(&hasDefault), 1);
    if (hasDefault) {
        std::vector<uint8_t> addrData(21);
        file.read(reinterpret_cast<char*>(addrData.data()), 21);

        // Find matching address in vchAddresses
        for (const auto& addr : vchAddresses) {
            if (addr.GetData() == addrData) {
                defaultAddress = addr;
                break;
            }
        }
    }

    // Read transactions
    uint32_t numTxs;
    file.read(reinterpret_cast<char*>(&numTxs), sizeof(numTxs));

    for (uint32_t i = 0; i < numTxs; i++) {
        CWalletTx wtx;

        file.read(reinterpret_cast<char*>(wtx.txid.begin()), 32);
        file.read(reinterpret_cast<char*>(&wtx.vout), sizeof(wtx.vout));
        file.read(reinterpret_cast<char*>(&wtx.nValue), sizeof(wtx.nValue));

        std::vector<uint8_t> addrData(21);
        file.read(reinterpret_cast<char*>(addrData.data()), 21);

        // Find matching address
        for (const auto& addr : vchAddresses) {
            if (addr.GetData() == addrData) {
                wtx.address = addr;
                break;
            }
        }

        uint8_t fSpent;
        file.read(reinterpret_cast<char*>(&fSpent), 1);
        wtx.fSpent = (fSpent != 0);

        file.read(reinterpret_cast<char*>(&wtx.nHeight), sizeof(wtx.nHeight));

        mapWalletTx[wtx.txid] = wtx;
    }

    return file.good();
}

bool CWallet::Save(const std::string& filename) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Use current wallet file if no filename specified
    std::string saveFile = filename.empty() ? m_walletFile : filename;
    if (saveFile.empty()) {
        return false;  // No wallet file specified
    }

    std::ofstream file(saveFile, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // Write header
    const char magic[9] = "DILWLT01";
    file.write(magic, 8);  // Write 8 bytes (without null terminator)

    uint32_t version = 1;
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));

    uint32_t flags = masterKey.IsValid() ? 0x01 : 0x00;  // Bit 0 = encrypted
    file.write(reinterpret_cast<const char*>(&flags), sizeof(flags));

    // Reserved bytes
    uint8_t reserved[16] = {0};
    file.write(reinterpret_cast<const char*>(reserved), 16);

    // Write master key if encrypted
    if (masterKey.IsValid()) {
        uint32_t cryptedKeyLen = static_cast<uint32_t>(masterKey.vchCryptedKey.size());
        file.write(reinterpret_cast<const char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));
        file.write(reinterpret_cast<const char*>(masterKey.vchCryptedKey.data()), cryptedKeyLen);

        file.write(reinterpret_cast<const char*>(masterKey.vchSalt.data()), 32);
        file.write(reinterpret_cast<const char*>(masterKey.vchIV.data()), 16);
        file.write(reinterpret_cast<const char*>(&masterKey.nDerivationMethod), sizeof(masterKey.nDerivationMethod));
        file.write(reinterpret_cast<const char*>(&masterKey.nDeriveIterations), sizeof(masterKey.nDeriveIterations));
    }

    // Write keys
    if (masterKey.IsValid()) {
        // Encrypted wallet - write encrypted keys
        uint32_t numKeys = static_cast<uint32_t>(mapCryptedKeys.size());
        file.write(reinterpret_cast<const char*>(&numKeys), sizeof(numKeys));

        for (const auto& pair : mapCryptedKeys) {
            const CAddress& addr = pair.first;
            const CEncryptedKey& encKey = pair.second;

            // Write address
            file.write(reinterpret_cast<const char*>(addr.GetData().data()), 21);

            // Write public key
            file.write(reinterpret_cast<const char*>(encKey.vchPubKey.data()), DILITHIUM_PUBLICKEY_SIZE);

            // Write encrypted private key
            uint32_t cryptedKeyLen = static_cast<uint32_t>(encKey.vchCryptedKey.size());
            file.write(reinterpret_cast<const char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));
            file.write(reinterpret_cast<const char*>(encKey.vchCryptedKey.data()), cryptedKeyLen);

            // Write IV
            file.write(reinterpret_cast<const char*>(encKey.vchIV.data()), 16);
        }
    } else {
        // Unencrypted wallet - write unencrypted keys
        uint32_t numKeys = static_cast<uint32_t>(mapKeys.size());
        file.write(reinterpret_cast<const char*>(&numKeys), sizeof(numKeys));

        for (const auto& pair : mapKeys) {
            const CAddress& addr = pair.first;
            const CKey& key = pair.second;

            // Write address
            file.write(reinterpret_cast<const char*>(addr.GetData().data()), 21);

            // Write public key
            file.write(reinterpret_cast<const char*>(key.vchPubKey.data()), DILITHIUM_PUBLICKEY_SIZE);

            // Write private key
            file.write(reinterpret_cast<const char*>(key.vchPrivKey.data()), DILITHIUM_SECRETKEY_SIZE);
        }
    }

    // Write default address
    uint8_t hasDefault = defaultAddress.IsValid() ? 1 : 0;
    file.write(reinterpret_cast<const char*>(&hasDefault), 1);
    if (hasDefault) {
        file.write(reinterpret_cast<const char*>(defaultAddress.GetData().data()), 21);
    }

    // Write transactions
    uint32_t numTxs = static_cast<uint32_t>(mapWalletTx.size());
    file.write(reinterpret_cast<const char*>(&numTxs), sizeof(numTxs));

    for (const auto& pair : mapWalletTx) {
        const CWalletTx& wtx = pair.second;

        file.write(reinterpret_cast<const char*>(wtx.txid.begin()), 32);
        file.write(reinterpret_cast<const char*>(&wtx.vout), sizeof(wtx.vout));
        file.write(reinterpret_cast<const char*>(&wtx.nValue), sizeof(wtx.nValue));
        file.write(reinterpret_cast<const char*>(wtx.address.GetData().data()), 21);
        uint8_t fSpent = wtx.fSpent ? 1 : 0;
        file.write(reinterpret_cast<const char*>(&fSpent), 1);
        file.write(reinterpret_cast<const char*>(&wtx.nHeight), sizeof(wtx.nHeight));
    }

    file.close();
    return file.good();
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
        memset(vMasterKey.data_ptr(), 0, vMasterKey.size());
    }

    // Clear master key data
    masterKey = CMasterKey();
}
