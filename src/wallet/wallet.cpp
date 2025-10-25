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

CWallet::CWallet() {
}

CWallet::~CWallet() {
    Clear();
}

bool CWallet::GenerateNewKey() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    CKey key;
    if (!WalletCrypto::GenerateKeyPair(key)) {
        return false;
    }

    CAddress address(key.vchPubKey);
    mapKeys[address] = key;
    vchAddresses.push_back(address);

    // Set as default if first key
    if (vchAddresses.size() == 1) {
        defaultAddress = address;
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
    return mapKeys.find(address) != mapKeys.end();
}

bool CWallet::GetKey(const CAddress& address, CKey& keyOut) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    auto it = mapKeys.find(address);
    if (it == mapKeys.end()) {
        return false;
    }

    keyOut = it->second;
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
    return mapKeys.size();
}

bool CWallet::Load(const std::string& filename) {
    // Simple file format for now
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // TODO: Implement wallet file format
    // For now, just return true
    return true;
}

bool CWallet::Save(const std::string& filename) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // TODO: Implement wallet file format
    // For now, just return true
    return true;
}

void CWallet::Clear() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    mapKeys.clear();
    vchAddresses.clear();
    mapWalletTx.clear();
    defaultAddress = CAddress();
}
