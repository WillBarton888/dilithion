// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license.

#include <key.h>
#include <pubkey.h>
#include <crypto/dilithium/dilithium.h>
#include <crypto/dilithium/dilithium_paranoid.h>
#include <support/cleanse.h>
#include <random.h>
#include <cstring>

// Placeholder for uint256 - will be defined by Bitcoin Core
class uint256 {
public:
    unsigned char data[32];
    const unsigned char* begin() const { return data; }
    const unsigned char* end() const { return data + 32; }
};

bool CKey::Set(const unsigned char* pbegin, const unsigned char* pend, bool fParanoidIn)
{
    if (pend - pbegin != DILITHIUM_SECRETKEYBYTES) {
        return false;
    }

    memcpy(keydata.data(), pbegin, DILITHIUM_SECRETKEYBYTES);
    fValid = true;
    fParanoid = fParanoidIn;

    // Verify canaries after setting data
    if (!keydata.verify_integrity()) {
        fValid = false;
        return false;
    }

    return true;
}

bool CKey::MakeNewKey(bool fParanoidMode)
{
    fParanoid = fParanoidMode;

    // Generate public key (we'll discard it, will regenerate from secret key)
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];

    int ret;
    if (fParanoid) {
        ret = dilithium::paranoid::keypair_paranoid(pk, keydata.data());
    } else {
        ret = dilithium::keypair(pk, keydata.data());
    }

    if (ret != 0) {
        fValid = false;
        return false;
    }

    // Verify canaries
    if (!keydata.verify_integrity()) {
        fValid = false;
        return false;
    }

    fValid = true;
    return true;
}

CPubKey CKey::GetPubKey() const
{
    if (!fValid) {
        return CPubKey(); // Return invalid public key
    }

    // Generate public key from secret key
    // Note: Dilithium requires regenerating the full keypair
    // We'll need to extract the public key from the secret key structure

    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk_copy[DILITHIUM_SECRETKEYBYTES];

    // Copy secret key to avoid modifying original
    memcpy(sk_copy, keydata.data(), DILITHIUM_SECRETKEYBYTES);

    // Regenerate keypair (public key is deterministic from seed in secret key)
    int ret = dilithium::keypair(pk, sk_copy);

    // Clean up temporary copy
    memory_cleanse(sk_copy, DILITHIUM_SECRETKEYBYTES);

    if (ret != 0) {
        return CPubKey(); // Return invalid
    }

    return CPubKey(pk, pk + DILITHIUM_PUBLICKEYBYTES);
}

bool CKey::Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const
{
    if (!fValid) {
        return false;
    }

    // Resize signature buffer
    vchSig.resize(DILITHIUM_BYTES);
    size_t siglen;

    int ret;
    if (fParanoid) {
        ret = dilithium::paranoid::sign_paranoid(
            vchSig.data(), &siglen,
            hash.begin(), 32,
            keydata.data()
        );
    } else {
        ret = dilithium::sign(
            vchSig.data(), &siglen,
            hash.begin(), 32,
            keydata.data()
        );
    }

    if (ret != 0) {
        vchSig.clear();
        return false;
    }

    // Verify canaries still intact after signing
    if (!keydata.verify_integrity()) {
        vchSig.clear();
        return false;
    }

    vchSig.resize(siglen);
    return true;
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const
{
    if (!fValid || !pubkey.IsValid()) {
        return false;
    }

    // Verify that GetPubKey() matches the provided pubkey
    CPubKey computed_pubkey = GetPubKey();
    return computed_pubkey == pubkey;
}

CKey::CKey(CKey&& other) noexcept
    : fValid(other.fValid), fParanoid(other.fParanoid)
{
    // Move key data
    memcpy(keydata.data(), other.keydata.data(), DILITHIUM_SECRETKEYBYTES);

    // Invalidate other
    other.fValid = false;
}

CKey& CKey::operator=(CKey&& other) noexcept
{
    if (this != &other) {
        fValid = other.fValid;
        fParanoid = other.fParanoid;

        // Move key data
        memcpy(keydata.data(), other.keydata.data(), DILITHIUM_SECRETKEYBYTES);

        // Invalidate other
        other.fValid = false;
    }
    return *this;
}
