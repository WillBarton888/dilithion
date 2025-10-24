// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license.

#include <pubkey.h>
#include <crypto/dilithium/dilithium.h>
#include <crypto/dilithium/dilithium_paranoid.h>
#include <cstring>

// Placeholder for uint256
class uint256 {
public:
    unsigned char data[32];
    const unsigned char* begin() const { return data; }
};

CPubKey::CPubKey(const unsigned char* pbegin, const unsigned char* pend)
    : fValid(false)
{
    Set(pbegin, pend);
}

void CPubKey::Set(const unsigned char* pbegin, const unsigned char* pend)
{
    if (pend - pbegin == DILITHIUM_PUBLICKEYBYTES) {
        memcpy(vch, pbegin, DILITHIUM_PUBLICKEYBYTES);
        fValid = true;
    } else {
        memset(vch, 0, sizeof(vch));
        fValid = false;
    }
}

bool CPubKey::Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const
{
    if (!fValid) {
        return false;
    }

    if (vchSig.size() != DILITHIUM_BYTES) {
        return false;
    }

    int ret = dilithium::verify(
        vchSig.data(), vchSig.size(),
        hash.begin(), 32,
        vch
    );

    return (ret == 0);
}

bool CPubKey::VerifyParanoid(const uint256& hash, const std::vector<unsigned char>& vchSig) const
{
    if (!fValid) {
        return false;
    }

    if (vchSig.size() != DILITHIUM_BYTES) {
        return false;
    }

    int ret = dilithium::paranoid::verify_paranoid(
        vchSig.data(), vchSig.size(),
        hash.begin(), 32,
        vch
    );

    return (ret == 0);
}
