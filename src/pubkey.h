// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license.

#ifndef BITCOIN_PUBKEY_H
#define BITCOIN_PUBKEY_H

#include <crypto/dilithium/dilithium.h>
#include <stdexcept>
#include <vector>

class uint256;

/**
 * CPubKey: An encapsulated Dilithium public key.
 *
 * Bitcoin Core-compatible interface for Dilithium public keys.
 * Replaces ECDSA (secp256k1) with CRYSTALS-Dilithium post-quantum signatures.
 *
 * Size: 1312 bytes (vs 33 bytes for compressed ECDSA)
 */
class CPubKey
{
private:
    //! The public key data (Dilithium-2: 1312 bytes)
    unsigned char vch[DILITHIUM_PUBLICKEYBYTES];

    //! Validation flag
    bool fValid;

public:
    //! Construct an invalid public key
    CPubKey() : fValid(false) {
        memset(vch, 0, sizeof(vch));
    }

    //! Initialize from data
    CPubKey(const unsigned char* pbegin, const unsigned char* pend);

    //! Simple equality
    friend bool operator==(const CPubKey& a, const CPubKey& b) {
        return a.fValid == b.fValid &&
               memcmp(a.vch, b.vch, DILITHIUM_PUBLICKEYBYTES) == 0;
    }

    friend bool operator!=(const CPubKey& a, const CPubKey& b) {
        return !(a == b);
    }

    //! Implement serialization
    template <typename Stream>
    void Serialize(Stream& s) const {
        s.write((char*)vch, DILITHIUM_PUBLICKEYBYTES);
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        s.read((char*)vch, DILITHIUM_PUBLICKEYBYTES);
        fValid = true; // Assume valid after deserialization
    }

    //! Get the size
    unsigned int size() const { return DILITHIUM_PUBLICKEYBYTES; }

    //! Get the data
    const unsigned char* data() const { return vch; }
    const unsigned char* begin() const { return vch; }
    const unsigned char* end() const { return vch + size(); }

    //! Check validity
    bool IsValid() const { return fValid; }

    //! Set from data range
    void Set(const unsigned char* pbegin, const unsigned char* pend);

    //! Verify a signature
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const;

    //! Verify with paranoid triple-verification
    bool VerifyParanoid(const uint256& hash, const std::vector<unsigned char>& vchSig) const;
};

#endif // BITCOIN_PUBKEY_H
