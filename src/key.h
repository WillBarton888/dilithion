// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license.

#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include <crypto/dilithium/dilithium.h>
#include <crypto/dilithium/dilithium_paranoid.h>
#include <stdexcept>
#include <vector>

class CPubKey;
class uint256;

/**
 * CKey: An encapsulated Dilithium secret key.
 *
 * This class provides Bitcoin Core-compatible interface for Dilithium secret keys.
 * Replaces ECDSA (secp256k1) with CRYSTALS-Dilithium post-quantum signatures.
 *
 * Security properties:
 * - Constant-time operations (timing attack resistant)
 * - Automatic memory clearing on destruction
 * - Paranoid mode available for enhanced security
 * - Canary-based memory protection
 */
class CKey
{
private:
    //! Whether this private key is valid (initialized)
    bool fValid;

    //! Whether to use paranoid security mode
    bool fParanoid;

    //! The secret key data (Dilithium-2: 2528 bytes)
    //! Protected by SecureKeyBuffer with canary protection
    dilithium::paranoid::SecureKeyBuffer keydata;

public:
    //! Construct an invalid private key
    CKey() : fValid(false), fParanoid(false) {}

    //! Destructor - securely clears key data
    ~CKey() {
        // SecureKeyBuffer handles secure cleanup automatically
    }

    //! Initialize from existing key data
    bool Set(const unsigned char* pbegin, const unsigned char* pend, bool fParanoidIn = false);

    //! Generate a new random private key
    bool MakeNewKey(bool fParanoidMode = false);

    //! Check whether this private key is valid
    bool IsValid() const { return fValid; }

    //! Check if using paranoid mode
    bool IsParanoid() const { return fParanoid; }

    //! Get the corresponding public key
    CPubKey GetPubKey() const;

    //! Create a signature
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const;

    //! Verify that this key can sign/verify correctly
    bool VerifyPubKey(const CPubKey& pubkey) const;

    //! Get pointer to key data (const)
    const unsigned char* data() const { return keydata.data(); }

    //! Get key size
    static constexpr size_t size() { return DILITHIUM_SECRETKEYBYTES; }

    //! Serialization
    template <typename Stream>
    void Serialize(Stream& s) const {
        if (!fValid) {
            throw std::runtime_error("Cannot serialize invalid key");
        }
        s.write((char*)keydata.data(), DILITHIUM_SECRETKEYBYTES);
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        s.read((char*)keydata.data(), DILITHIUM_SECRETKEYBYTES);
        fValid = true;
        fParanoid = false; // Default to non-paranoid after deserialization
    }

    //! Prevent copying (secret keys should not be copied)
    CKey(const CKey&) = delete;
    CKey& operator=(const CKey&) = delete;

    //! Allow moving
    CKey(CKey&& other) noexcept;
    CKey& operator=(CKey&& other) noexcept;
};

#endif // BITCOIN_KEY_H
