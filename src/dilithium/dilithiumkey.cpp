// Copyright (c) 2025 The Dilithion Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dilithium/dilithiumkey.h>
#include <dilithium/dilithiumpubkey.h>
#include <crypto/dilithium/dilithium.h>
#include <random.h>
#include <support/cleanse.h>

DilithiumKey::~DilithiumKey() {
    // CRITICAL: Clear secret key from memory
    memory_cleanse(keydata.data(), keydata.size());
}

bool DilithiumKey::MakeNewKey() {
    keydata.resize(DILITHIUM_SECRETKEYBYTES);
    pubkey.resize(DILITHIUM_PUBLICKEYBYTES);

    // Generate keypair using crypto layer
    int result = dilithium::keypair(pubkey.data(), keydata.data());

    if (result != 0) {
        keydata.clear();
        pubkey.clear();
        fValid = false;
        return false;
    }

    fValid = true;
    return true;
}
bool DilithiumKey::Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid) return false;

    // Dilithium signature + hash type byte (following Bitcoin convention)
    vchSig.resize(DILITHIUM_BYTES + 1);
    size_t siglen = DILITHIUM_BYTES;

    // Sign the 32-byte hash
    int result = dilithium::sign(
        vchSig.data(), &siglen,
        hash.begin(), 32,
        keydata.data()
    );

    if (result != 0 || siglen != DILITHIUM_BYTES) {
        vchSig.clear();
        return false;
    }

    // Append hash type byte (SIGHASH_ALL = 1)
    vchSig[DILITHIUM_BYTES] = 1;  // SIGHASH_ALL
    return true;
}

DilithiumPubKey DilithiumKey::GetPubKey() const {
    if (!fValid) return DilithiumPubKey();
    return DilithiumPubKey(pubkey);
}

std::vector<unsigned char> DilithiumKey::GetPrivKey() const {
    return keydata;
}

    // Validate size
    if (vchPrivKey.size() != DILITHIUM_SECRETKEYBYTES) {
        return false;
    }

    // Set the private key
    keydata = vchPrivKey;
    
    // Extract public key from secret key
    // In Dilithium, the secret key format includes the public key at the end
    size_t pk_offset = DILITHIUM_SECRETKEYBYTES - DILITHIUM_PUBLICKEYBYTES;
    pubkey.assign(vchPrivKey.begin() + pk_offset, vchPrivKey.end());
    
    fValid = true;
    return true;
}
}
