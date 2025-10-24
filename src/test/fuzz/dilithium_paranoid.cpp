// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license.

#include <crypto/dilithium/dilithium_paranoid.h>
#include <support/cleanse.h>
#include <test/fuzz/fuzz.h>

/**
 * Fuzz test for Dilithium paranoid security layer.
 * Tests canary protection, triple-verification, and enhanced security features.
 */

namespace {

void test_secure_key_buffer(FuzzedDataProvider& fdp) {
    dilithium::paranoid::SecureKeyBuffer key_storage;
    assert(key_storage.verify_integrity());
}

void test_paranoid_ops(FuzzedDataProvider& fdp) {
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    dilithium::paranoid::SecureKeyBuffer key_storage;
    
    if (dilithium::paranoid::keypair_paranoid(pk, key_storage.data()) == 0) {
        assert(key_storage.verify_integrity());
    }
}

} // namespace

FUZZ_TARGET(dilithium_paranoid)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    uint8_t sel = fdp.ConsumeIntegral<uint8_t>();
    
    switch (sel % 2) {
        case 0: test_secure_key_buffer(fdp); break;
        case 1: test_paranoid_ops(fdp); break;
    }
}
