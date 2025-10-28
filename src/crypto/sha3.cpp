// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <crypto/sha3.h>
#include <cstring>
#include <stdexcept>

// Import SHA-3 from Dilithium's FIPS 202 implementation
extern "C" {
    typedef struct {
        uint64_t s[25];
        unsigned int pos;
    } keccak_state;

    void pqcrystals_dilithium_fips202_ref_sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
    void pqcrystals_dilithium_fips202_ref_sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);
}

// SHA-3-256 implementation

CSHA3_256::CSHA3_256() : finalized(false) {
    state = new keccak_state();
    Reset();
}

CSHA3_256::~CSHA3_256() {
    if (state) {
        delete static_cast<keccak_state*>(state);
    }
}

CSHA3_256& CSHA3_256::Write(const uint8_t* data, size_t len) {
    // CRITICAL: Streaming API not implemented! Use SHA3_256() one-shot function instead.
    // This method is a stub and will cause assertion failure if called.
    (void)data;
    (void)len;
    throw std::runtime_error("CSHA3_256::Write() not implemented - use SHA3_256() one-shot function");
    return *this;
}

void CSHA3_256::Finalize(uint8_t hash[OUTPUT_SIZE]) {
    // CRITICAL: Streaming API not implemented! Use SHA3_256() one-shot function instead.
    (void)hash;
    throw std::runtime_error("CSHA3_256::Finalize() not implemented - use SHA3_256() one-shot function");
}

CSHA3_256& CSHA3_256::Reset() {
    if (state) {
        memset(state, 0, sizeof(keccak_state));
    }
    finalized = false;
    return *this;
}

// SHA-3-512 implementation

CSHA3_512::CSHA3_512() : finalized(false) {
    state = new keccak_state();
    Reset();
}

CSHA3_512::~CSHA3_512() {
    if (state) {
        delete static_cast<keccak_state*>(state);
    }
}

CSHA3_512& CSHA3_512::Write(const uint8_t* data, size_t len) {
    // CRITICAL: Streaming API not implemented! Use SHA3_512() one-shot function instead.
    (void)data;
    (void)len;
    throw std::runtime_error("CSHA3_512::Write() not implemented - use SHA3_512() one-shot function");
    return *this;
}

void CSHA3_512::Finalize(uint8_t hash[OUTPUT_SIZE]) {
    // CRITICAL: Streaming API not implemented! Use SHA3_512() one-shot function instead.
    (void)hash;
    throw std::runtime_error("CSHA3_512::Finalize() not implemented - use SHA3_512() one-shot function");
}

CSHA3_512& CSHA3_512::Reset() {
    if (state) {
        memset(state, 0, sizeof(keccak_state));
    }
    finalized = false;
    return *this;
}

// Convenience functions (one-shot hashing)

void SHA3_256(const uint8_t* data, size_t len, uint8_t hash[32]) {
    pqcrystals_dilithium_fips202_ref_sha3_256(hash, data, len);
}

void SHA3_512(const uint8_t* data, size_t len, uint8_t hash[64]) {
    pqcrystals_dilithium_fips202_ref_sha3_512(hash, data, len);
}
