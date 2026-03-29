/**
 * Dilithium WebAssembly Wrapper for Dilithion Light Wallet
 *
 * Uses pqcrystals Dilithium3 reference implementation directly.
 * This is the SAME source code the node binary uses (depends/dilithium/ref/),
 * ensuring cryptographic compatibility between node and browser wallets.
 *
 * Compiled with: -DDILITHIUM_MODE=3 -DDILITHIUM_RANDOMIZED_SIGNING
 *
 * Copyright (c) 2025-2026 The Dilithion Core developers
 * Distributed under the MIT software license
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Dilithium3 reference implementation headers.
 * DILITHIUM_MODE=3 is set via compiler flag (-DDILITHIUM_MODE=3). */
#include "sign.h"
#include "randombytes.h"
#include "params.h"

/* Compile-time assertions for key sizes (Dilithium3 / ML-DSA-65) */
_Static_assert(CRYPTO_PUBLICKEYBYTES == 1952, "PK size mismatch");
_Static_assert(CRYPTO_SECRETKEYBYTES == 4032, "SK size mismatch");
_Static_assert(CRYPTO_BYTES == 3309, "Signature size mismatch");

/**
 * Initialize the Dilithium module.
 * No-op for the reference implementation (no global state needed).
 * Kept for API compatibility with the JS layer.
 * @return 0 (always succeeds)
 */
int dilithium_init(void) {
    return 0;
}

/**
 * Cleanup the Dilithium module.
 * No-op for the reference implementation.
 */
void dilithium_cleanup(void) {
    /* Nothing to do */
}

/**
 * Get public key size in bytes.
 */
size_t dilithium_get_publickey_bytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

/**
 * Get secret key size in bytes.
 */
size_t dilithium_get_secretkey_bytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

/**
 * Get maximum signature size in bytes.
 */
size_t dilithium_get_signature_bytes(void) {
    return CRYPTO_BYTES;
}

/**
 * Get seed size in bytes.
 */
size_t dilithium_get_seed_bytes(void) {
    return SEEDBYTES;
}

/**
 * Generate a random Dilithium3 keypair.
 * Uses crypto.getRandomValues() (browser) via WASI random_get.
 * @param pk Output buffer for public key (CRYPTO_PUBLICKEYBYTES bytes)
 * @param sk Output buffer for secret key (CRYPTO_SECRETKEYBYTES bytes)
 * @return 0 on success
 */
int dilithium_keypair(uint8_t *pk, uint8_t *sk) {
    return crypto_sign_keypair(pk, sk);
}

/**
 * Generate a deterministic Dilithium3 keypair from a 32-byte seed.
 * This is the critical function for HD wallet / mnemonic import.
 * Same seed always produces the same keypair.
 * @param pk Output buffer for public key (CRYPTO_PUBLICKEYBYTES bytes)
 * @param sk Output buffer for secret key (CRYPTO_SECRETKEYBYTES bytes)
 * @param seed 32-byte input seed
 * @return 0 on success
 */
int dilithium3_keypair_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    return crypto_sign_keypair_from_seed(pk, sk, seed);
}

/**
 * Sign a message with Dilithium3.
 * Uses empty context (NULL, 0) for compatibility with node signatures.
 * @param sig Output buffer for signature (CRYPTO_BYTES bytes)
 * @param sig_len Output: actual signature length
 * @param msg Message to sign
 * @param msg_len Message length
 * @param sk Secret key (CRYPTO_SECRETKEYBYTES bytes)
 * @return 0 on success, -1 on failure
 */
int dilithium_sign(uint8_t *sig, size_t *sig_len,
                   const uint8_t *msg, size_t msg_len,
                   const uint8_t *sk) {
    return crypto_sign_signature(sig, sig_len, msg, msg_len, NULL, 0, sk);
}

/**
 * Verify a Dilithium3 signature.
 * Uses empty context (NULL, 0) for compatibility with node verification.
 * @param msg Message that was signed
 * @param msg_len Message length
 * @param sig Signature to verify
 * @param sig_len Signature length
 * @param pk Public key (CRYPTO_PUBLICKEYBYTES bytes)
 * @return 0 if valid, -1 if invalid
 */
int dilithium_verify(const uint8_t *msg, size_t msg_len,
                     const uint8_t *sig, size_t sig_len,
                     const uint8_t *pk) {
    return crypto_sign_verify(sig, sig_len, msg, msg_len, NULL, 0, pk);
}

/**
 * Allocate memory (for JavaScript to use via WASM).
 */
void *dilithium_malloc(size_t size) {
    return malloc(size);
}

/**
 * Free memory (for JavaScript to use via WASM).
 */
void dilithium_free(void *ptr) {
    free(ptr);
}

/**
 * Securely free memory by zeroing before freeing.
 * Use for buffers that contained secret keys or seeds.
 * Uses volatile to prevent compiler dead-store elimination.
 * @param ptr Pointer to memory
 * @param size Number of bytes to zero before freeing
 */
void dilithium_secure_free(void *ptr, size_t size) {
    if (ptr) {
        volatile uint8_t *p = (volatile uint8_t *)ptr;
        for (size_t i = 0; i < size; i++) {
            p[i] = 0;
        }
        /* Memory barrier to prevent reordering past the zeroing */
        __asm__ volatile("" ::: "memory");
        free(ptr);
    }
}
