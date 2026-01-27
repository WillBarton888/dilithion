/**
 * Dilithium WebAssembly Wrapper for Dilithion Light Wallet
 *
 * Uses liboqs ML-DSA-65 (equivalent to Dilithium3)
 *
 * Copyright (c) 2025 The Dilithion Core developers
 * Distributed under the MIT software license
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

// ML-DSA-65 (Dilithium3) parameters
#define DILITHIUM3_PUBLICKEY_BYTES 1952
#define DILITHIUM3_SECRETKEY_BYTES 4032
#define DILITHIUM3_SIGNATURE_BYTES 3309

// Algorithm name
#define ALGORITHM_NAME OQS_SIG_alg_ml_dsa_65

// Global OQS_SIG object (lazily initialized)
static OQS_SIG *g_sig = NULL;

/**
 * Initialize the Dilithium module
 * @return 0 on success, -1 on failure
 */
int dilithium_init(void) {
    if (g_sig != NULL) {
        return 0;  // Already initialized
    }

    g_sig = OQS_SIG_new(ALGORITHM_NAME);
    if (g_sig == NULL) {
        return -1;  // Failed to create algorithm
    }

    return 0;
}

/**
 * Cleanup the Dilithium module
 */
void dilithium_cleanup(void) {
    if (g_sig != NULL) {
        OQS_SIG_free(g_sig);
        g_sig = NULL;
    }
}

/**
 * Get public key size
 */
size_t dilithium_get_publickey_bytes(void) {
    return DILITHIUM3_PUBLICKEY_BYTES;
}

/**
 * Get secret key size
 */
size_t dilithium_get_secretkey_bytes(void) {
    return DILITHIUM3_SECRETKEY_BYTES;
}

/**
 * Get signature size
 */
size_t dilithium_get_signature_bytes(void) {
    return DILITHIUM3_SIGNATURE_BYTES;
}

/**
 * Generate a keypair
 * @param public_key Output buffer for public key (must be DILITHIUM3_PUBLICKEY_BYTES)
 * @param secret_key Output buffer for secret key (must be DILITHIUM3_SECRETKEY_BYTES)
 * @return 0 on success, -1 on failure
 */
int dilithium_keypair(uint8_t *public_key, uint8_t *secret_key) {
    if (g_sig == NULL) {
        if (dilithium_init() != 0) {
            return -1;
        }
    }

    OQS_STATUS status = OQS_SIG_keypair(g_sig, public_key, secret_key);
    return (status == OQS_SUCCESS) ? 0 : -1;
}

/**
 * Sign a message
 * @param signature Output buffer for signature (must be DILITHIUM3_SIGNATURE_BYTES)
 * @param signature_len Output for actual signature length
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Secret key
 * @return 0 on success, -1 on failure
 */
int dilithium_sign(uint8_t *signature, size_t *signature_len,
                   const uint8_t *message, size_t message_len,
                   const uint8_t *secret_key) {
    if (g_sig == NULL) {
        if (dilithium_init() != 0) {
            return -1;
        }
    }

    OQS_STATUS status = OQS_SIG_sign(g_sig, signature, signature_len,
                                      message, message_len, secret_key);
    return (status == OQS_SUCCESS) ? 0 : -1;
}

/**
 * Verify a signature
 * @param message Message that was signed
 * @param message_len Length of message
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @param public_key Public key
 * @return 0 if valid, -1 if invalid
 */
int dilithium_verify(const uint8_t *message, size_t message_len,
                     const uint8_t *signature, size_t signature_len,
                     const uint8_t *public_key) {
    if (g_sig == NULL) {
        if (dilithium_init() != 0) {
            return -1;
        }
    }

    OQS_STATUS status = OQS_SIG_verify(g_sig, message, message_len,
                                        signature, signature_len, public_key);
    return (status == OQS_SUCCESS) ? 0 : -1;
}

/**
 * Allocate memory (for JavaScript to use)
 */
void *dilithium_malloc(size_t size) {
    return malloc(size);
}

/**
 * Free memory (for JavaScript to use)
 */
void dilithium_free(void *ptr) {
    free(ptr);
}
