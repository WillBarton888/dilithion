/**
 * WASM-compatible random bytes implementation for Dilithium.
 * Replaces depends/dilithium/ref/randombytes.c for WebAssembly builds.
 *
 * Uses WASI random_get, which Emscripten maps to:
 *   - Browser: crypto.getRandomValues() (CSPRNG, W3C Web Crypto)
 *   - Node.js: crypto.randomFillSync()
 *
 * Note: keypair_from_seed() does NOT call randombytes() — it takes the
 * seed as input. This RNG is only used for random keypair generation
 * and for the randomized signing nonce (DILITHIUM_RANDOMIZED_SIGNING).
 *
 * Copyright (c) 2025-2026 The Dilithion Core developers
 * Distributed under the MIT software license
 */

#include <stddef.h>
#include <stdint.h>
#include "randombytes.h"

/* WASI random_get: cryptographically secure random bytes.
 * Emscripten provides this import in the wasi_snapshot_preview1 namespace. */
extern int __wasi_random_get(uint8_t *buf, size_t buf_len)
    __attribute__((__import_module__("wasi_snapshot_preview1"),
                   __import_name__("random_get")));

void randombytes(uint8_t *out, size_t outlen) {
    /* __wasi_random_get returns 0 on success */
    if (__wasi_random_get(out, outlen) != 0) {
        /* Fatal: RNG failure must never produce uninitialized keys.
         * In browser, this should never happen. */
        __builtin_trap();
    }
}
