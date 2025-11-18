// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef BITCOIN_CRYPTO_RANDOMX_HASH_H
#define BITCOIN_CRYPTO_RANDOMX_HASH_H

#include <stdint.h>
#include <stdlib.h>

static const size_t RANDOMX_HASH_SIZE = 32;

#ifdef __cplusplus
extern "C" {
#endif

void randomx_hash(const void* input, size_t input_len, void* output,
                  const void* key, size_t key_len);

// LEGACY API: Uses global VM with mutex (serialized access)
// USE CASE: Block verification, tests, and other non-performance-critical operations
// For mining hot loops, use randomx_hash_thread() instead (BUG #28 fix)
void randomx_hash_fast(const void* input, size_t input_len, void* output);

void randomx_init_for_hashing(const void* key, size_t key_len, int light_mode);

void randomx_cleanup();

// Async initialization (Monero-style)
// Returns immediately, initialization happens in background thread
void randomx_init_async(const void* key, size_t key_len, int light_mode);

// Check if RandomX is ready for hashing
int randomx_is_ready();

// Wait for RandomX initialization to complete
void randomx_wait_for_init();

// BUG #28 FIX: Per-Thread RandomX VM API
// Create VM for thread (call once per mining thread)
// Returns: opaque VM pointer, or NULL on failure
void* randomx_create_thread_vm();

// Destroy VM when thread exits (call once per mining thread)
// Parameter: VM pointer returned by randomx_create_thread_vm()
void randomx_destroy_thread_vm(void* vm);

// Hash with thread-local VM (no mutex, fully parallel)
// Parameters:
//   vm: VM pointer from randomx_create_thread_vm()
//   input: data to hash
//   input_len: length of input data
//   output: buffer for hash result (must be 32 bytes)
void randomx_hash_thread(void* vm, const void* input, size_t input_len, void* output);

#ifdef __cplusplus
}
#endif

#endif // BITCOIN_CRYPTO_RANDOMX_HASH_H
