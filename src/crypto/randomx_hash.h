// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef BITCOIN_CRYPTO_RANDOMX_HASH_H
#define BITCOIN_CRYPTO_RANDOMX_HASH_H

#include <stdint.h>
#include <stdlib.h>

static const size_t RANDOMX_HASH_SIZE = 32;

void randomx_hash(const void* input, size_t input_len, void* output,
                  const void* key, size_t key_len);

void randomx_hash_fast(const void* input, size_t input_len, void* output);

void randomx_init_cache(const void* key, size_t key_len, bool light_mode = false);

void randomx_cleanup();

#endif // BITCOIN_CRYPTO_RANDOMX_HASH_H
