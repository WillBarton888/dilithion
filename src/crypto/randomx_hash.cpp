// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <crypto/randomx_hash.h>
#include <randomx.h>

#include <vector>
#include <mutex>
#include <stdexcept>

namespace {
    randomx_cache* g_randomx_cache = nullptr;
    randomx_vm* g_randomx_vm = nullptr;
    std::mutex g_randomx_mutex;
    std::vector<uint8_t> g_current_key;
}

void randomx_init_cache(const void* key, size_t key_len) {
    std::lock_guard<std::mutex> lock(g_randomx_mutex);

    std::vector<uint8_t> new_key((const uint8_t*)key, (const uint8_t*)key + key_len);
    if (g_randomx_cache != nullptr && g_current_key == new_key) {
        return;
    }

    if (g_randomx_vm != nullptr) {
        randomx_destroy_vm(g_randomx_vm);
        g_randomx_vm = nullptr;
    }
    if (g_randomx_cache != nullptr) {
        randomx_release_cache(g_randomx_cache);
        g_randomx_cache = nullptr;
    }

    randomx_flags flags = randomx_get_flags();
    g_randomx_cache = randomx_alloc_cache(flags);
    if (g_randomx_cache == nullptr) {
        throw std::runtime_error("Failed to allocate RandomX cache");
    }

    randomx_init_cache(g_randomx_cache, key, key_len);

    g_randomx_vm = randomx_create_vm(flags, g_randomx_cache, nullptr);
    if (g_randomx_vm == nullptr) {
        randomx_release_cache(g_randomx_cache);
        g_randomx_cache = nullptr;
        throw std::runtime_error("Failed to create RandomX VM");
    }

    g_current_key = new_key;
}

void randomx_cleanup() {
    std::lock_guard<std::mutex> lock(g_randomx_mutex);

    if (g_randomx_vm != nullptr) {
        randomx_destroy_vm(g_randomx_vm);
        g_randomx_vm = nullptr;
    }
    if (g_randomx_cache != nullptr) {
        randomx_release_cache(g_randomx_cache);
        g_randomx_cache = nullptr;
    }
    g_current_key.clear();
}

void randomx_hash(const void* input, size_t input_len, void* output,
                  const void* key, size_t key_len) {
    randomx_init_cache(key, key_len);
    randomx_hash_fast(input, input_len, output);
}

void randomx_hash_fast(const void* input, size_t input_len, void* output) {
    std::lock_guard<std::mutex> lock(g_randomx_mutex);

    if (g_randomx_vm == nullptr) {
        throw std::runtime_error("RandomX VM not initialized");
    }

    randomx_calculate_hash(g_randomx_vm, input, input_len, output);
}
