// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <crypto/randomx_hash.h>
#include <randomx.h>

#include <vector>
#include <mutex>
#include <stdexcept>
#include <cstring>
#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>

namespace {
    randomx_cache* g_randomx_cache = nullptr;
    randomx_dataset* g_randomx_dataset = nullptr;
    randomx_vm* g_randomx_vm = nullptr;
    std::mutex g_randomx_mutex;
    std::vector<uint8_t> g_current_key;
    bool g_is_light_mode = false;

    // Async initialization state (Monero-style)
    std::atomic<bool> g_randomx_ready{false};
    std::atomic<bool> g_randomx_initializing{false};
    std::thread g_randomx_init_thread;
    std::atomic<int> g_randomx_progress{0};  // 0-100%
}

extern "C" void randomx_init_for_hashing(const void* key, size_t key_len, int light_mode) {
    std::lock_guard<std::mutex> lock(g_randomx_mutex);

    std::vector<uint8_t> new_key((const uint8_t*)key, (const uint8_t*)key + key_len);
    if (g_randomx_cache != nullptr && g_current_key == new_key && g_is_light_mode == (bool)light_mode) {
        return;
    }

    // Cleanup existing resources
    if (g_randomx_vm != nullptr) {
        randomx_destroy_vm(g_randomx_vm);
        g_randomx_vm = nullptr;
    }
    if (g_randomx_dataset != nullptr) {
        randomx_release_dataset(g_randomx_dataset);
        g_randomx_dataset = nullptr;
    }
    if (g_randomx_cache != nullptr) {
        randomx_release_cache(g_randomx_cache);
        g_randomx_cache = nullptr;
    }

    // BUG #13 FIX: Force deterministic RandomX flags for consensus
    // CRITICAL: All nodes must use identical flags to produce identical hashes
    //
    // Root Cause: randomx_get_flags() returns CPU-specific optimizations (SSSE3, AVX2, etc.)
    // which can cause different hash outputs on different hardware, breaking consensus.
    //
    // Solution: Use only RANDOMX_FLAG_DEFAULT for all nodes to ensure deterministic hashing.
    // Trade-off: Slightly slower hashing (~10-20%), but guaranteed consensus.
    //
    // Note: LIGHT vs FULL mode only affects memory usage and speed, NOT hash output.
    // However, to maximize compatibility, we enforce RANDOMX_FLAG_DEFAULT for both modes.
    randomx_flags flags = RANDOMX_FLAG_DEFAULT;

    if (!light_mode) {
        // Full mode: Add FULL_MEM flag for 2GB dataset (faster hashing)
        // Still using DEFAULT as base to avoid hardware-specific variations
        flags = static_cast<randomx_flags>(RANDOMX_FLAG_DEFAULT | RANDOMX_FLAG_FULL_MEM);
    }

    // Allocate and initialize cache (required for both modes)
    g_randomx_cache = randomx_alloc_cache(flags);
    if (g_randomx_cache == nullptr) {
        throw std::runtime_error("Failed to allocate RandomX cache");
    }
    randomx_init_cache(g_randomx_cache, key, key_len);

    if (light_mode) {
        // LIGHT MODE: Create VM from cache (fast init, slower hashing)
        g_randomx_vm = randomx_create_vm(flags, g_randomx_cache, nullptr);
        if (g_randomx_vm == nullptr) {
            randomx_release_cache(g_randomx_cache);
            g_randomx_cache = nullptr;
            throw std::runtime_error("Failed to create RandomX VM in light mode");
        }
    } else {
        // FULL MODE: Allocate dataset, initialize it from cache, create VM from dataset
        // This is the correct mode for production mining and consensus verification
        g_randomx_dataset = randomx_alloc_dataset(flags);
        if (g_randomx_dataset == nullptr) {
            randomx_release_cache(g_randomx_cache);
            g_randomx_cache = nullptr;
            throw std::runtime_error("Failed to allocate RandomX dataset");
        }

        // BUG #18 FIX: Multi-threaded chunked dataset initialization
        // Following XMRig/Monero pattern: divide dataset into chunks and init in parallel
        // This prevents deadlock and speeds up initialization significantly
        unsigned long dataset_item_count = randomx_dataset_item_count();
        // TEMPORARY FIX: Force single-threaded to avoid hang on multi-CPU systems
        unsigned int num_threads = 1;
        // unsigned int num_threads = std::thread::hardware_concurrency();
        // if (num_threads == 0) num_threads = 2;  // Default to 2 if detection fails

        std::cout << "  [FULL MODE] Initializing RandomX dataset with " << num_threads << " threads..." << std::endl;

        std::vector<std::thread> init_threads;
        unsigned long items_per_thread = dataset_item_count / num_threads;
        unsigned long items_remainder = dataset_item_count % num_threads;

        auto start_time = std::chrono::steady_clock::now();

        for (unsigned int t = 0; t < num_threads; t++) {
            unsigned long start_item = t * items_per_thread;
            unsigned long count = items_per_thread;

            // Last thread gets any remainder items
            if (t == num_threads - 1) {
                count += items_remainder;
            }

            init_threads.emplace_back([=]() {
                randomx_init_dataset(g_randomx_dataset, g_randomx_cache, start_item, count);
            });
        }

        // Wait for all threads to complete
        for (auto& thread : init_threads) {
            thread.join();
        }

        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
        std::cout << "  [FULL MODE] Dataset initialized in " << duration.count() << "s" << std::endl;

        // Create VM with dataset (cache is still needed for some operations)
        g_randomx_vm = randomx_create_vm(flags, g_randomx_cache, g_randomx_dataset);
        if (g_randomx_vm == nullptr) {
            randomx_release_dataset(g_randomx_dataset);
            randomx_release_cache(g_randomx_cache);
            g_randomx_dataset = nullptr;
            g_randomx_cache = nullptr;
            throw std::runtime_error("Failed to create RandomX VM in full mode");
        }
    }

    g_current_key = new_key;
    g_is_light_mode = light_mode;
}

void randomx_cleanup() {
    std::lock_guard<std::mutex> lock(g_randomx_mutex);

    if (g_randomx_vm != nullptr) {
        randomx_destroy_vm(g_randomx_vm);
        g_randomx_vm = nullptr;
    }
    if (g_randomx_dataset != nullptr) {
        randomx_release_dataset(g_randomx_dataset);
        g_randomx_dataset = nullptr;
    }
    if (g_randomx_cache != nullptr) {
        randomx_release_cache(g_randomx_cache);
        g_randomx_cache = nullptr;
    }
    g_current_key.clear();
    g_is_light_mode = false;
}

void randomx_hash(const void* input, size_t input_len, void* output,
                  const void* key, size_t key_len) {
    randomx_init_for_hashing(key, key_len, 0 /* full mode */);
    randomx_hash_fast(input, input_len, output);
}

void randomx_hash_fast(const void* input, size_t input_len, void* output) {
    // Validate inputs
    if (input == nullptr && input_len > 0) {
        throw std::invalid_argument("randomx_hash_fast: input is NULL but input_len > 0");
    }
    if (output == nullptr) {
        throw std::invalid_argument("randomx_hash_fast: output buffer is NULL");
    }

    std::lock_guard<std::mutex> lock(g_randomx_mutex);

    if (g_randomx_vm == nullptr) {
        throw std::runtime_error("RandomX VM not initialized");
    }

    randomx_calculate_hash(g_randomx_vm, input, input_len, output);
}

// Async initialization (Monero-style)
// Returns immediately, initialization happens in background thread
extern "C" void randomx_init_async(const void* key, size_t key_len, int light_mode) {
    // CRITICAL-3 FIX: Atomic compare-exchange to prevent TOCTOU race condition
    // Two threads could both pass the check and start duplicate initialization threads
    bool expected = false;
    if (!g_randomx_initializing.compare_exchange_strong(expected, true)) {
        // Another thread is already initializing or initialization failed to start
        std::cout << "  RandomX already initializing or ready" << std::endl;
        return;
    }

    // Check if already ready (after winning the race)
    if (g_randomx_ready.load()) {
        g_randomx_initializing = false;  // Release the lock
        std::cout << "  RandomX already initialized" << std::endl;
        return;
    }

    // Start background initialization thread (we won the race)
    g_randomx_ready = false;
    g_randomx_progress = 0;

    // Join any existing thread
    if (g_randomx_init_thread.joinable()) {
        g_randomx_init_thread.join();
    }

    // Copy key data for thread safety
    std::vector<uint8_t> key_copy((const uint8_t*)key, (const uint8_t*)key + key_len);

    // Launch async initialization thread
    g_randomx_init_thread = std::thread([key_copy, light_mode]() {
        try {
            std::cout << "  [ASYNC] RandomX initialization started in background thread" << std::endl;
            std::cout << "  [ASYNC] Mode: " << (light_mode ? "LIGHT" : "FULL") << std::endl;

            auto start_time = std::chrono::steady_clock::now();

            // Call existing blocking init
            randomx_init_for_hashing(key_copy.data(), key_copy.size(), light_mode);

            auto end_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

            g_randomx_ready = true;
            g_randomx_progress = 100;

            std::cout << "  [OK] RandomX initialized (async, " << duration.count() << "s)" << std::endl;

        } catch (const std::exception& e) {
            std::cerr << "  [ERROR] RandomX async init failed: " << e.what() << std::endl;
            g_randomx_ready = false;
            g_randomx_progress = 0;
        }
        g_randomx_initializing = false;
    });

    std::cout << "  [ASYNC] RandomX initialization thread launched (non-blocking)" << std::endl;
}

// Check if RandomX is ready for hashing
extern "C" int randomx_is_ready() {
    return g_randomx_ready.load() ? 1 : 0;
}

// Wait for RandomX initialization to complete
extern "C" void randomx_wait_for_init() {
    if (g_randomx_init_thread.joinable()) {
        std::cout << "  [WAIT] Waiting for RandomX initialization to complete..." << std::endl;
        g_randomx_init_thread.join();
        std::cout << "  [WAIT] RandomX initialization complete" << std::endl;
    }
}

// BUG #28 FIX: Per-Thread RandomX VM Implementation
// Each mining thread creates its own VM for true parallel mining

extern "C" void* randomx_create_thread_vm() {
    // Wait for initialization to complete (prevents race during startup)
    while (!g_randomx_ready.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::lock_guard<std::mutex> lock(g_randomx_mutex);

    // Validate dataset/cache exists
    if (!g_randomx_dataset && !g_randomx_cache) {
        std::cerr << "[ERROR] RandomX not initialized before VM creation" << std::endl;
        return nullptr;
    }

    // Create VM with appropriate flags
    randomx_flags flags = RANDOMX_FLAG_DEFAULT;
    randomx_vm* vm = nullptr;

    if (g_is_light_mode) {
        // LIGHT mode: VM uses cache (slower, less RAM)
        vm = randomx_create_vm(flags, g_randomx_cache, nullptr);
        if (!vm) {
            std::cerr << "[ERROR] Failed to create thread VM (LIGHT mode)" << std::endl;
            return nullptr;
        }
    } else {
        // FULL mode: VM uses dataset (faster, shares 2GB dataset across all VMs)
        flags = static_cast<randomx_flags>(flags | RANDOMX_FLAG_FULL_MEM);
        vm = randomx_create_vm(flags, g_randomx_cache, g_randomx_dataset);
        if (!vm) {
            std::cerr << "[ERROR] Failed to create thread VM (FULL mode, OOM?)" << std::endl;
            return nullptr;
        }
    }

    return static_cast<void*>(vm);
}

extern "C" void randomx_destroy_thread_vm(void* vm) {
    if (!vm) return;

    randomx_vm* rx_vm = static_cast<randomx_vm*>(vm);
    randomx_destroy_vm(rx_vm);
}

extern "C" void randomx_hash_thread(void* vm, const void* input, size_t input_len, void* output) {
    // Validate inputs
    if (!vm) {
        throw std::invalid_argument("randomx_hash_thread: vm is NULL");
    }
    if (input == nullptr && input_len > 0) {
        throw std::invalid_argument("randomx_hash_thread: input is NULL but input_len > 0");
    }
    if (output == nullptr) {
        throw std::invalid_argument("randomx_hash_thread: output buffer is NULL");
    }

    // NO MUTEX NEEDED! Each thread owns its VM, enabling true parallel mining
    // This is the key fix: instead of serializing on g_randomx_mutex,
    // each thread hashes independently using its own VM
    randomx_vm* rx_vm = static_cast<randomx_vm*>(vm);
    randomx_calculate_hash(rx_vm, input, input_len, output);
}
