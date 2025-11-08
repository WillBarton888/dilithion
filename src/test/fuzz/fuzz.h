// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_TEST_FUZZ_FUZZ_H
#define DILITHION_TEST_FUZZ_FUZZ_H

#include <cstddef>
#include <cstdint>
#include <vector>

/**
 * Fuzz Testing Infrastructure for Dilithion
 *
 * Based on Bitcoin Core's libFuzzer integration patterns.
 * Each fuzz target tests a specific component for crashes,
 * undefined behavior, and logic errors.
 */

/**
 * FUZZ_TARGET macro - Define a fuzz harness entry point
 *
 * Usage:
 *   FUZZ_TARGET(my_component)
 *   {
 *       // Fuzz logic here using buffer
 *   }
 *
 * The fuzzer will call this function repeatedly with different inputs.
 */
#define FUZZ_TARGET(name) \
    void fuzz_target_##name(const uint8_t* data, size_t size); \
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) { \
        fuzz_target_##name(data, size); \
        return 0; \
    } \
    void fuzz_target_##name(const uint8_t* data, size_t size)

/**
 * Buffer wrapper for fuzz input data
 */
struct FuzzBuffer {
    const uint8_t* data;
    size_t size;

    FuzzBuffer(const uint8_t* d, size_t s) : data(d), size(s) {}

    std::vector<uint8_t> toVector() const {
        return std::vector<uint8_t>(data, data + size);
    }
};

/**
 * Initialize fuzz testing environment
 * Should be called at the start of each fuzz target
 */
inline void InitializeFuzzEnvironment() {
    // Deterministic behavior for reproducibility
    // Set any global state needed for fuzzing
}

/**
 * Clean up fuzz testing environment
 * Should be called at the end of each fuzz target if needed
 */
inline void CleanupFuzzEnvironment() {
    // Reset any modified global state
}

#endif // DILITHION_TEST_FUZZ_FUZZ_H
