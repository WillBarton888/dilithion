// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * RandomX Mode Verification Test
 *
 * This test verifies that LIGHT mode and FULL mode produce identical hashes.
 * This is CRITICAL for consensus - if they produce different hashes, the
 * network will fork between nodes using different modes.
 */

#include <crypto/randomx_hash.h>
#include <iostream>
#include <iomanip>
#include <cstring>

void print_hash(const char* label, const uint8_t* hash) {
    std::cout << label << ": ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "======================================" << std::endl;
    std::cout << "RandomX Mode Verification Test" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;

    const char* key = "Dilithion-RandomX-v1";
    const char* input = "test block header data";

    uint8_t hash_light[32];
    uint8_t hash_full[32];

    // Test 1: Hash with LIGHT mode
    std::cout << "Test 1: Hashing with LIGHT mode..." << std::endl;
    randomx_init_for_hashing(key, strlen(key), 1);  // light_mode=1
    randomx_hash_fast(input, strlen(input), hash_light);
    print_hash("LIGHT mode hash", hash_light);
    std::cout << std::endl;

    // Test 2: Hash with FULL mode
    std::cout << "Test 2: Hashing with FULL mode..." << std::endl;
    randomx_init_for_hashing(key, strlen(key), 0);  // light_mode=0 (FULL mode)
    randomx_hash_fast(input, strlen(input), hash_full);
    print_hash("FULL mode hash", hash_full);
    std::cout << std::endl;

    // Compare hashes
    std::cout << "======================================" << std::endl;
    if (memcmp(hash_light, hash_full, 32) == 0) {
        std::cout << "✓ SUCCESS: LIGHT and FULL modes produce IDENTICAL hashes" << std::endl;
        std::cout << "  This is correct behavior - consensus will work across nodes" << std::endl;
        std::cout << std::endl;

        std::cout << "Implications:" << std::endl;
        std::cout << "  - 2GB nodes can use LIGHT mode (~256MB RAM, slower hashing)" << std::endl;
        std::cout << "  - 4GB+ nodes can use FULL mode (~2GB RAM, faster hashing)" << std::endl;
        std::cout << "  - All nodes will agree on block validity" << std::endl;
        std::cout << "  - External miners can use either mode" << std::endl;

        return 0;
    } else {
        std::cout << "✗ FAILURE: LIGHT and FULL modes produce DIFFERENT hashes!" << std::endl;
        std::cout << "  This breaks consensus - nodes will reject each other's blocks" << std::endl;
        std::cout << std::endl;

        std::cout << "Required action:" << std::endl;
        std::cout << "  - ALL nodes must use the same mode" << std::endl;
        std::cout << "  - Either all LIGHT (2GB compatible) or all FULL (4GB+ required)" << std::endl;
        std::cout << "  - Cannot mix modes on the network" << std::endl;

        return 1;
    }
}
