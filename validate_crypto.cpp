// Quick validation of HMAC-SHA3-512 and PBKDF2-SHA3-512 implementations
// Verifies core functionality without requiring Boost Test framework

#include "src/crypto/hmac_sha3.h"
#include "src/crypto/pbkdf2_sha3.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>

// Helper to print hex
void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

bool test_hmac_basic() {
    std::cout << "\n=== Test 1: HMAC-SHA3-512 Basic Operation ===" << std::endl;

    // Test vector from RFC 2104 adapted for SHA3
    const uint8_t key[] = "test key";
    const uint8_t data[] = "test data";
    uint8_t output1[64], output2[64];

    // Compute HMAC twice
    HMAC_SHA3_512(key, sizeof(key) - 1, data, sizeof(data) - 1, output1);
    HMAC_SHA3_512(key, sizeof(key) - 1, data, sizeof(data) - 1, output2);

    // Check determinism
    if (std::memcmp(output1, output2, 64) != 0) {
        std::cout << "FAIL: HMAC not deterministic!" << std::endl;
        return false;
    }

    // Check output is not all zeros
    bool all_zeros = true;
    for (int i = 0; i < 64; i++) {
        if (output1[i] != 0) {
            all_zeros = false;
            break;
        }
    }

    if (all_zeros) {
        std::cout << "FAIL: HMAC output is all zeros!" << std::endl;
        return false;
    }

    print_hex("HMAC", output1, 32);  // Print first 32 bytes
    std::cout << "PASS: HMAC is deterministic and produces non-zero output" << std::endl;
    return true;
}

bool test_hmac_different_keys() {
    std::cout << "\n=== Test 2: HMAC Different Keys Produce Different Outputs ===" << std::endl;

    const uint8_t key1[] = "key1";
    const uint8_t key2[] = "key2";
    const uint8_t data[] = "same data";
    uint8_t output1[64], output2[64];

    HMAC_SHA3_512(key1, sizeof(key1) - 1, data, sizeof(data) - 1, output1);
    HMAC_SHA3_512(key2, sizeof(key2) - 1, data, sizeof(data) - 1, output2);

    if (std::memcmp(output1, output2, 64) == 0) {
        std::cout << "FAIL: Different keys produced same output!" << std::endl;
        return false;
    }

    std::cout << "PASS: Different keys produce different outputs" << std::endl;
    return true;
}

bool test_hmac_long_key() {
    std::cout << "\n=== Test 3: HMAC with Long Key (>72 bytes) ===" << std::endl;

    // Key longer than SHA3-512 block size (72 bytes)
    uint8_t key[100];
    std::memset(key, 0xAA, sizeof(key));

    const uint8_t data[] = "test data";
    uint8_t output[64];

    try {
        HMAC_SHA3_512(key, sizeof(key), data, sizeof(data) - 1, output);

        // Check output is not all zeros
        bool all_zeros = true;
        for (int i = 0; i < 64; i++) {
            if (output[i] != 0) {
                all_zeros = false;
                break;
            }
        }

        if (all_zeros) {
            std::cout << "FAIL: Long key produced all-zero output!" << std::endl;
            return false;
        }

        std::cout << "PASS: Long key handled correctly" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cout << "FAIL: Exception thrown: " << e.what() << std::endl;
        return false;
    }
}

bool test_hmac_input_validation() {
    std::cout << "\n=== Test 4: HMAC Input Validation ===" << std::endl;

    const uint8_t key[] = "key";
    const uint8_t data[] = "data";
    uint8_t output[64];

    // Test NULL output buffer
    bool caught_exception = false;
    try {
        HMAC_SHA3_512(key, sizeof(key) - 1, data, sizeof(data) - 1, nullptr);
    } catch (const std::invalid_argument&) {
        caught_exception = true;
    }

    if (!caught_exception) {
        std::cout << "FAIL: NULL output buffer not rejected!" << std::endl;
        return false;
    }

    // Test NULL key with non-zero length
    caught_exception = false;
    try {
        HMAC_SHA3_512(nullptr, 10, data, sizeof(data) - 1, output);
    } catch (const std::invalid_argument&) {
        caught_exception = true;
    }

    if (!caught_exception) {
        std::cout << "FAIL: NULL key with non-zero length not rejected!" << std::endl;
        return false;
    }

    std::cout << "PASS: Input validation working correctly" << std::endl;
    return true;
}

bool test_pbkdf2_basic() {
    std::cout << "\n=== Test 5: PBKDF2-SHA3-512 Basic Operation ===" << std::endl;

    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 2048;
    uint8_t output1[64], output2[64];

    // Derive key twice
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1,
                    iterations, output1, 64);
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1,
                    iterations, output2, 64);

    // Check determinism (CRITICAL for HD wallets)
    if (std::memcmp(output1, output2, 64) != 0) {
        std::cout << "FAIL: PBKDF2 not deterministic - CATASTROPHIC for wallets!" << std::endl;
        return false;
    }

    // Check output is not all zeros
    bool all_zeros = true;
    for (int i = 0; i < 64; i++) {
        if (output1[i] != 0) {
            all_zeros = false;
            break;
        }
    }

    if (all_zeros) {
        std::cout << "FAIL: PBKDF2 output is all zeros!" << std::endl;
        return false;
    }

    print_hex("PBKDF2 (2048 iter)", output1, 32);
    std::cout << "PASS: PBKDF2 is deterministic with 2048 iterations" << std::endl;
    return true;
}

bool test_pbkdf2_iteration_effect() {
    std::cout << "\n=== Test 6: PBKDF2 Different Iterations ===" << std::endl;

    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    uint8_t output1[64], output2[64];

    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, 1, output1, 64);
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, 2, output2, 64);

    if (std::memcmp(output1, output2, 64) == 0) {
        std::cout << "FAIL: Different iteration counts produced same output!" << std::endl;
        return false;
    }

    std::cout << "PASS: Different iteration counts produce different outputs" << std::endl;
    return true;
}

bool test_pbkdf2_input_validation() {
    std::cout << "\n=== Test 7: PBKDF2 Input Validation ===" << std::endl;

    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    uint8_t output[64];

    // Test zero iterations
    bool caught_exception = false;
    try {
        PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1,
                        0, output, 64);
    } catch (const std::invalid_argument&) {
        caught_exception = true;
    }

    if (!caught_exception) {
        std::cout << "FAIL: Zero iterations not rejected!" << std::endl;
        return false;
    }

    // Test NULL output
    caught_exception = false;
    try {
        PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1,
                        1, nullptr, 64);
    } catch (const std::invalid_argument&) {
        caught_exception = true;
    }

    if (!caught_exception) {
        std::cout << "FAIL: NULL output not rejected!" << std::endl;
        return false;
    }

    std::cout << "PASS: PBKDF2 input validation working correctly" << std::endl;
    return true;
}

bool test_bip39_mnemonic_to_seed() {
    std::cout << "\n=== Test 8: BIP39 MnemonicToSeed Function ===" << std::endl;

    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* passphrase = "";
    uint8_t seed1[64], seed2[64];

    // Generate seed twice
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic),
                         passphrase, std::strlen(passphrase), seed1);
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic),
                         passphrase, std::strlen(passphrase), seed2);

    // Check determinism
    if (std::memcmp(seed1, seed2, 64) != 0) {
        std::cout << "FAIL: BIP39 seed derivation not deterministic!" << std::endl;
        return false;
    }

    // Test with different passphrase
    const char* passphrase2 = "TREZOR";
    uint8_t seed3[64];
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic),
                         passphrase2, std::strlen(passphrase2), seed3);

    if (std::memcmp(seed1, seed3, 64) == 0) {
        std::cout << "FAIL: Different passphrases produced same seed!" << std::endl;
        return false;
    }

    print_hex("BIP39 Seed", seed1, 32);
    std::cout << "PASS: BIP39 seed derivation working correctly" << std::endl;
    return true;
}

int main() {
    std::cout << "======================================" << std::endl;
    std::cout << "Dilithion Cryptography Validation" << std::endl;
    std::cout << "HMAC-SHA3-512 & PBKDF2-SHA3-512 Tests" << std::endl;
    std::cout << "======================================" << std::endl;

    int passed = 0, failed = 0;

    // Run all tests
    if (test_hmac_basic()) passed++; else failed++;
    if (test_hmac_different_keys()) passed++; else failed++;
    if (test_hmac_long_key()) passed++; else failed++;
    if (test_hmac_input_validation()) passed++; else failed++;
    if (test_pbkdf2_basic()) passed++; else failed++;
    if (test_pbkdf2_iteration_effect()) passed++; else failed++;
    if (test_pbkdf2_input_validation()) passed++; else failed++;
    if (test_bip39_mnemonic_to_seed()) passed++; else failed++;

    std::cout << "\n======================================" << std::endl;
    std::cout << "Test Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "======================================" << std::endl;

    if (failed == 0) {
        std::cout << "\n✓ All cryptography validation tests PASSED" << std::endl;
        std::cout << "\nNote: Comprehensive test suites exist:" << std::endl;
        std::cout << "  - src/test/hmac_sha3_tests.cpp (25 test cases)" << std::endl;
        std::cout << "  - src/test/pbkdf2_tests.cpp (32 test cases)" << std::endl;
        std::cout << "  These require Boost Test framework to run." << std::endl;
        return 0;
    } else {
        std::cout << "\n✗ CRITICAL FAILURES DETECTED" << std::endl;
        return 1;
    }
}
