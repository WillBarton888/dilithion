// Test program for passphrase validator
// Copyright (c) 2025 The Dilithion Core developers

#include <wallet/passphrase_validator.h>
#include <iostream>
#include <vector>
#include <string>

struct TestCase {
    std::string passphrase;
    bool should_pass;
    std::string description;
};

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Passphrase Validator Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    PassphraseValidator validator;

    // Test cases
    std::vector<TestCase> test_cases = {
        // Weak passphrases (should fail)
        {"short", false, "Too short (< 12 characters)"},
        {"password", false, "Common password"},
        {"password123", false, "Common password variant"},
        {"123456789012", false, "No uppercase, lowercase, or special chars"},
        {"abcdefghijkl", false, "No uppercase, digits, or special chars"},
        {"ABCDEFGHIJKL", false, "No lowercase, digits, or special chars"},
        {"Welcome123", false, "Common password"},
        {"P@ssw0rd", false, "Too short and common"},

        // Borderline passphrases (should pass but warn)
        {"MyP@ssw0rd12", true, "Minimum length, all character types"},
        {"Weak1234567!", true, "Sequential characters (warned)"},
        {"Aaaa1234567!", true, "Repeating characters (warned)"},

        // Strong passphrases (should pass)
        {"MyStr0ng!P@ss", true, "Good mix of characters"},
        {"C0mpl3x!Passphr@se", true, "Long and complex"},
        {"Qw3rty!Secure#2024", true, "Very strong passphrase"},
        {"!Ungu3ss@ble#P4ss$", true, "Excellent passphrase"},
        {"My$up3r!Secur3#Wallet2024", true, "Very long and strong"}
    };

    int passed = 0;
    int failed = 0;

    for (const auto& test : test_cases) {
        std::cout << "Testing: \"" << test.passphrase << "\"" << std::endl;
        std::cout << "  Expected: " << (test.should_pass ? "PASS" : "FAIL") << std::endl;
        std::cout << "  Description: " << test.description << std::endl;

        PassphraseValidationResult result = validator.Validate(test.passphrase);

        std::cout << "  Result: " << (result.is_valid ? "PASS" : "FAIL") << std::endl;
        std::cout << "  Strength: " << PassphraseValidator::GetStrengthDescription(result.strength_score)
                  << " (" << result.strength_score << "/100)" << std::endl;

        if (!result.is_valid) {
            std::cout << "  Error: " << result.error_message << std::endl;
        }

        if (!result.warnings.empty()) {
            std::cout << "  Warnings:" << std::endl;
            for (const auto& warning : result.warnings) {
                std::cout << "    - " << warning << std::endl;
            }
        }

        // Check if result matches expectation
        bool test_passed = (result.is_valid == test.should_pass);

        if (test_passed) {
            std::cout << "  Status: ✓ TEST PASSED" << std::endl;
            passed++;
        } else {
            std::cout << "  Status: ✗ TEST FAILED (Expected "
                      << (test.should_pass ? "PASS" : "FAIL")
                      << ", got " << (result.is_valid ? "PASS" : "FAIL") << ")" << std::endl;
            failed++;
        }

        std::cout << std::endl;
    }

    std::cout << "========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Total tests: " << (passed + failed) << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << failed << std::endl;
    std::cout << std::endl;

    if (failed == 0) {
        std::cout << "✓ All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "✗ Some tests failed!" << std::endl;
        return 1;
    }
}
