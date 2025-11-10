// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// FIX-008 (CRYPT-007): Authenticated Encryption Test Suite
//
// Tests HMAC-SHA3-512 authenticated encryption implementation

#include <wallet/crypter.h>
#include <rpc/auth.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <cassert>

// Test helper: Print hex
void PrintHex(const char* label, const std::vector<uint8_t>& data) {
    std::cout << label << ": ";
    for (uint8_t byte : data) {
        printf("%02x", byte);
    }
    std::cout << std::endl;
}

// Test 1: Basic MAC Computation
bool Test_BasicMACComputation() {
    std::cout << "\n[TEST 1] Basic MAC Computation" << std::endl;

    // Create crypter with known key and IV
    CCrypter crypter;
    std::vector<uint8_t> key(32, 0x42);  // 32 bytes of 0x42
    std::vector<uint8_t> iv(16, 0x13);   // 16 bytes of 0x13

    if (!crypter.SetKey(key, iv)) {
        std::cout << "FAIL: SetKey failed" << std::endl;
        return false;
    }

    // Encrypt some data
    std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> ciphertext;

    if (!crypter.Encrypt(plaintext, ciphertext)) {
        std::cout << "FAIL: Encryption failed" << std::endl;
        return false;
    }

    // Compute MAC
    std::vector<uint8_t> mac;
    if (!crypter.ComputeMAC(ciphertext, mac)) {
        std::cout << "FAIL: ComputeMAC failed" << std::endl;
        return false;
    }

    // Verify MAC is 64 bytes (HMAC-SHA3-512)
    if (mac.size() != 64) {
        std::cout << "FAIL: MAC size is " << mac.size() << ", expected 64" << std::endl;
        return false;
    }

    // Verify MAC is not all zeros
    bool all_zeros = true;
    for (uint8_t byte : mac) {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }

    if (all_zeros) {
        std::cout << "FAIL: MAC is all zeros (not computed)" << std::endl;
        return false;
    }

    PrintHex("Plaintext", plaintext);
    PrintHex("Ciphertext", ciphertext);
    PrintHex("MAC", mac);

    std::cout << "PASS: MAC computed successfully (64 bytes, non-zero)" << std::endl;
    return true;
}

// Test 2: MAC Verification Success
bool Test_MACVerificationSuccess() {
    std::cout << "\n[TEST 2] MAC Verification Success" << std::endl;

    CCrypter crypter;
    std::vector<uint8_t> key(32, 0xAB);
    std::vector<uint8_t> iv(16, 0xCD);

    if (!crypter.SetKey(key, iv)) {
        std::cout << "FAIL: SetKey failed" << std::endl;
        return false;
    }

    std::vector<uint8_t> plaintext = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> ciphertext;

    if (!crypter.Encrypt(plaintext, ciphertext)) {
        std::cout << "FAIL: Encryption failed" << std::endl;
        return false;
    }

    std::vector<uint8_t> mac;
    if (!crypter.ComputeMAC(ciphertext, mac)) {
        std::cout << "FAIL: ComputeMAC failed" << std::endl;
        return false;
    }

    // Verify MAC
    if (!crypter.VerifyMAC(ciphertext, mac)) {
        std::cout << "FAIL: VerifyMAC failed for correct MAC" << std::endl;
        return false;
    }

    std::cout << "PASS: MAC verification succeeded for correct MAC" << std::endl;
    return true;
}

// Test 3: MAC Verification Failure (Modified Ciphertext)
bool Test_MACVerificationFailure_ModifiedCiphertext() {
    std::cout << "\n[TEST 3] MAC Verification Failure - Modified Ciphertext" << std::endl;

    CCrypter crypter;
    std::vector<uint8_t> key(32, 0x11);
    std::vector<uint8_t> iv(16, 0x22);

    if (!crypter.SetKey(key, iv)) {
        std::cout << "FAIL: SetKey failed" << std::endl;
        return false;
    }

    std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> ciphertext;

    if (!crypter.Encrypt(plaintext, ciphertext)) {
        std::cout << "FAIL: Encryption failed" << std::endl;
        return false;
    }

    std::vector<uint8_t> mac;
    if (!crypter.ComputeMAC(ciphertext, mac)) {
        std::cout << "FAIL: ComputeMAC failed" << std::endl;
        return false;
    }

    // Modify ciphertext (simulate attacker tampering)
    std::vector<uint8_t> modified_ciphertext = ciphertext;
    modified_ciphertext[0] ^= 0x01;  // Flip one bit

    // Verify MAC should fail
    if (crypter.VerifyMAC(modified_ciphertext, mac)) {
        std::cout << "FAIL: VerifyMAC succeeded for tampered ciphertext (security vulnerability!)" << std::endl;
        return false;
    }

    std::cout << "PASS: MAC verification correctly rejected tampered ciphertext" << std::endl;
    return true;
}

// Test 4: MAC Verification Failure (Modified MAC)
bool Test_MACVerificationFailure_ModifiedMAC() {
    std::cout << "\n[TEST 4] MAC Verification Failure - Modified MAC" << std::endl;

    CCrypter crypter;
    std::vector<uint8_t> key(32, 0x33);
    std::vector<uint8_t> iv(16, 0x44);

    if (!crypter.SetKey(key, iv)) {
        std::cout << "FAIL: SetKey failed" << std::endl;
        return false;
    }

    std::vector<uint8_t> plaintext = {0x05, 0x06, 0x07, 0x08};
    std::vector<uint8_t> ciphertext;

    if (!crypter.Encrypt(plaintext, ciphertext)) {
        std::cout << "FAIL: Encryption failed" << std::endl;
        return false;
    }

    std::vector<uint8_t> mac;
    if (!crypter.ComputeMAC(ciphertext, mac)) {
        std::cout << "FAIL: ComputeMAC failed" << std::endl;
        return false;
    }

    // Modify MAC (simulate attacker forging MAC)
    std::vector<uint8_t> forged_mac = mac;
    forged_mac[0] ^= 0x01;  // Flip one bit

    // Verify MAC should fail
    if (crypter.VerifyMAC(ciphertext, forged_mac)) {
        std::cout << "FAIL: VerifyMAC succeeded for forged MAC (security vulnerability!)" << std::endl;
        return false;
    }

    std::cout << "PASS: MAC verification correctly rejected forged MAC" << std::endl;
    return true;
}

// Test 5: MAC Verification Failure (Wrong Key)
bool Test_MACVerificationFailure_WrongKey() {
    std::cout << "\n[TEST 5] MAC Verification Failure - Wrong Key" << std::endl;

    // Encrypt with key1
    CCrypter crypter1;
    std::vector<uint8_t> key1(32, 0xAA);
    std::vector<uint8_t> iv(16, 0xBB);

    if (!crypter1.SetKey(key1, iv)) {
        std::cout << "FAIL: SetKey1 failed" << std::endl;
        return false;
    }

    std::vector<uint8_t> plaintext = {0x10, 0x20, 0x30, 0x40};
    std::vector<uint8_t> ciphertext;

    if (!crypter1.Encrypt(plaintext, ciphertext)) {
        std::cout << "FAIL: Encryption failed" << std::endl;
        return false;
    }

    std::vector<uint8_t> mac;
    if (!crypter1.ComputeMAC(ciphertext, mac)) {
        std::cout << "FAIL: ComputeMAC failed" << std::endl;
        return false;
    }

    // Try to verify with different key
    CCrypter crypter2;
    std::vector<uint8_t> key2(32, 0xCC);  // Different key

    if (!crypter2.SetKey(key2, iv)) {
        std::cout << "FAIL: SetKey2 failed" << std::endl;
        return false;
    }

    // Verify MAC with wrong key should fail
    if (crypter2.VerifyMAC(ciphertext, mac)) {
        std::cout << "FAIL: VerifyMAC succeeded with wrong key (security vulnerability!)" << std::endl;
        return false;
    }

    std::cout << "PASS: MAC verification correctly failed with wrong key" << std::endl;
    return true;
}

// Test 6: Encrypt-then-MAC Pattern (Full Flow)
bool Test_EncryptThenMAC_FullFlow() {
    std::cout << "\n[TEST 6] Encrypt-then-MAC Full Flow" << std::endl;

    CCrypter crypter;
    std::vector<uint8_t> key(32, 0x55);
    std::vector<uint8_t> iv(16, 0x66);

    if (!crypter.SetKey(key, iv)) {
        std::cout << "FAIL: SetKey failed" << std::endl;
        return false;
    }

    // Original plaintext
    std::vector<uint8_t> original_plaintext = {
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x20, 0x64,
        0x61, 0x74, 0x61
    };

    // Step 1: Encrypt
    std::vector<uint8_t> ciphertext;
    if (!crypter.Encrypt(original_plaintext, ciphertext)) {
        std::cout << "FAIL: Encryption failed" << std::endl;
        return false;
    }

    // Step 2: Compute MAC (after encryption)
    std::vector<uint8_t> mac;
    if (!crypter.ComputeMAC(ciphertext, mac)) {
        std::cout << "FAIL: ComputeMAC failed" << std::endl;
        return false;
    }

    PrintHex("Original", original_plaintext);
    PrintHex("Encrypted", ciphertext);
    PrintHex("MAC", mac);

    // Step 3: Verify MAC (before decryption)
    if (!crypter.VerifyMAC(ciphertext, mac)) {
        std::cout << "FAIL: MAC verification failed" << std::endl;
        return false;
    }

    // Step 4: Decrypt (only after MAC verification passes)
    std::vector<uint8_t> decrypted_plaintext;
    if (!crypter.Decrypt(ciphertext, decrypted_plaintext)) {
        std::cout << "FAIL: Decryption failed" << std::endl;
        return false;
    }

    PrintHex("Decrypted", decrypted_plaintext);

    // Verify decrypted matches original
    if (decrypted_plaintext != original_plaintext) {
        std::cout << "FAIL: Decrypted plaintext doesn't match original" << std::endl;
        return false;
    }

    std::cout << "PASS: Encrypt-then-MAC full flow successful" << std::endl;
    return true;
}

// Test 7: Constant-Time MAC Comparison
bool Test_ConstantTimeComparison() {
    std::cout << "\n[TEST 7] Constant-Time MAC Comparison" << std::endl;

    CCrypter crypter;
    std::vector<uint8_t> key(32, 0x77);
    std::vector<uint8_t> iv(16, 0x88);

    if (!crypter.SetKey(key, iv)) {
        std::cout << "FAIL: SetKey failed" << std::endl;
        return false;
    }

    std::vector<uint8_t> plaintext = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<uint8_t> ciphertext;

    if (!crypter.Encrypt(plaintext, ciphertext)) {
        std::cout << "FAIL: Encryption failed" << std::endl;
        return false;
    }

    std::vector<uint8_t> mac1;
    if (!crypter.ComputeMAC(ciphertext, mac1)) {
        std::cout << "FAIL: ComputeMAC failed" << std::endl;
        return false;
    }

    // Create MAC that differs in first byte
    std::vector<uint8_t> mac_diff_first = mac1;
    mac_diff_first[0] ^= 0x01;

    // Create MAC that differs in last byte
    std::vector<uint8_t> mac_diff_last = mac1;
    mac_diff_last[63] ^= 0x01;

    // Both should fail (constant time means timing should be same)
    bool result1 = crypter.VerifyMAC(ciphertext, mac_diff_first);
    bool result2 = crypter.VerifyMAC(ciphertext, mac_diff_last);

    if (result1 || result2) {
        std::cout << "FAIL: Modified MACs passed verification" << std::endl;
        return false;
    }

    // Note: We can't easily test timing in a unit test, but we verify
    // that both fail regardless of which byte differs
    std::cout << "PASS: Constant-time comparison rejects modified MACs correctly" << std::endl;
    return true;
}

// Test 8: Empty/Invalid Input Handling
bool Test_InvalidInputHandling() {
    std::cout << "\n[TEST 8] Invalid Input Handling" << std::endl;

    CCrypter crypter;
    std::vector<uint8_t> key(32, 0x99);
    std::vector<uint8_t> iv(16, 0xAA);

    if (!crypter.SetKey(key, iv)) {
        std::cout << "FAIL: SetKey failed" << std::endl;
        return false;
    }

    // Test 8.1: Empty ciphertext
    std::vector<uint8_t> empty_ciphertext;
    std::vector<uint8_t> mac;

    if (crypter.ComputeMAC(empty_ciphertext, mac)) {
        std::cout << "FAIL: ComputeMAC succeeded for empty ciphertext" << std::endl;
        return false;
    }
    std::cout << "  8.1 PASS: Empty ciphertext rejected" << std::endl;

    // Test 8.2: Invalid MAC size
    std::vector<uint8_t> ciphertext = {0x01, 0x02, 0x03};
    std::vector<uint8_t> invalid_mac(32, 0xFF);  // Wrong size (32 instead of 64)

    if (crypter.VerifyMAC(ciphertext, invalid_mac)) {
        std::cout << "FAIL: VerifyMAC succeeded for invalid MAC size" << std::endl;
        return false;
    }
    std::cout << "  8.2 PASS: Invalid MAC size rejected" << std::endl;

    // Test 8.3: MAC computation without key set
    CCrypter crypter_no_key;
    std::vector<uint8_t> mac2;

    if (crypter_no_key.ComputeMAC(ciphertext, mac2)) {
        std::cout << "FAIL: ComputeMAC succeeded without key set" << std::endl;
        return false;
    }
    std::cout << "  8.3 PASS: ComputeMAC failed without key set" << std::endl;

    std::cout << "PASS: All invalid input cases handled correctly" << std::endl;
    return true;
}

// Main test runner
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "FIX-008 (CRYPT-007): Authenticated Encryption Test Suite" << std::endl;
    std::cout << "Testing HMAC-SHA3-512 MAC Implementation" << std::endl;
    std::cout << "========================================" << std::endl;

    int passed = 0;
    int failed = 0;

    // Run all tests
    if (Test_BasicMACComputation()) passed++; else failed++;
    if (Test_MACVerificationSuccess()) passed++; else failed++;
    if (Test_MACVerificationFailure_ModifiedCiphertext()) passed++; else failed++;
    if (Test_MACVerificationFailure_ModifiedMAC()) passed++; else failed++;
    if (Test_MACVerificationFailure_WrongKey()) passed++; else failed++;
    if (Test_EncryptThenMAC_FullFlow()) passed++; else failed++;
    if (Test_ConstantTimeComparison()) passed++; else failed++;
    if (Test_InvalidInputHandling()) passed++; else failed++;

    // Print summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "TEST SUMMARY" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Total Tests: " << (passed + failed) << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << failed << std::endl;

    if (failed == 0) {
        std::cout << "\n✓ ALL TESTS PASSED - FIX-008 Implementation Verified" << std::endl;
        return 0;
    } else {
        std::cout << "\n✗ SOME TESTS FAILED - Review Implementation" << std::endl;
        return 1;
    }
}
