// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * DFMP v2.0 Mining Identity Key (MIK) Unit Tests
 *
 * Tests:
 * 1. MIK generation (Dilithium3 keypair)
 * 2. MIK signing and verification
 * 3. Identity derivation from pubkey
 * 4. ScriptSig building and parsing
 * 5. Maturity penalty calculation
 * 6. Heat penalty calculation
 * 7. Total multiplier calculation
 */

#include <dfmp/mik.h>
#include <dfmp/dfmp.h>
#include <uint256.h>

#include <iostream>
#include <vector>
#include <string>
#include <cmath>

// ANSI color codes
#define RESET   "\033[0m"
#define GREEN   "\033[32m"
#define RED     "\033[31m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"

// Test result tracking
int g_tests_passed = 0;
int g_tests_failed = 0;

// Helper macros
#define TEST(name) \
    void test_##name(); \
    void test_##name##_wrapper() { \
        std::cout << BLUE << "[TEST] " << #name << RESET << std::endl; \
        try { \
            test_##name(); \
            std::cout << GREEN << "  PASSED" << RESET << std::endl; \
            g_tests_passed++; \
        } catch (const std::exception& e) { \
            std::cout << RED << "  FAILED: " << e.what() << RESET << std::endl; \
            g_tests_failed++; \
        } catch (...) { \
            std::cout << RED << "  FAILED: Unknown exception" << RESET << std::endl; \
            g_tests_failed++; \
        } \
    } \
    void test_##name()

#define ASSERT(condition, message) \
    if (!(condition)) { \
        throw std::runtime_error(message); \
    }

#define ASSERT_EQ(a, b, message) \
    if ((a) != (b)) { \
        throw std::runtime_error(std::string(message) + " (expected " + std::to_string(b) + ", got " + std::to_string(a) + ")"); \
    }

#define ASSERT_NEAR(a, b, epsilon, message) \
    if (std::abs((a) - (b)) > (epsilon)) { \
        throw std::runtime_error(std::string(message) + " (expected ~" + std::to_string(b) + ", got " + std::to_string(a) + ")"); \
    }

// =======================================================================
// Test 1: MIK Generation
// =======================================================================
TEST(mik_generation) {
    DFMP::CMiningIdentityKey mik;

    // Initially should be invalid
    ASSERT(!mik.IsValid(), "New MIK should be invalid");
    ASSERT(!mik.HasPrivateKey(), "New MIK should not have private key");

    // Generate keypair
    bool generated = mik.Generate();
    ASSERT(generated, "MIK generation should succeed");

    // Should now be valid
    ASSERT(mik.IsValid(), "Generated MIK should be valid");
    ASSERT(mik.HasPrivateKey(), "Generated MIK should have private key");

    // Check key sizes
    ASSERT_EQ(mik.pubkey.size(), DFMP::MIK_PUBKEY_SIZE, "Pubkey size incorrect");
    ASSERT_EQ(mik.privkey.size(), DFMP::MIK_PRIVKEY_SIZE, "Privkey size incorrect");

    // Identity should be derived
    ASSERT(!mik.identity.IsNull(), "Identity should not be null");

    std::cout << "    Generated MIK identity: " << mik.GetIdentityHex() << std::endl;
    std::cout << "    Pubkey size: " << mik.pubkey.size() << " bytes" << std::endl;
    std::cout << "    Privkey size: " << mik.privkey.size() << " bytes" << std::endl;
}

// =======================================================================
// Test 2: MIK Signing and Verification
// =======================================================================
TEST(mik_sign_verify) {
    DFMP::CMiningIdentityKey mik;
    ASSERT(mik.Generate(), "MIK generation failed");

    // Create test message parameters
    uint256 prevHash;
    prevHash.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    int height = 12345;
    uint32_t timestamp = 1700000000;

    // Sign
    std::vector<uint8_t> signature;
    bool signed_ok = mik.Sign(prevHash, height, timestamp, signature);
    ASSERT(signed_ok, "Signing should succeed");
    ASSERT_EQ(signature.size(), DFMP::MIK_SIGNATURE_SIZE, "Signature size incorrect");

    // Verify with correct parameters
    bool verified = DFMP::VerifyMIKSignature(
        mik.pubkey, signature, prevHash, height, timestamp, mik.identity);
    ASSERT(verified, "Verification should succeed with correct parameters");

    // Verify with wrong height should fail
    bool wrong_height = DFMP::VerifyMIKSignature(
        mik.pubkey, signature, prevHash, height + 1, timestamp, mik.identity);
    ASSERT(!wrong_height, "Verification should fail with wrong height");

    // Verify with wrong timestamp should fail
    bool wrong_time = DFMP::VerifyMIKSignature(
        mik.pubkey, signature, prevHash, height, timestamp + 1, mik.identity);
    ASSERT(!wrong_time, "Verification should fail with wrong timestamp");

    // Verify with wrong prevHash should fail
    uint256 wrongHash;
    wrongHash.SetHex("0000000000000000000000000000000000000000000000000000000000000002");
    bool wrong_hash = DFMP::VerifyMIKSignature(
        mik.pubkey, signature, wrongHash, height, timestamp, mik.identity);
    ASSERT(!wrong_hash, "Verification should fail with wrong prevHash");

    std::cout << "    Signature size: " << signature.size() << " bytes" << std::endl;
    std::cout << "    Verification tests passed" << std::endl;
}

// =======================================================================
// Test 3: Identity Derivation
// =======================================================================
TEST(identity_derivation) {
    DFMP::CMiningIdentityKey mik;
    ASSERT(mik.Generate(), "MIK generation failed");

    // Derive identity from pubkey
    DFMP::Identity derived = DFMP::DeriveIdentityFromMIK(mik.pubkey);

    // Should match the stored identity
    ASSERT(derived == mik.identity, "Derived identity should match stored identity");
    ASSERT(!derived.IsNull(), "Derived identity should not be null");

    // Identity should be 20 bytes (displayed as 40 hex chars)
    std::string hex = derived.GetHex();
    ASSERT_EQ(hex.length(), 40, "Identity hex should be 40 characters");

    // Deriving from empty pubkey should return null identity
    std::vector<uint8_t> emptyPubkey;
    DFMP::Identity nullIdentity = DFMP::DeriveIdentityFromMIK(emptyPubkey);
    ASSERT(nullIdentity.IsNull(), "Empty pubkey should give null identity");

    std::cout << "    Identity: " << hex << std::endl;
}

// =======================================================================
// Test 4: ScriptSig Registration Building and Parsing
// =======================================================================
TEST(scriptsig_registration) {
    DFMP::CMiningIdentityKey mik;
    ASSERT(mik.Generate(), "MIK generation failed");

    // Create signature
    uint256 prevHash;
    prevHash.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    std::vector<uint8_t> signature;
    ASSERT(mik.Sign(prevHash, 1, 1700000000, signature), "Signing failed");

    // Build registration scriptSig data
    std::vector<uint8_t> scriptSigData;
    bool built = DFMP::BuildMIKScriptSigRegistration(mik.pubkey, signature, scriptSigData);
    ASSERT(built, "Building registration scriptSig should succeed");

    // Check size: marker(1) + type(1) + pubkey(1952) + sig(3309) = 5263
    ASSERT_EQ(scriptSigData.size(), DFMP::MIK_REGISTRATION_SIZE, "Registration size incorrect");

    // Check marker and type
    ASSERT_EQ(scriptSigData[0], DFMP::MIK_MARKER, "Marker byte incorrect");
    ASSERT_EQ(scriptSigData[1], DFMP::MIK_TYPE_REGISTRATION, "Type byte incorrect");

    // Parse it back
    DFMP::CMIKScriptData parsed;
    bool parseOk = DFMP::ParseMIKFromScriptSig(scriptSigData, parsed);
    ASSERT(parseOk, "Parsing registration should succeed");
    ASSERT(parsed.isRegistration, "Should be recognized as registration");
    ASSERT(parsed.identity == mik.identity, "Parsed identity should match");
    ASSERT(parsed.pubkey == mik.pubkey, "Parsed pubkey should match");
    ASSERT(parsed.signature == signature, "Parsed signature should match");

    std::cout << "    Registration scriptSig size: " << scriptSigData.size() << " bytes" << std::endl;
}

// =======================================================================
// Test 5: ScriptSig Reference Building and Parsing
// =======================================================================
TEST(scriptsig_reference) {
    DFMP::CMiningIdentityKey mik;
    ASSERT(mik.Generate(), "MIK generation failed");

    // Create signature
    uint256 prevHash;
    prevHash.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    std::vector<uint8_t> signature;
    ASSERT(mik.Sign(prevHash, 100, 1700000000, signature), "Signing failed");

    // Build reference scriptSig data
    std::vector<uint8_t> scriptSigData;
    bool built = DFMP::BuildMIKScriptSigReference(mik.identity, signature, scriptSigData);
    ASSERT(built, "Building reference scriptSig should succeed");

    // Check size: marker(1) + type(1) + identity(20) + sig(3309) = 3331
    ASSERT_EQ(scriptSigData.size(), DFMP::MIK_REFERENCE_MIN_SIZE, "Reference size incorrect");

    // Check marker and type
    ASSERT_EQ(scriptSigData[0], DFMP::MIK_MARKER, "Marker byte incorrect");
    ASSERT_EQ(scriptSigData[1], DFMP::MIK_TYPE_REFERENCE, "Type byte incorrect");

    // Parse it back
    DFMP::CMIKScriptData parsed;
    bool parseOk = DFMP::ParseMIKFromScriptSig(scriptSigData, parsed);
    ASSERT(parseOk, "Parsing reference should succeed");
    ASSERT(!parsed.isRegistration, "Should be recognized as reference");
    ASSERT(parsed.identity == mik.identity, "Parsed identity should match");
    ASSERT(parsed.pubkey.empty(), "Reference should not have pubkey");
    ASSERT(parsed.signature == signature, "Parsed signature should match");

    std::cout << "    Reference scriptSig size: " << scriptSigData.size() << " bytes" << std::endl;
}

// =======================================================================
// Test 6: Maturity Penalty Calculation (v2.0)
// =======================================================================
TEST(maturity_penalty_v2) {
    // New identity (firstSeen = -1): should be 3.0x (no grace in v2.0)
    double newPenalty = DFMP::GetPendingPenalty(100, -1);
    ASSERT_NEAR(newPenalty, 3.0, 0.01, "New identity should have 3.0x penalty");

    // Just registered (age = 0): should be 3.0x
    double age0 = DFMP::GetPendingPenalty(100, 100);
    ASSERT_NEAR(age0, 3.0, 0.01, "Age 0 should have 3.0x penalty");

    // Age 99: still 3.0x (first 100 blocks)
    double age99 = DFMP::GetPendingPenalty(199, 100);
    ASSERT_NEAR(age99, 3.0, 0.01, "Age 99 should have 3.0x penalty");

    // Age 100: drops to 2.5x
    double age100 = DFMP::GetPendingPenalty(200, 100);
    ASSERT_NEAR(age100, 2.5, 0.01, "Age 100 should have 2.5x penalty");

    // Age 200: drops to 2.0x
    double age200 = DFMP::GetPendingPenalty(300, 100);
    ASSERT_NEAR(age200, 2.0, 0.01, "Age 200 should have 2.0x penalty");

    // Age 300: drops to 1.5x
    double age300 = DFMP::GetPendingPenalty(400, 100);
    ASSERT_NEAR(age300, 1.5, 0.01, "Age 300 should have 1.5x penalty");

    // Age 400+: mature at 1.0x
    double age400 = DFMP::GetPendingPenalty(500, 100);
    ASSERT_NEAR(age400, 1.0, 0.01, "Age 400+ should have 1.0x penalty");

    std::cout << "    New identity: " << newPenalty << "x" << std::endl;
    std::cout << "    Age 0-99: " << age0 << "x" << std::endl;
    std::cout << "    Age 100-199: " << age100 << "x" << std::endl;
    std::cout << "    Age 200-299: " << age200 << "x" << std::endl;
    std::cout << "    Age 300-399: " << age300 << "x" << std::endl;
    std::cout << "    Age 400+: " << age400 << "x (mature)" << std::endl;
}

// =======================================================================
// Test 7: Heat Penalty Calculation (v2.0)
// =======================================================================
TEST(heat_penalty_v2) {
    // Free tier: 0-20 blocks = 1.0x
    double heat0 = DFMP::GetHeatMultiplier(0);
    ASSERT_NEAR(heat0, 1.0, 0.01, "Heat 0 should be 1.0x");

    double heat10 = DFMP::GetHeatMultiplier(10);
    ASSERT_NEAR(heat10, 1.0, 0.01, "Heat 10 should be 1.0x");

    double heat20 = DFMP::GetHeatMultiplier(20);
    ASSERT_NEAR(heat20, 1.0, 0.01, "Heat 20 should be 1.0x (free tier boundary)");

    // Linear zone: 21-25 blocks = 1.0 + 0.1*(blocks-20)
    double heat21 = DFMP::GetHeatMultiplier(21);
    ASSERT_NEAR(heat21, 1.1, 0.01, "Heat 21 should be 1.1x");

    double heat23 = DFMP::GetHeatMultiplier(23);
    ASSERT_NEAR(heat23, 1.3, 0.01, "Heat 23 should be 1.3x");

    double heat25 = DFMP::GetHeatMultiplier(25);
    ASSERT_NEAR(heat25, 1.5, 0.01, "Heat 25 should be 1.5x");

    // Exponential zone: 26+ blocks = 1.5 * 1.08^(blocks-25)
    double heat26 = DFMP::GetHeatMultiplier(26);
    ASSERT_NEAR(heat26, 1.62, 0.02, "Heat 26 should be ~1.62x");

    double heat30 = DFMP::GetHeatMultiplier(30);
    ASSERT_NEAR(heat30, 2.20, 0.05, "Heat 30 should be ~2.20x");

    double heat40 = DFMP::GetHeatMultiplier(40);
    ASSERT_NEAR(heat40, 4.76, 0.1, "Heat 40 should be ~4.76x");

    std::cout << "    Free tier (0-20): " << heat20 << "x" << std::endl;
    std::cout << "    Linear (21): " << heat21 << "x" << std::endl;
    std::cout << "    Linear (25): " << heat25 << "x" << std::endl;
    std::cout << "    Exponential (26): " << heat26 << "x" << std::endl;
    std::cout << "    Exponential (30): " << heat30 << "x" << std::endl;
    std::cout << "    Exponential (40): " << heat40 << "x" << std::endl;
}

// =======================================================================
// Test 8: Total Multiplier Calculation
// =======================================================================
TEST(total_multiplier) {
    // New identity, no heat: 3.0 * 1.0 = 3.0x
    double total1 = DFMP::GetTotalMultiplier(100, -1, 0);
    ASSERT_NEAR(total1, 3.0, 0.01, "New identity, no heat should be 3.0x");

    // New identity, heat 25: 3.0 * 1.5 = 4.5x
    double total2 = DFMP::GetTotalMultiplier(100, -1, 25);
    ASSERT_NEAR(total2, 4.5, 0.02, "New identity, heat 25 should be 4.5x");

    // Mature identity, heat 30: 1.0 * ~2.2 = ~2.2x
    double total3 = DFMP::GetTotalMultiplier(600, 100, 30);
    ASSERT_NEAR(total3, 2.20, 0.05, "Mature identity, heat 30 should be ~2.2x");

    // Age 100, heat 21: 2.5 * 1.1 = 2.75x
    double total4 = DFMP::GetTotalMultiplier(200, 100, 21);
    ASSERT_NEAR(total4, 2.75, 0.02, "Age 100, heat 21 should be 2.75x");

    std::cout << "    New + no heat: " << total1 << "x" << std::endl;
    std::cout << "    New + heat 25: " << total2 << "x" << std::endl;
    std::cout << "    Mature + heat 30: " << total3 << "x" << std::endl;
    std::cout << "    Age 100 + heat 21: " << total4 << "x" << std::endl;
}

// =======================================================================
// Test 9: Constants Verification
// =======================================================================
TEST(constants_verification) {
    // Verify key sizes match Dilithium3 spec
    ASSERT_EQ(DFMP::MIK_PUBKEY_SIZE, 1952, "Pubkey size should be 1952");
    ASSERT_EQ(DFMP::MIK_PRIVKEY_SIZE, 4032, "Privkey size should be 4032");
    ASSERT_EQ(DFMP::MIK_SIGNATURE_SIZE, 3309, "Signature size should be 3309");
    ASSERT_EQ(DFMP::MIK_IDENTITY_SIZE, 20, "Identity size should be 20");

    // Verify marker bytes
    ASSERT_EQ(DFMP::MIK_MARKER, 0xDF, "MIK marker should be 0xDF");
    ASSERT_EQ(DFMP::MIK_TYPE_REGISTRATION, 0x01, "Registration type should be 0x01");
    ASSERT_EQ(DFMP::MIK_TYPE_REFERENCE, 0x02, "Reference type should be 0x02");

    // Verify v2.0 constants
    ASSERT_EQ(DFMP::OBSERVATION_WINDOW, 360, "Observation window should be 360");
    ASSERT_EQ(DFMP::FREE_TIER_THRESHOLD, 12, "Free tier should be 12");
    ASSERT_EQ(DFMP::MATURITY_BLOCKS, 800, "Maturity blocks should be 800");

    std::cout << "    All constants verified" << std::endl;
}

// =======================================================================
// Test 10: MIK Clear (Secure Wipe)
// =======================================================================
TEST(mik_clear) {
    DFMP::CMiningIdentityKey mik;
    ASSERT(mik.Generate(), "MIK generation failed");
    ASSERT(mik.IsValid(), "MIK should be valid after generation");

    // Store identity for comparison
    std::string identityBefore = mik.GetIdentityHex();

    // Clear the MIK
    mik.Clear();

    // Should now be invalid
    ASSERT(!mik.IsValid(), "MIK should be invalid after clear");
    ASSERT(!mik.HasPrivateKey(), "MIK should not have private key after clear");
    ASSERT(mik.pubkey.empty(), "Pubkey should be empty after clear");
    ASSERT(mik.privkey.empty(), "Privkey should be empty after clear");
    ASSERT(mik.identity.IsNull(), "Identity should be null after clear");

    std::cout << "    Identity before clear: " << identityBefore << std::endl;
    std::cout << "    MIK securely wiped" << std::endl;
}

// =======================================================================
// Main Test Runner
// =======================================================================
int main() {
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << YELLOW << "DFMP v2.0 MIK Unit Tests" << RESET << std::endl;
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << std::endl;

    // Run all tests
    test_mik_generation_wrapper();
    test_mik_sign_verify_wrapper();
    test_identity_derivation_wrapper();
    test_scriptsig_registration_wrapper();
    test_scriptsig_reference_wrapper();
    test_maturity_penalty_v2_wrapper();
    test_heat_penalty_v2_wrapper();
    test_total_multiplier_wrapper();
    test_constants_verification_wrapper();
    test_mik_clear_wrapper();

    // Print summary
    std::cout << std::endl;
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << YELLOW << "Test Summary" << RESET << std::endl;
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << GREEN << "Passed: " << g_tests_passed << RESET << std::endl;
    std::cout << RED << "Failed: " << g_tests_failed << RESET << std::endl;
    std::cout << YELLOW << "Total:  " << (g_tests_passed + g_tests_failed) << RESET << std::endl;
    std::cout << std::endl;

    if (g_tests_failed == 0) {
        std::cout << GREEN << "ALL TESTS PASSED!" << RESET << std::endl;
        return 0;
    } else {
        std::cout << RED << "SOME TESTS FAILED" << RESET << std::endl;
        return 1;
    }
}
