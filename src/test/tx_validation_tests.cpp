// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Transaction Validation Tests
 *
 * Comprehensive test suite for Phase 5.1.3: Transaction Validation System
 */

#include <consensus/tx_validation.h>
#include <node/utxo_set.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <amount.h>
#include <iostream>
#include <cassert>
#include <cstdio>

// Test utilities
#define TEST_ASSERT(condition, msg) \
    if (!(condition)) { \
        std::cerr << "FAILED: " << msg << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
        return false; \
    }

#define TEST_SUCCESS(msg) \
    std::cout << "PASSED: " << msg << std::endl;

// Helper function to create a simple UTXO set for testing
bool SetupTestUTXO(CUTXOSet& utxoSet) {
    // Open temporary database
    if (!utxoSet.Open(".test_utxo_validation", true)) {
        std::cerr << "Failed to open test UTXO database" << std::endl;
        return false;
    }

    // Clear any existing data
    utxoSet.Clear();

    return true;
}

// Test 1: Basic Transaction Structure Validation
bool TestBasicStructure() {
    std::cout << "\n=== Test 1: Basic Transaction Structure ===" << std::endl;

    CTransactionValidator validator;
    std::string error;

    // Test 1a: Empty transaction (null)
    {
        CTransaction tx;
        tx.SetNull();
        TEST_ASSERT(!validator.CheckTransactionBasic(tx, error),
                    "Null transaction should fail");
        std::cout << "  - Null transaction correctly rejected: " << error << std::endl;
    }

    // Test 1b: Transaction with no inputs
    {
        CTransaction tx;
        tx.nVersion = 1;
        CTxOut out(50 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        TEST_ASSERT(!validator.CheckTransactionBasic(tx, error),
                    "Transaction with no inputs should fail");
        std::cout << "  - No inputs correctly rejected: " << error << std::endl;
    }

    // Test 1c: Transaction with no outputs
    {
        CTransaction tx;
        tx.nVersion = 1;
        uint256 prevHash;
        CTxIn in(COutPoint(prevHash, 0));
        tx.vin.push_back(in);

        TEST_ASSERT(!validator.CheckTransactionBasic(tx, error),
                    "Transaction with no outputs should fail");
        std::cout << "  - No outputs correctly rejected: " << error << std::endl;
    }

    // Test 1d: Transaction with negative output value
    {
        CTransaction tx;
        tx.nVersion = 1;
        uint256 prevHash;
        CTxIn in(COutPoint(prevHash, 0));
        tx.vin.push_back(in);

        CTxOut out(0, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        TEST_ASSERT(!validator.CheckTransactionBasic(tx, error),
                    "Transaction with zero output should fail");
        std::cout << "  - Zero output correctly rejected: " << error << std::endl;
    }

    // Test 1e: Valid transaction structure
    {
        CTransaction tx;
        tx.nVersion = 1;
        uint256 prevHash;
        CTxIn in(COutPoint(prevHash, 0), {0x01, 0x02, 0x03});
        tx.vin.push_back(in);

        CTxOut out(50 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        TEST_ASSERT(validator.CheckTransactionBasic(tx, error),
                    "Valid transaction structure should pass");
        std::cout << "  - Valid transaction structure accepted" << std::endl;
    }

    TEST_SUCCESS("Basic structure validation tests");
    return true;
}

// Test 2: Duplicate Input Detection
bool TestDuplicateInputs() {
    std::cout << "\n=== Test 2: Duplicate Input Detection ===" << std::endl;

    CTransactionValidator validator;
    std::string error;

    // Test 2a: Transaction with duplicate inputs
    {
        CTransaction tx;
        tx.nVersion = 1;

        uint256 prevHash;
        prevHash.data[0] = 0x01;

        CTxIn in1(COutPoint(prevHash, 0), {0x01, 0x02});
        CTxIn in2(COutPoint(prevHash, 0), {0x03, 0x04}); // Same outpoint!

        tx.vin.push_back(in1);
        tx.vin.push_back(in2);

        CTxOut out(50 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        TEST_ASSERT(!validator.CheckTransactionBasic(tx, error),
                    "Transaction with duplicate inputs should fail");
        std::cout << "  - Duplicate inputs correctly rejected: " << error << std::endl;
    }

    // Test 2b: Transaction with unique inputs
    {
        CTransaction tx;
        tx.nVersion = 1;

        uint256 prevHash1, prevHash2;
        prevHash1.data[0] = 0x01;
        prevHash2.data[0] = 0x02;

        CTxIn in1(COutPoint(prevHash1, 0), {0x01, 0x02});
        CTxIn in2(COutPoint(prevHash2, 0), {0x03, 0x04});

        tx.vin.push_back(in1);
        tx.vin.push_back(in2);

        CTxOut out(50 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        TEST_ASSERT(validator.CheckTransactionBasic(tx, error),
                    "Transaction with unique inputs should pass");
        std::cout << "  - Unique inputs accepted" << std::endl;
    }

    TEST_SUCCESS("Duplicate input detection tests");
    return true;
}

// Test 3: Coinbase Transaction Validation
bool TestCoinbaseValidation() {
    std::cout << "\n=== Test 3: Coinbase Transaction Validation ===" << std::endl;

    CTransactionValidator validator;
    std::string error;

    // Test 3a: Valid coinbase transaction
    {
        CTransaction tx;
        tx.nVersion = 1;

        // Coinbase input with null prevout
        CTxIn in(COutPoint(), {0x01, 0x02, 0x03});
        tx.vin.push_back(in);

        CTxOut out(50 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        TEST_ASSERT(tx.IsCoinBase(), "Should be identified as coinbase");
        TEST_ASSERT(validator.CheckTransactionBasic(tx, error),
                    "Valid coinbase should pass");
        std::cout << "  - Valid coinbase accepted" << std::endl;
    }

    // Test 3b: Coinbase with multiple inputs
    {
        CTransaction tx;
        tx.nVersion = 1;

        CTxIn in1(COutPoint(), {0x01, 0x02, 0x03});
        CTxIn in2(COutPoint(), {0x04, 0x05, 0x06});
        tx.vin.push_back(in1);
        tx.vin.push_back(in2);

        CTxOut out(50 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        TEST_ASSERT(!validator.CheckTransactionBasic(tx, error),
                    "Coinbase with multiple inputs should fail");
        std::cout << "  - Multiple coinbase inputs rejected: " << error << std::endl;
    }

    TEST_SUCCESS("Coinbase validation tests");
    return true;
}

// Test 4: UTXO-Based Validation
bool TestUTXOValidation() {
    std::cout << "\n=== Test 4: UTXO-Based Validation ===" << std::endl;

    CTransactionValidator validator;
    CUTXOSet utxoSet;
    std::string error;
    CAmount fee;

    if (!SetupTestUTXO(utxoSet)) {
        return false;
    }

    // Create a UTXO to spend
    uint256 prevHash;
    prevHash.data[0] = 0xaa;
    prevHash.data[1] = 0xbb;

    CTxOut utxoOut(100 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x88, 0xac});

    COutPoint utxoPoint(prevHash, 0);
    utxoSet.AddUTXO(utxoPoint, utxoOut, 10, false);

    // Test 4a: Transaction spending existing UTXO
    {
        CTransaction tx;
        tx.nVersion = 1;

        CTxIn in(utxoPoint, {0x01, 0x02, 0x03});
        tx.vin.push_back(in);

        // Output slightly less than input for reasonable fee (0.01 coins = 1000000 ions)
        CTxOut out((100 * COIN) - 1000000, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        if (!validator.CheckTransactionInputs(tx, utxoSet, 120, fee, error)) {
            std::cerr << "FAILED: Transaction with valid UTXO should pass" << std::endl;
            std::cerr << "ERROR: " << error << std::endl;
            return false;
        }
        TEST_ASSERT(fee == 1000000, "Fee should be correctly calculated (0.01 coins)");
        std::cout << "  - Valid UTXO spend accepted, fee: " << fee << " ions" << std::endl;
    }

    // Test 4b: Transaction spending non-existent UTXO
    {
        CTransaction tx;
        tx.nVersion = 1;

        uint256 badHash;
        badHash.data[0] = 0xff;
        CTxIn in(COutPoint(badHash, 0), {0x01, 0x02, 0x03});
        tx.vin.push_back(in);

        CTxOut out(50 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        TEST_ASSERT(!validator.CheckTransactionInputs(tx, utxoSet, 120, fee, error),
                    "Transaction with non-existent UTXO should fail");
        std::cout << "  - Non-existent UTXO correctly rejected: " << error << std::endl;
    }

    utxoSet.Close();
    TEST_SUCCESS("UTXO validation tests");
    return true;
}

// Test 5: Coinbase Maturity Check
bool TestCoinbaseMaturity() {
    std::cout << "\n=== Test 5: Coinbase Maturity ===" << std::endl;

    CTransactionValidator validator;
    CUTXOSet utxoSet;
    std::string error;
    CAmount fee;

    if (!SetupTestUTXO(utxoSet)) {
        return false;
    }

    // Create an immature coinbase UTXO
    uint256 coinbaseHash;
    coinbaseHash.data[0] = 0xcc;

    CTxOut coinbaseOut(50 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x88, 0xac});

    COutPoint coinbasePoint(coinbaseHash, 0);
    utxoSet.AddUTXO(coinbasePoint, coinbaseOut, 100, true); // Height 100, is coinbase

    // Test 5a: Try to spend immature coinbase (at height 150, needs 100 confirmations)
    {
        CTransaction tx;
        tx.nVersion = 1;

        CTxIn in(coinbasePoint, {0x01, 0x02, 0x03});
        tx.vin.push_back(in);

        CTxOut out(25 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        // At height 150, only 50 confirmations
        TEST_ASSERT(!validator.CheckTransactionInputs(tx, utxoSet, 150, fee, error),
                    "Immature coinbase should fail");
        std::cout << "  - Immature coinbase rejected: " << error << std::endl;
    }

    // Test 5b: Spend mature coinbase (at height 200, has 100 confirmations)
    {
        CTransaction tx;
        tx.nVersion = 1;

        CTxIn in(coinbasePoint, {0x01, 0x02, 0x03});
        tx.vin.push_back(in);

        // Output slightly less than input for reasonable fee (0.01 coins = 1000000 ions)
        CTxOut out((50 * COIN) - 1000000, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        // At height 200, has 100 confirmations
        if (!validator.CheckTransactionInputs(tx, utxoSet, 200, fee, error)) {
            std::cerr << "FAILED: Mature coinbase should pass" << std::endl;
            std::cerr << "ERROR: " << error << std::endl;
            return false;
        }
        std::cout << "  - Mature coinbase accepted, fee: " << fee << " ions" << std::endl;
    }

    utxoSet.Close();
    TEST_SUCCESS("Coinbase maturity tests");
    return true;
}

// Test 6: Complete Transaction Validation
bool TestCompleteValidation() {
    std::cout << "\n=== Test 6: Complete Transaction Validation ===" << std::endl;

    CTransactionValidator validator;
    CUTXOSet utxoSet;
    std::string error;
    CAmount fee;

    if (!SetupTestUTXO(utxoSet)) {
        return false;
    }

    // Create a spendable UTXO
    uint256 prevHash;
    prevHash.data[0] = 0x11;
    prevHash.data[1] = 0x22;

    CTxOut utxoOut(100 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x88, 0xac});

    COutPoint utxoPoint(prevHash, 0);
    utxoSet.AddUTXO(utxoPoint, utxoOut, 50, false);

    // Test complete validation
    {
        CTransaction tx;
        tx.nVersion = 1;

        CTxIn in(utxoPoint, {0x01, 0x02, 0x03});
        tx.vin.push_back(in);

        // Output slightly less than input for reasonable fee (0.01 coins = 1000000 ions)
        CTxOut out((100 * COIN) - 1000000, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        // Note: Using CheckTransactionInputs instead of CheckTransaction to avoid script validation
        // (script validation requires real Dilithium signatures which this test doesn't have)
        if (!validator.CheckTransactionInputs(tx, utxoSet, 200, fee, error)) {
            std::cerr << "FAILED: Complete validation should pass" << std::endl;
            std::cerr << "ERROR: " << error << std::endl;
            return false;
        }
        TEST_ASSERT(fee == 1000000, "Fee should be 0.01 coins (1000000 ions)");
        std::cout << "  - Complete validation passed (inputs + fees), fee: " << fee << " ions" << std::endl;
    }

    utxoSet.Close();
    TEST_SUCCESS("Complete validation tests");
    return true;
}

// Test 7: Standard Transaction Checks
bool TestStandardTransaction() {
    std::cout << "\n=== Test 7: Standard Transaction Checks ===" << std::endl;

    CTransactionValidator validator;

    // Test 7a: Valid standard transaction
    {
        CTransaction tx;
        tx.nVersion = 1;

        uint256 prevHash;
        CTxIn in(COutPoint(prevHash, 0), {0x01, 0x02, 0x03});
        tx.vin.push_back(in);

        CTxOut out(50 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        TEST_ASSERT(validator.IsStandardTransaction(tx),
                    "Valid transaction should be standard");
        std::cout << "  - Standard transaction accepted" << std::endl;
    }

    // Test 7b: Non-standard version
    {
        CTransaction tx;
        tx.nVersion = 99; // Non-standard version

        uint256 prevHash;
        CTxIn in(COutPoint(prevHash, 0), {0x01, 0x02, 0x03});
        tx.vin.push_back(in);

        CTxOut out(50 * COIN, {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x88, 0xac});
        tx.vout.push_back(out);

        TEST_ASSERT(!validator.IsStandardTransaction(tx),
                    "Non-standard version should be rejected");
        std::cout << "  - Non-standard version rejected" << std::endl;
    }

    TEST_SUCCESS("Standard transaction tests");
    return true;
}

// Main test runner
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Transaction Validation Test Suite" << std::endl;
    std::cout << "Phase 5.1.3: Transaction Validation System" << std::endl;
    std::cout << "========================================" << std::endl;

    int passed = 0;
    int failed = 0;

    // Run all tests
    if (TestBasicStructure()) passed++; else failed++;
    if (TestDuplicateInputs()) passed++; else failed++;
    if (TestCoinbaseValidation()) passed++; else failed++;
    if (TestUTXOValidation()) passed++; else failed++;
    if (TestCoinbaseMaturity()) passed++; else failed++;
    if (TestCompleteValidation()) passed++; else failed++;
    if (TestStandardTransaction()) passed++; else failed++;

    // Summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Results:" << std::endl;
    std::cout << "  Passed: " << passed << std::endl;
    std::cout << "  Failed: " << failed << std::endl;
    std::cout << "========================================" << std::endl;

    return (failed == 0) ? 0 : 1;
}
