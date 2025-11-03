// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Transaction Tests
 *
 * Tests for CTransaction, CTxIn, CTxOut, and COutPoint primitives
 * Following Bitcoin Core testing standards with Boost Test Framework
 */

#include <boost/test/unit_test.hpp>

#include <primitives/transaction.h>
#include <amount.h>
#include <vector>
#include <cstring>

BOOST_AUTO_TEST_SUITE(transaction_tests)

/**
 * Test Suite 1: COutPoint Tests
 */
BOOST_AUTO_TEST_SUITE(outpoint_tests)

BOOST_AUTO_TEST_CASE(outpoint_construction) {
    // Test default constructor
    COutPoint outpoint1;
    BOOST_CHECK(outpoint1.IsNull());
    BOOST_CHECK_EQUAL(outpoint1.n, 0xffffffff);

    // Test parameterized constructor
    uint256 hash;
    memset(hash.data, 0x42, 32);
    COutPoint outpoint2(hash, 5);
    BOOST_CHECK(!outpoint2.IsNull());
    BOOST_CHECK_EQUAL(outpoint2.n, 5);
    BOOST_CHECK(outpoint2.hash == hash);
}

BOOST_AUTO_TEST_CASE(outpoint_setnull) {
    uint256 hash;
    memset(hash.data, 0x42, 32);
    COutPoint outpoint(hash, 5);
    BOOST_CHECK(!outpoint.IsNull());

    outpoint.SetNull();
    BOOST_CHECK(outpoint.IsNull());
    BOOST_CHECK(outpoint.hash.IsNull());
    BOOST_CHECK_EQUAL(outpoint.n, 0xffffffff);
}

BOOST_AUTO_TEST_CASE(outpoint_equality) {
    uint256 hash1, hash2;
    memset(hash1.data, 0x42, 32);
    memset(hash2.data, 0x42, 32);

    COutPoint op1(hash1, 5);
    COutPoint op2(hash2, 5);
    COutPoint op3(hash1, 6);

    BOOST_CHECK(op1 == op2);  // Same hash and index
    BOOST_CHECK(!(op1 == op3));  // Different index
}

BOOST_AUTO_TEST_CASE(outpoint_comparison) {
    uint256 hash1, hash2;
    memset(hash1.data, 0x41, 32);
    memset(hash2.data, 0x42, 32);

    COutPoint op1(hash1, 5);
    COutPoint op2(hash2, 5);
    COutPoint op3(hash1, 6);

    BOOST_CHECK(op1 < op2);  // hash1 < hash2
    BOOST_CHECK(op1 < op3);  // Same hash, but n=5 < n=6
}

BOOST_AUTO_TEST_SUITE_END() // outpoint_tests

/**
 * Test Suite 2: CTxIn Tests
 */
BOOST_AUTO_TEST_SUITE(txin_tests)

BOOST_AUTO_TEST_CASE(txin_construction) {
    // Test default constructor
    CTxIn input1;
    BOOST_CHECK(input1.prevout.IsNull());
    BOOST_CHECK(input1.scriptSig.empty());
    BOOST_CHECK_EQUAL(input1.nSequence, CTxIn::SEQUENCE_FINAL);

    // Test parameterized constructor
    uint256 hash;
    memset(hash.data, 0x42, 32);
    std::vector<uint8_t> script = {0x01, 0x02, 0x03};
    COutPoint prevout(hash, 2);
    CTxIn input2(prevout, script, 100);

    BOOST_CHECK(input2.prevout == prevout);
    BOOST_CHECK(input2.scriptSig == script);
    BOOST_CHECK_EQUAL(input2.nSequence, 100);
}

BOOST_AUTO_TEST_CASE(txin_convenience_constructor) {
    uint256 hash;
    memset(hash.data, 0x42, 32);
    std::vector<uint8_t> script = {0xaa, 0xbb};

    CTxIn input(hash, 3, script, 200);

    BOOST_CHECK(input.prevout.hash == hash);
    BOOST_CHECK_EQUAL(input.prevout.n, 3);
    BOOST_CHECK(input.scriptSig == script);
    BOOST_CHECK_EQUAL(input.nSequence, 200);
}

BOOST_AUTO_TEST_CASE(txin_equality) {
    uint256 hash;
    memset(hash.data, 0x42, 32);
    std::vector<uint8_t> script = {0x01, 0x02};

    CTxIn input1(hash, 1, script, 100);
    CTxIn input2(hash, 1, script, 100);
    CTxIn input3(hash, 2, script, 100);  // Different n

    BOOST_CHECK(input1 == input2);
    BOOST_CHECK(!(input1 == input3));
}

BOOST_AUTO_TEST_SUITE_END() // txin_tests

/**
 * Test Suite 3: CTxOut Tests
 */
BOOST_AUTO_TEST_SUITE(txout_tests)

BOOST_AUTO_TEST_CASE(txout_construction) {
    // Test default constructor
    CTxOut output1;
    BOOST_CHECK(output1.IsNull());
    BOOST_CHECK_EQUAL(output1.nValue, 0);
    BOOST_CHECK(output1.scriptPubKey.empty());

    // Test parameterized constructor
    std::vector<uint8_t> script = {0x76, 0xa9, 0x14};  // P2PKH prefix
    CTxOut output2(50 * COIN, script);

    BOOST_CHECK(!output2.IsNull());
    BOOST_CHECK_EQUAL(output2.nValue, 50 * COIN);
    BOOST_CHECK(output2.scriptPubKey == script);
}

BOOST_AUTO_TEST_CASE(txout_setnull) {
    std::vector<uint8_t> script = {0x76, 0xa9};
    CTxOut output(100 * COIN, script);
    BOOST_CHECK(!output.IsNull());

    output.SetNull();
    BOOST_CHECK(output.IsNull());
    BOOST_CHECK_EQUAL(output.nValue, 0);
    BOOST_CHECK(output.scriptPubKey.empty());
}

BOOST_AUTO_TEST_CASE(txout_equality) {
    std::vector<uint8_t> script1 = {0x01, 0x02};
    std::vector<uint8_t> script2 = {0x01, 0x02};
    std::vector<uint8_t> script3 = {0x03, 0x04};

    CTxOut out1(50 * COIN, script1);
    CTxOut out2(50 * COIN, script2);
    CTxOut out3(100 * COIN, script1);
    CTxOut out4(50 * COIN, script3);

    BOOST_CHECK(out1 == out2);  // Same value and script
    BOOST_CHECK(!(out1 == out3));  // Different value
    BOOST_CHECK(!(out1 == out4));  // Different script
}

BOOST_AUTO_TEST_SUITE_END() // txout_tests

/**
 * Test Suite 4: CTransaction Tests
 */
BOOST_AUTO_TEST_SUITE(transaction_tests)

BOOST_AUTO_TEST_CASE(transaction_default_construction) {
    CTransaction tx;

    BOOST_CHECK_EQUAL(tx.nVersion, 1);
    BOOST_CHECK(tx.vin.empty());
    BOOST_CHECK(tx.vout.empty());
    BOOST_CHECK_EQUAL(tx.nLockTime, 0);
    BOOST_CHECK(tx.IsNull());
}

BOOST_AUTO_TEST_CASE(transaction_parameterized_construction) {
    // Create inputs
    uint256 hash;
    memset(hash.data, 0x42, 32);
    std::vector<uint8_t> script_sig = {0xaa, 0xbb};
    std::vector<CTxIn> inputs;
    inputs.push_back(CTxIn(hash, 0, script_sig));

    // Create outputs
    std::vector<uint8_t> script_pubkey = {0x76, 0xa9};
    std::vector<CTxOut> outputs;
    outputs.push_back(CTxOut(50 * COIN, script_pubkey));

    // Create transaction
    CTransaction tx(1, inputs, outputs, 0);

    BOOST_CHECK_EQUAL(tx.nVersion, 1);
    BOOST_CHECK_EQUAL(tx.vin.size(), 1);
    BOOST_CHECK_EQUAL(tx.vout.size(), 1);
    BOOST_CHECK_EQUAL(tx.nLockTime, 0);
    BOOST_CHECK(!tx.IsNull());
}

BOOST_AUTO_TEST_CASE(transaction_copy_constructor) {
    // Create original transaction
    uint256 hash;
    memset(hash.data, 0x42, 32);
    std::vector<CTxIn> inputs;
    inputs.push_back(CTxIn(hash, 0));
    std::vector<CTxOut> outputs;
    outputs.push_back(CTxOut(50 * COIN, {0x76}));

    CTransaction tx1(2, inputs, outputs, 100);

    // Copy construct
    CTransaction tx2(tx1);

    BOOST_CHECK_EQUAL(tx2.nVersion, tx1.nVersion);
    BOOST_CHECK_EQUAL(tx2.vin.size(), tx1.vin.size());
    BOOST_CHECK_EQUAL(tx2.vout.size(), tx1.vout.size());
    BOOST_CHECK_EQUAL(tx2.nLockTime, tx1.nLockTime);
}

BOOST_AUTO_TEST_CASE(transaction_assignment) {
    // Create original transaction
    uint256 hash;
    memset(hash.data, 0x42, 32);
    std::vector<CTxIn> inputs;
    inputs.push_back(CTxIn(hash, 0));
    std::vector<CTxOut> outputs;
    outputs.push_back(CTxOut(50 * COIN, {0x76}));

    CTransaction tx1(2, inputs, outputs, 100);
    CTransaction tx2;

    // Assignment
    tx2 = tx1;

    BOOST_CHECK_EQUAL(tx2.nVersion, tx1.nVersion);
    BOOST_CHECK_EQUAL(tx2.vin.size(), tx1.vin.size());
    BOOST_CHECK_EQUAL(tx2.vout.size(), tx1.vout.size());
    BOOST_CHECK_EQUAL(tx2.nLockTime, tx1.nLockTime);
}

BOOST_AUTO_TEST_CASE(transaction_is_null) {
    CTransaction tx1;
    BOOST_CHECK(tx1.IsNull());

    // Add input
    uint256 hash;
    tx1.vin.push_back(CTxIn(hash, 0));
    BOOST_CHECK(!tx1.IsNull());  // Has input, not null

    // Clear and add output
    CTransaction tx2;
    tx2.vout.push_back(CTxOut(50 * COIN, {0x76}));
    BOOST_CHECK(!tx2.IsNull());  // Has output, not null
}

BOOST_AUTO_TEST_CASE(transaction_multiple_inputs_outputs) {
    CTransaction tx;
    tx.nVersion = 1;

    // Add multiple inputs
    uint256 hash1, hash2, hash3;
    memset(hash1.data, 0x41, 32);
    memset(hash2.data, 0x42, 32);
    memset(hash3.data, 0x43, 32);

    tx.vin.push_back(CTxIn(hash1, 0));
    tx.vin.push_back(CTxIn(hash2, 1));
    tx.vin.push_back(CTxIn(hash3, 0));

    // Add multiple outputs
    tx.vout.push_back(CTxOut(25 * COIN, {0x76}));
    tx.vout.push_back(CTxOut(25 * COIN, {0x77}));

    BOOST_CHECK_EQUAL(tx.vin.size(), 3);
    BOOST_CHECK_EQUAL(tx.vout.size(), 2);
    BOOST_CHECK(!tx.IsNull());
}

BOOST_AUTO_TEST_CASE(transaction_amount_arithmetic) {
    CTransaction tx;

    // Add outputs with different amounts
    tx.vout.push_back(CTxOut(10 * COIN, {0x76}));
    tx.vout.push_back(CTxOut(20 * COIN, {0x77}));
    tx.vout.push_back(CTxOut(30 * COIN, {0x78}));

    // Calculate total output value
    uint64_t total = 0;
    for (const auto& out : tx.vout) {
        total += out.nValue;
    }

    BOOST_CHECK_EQUAL(total, 60 * COIN);
}

BOOST_AUTO_TEST_CASE(transaction_zero_value_output) {
    // Zero-value outputs should be allowed (OP_RETURN, for example)
    CTransaction tx;
    tx.vout.push_back(CTxOut(0, {0x6a}));  // OP_RETURN = 0x6a

    BOOST_CHECK_EQUAL(tx.vout.size(), 1);
    BOOST_CHECK_EQUAL(tx.vout[0].nValue, 0);
}

BOOST_AUTO_TEST_CASE(transaction_locktime) {
    CTransaction tx;

    // Default locktime is 0 (not locked)
    BOOST_CHECK_EQUAL(tx.nLockTime, 0);

    // Set locktime to block height
    tx.nLockTime = 500000;
    BOOST_CHECK_EQUAL(tx.nLockTime, 500000);

    // Set locktime to timestamp
    tx.nLockTime = 1609459200;  // Jan 1, 2021
    BOOST_CHECK_EQUAL(tx.nLockTime, 1609459200);
}

BOOST_AUTO_TEST_SUITE_END() // transaction_tests

BOOST_AUTO_TEST_SUITE_END() // transaction_tests (outer)
