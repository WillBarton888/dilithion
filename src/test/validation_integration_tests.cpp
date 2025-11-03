// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Validation Integration Tests
 *
 * Integration tests that exercise multiple consensus components together
 * to achieve 85%+ coverage by testing realistic workflows.
 *
 * These tests verify that primitives, validation, and consensus work together correctly.
 */

#include <boost/test/unit_test.hpp>

#include <primitives/transaction.h>
#include <primitives/block.h>
#include <consensus/pow.h>
#include <crypto/sha3.h>
#include <amount.h>

#include <vector>
#include <cstring>

BOOST_AUTO_TEST_SUITE(validation_integration_tests)

/**
 * Integration Test 1: Transaction Creation → Serialization → Hashing → Validation
 */
BOOST_AUTO_TEST_CASE(transaction_full_lifecycle) {
    // Step 1: Create a realistic transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    // Add realistic input (spending a previous output)
    uint256 prevTxHash;
    memset(prevTxHash.data, 0x42, 32);
    std::vector<uint8_t> signature(100, 0xAA);  // Mock Dilithium signature
    tx.vin.push_back(CTxIn(prevTxHash, 0, signature, CTxIn::SEQUENCE_FINAL));

    // Add realistic output (payment to address)
    std::vector<uint8_t> pubKeyScript(50, 0xBB);
    tx.vout.push_back(CTxOut(25 * COIN, pubKeyScript));
    tx.vout.push_back(CTxOut(24 * COIN, pubKeyScript));  // Change output

    // Step 2: Validate basic structure
    BOOST_CHECK(tx.CheckBasicStructure());
    BOOST_CHECK(!tx.IsNull());
    BOOST_CHECK(!tx.IsCoinBase());

    // Step 3: Serialize transaction
    std::vector<uint8_t> serialized = tx.Serialize();
    BOOST_CHECK(serialized.size() > 0);
    BOOST_CHECK_EQUAL(serialized.size(), tx.GetSerializedSize());

    // Step 4: Get transaction hash (TXID)
    uint256 txid = tx.GetHash();
    BOOST_CHECK(!txid.IsNull());

    // Step 5: Deserialize and verify
    CTransaction tx2;
    std::string error;
    bool success = tx2.Deserialize(serialized.data(), serialized.size(), &error);
    BOOST_CHECK_MESSAGE(success, "Deserialization failed: " + error);

    // Step 6: Verify roundtrip produced identical transaction
    BOOST_CHECK_EQUAL(tx2.GetHash(), txid);
    BOOST_CHECK_EQUAL(tx2.nVersion, tx.nVersion);
    BOOST_CHECK(tx2.CheckBasicStructure());
}

/**
 * Integration Test 2: Coinbase Transaction → Block Creation → PoW Validation
 */
BOOST_AUTO_TEST_CASE(block_mining_workflow) {
    // Step 1: Create coinbase transaction
    CTransaction coinbase;
    coinbase.nVersion = 1;
    coinbase.nLockTime = 0;

    // Coinbase input (null prevout)
    std::vector<uint8_t> coinbase_script = {0x03, 0x12, 0x34, 0x56};  // Block height in script
    coinbase.vin.push_back(CTxIn(COutPoint(), coinbase_script, CTxIn::SEQUENCE_FINAL));

    // Coinbase output (50 DIL subsidy)
    std::vector<uint8_t> miner_pubkey(50, 0xCC);
    coinbase.vout.push_back(CTxOut(50 * COIN, miner_pubkey));

    // Validate coinbase
    BOOST_CHECK(coinbase.IsCoinBase());
    BOOST_CHECK(coinbase.CheckBasicStructure());

    // Step 2: Create block with coinbase
    CBlock block;
    block.nVersion = 1;
    block.nTime = 1234567890;
    block.nBits = 0x1f0fffff;  // Testnet difficulty (easy)
    block.nNonce = 0;

    // Set previous block hash
    memset(block.hashPrevBlock.data, 0, 32);  // Genesis has null prev

    // Serialize coinbase and set merkle root
    std::vector<uint8_t> coinbase_data = coinbase.Serialize();
    uint8_t merkle_hash[32];
    SHA3_256(coinbase_data.data(), coinbase_data.size(), merkle_hash);
    memcpy(block.hashMerkleRoot.data, merkle_hash, 32);

    // Step 3: Get block hash
    uint256 block_hash = block.GetHash();
    BOOST_CHECK(!block_hash.IsNull());

    // Step 4: Check if block satisfies PoW
    bool pow_valid = CheckProofOfWork(block_hash, block.nBits);

    // With nNonce=0 and easy difficulty, PoW likely invalid
    // But the check should not crash
    (void)pow_valid;  // May be true or false depending on hash
}

/**
 * Integration Test 3: Transaction Chain (Output → Input)
 */
BOOST_AUTO_TEST_CASE(transaction_chain) {
    // Transaction 1: Creates an output
    CTransaction tx1;
    tx1.nVersion = 1;

    // tx1 is coinbase
    std::vector<uint8_t> coinbase_script = {0x01, 0x02};
    tx1.vin.push_back(CTxIn(COutPoint(), coinbase_script, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> pubkey = {0xAA, 0xBB};
    tx1.vout.push_back(CTxOut(50 * COIN, pubkey));

    BOOST_CHECK(tx1.CheckBasicStructure());
    uint256 tx1_hash = tx1.GetHash();

    // Transaction 2: Spends tx1's output
    CTransaction tx2;
    tx2.nVersion = 1;

    // Spend output 0 of tx1
    std::vector<uint8_t> signature = {0xCC, 0xDD};
    tx2.vin.push_back(CTxIn(tx1_hash, 0, signature, CTxIn::SEQUENCE_FINAL));

    // Send to new output
    tx2.vout.push_back(CTxOut(49 * COIN, pubkey));  // 49 DIL (1 DIL fee)

    BOOST_CHECK(tx2.CheckBasicStructure());
    BOOST_CHECK(!tx2.IsCoinBase());

    // Verify the chain
    BOOST_CHECK(tx2.vin[0].prevout.hash == tx1_hash);
    BOOST_CHECK_EQUAL(tx2.vin[0].prevout.n, 0);
}

/**
 * Integration Test 4: Difficulty Target Conversion → PoW Checking
 */
BOOST_AUTO_TEST_CASE(difficulty_pow_integration) {
    // Step 1: Convert difficulty bits to target
    uint32_t difficulty_bits = 0x1d00ffff;  // MIN_DIFFICULTY_BITS
    uint256 target = CompactToBig(difficulty_bits);

    BOOST_CHECK(!target.IsNull());

    // Step 2: Create a block hash that's definitely below target
    uint256 easy_hash;
    memset(easy_hash.data, 0, 32);
    easy_hash.data[0] = 0x01;

    // Step 3: Verify PoW
    bool pow_valid = CheckProofOfWork(easy_hash, difficulty_bits);
    BOOST_CHECK(pow_valid);

    // Step 4: Create hash above target
    uint256 hard_hash;
    memset(hard_hash.data, 0xFF, 32);

    bool pow_invalid = CheckProofOfWork(hard_hash, difficulty_bits);
    BOOST_CHECK(!pow_invalid);
}

/**
 * Integration Test 5: Multiple Transaction Block
 */
BOOST_AUTO_TEST_CASE(block_with_multiple_transactions) {
    // Create 3 transactions
    std::vector<CTransaction> transactions;

    // tx1: Coinbase
    CTransaction tx1;
    tx1.nVersion = 1;
    std::vector<uint8_t> cb_script = {0x01, 0x00};  // Coinbase scriptSig must be 2-100 bytes
    tx1.vin.push_back(CTxIn(COutPoint(), cb_script, CTxIn::SEQUENCE_FINAL));
    std::vector<uint8_t> pk = {0xAA};
    tx1.vout.push_back(CTxOut(50 * COIN, pk));
    transactions.push_back(tx1);

    // tx2: Regular transaction
    CTransaction tx2;
    tx2.nVersion = 1;
    uint256 prev_hash = tx1.GetHash();
    tx2.vin.push_back(CTxIn(prev_hash, 0, pk, CTxIn::SEQUENCE_FINAL));
    tx2.vout.push_back(CTxOut(25 * COIN, pk));
    tx2.vout.push_back(CTxOut(24 * COIN, pk));
    transactions.push_back(tx2);

    // tx3: Another transaction
    CTransaction tx3;
    tx3.nVersion = 1;
    uint256 prev_hash2 = tx2.GetHash();
    tx3.vin.push_back(CTxIn(prev_hash2, 0, pk, CTxIn::SEQUENCE_FINAL));
    tx3.vout.push_back(CTxOut(24 * COIN, pk));
    transactions.push_back(tx3);

    // Validate all transactions
    for (const auto& tx : transactions) {
        BOOST_CHECK(tx.CheckBasicStructure());
        BOOST_CHECK(!tx.GetHash().IsNull());
    }

    // Create block (simplified - would normally compute merkle root of all txs)
    CBlock block;
    block.nVersion = 1;
    block.nTime = 1234567890;
    block.nBits = 0x1f0fffff;

    // Verify block can be created
    uint256 block_hash = block.GetHash();
    BOOST_CHECK(!block_hash.IsNull());
}

/**
 * Integration Test 6: Transaction Value Calculations
 */
BOOST_AUTO_TEST_CASE(transaction_value_flow) {
    // Create transaction with multiple inputs and outputs
    CTransaction tx;
    tx.nVersion = 1;

    // Add 3 inputs (spending previous outputs)
    uint256 prev_hash;
    memset(prev_hash.data, 0x11, 32);
    std::vector<uint8_t> sig = {0x22};

    tx.vin.push_back(CTxIn(prev_hash, 0, sig, CTxIn::SEQUENCE_FINAL));
    tx.vin.push_back(CTxIn(prev_hash, 1, sig, CTxIn::SEQUENCE_FINAL));
    tx.vin.push_back(CTxIn(prev_hash, 2, sig, CTxIn::SEQUENCE_FINAL));

    // Add 2 outputs
    std::vector<uint8_t> pk = {0x33};
    tx.vout.push_back(CTxOut(10 * COIN, pk));
    tx.vout.push_back(CTxOut(5 * COIN, pk));

    // Calculate total output value
    uint64_t total_out = tx.GetValueOut();
    BOOST_CHECK_EQUAL(total_out, 15 * COIN);

    // Verify structure
    BOOST_CHECK(tx.CheckBasicStructure());
    BOOST_CHECK_EQUAL(tx.vin.size(), 3);
    BOOST_CHECK_EQUAL(tx.vout.size(), 2);
}

/**
 * Integration Test 7: Serialization Size Calculations
 */
BOOST_AUTO_TEST_CASE(serialization_size_accuracy) {
    // Create transaction with known size
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 12345;

    uint256 hash;
    memset(hash.data, 0x42, 32);
    std::vector<uint8_t> script(75, 0xAA);  // 75-byte script

    tx.vin.push_back(CTxIn(hash, 0, script, CTxIn::SEQUENCE_FINAL));
    tx.vout.push_back(CTxOut(50 * COIN, script));

    // Get calculated size
    size_t calculated_size = tx.GetSerializedSize();

    // Actually serialize
    std::vector<uint8_t> serialized = tx.Serialize();

    // Sizes should match exactly
    BOOST_CHECK_EQUAL(calculated_size, serialized.size());

    // Size should be reasonable (> 0 and < 1KB for simple tx)
    BOOST_CHECK(serialized.size() > 50);
    BOOST_CHECK(serialized.size() < 1000);
}

/**
 * Integration Test 8: Hash Uniqueness Across Modifications
 */
BOOST_AUTO_TEST_CASE(transaction_hash_sensitivity) {
    // Create base transaction
    CTransaction base;
    base.nVersion = 1;

    uint256 prev;
    memset(prev.data, 0x42, 32);
    std::vector<uint8_t> script = {0x01, 0x02};

    base.vin.push_back(CTxIn(prev, 0, script, CTxIn::SEQUENCE_FINAL));
    base.vout.push_back(CTxOut(50 * COIN, script));

    uint256 base_hash = base.GetHash();

    // Modify version
    CTransaction modified1 = base;
    modified1.nVersion = 2;
    BOOST_CHECK(modified1.GetHash() != base_hash);

    // Modify locktime
    CTransaction modified2 = base;
    modified2.nLockTime = 100;
    BOOST_CHECK(modified2.GetHash() != base_hash);

    // Modify input script
    CTransaction modified3 = base;
    modified3.vin[0].scriptSig.push_back(0x03);
    BOOST_CHECK(modified3.GetHash() != base_hash);

    // Modify output value
    CTransaction modified4 = base;
    modified4.vout[0].nValue = 49 * COIN;
    BOOST_CHECK(modified4.GetHash() != base_hash);

    // All modifications should produce unique hashes
    BOOST_CHECK(modified1.GetHash() != modified2.GetHash());
    BOOST_CHECK(modified2.GetHash() != modified3.GetHash());
    BOOST_CHECK(modified3.GetHash() != modified4.GetHash());
}

BOOST_AUTO_TEST_SUITE_END() // validation_integration_tests
