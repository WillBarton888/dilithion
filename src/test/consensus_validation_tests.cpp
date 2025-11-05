// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Consensus Validation Tests - Week 6 Day 1 Coverage Expansion
 *
 * TARGET: Increase consensus component coverage from 50% to 70%+
 *
 * This file adds comprehensive unit tests for previously untested
 * consensus functions:
 * - consensus/fees.cpp (CalculateMinFee, CheckFee, CalculateFeeRate, EstimateDilithiumTxSize)
 * - consensus/validation.cpp (CalculateBlockSubsidy, BuildMerkleRoot, DeserializeBlockTransactions)
 * - consensus/pow.cpp (GetNextWorkRequired edge cases)
 *
 * Priority: P0 CRITICAL - Consensus functions must be thoroughly tested
 */

#include <boost/test/unit_test.hpp>

#include <consensus/fees.h>
#include <consensus/validation.h>
#include <consensus/pow.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <node/block_index.h>
#include <core/chainparams.h>
#include <amount.h>
#include <uint256.h>
#include <crypto/sha3.h>

#include <vector>
#include <cstring>
#include <memory>

BOOST_AUTO_TEST_SUITE(consensus_validation_tests)

// ============================================================================
// FEES TESTS (consensus/fees.cpp)
// ============================================================================

/**
 * Test CalculateMinFee with various transaction sizes
 */
BOOST_AUTO_TEST_CASE(calculate_min_fee_various_sizes) {
    using namespace Consensus;

    // Test minimum transaction size
    CAmount min_fee_small = CalculateMinFee(100);
    BOOST_CHECK(min_fee_small >= MIN_TX_FEE);
    BOOST_CHECK_EQUAL(min_fee_small, MIN_TX_FEE + (100 * FEE_PER_BYTE));

    // Test medium transaction size
    CAmount min_fee_medium = CalculateMinFee(1000);
    BOOST_CHECK_EQUAL(min_fee_medium, MIN_TX_FEE + (1000 * FEE_PER_BYTE));

    // Test large transaction size (e.g., many inputs/outputs)
    CAmount min_fee_large = CalculateMinFee(10000);
    BOOST_CHECK_EQUAL(min_fee_large, MIN_TX_FEE + (10000 * FEE_PER_BYTE));

    // Fee should increase with size
    BOOST_CHECK(min_fee_small < min_fee_medium);
    BOOST_CHECK(min_fee_medium < min_fee_large);
}

/**
 * Test CalculateMinFee edge case: zero size
 */
BOOST_AUTO_TEST_CASE(calculate_min_fee_zero_size) {
    using namespace Consensus;

    // Zero size should give just MIN_TX_FEE
    CAmount min_fee = CalculateMinFee(0);
    BOOST_CHECK_EQUAL(min_fee, MIN_TX_FEE);
}

/**
 * Test CheckFee with valid fee
 */
BOOST_AUTO_TEST_CASE(check_fee_valid) {
    using namespace Consensus;

    // Create a transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    // Add minimal input and output
    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx.vout.push_back(CTxOut(25 * COIN, scriptPubKey));

    // Calculate required fee
    size_t tx_size = tx.GetSerializedSize();
    CAmount min_fee = CalculateMinFee(tx_size);
    CAmount paid_fee = min_fee + 1000;  // Pay slightly more

    // Should pass
    std::string error;
    BOOST_CHECK(CheckFee(tx, paid_fee, false, &error));
    BOOST_CHECK(error.empty());
}

/**
 * Test CheckFee with fee too low
 */
BOOST_AUTO_TEST_CASE(check_fee_too_low) {
    using namespace Consensus;

    // Create a transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx.vout.push_back(CTxOut(25 * COIN, scriptPubKey));

    // Pay less than minimum fee
    size_t tx_size = tx.GetSerializedSize();
    CAmount min_fee = CalculateMinFee(tx_size);
    CAmount paid_fee = min_fee - 1;  // Pay less

    // Should fail
    std::string error;
    BOOST_CHECK(!CheckFee(tx, paid_fee, false, &error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(error.find("Fee too low") != std::string::npos);
}

/**
 * Test CheckFee with fee too high (unreasonable)
 */
BOOST_AUTO_TEST_CASE(check_fee_too_high) {
    using namespace Consensus;

    // Create a transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx.vout.push_back(CTxOut(25 * COIN, scriptPubKey));

    // Pay more than MAX_REASONABLE_FEE
    CAmount paid_fee = MAX_REASONABLE_FEE + 1;

    // Should fail
    std::string error;
    BOOST_CHECK(!CheckFee(tx, paid_fee, false, &error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(error.find("Fee too high") != std::string::npos);
}

/**
 * Test CheckFee with relay check
 */
BOOST_AUTO_TEST_CASE(check_fee_relay_check) {
    using namespace Consensus;

    // Create a transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx.vout.push_back(CTxOut(25 * COIN, scriptPubKey));

    // Pay minimum fee but below relay minimum
    size_t tx_size = tx.GetSerializedSize();
    CAmount min_fee = CalculateMinFee(tx_size);
    CAmount paid_fee = std::min(min_fee, MIN_RELAY_TX_FEE - 1);

    // Should pass without relay check
    std::string error;
    BOOST_CHECK(CheckFee(tx, paid_fee + 1000, false, &error));

    // Should fail with relay check if below MIN_RELAY_TX_FEE
    if (paid_fee < MIN_RELAY_TX_FEE) {
        error.clear();
        BOOST_CHECK(!CheckFee(tx, paid_fee, true, &error));
        BOOST_CHECK(error.find("Below relay min") != std::string::npos);
    }
}

/**
 * Test CalculateFeeRate
 */
BOOST_AUTO_TEST_CASE(calculate_fee_rate) {
    using namespace Consensus;

    // Test normal fee rate calculation
    CAmount fee = 1000 * COIN;
    size_t size = 1000;
    double rate = CalculateFeeRate(fee, size);
    BOOST_CHECK_EQUAL(rate, static_cast<double>(fee) / static_cast<double>(size));

    // Test with different values
    fee = 5000;
    size = 2500;
    rate = CalculateFeeRate(fee, size);
    BOOST_CHECK_EQUAL(rate, 2.0);
}

/**
 * Test CalculateFeeRate with zero size
 */
BOOST_AUTO_TEST_CASE(calculate_fee_rate_zero_size) {
    using namespace Consensus;

    // Zero size should return 0.0 to avoid division by zero
    CAmount fee = 1000;
    double rate = CalculateFeeRate(fee, 0);
    BOOST_CHECK_EQUAL(rate, 0.0);
}

/**
 * Test EstimateDilithiumTxSize
 */
BOOST_AUTO_TEST_CASE(estimate_dilithium_tx_size) {
    using namespace Consensus;

    // Test single input, single output (typical payment)
    size_t est_size = EstimateDilithiumTxSize(1, 1, 0);
    // Formula: 42 + (1 * 3782) + (1 * 40) + 0 = 3864 bytes
    BOOST_CHECK_EQUAL(est_size, 42 + 3782 + 40);

    // Test multiple inputs/outputs
    est_size = EstimateDilithiumTxSize(2, 2, 0);
    // Formula: 42 + (2 * 3782) + (2 * 40) + 0 = 7686 bytes
    BOOST_CHECK_EQUAL(est_size, 42 + (2 * 3782) + (2 * 40));

    // Test with extra data
    est_size = EstimateDilithiumTxSize(1, 1, 100);
    BOOST_CHECK_EQUAL(est_size, 42 + 3782 + 40 + 100);
}

// ============================================================================
// VALIDATION TESTS (consensus/validation.cpp)
// ============================================================================

/**
 * Test CalculateBlockSubsidy at genesis
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_genesis) {
    CBlockValidator validator;

    // Genesis block should have full subsidy
    uint64_t subsidy = validator.CalculateBlockSubsidy(0);
    BOOST_CHECK_EQUAL(subsidy, 50 * COIN);
}

/**
 * Test CalculateBlockSubsidy before first halving
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_before_halving) {
    CBlockValidator validator;

    // Block 100,000 (before halving at 210,000)
    uint64_t subsidy = validator.CalculateBlockSubsidy(100000);
    BOOST_CHECK_EQUAL(subsidy, 50 * COIN);

    // Block 209,999 (last block before halving)
    subsidy = validator.CalculateBlockSubsidy(209999);
    BOOST_CHECK_EQUAL(subsidy, 50 * COIN);
}

/**
 * Test CalculateBlockSubsidy at first halving
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_first_halving) {
    CBlockValidator validator;

    // Block 210,000 (first halving)
    uint64_t subsidy = validator.CalculateBlockSubsidy(210000);
    BOOST_CHECK_EQUAL(subsidy, 25 * COIN);

    // Block 210,001
    subsidy = validator.CalculateBlockSubsidy(210001);
    BOOST_CHECK_EQUAL(subsidy, 25 * COIN);
}

/**
 * Test CalculateBlockSubsidy at second halving
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_second_halving) {
    CBlockValidator validator;

    // Block 420,000 (second halving)
    uint64_t subsidy = validator.CalculateBlockSubsidy(420000);
    BOOST_CHECK_EQUAL(subsidy, 12.5 * COIN);
}

/**
 * Test CalculateBlockSubsidy at third halving
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_third_halving) {
    CBlockValidator validator;

    // Block 630,000 (third halving)
    uint64_t subsidy = validator.CalculateBlockSubsidy(630000);
    BOOST_CHECK_EQUAL(subsidy, 6.25 * COIN);
}

/**
 * Test CalculateBlockSubsidy after 64 halvings (zero subsidy)
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_after_64_halvings) {
    CBlockValidator validator;

    // After 64 halvings, subsidy should be 0
    uint32_t height = 64 * 210000;
    uint64_t subsidy = validator.CalculateBlockSubsidy(height);
    BOOST_CHECK_EQUAL(subsidy, 0);

    // Way in the future
    subsidy = validator.CalculateBlockSubsidy(height + 1000000);
    BOOST_CHECK_EQUAL(subsidy, 0);
}

/**
 * Test BuildMerkleRoot with empty transactions
 */
BOOST_AUTO_TEST_CASE(build_merkle_root_empty) {
    CBlockValidator validator;

    std::vector<CTransactionRef> transactions;
    uint256 root = validator.BuildMerkleRoot(transactions);

    // Empty block should have null root
    BOOST_CHECK(root.IsNull());
}

/**
 * Test BuildMerkleRoot with single transaction
 */
BOOST_AUTO_TEST_CASE(build_merkle_root_single_tx) {
    CBlockValidator validator;

    // Create a transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx.vout.push_back(CTxOut(25 * COIN, scriptPubKey));

    // Build merkle root
    std::vector<CTransactionRef> transactions;
    transactions.push_back(std::make_shared<CTransaction>(tx));

    uint256 root = validator.BuildMerkleRoot(transactions);

    // Root should equal transaction hash for single tx
    BOOST_CHECK_EQUAL(root, tx.GetHash());
}

/**
 * Test BuildMerkleRoot with two transactions
 */
BOOST_AUTO_TEST_CASE(build_merkle_root_two_tx) {
    CBlockValidator validator;

    // Create two transactions
    CTransaction tx1, tx2;
    tx1.nVersion = 1;
    tx1.nLockTime = 0;
    tx2.nVersion = 1;
    tx2.nLockTime = 1;  // Make different from tx1

    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx1.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));
    tx2.vin.push_back(CTxIn(prevHash, 1, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx1.vout.push_back(CTxOut(25 * COIN, scriptPubKey));
    tx2.vout.push_back(CTxOut(30 * COIN, scriptPubKey));

    // Build merkle root
    std::vector<CTransactionRef> transactions;
    transactions.push_back(std::make_shared<CTransaction>(tx1));
    transactions.push_back(std::make_shared<CTransaction>(tx2));

    uint256 root = validator.BuildMerkleRoot(transactions);

    // Root should be hash of combined tx hashes
    BOOST_CHECK(!root.IsNull());
    BOOST_CHECK(root != tx1.GetHash());
    BOOST_CHECK(root != tx2.GetHash());
}

/**
 * Test BuildMerkleRoot with multiple transactions (odd count)
 */
BOOST_AUTO_TEST_CASE(build_merkle_root_odd_count) {
    CBlockValidator validator;

    // Create three transactions
    std::vector<CTransactionRef> transactions;

    for (int i = 0; i < 3; i++) {
        CTransaction tx;
        tx.nVersion = 1;
        tx.nLockTime = i;  // Make each different

        uint256 prevHash;
        memset(prevHash.data, 0x42 + i, 32);
        std::vector<uint8_t> sig(100, 0xAA + i);
        tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

        std::vector<uint8_t> scriptPubKey(50, 0xBB + i);
        tx.vout.push_back(CTxOut((25 + i) * COIN, scriptPubKey));

        transactions.push_back(std::make_shared<CTransaction>(tx));
    }

    uint256 root = validator.BuildMerkleRoot(transactions);

    // Root should be non-null and different from any individual tx
    BOOST_CHECK(!root.IsNull());
    for (const auto& tx : transactions) {
        BOOST_CHECK(root != tx->GetHash());
    }
}

/**
 * Test BuildMerkleRoot determinism
 */
BOOST_AUTO_TEST_CASE(build_merkle_root_determinism) {
    CBlockValidator validator;

    // Create transactions
    std::vector<CTransactionRef> transactions;

    for (int i = 0; i < 4; i++) {
        CTransaction tx;
        tx.nVersion = 1;
        tx.nLockTime = i;

        uint256 prevHash;
        memset(prevHash.data, i, 32);
        std::vector<uint8_t> sig(100, i);
        tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

        std::vector<uint8_t> scriptPubKey(50, i);
        tx.vout.push_back(CTxOut(i * COIN, scriptPubKey));

        transactions.push_back(std::make_shared<CTransaction>(tx));
    }

    // Build root twice
    uint256 root1 = validator.BuildMerkleRoot(transactions);
    uint256 root2 = validator.BuildMerkleRoot(transactions);

    // Should be identical (deterministic)
    BOOST_CHECK_EQUAL(root1, root2);
}

// ============================================================================
// POW TESTS - GetNextWorkRequired Edge Cases (consensus/pow.cpp)
// ============================================================================

/**
 * Test GetNextWorkRequired with nullptr (genesis case)
 */
BOOST_AUTO_TEST_CASE(get_next_work_required_nullptr) {
    // Initialize chain params if needed
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams();
        Dilithion::g_chainParams->genesisNBits = 0x1d00ffff;
        Dilithion::g_chainParams->difficultyAdjustment = 2016;
        Dilithion::g_chainParams->blockTime = 240;
    }

    // No previous block should return genesis difficulty
    uint32_t nBits = GetNextWorkRequired(nullptr);
    BOOST_CHECK_EQUAL(nBits, Dilithion::g_chainParams->genesisNBits);
}

/**
 * Test GetNextWorkRequired between adjustment periods
 */
BOOST_AUTO_TEST_CASE(get_next_work_required_between_adjustments) {
    // Initialize chain params
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams();
        Dilithion::g_chainParams->genesisNBits = 0x1d00ffff;
        Dilithion::g_chainParams->difficultyAdjustment = 2016;
        Dilithion::g_chainParams->blockTime = 240;
    }

    // Create a block index at height 100 (not at adjustment point)
    CBlockIndex index;
    index.nHeight = 100;
    index.nTime = 24000;
    index.header.nBits = 0x1d00ffff;
    index.nBits = 0x1d00ffff;
    index.pprev = nullptr;

    // Should return same difficulty (not at adjustment point)
    uint32_t nBits = GetNextWorkRequired(&index);
    BOOST_CHECK_EQUAL(nBits, 0x1d00ffff);
}

/**
 * Test EstimateDilithiumTxSize with multiple scenarios (Week 6 Phase 2.3)
 */
BOOST_AUTO_TEST_CASE(estimate_dilithium_tx_size_multiple_scenarios) {
    using namespace Consensus;

    // Single input/output (minimum transaction)
    size_t min_size = EstimateDilithiumTxSize(1, 1, 0);
    BOOST_CHECK_EQUAL(min_size, 42 + 3782 + 40);  // 3864 bytes

    // Typical payment (2 inputs, 2 outputs - payment + change)
    size_t typical = EstimateDilithiumTxSize(2, 2, 0);
    BOOST_CHECK_EQUAL(typical, 42 + (2 * 3782) + (2 * 40));  // 7686 bytes

    // Large transaction (10 inputs, 10 outputs)
    size_t large = EstimateDilithiumTxSize(10, 10, 0);
    BOOST_CHECK_EQUAL(large, 42 + (10 * 3782) + (10 * 40));  // 38,262 bytes
}

/**
 * Test CalculateFeeRate edge cases (Week 6 Phase 2.3)
 */
BOOST_AUTO_TEST_CASE(calculate_fee_rate_edge_cases) {
    using namespace Consensus;

    // Normal rate
    double rate1 = CalculateFeeRate(1000, 500);
    BOOST_CHECK_EQUAL(rate1, 2.0);

    // Very small rate
    double rate2 = CalculateFeeRate(1, 1000);
    BOOST_CHECK_EQUAL(rate2, 0.001);

    // Very large rate
    double rate3 = CalculateFeeRate(1000000, 1);
    BOOST_CHECK_EQUAL(rate3, 1000000.0);
}

BOOST_AUTO_TEST_SUITE_END()
