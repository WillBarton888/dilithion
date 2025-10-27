// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Phase 5.4: Mining Integration Tests
 *
 * Comprehensive test suite for transaction-mining integration.
 * Tests CreateBlockTemplate, fee collection, block validation, etc.
 */

#include <miner/controller.h>
#include <consensus/validation.h>
#include <consensus/tx_validation.h>
#include <node/mempool.h>
#include <node/utxo_set.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <amount.h>

#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>

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
            std::cout << GREEN << "  ✓ PASSED" << RESET << std::endl; \
            g_tests_passed++; \
        } catch (const std::exception& e) { \
            std::cout << RED << "  ✗ FAILED: " << e.what() << RESET << std::endl; \
            g_tests_failed++; \
        } catch (...) { \
            std::cout << RED << "  ✗ FAILED: Unknown exception" << RESET << std::endl; \
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

// Helper function to create a dummy miner address
std::vector<uint8_t> CreateMinerAddress() {
    std::vector<uint8_t> addr(25);  // P2PKH address (1 + 20 + 4 bytes)
    addr[0] = 0x76;  // OP_DUP
    addr[1] = 0xa9;  // OP_HASH160
    addr[2] = 0x14;  // Push 20 bytes
    // 20 bytes of address hash (dummy data)
    for (int i = 0; i < 20; i++) {
        addr[3 + i] = static_cast<uint8_t>(i);
    }
    addr[23] = 0x88;  // OP_EQUALVERIFY
    addr[24] = 0xac;  // OP_CHECKSIG
    return addr;
}

// =======================================================================
// Test 1: Block Subsidy Calculation
// =======================================================================
TEST(block_subsidy_calculation) {
    CMiningController miner(1);

    // Test initial subsidy (50 DIL)
    uint64_t subsidy0 = miner.CalculateBlockSubsidy(0);
    ASSERT_EQ(subsidy0, 50 * COIN, "Initial subsidy should be 50 DIL");

    // Test after first halving (210,000 blocks)
    uint64_t subsidy1 = miner.CalculateBlockSubsidy(210000);
    ASSERT_EQ(subsidy1, 25 * COIN, "First halving should give 25 DIL");

    // Test after second halving (420,000 blocks)
    uint64_t subsidy2 = miner.CalculateBlockSubsidy(420000);
    ASSERT_EQ(subsidy2, 12.5 * COIN, "Second halving should give 12.5 DIL");

    // Test very far in future (subsidy should be 0)
    uint64_t subsidy64 = miner.CalculateBlockSubsidy(210000 * 64);
    ASSERT_EQ(subsidy64, 0, "Subsidy after 64 halvings should be 0");

    std::cout << "    Initial subsidy: " << subsidy0 / COIN << " DIL" << std::endl;
    std::cout << "    After 1st halving: " << subsidy1 / COIN << " DIL" << std::endl;
    std::cout << "    After 2nd halving: " << (subsidy2 / (double)COIN) << " DIL" << std::endl;
}

// =======================================================================
// Test 2: Coinbase Transaction Creation
// =======================================================================
TEST(coinbase_transaction_creation) {
    CMiningController miner(1);
    std::vector<uint8_t> minerAddr = CreateMinerAddress();

    // Create coinbase for block 1 with no fees
    CTransactionRef coinbase1 = miner.CreateCoinbaseTransaction(1, 0, minerAddr);

    ASSERT(coinbase1 != nullptr, "Coinbase transaction should not be null");
    ASSERT(coinbase1->IsCoinBase(), "Transaction should be coinbase");
    ASSERT_EQ(coinbase1->vin.size(), 1, "Coinbase should have exactly 1 input");
    ASSERT_EQ(coinbase1->vout.size(), 1, "Coinbase should have exactly 1 output");
    ASSERT(coinbase1->vin[0].prevout.IsNull(), "Coinbase input prevout should be null");

    // Check coinbase value (should be 50 DIL subsidy + 0 fees)
    uint64_t expectedValue = 50 * COIN;
    ASSERT_EQ(coinbase1->vout[0].nValue, expectedValue, "Coinbase value incorrect");

    // Create coinbase with fees
    uint64_t fees = 0.5 * COIN;  // 0.5 DIL in fees
    CTransactionRef coinbase2 = miner.CreateCoinbaseTransaction(1, fees, minerAddr);

    uint64_t expectedValue2 = 50 * COIN + fees;
    ASSERT_EQ(coinbase2->vout[0].nValue, expectedValue2, "Coinbase with fees value incorrect");

    std::cout << "    Coinbase value (no fees): " << coinbase1->vout[0].nValue / COIN << " DIL" << std::endl;
    std::cout << "    Coinbase value (with 0.5 DIL fees): " << (coinbase2->vout[0].nValue / (double)COIN) << " DIL" << std::endl;
}

// =======================================================================
// Test 3: Merkle Root Calculation
// =======================================================================
TEST(merkle_root_calculation) {
    CMiningController miner(1);
    std::vector<uint8_t> minerAddr = CreateMinerAddress();

    // Create a few test transactions
    CTransactionRef tx1 = miner.CreateCoinbaseTransaction(1, 0, minerAddr);

    std::vector<CTransactionRef> txs;
    txs.push_back(tx1);

    // Build merkle root
    uint256 merkleRoot = miner.BuildMerkleRoot(txs);

    ASSERT(!merkleRoot.IsNull(), "Merkle root should not be null");

    // For single transaction, merkle root should equal transaction hash
    uint256 tx1Hash = tx1->GetHash();
    ASSERT(merkleRoot == tx1Hash, "Merkle root of single TX should equal TX hash");

    std::cout << "    Merkle root (1 TX): " << merkleRoot.GetHex().substr(0, 16) << "..." << std::endl;
}

// =======================================================================
// Test 4: CreateBlockTemplate - Empty Mempool
// =======================================================================
TEST(block_template_empty_mempool) {
    CMiningController miner(1);
    CTxMemPool mempool;
    CUTXOSet utxoSet;

    // Initialize UTXO set
    std::string utxoPath = ".test-mining-utxo";
    system(("rm -rf " + utxoPath).c_str());
    ASSERT(utxoSet.Open(utxoPath, true), "Failed to open UTXO set");

    std::vector<uint8_t> minerAddr = CreateMinerAddress();
    uint256 hashPrevBlock;
    hashPrevBlock.SetHex("0000000000000000000000000000000000000000000000000000000000000001");

    std::string error;
    auto templateOpt = miner.CreateBlockTemplate(
        mempool,
        utxoSet,
        hashPrevBlock,
        1,  // height
        0x1f00ffff,  // nBits
        minerAddr,
        error
    );

    ASSERT(templateOpt.has_value(), std::string("CreateBlockTemplate failed: ") + error);

    CBlockTemplate& blockTemplate = templateOpt.value();
    ASSERT_EQ(blockTemplate.nHeight, 1, "Block height incorrect");
    ASSERT(!blockTemplate.block.hashMerkleRoot.IsNull(), "Merkle root should not be null");
    ASSERT(!blockTemplate.block.vtx.empty(), "Block should have transaction data");

    std::cout << "    Block height: " << blockTemplate.nHeight << std::endl;
    std::cout << "    Merkle root: " << blockTemplate.block.hashMerkleRoot.GetHex().substr(0, 16) << "..." << std::endl;
    std::cout << "    TX data size: " << blockTemplate.block.vtx.size() << " bytes" << std::endl;

    // Cleanup
    utxoSet.Close();
    system(("rm -rf " + utxoPath).c_str());
}

// =======================================================================
// Test 5: Block Validation - Coinbase Check
// =======================================================================
TEST(block_validation_coinbase) {
    CBlockValidator validator;

    // Create valid coinbase
    CTransaction coinbase;
    coinbase.nVersion = 1;
    coinbase.nLockTime = 0;

    CTxIn coinbaseIn;
    coinbaseIn.prevout.SetNull();
    coinbaseIn.scriptSig.push_back(0x01);
    coinbaseIn.scriptSig.push_back(0x00);  // Height 0
    coinbaseIn.scriptSig.insert(coinbaseIn.scriptSig.end(), {'t', 'e', 's', 't'});
    coinbase.vin.push_back(coinbaseIn);

    CTxOut coinbaseOut;
    coinbaseOut.nValue = 50 * COIN;  // Exactly the subsidy
    coinbaseOut.scriptPubKey = CreateMinerAddress();
    coinbase.vout.push_back(coinbaseOut);

    std::string error;

    // Test valid coinbase
    bool valid = validator.CheckCoinbase(coinbase, 0, 0, error);
    ASSERT(valid, std::string("Valid coinbase rejected: ") + error);

    // Test coinbase with excessive value
    coinbase.vout[0].nValue = 100 * COIN;  // Too much!
    valid = validator.CheckCoinbase(coinbase, 0, 0, error);
    ASSERT(!valid, "Coinbase with excessive value should be rejected");

    std::cout << "    Valid coinbase accepted" << std::endl;
    std::cout << "    Excessive coinbase rejected" << std::endl;
}

// =======================================================================
// Test 6: Block Validation - No Duplicates
// =======================================================================
TEST(block_validation_no_duplicates) {
    CBlockValidator validator;
    CMiningController miner(1);
    std::vector<uint8_t> minerAddr = CreateMinerAddress();

    // Create two different transactions
    CTransactionRef tx1 = miner.CreateCoinbaseTransaction(1, 0, minerAddr);
    CTransactionRef tx2 = miner.CreateCoinbaseTransaction(2, 100000, minerAddr);

    std::vector<CTransactionRef> txs1;
    txs1.push_back(tx1);
    txs1.push_back(tx2);

    std::string error;
    bool valid = validator.CheckNoDuplicateTransactions(txs1, error);
    ASSERT(valid, "Should accept transactions with different IDs");

    // Try with duplicates
    std::vector<CTransactionRef> txs2;
    txs2.push_back(tx1);
    txs2.push_back(tx1);  // Duplicate!

    valid = validator.CheckNoDuplicateTransactions(txs2, error);
    ASSERT(!valid, "Should reject duplicate transactions");

    std::cout << "    Unique transactions accepted" << std::endl;
    std::cout << "    Duplicate transactions rejected" << std::endl;
}

// =======================================================================
// Test 7: Subsidy Consistency Check
// =======================================================================
TEST(subsidy_consistency) {
    // Verify that block subsidy calculation is consistent between
    // CMiningController and CBlockValidator

    CMiningController miner(1);

    for (uint32_t height : {0, 1, 100, 210000, 420000, 1000000}) {
        uint64_t minerSubsidy = miner.CalculateBlockSubsidy(height);
        uint64_t validatorSubsidy = CBlockValidator::CalculateBlockSubsidy(height);

        ASSERT_EQ(minerSubsidy, validatorSubsidy,
                  "Subsidy mismatch at height " + std::to_string(height));
    }

    std::cout << "    Subsidy calculations are consistent" << std::endl;
}

// =======================================================================
// Main Test Runner
// =======================================================================
int main() {
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << YELLOW << "Phase 5.4: Mining Integration Tests" << RESET << std::endl;
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << std::endl;

    // Run all tests
    test_block_subsidy_calculation_wrapper();
    test_coinbase_transaction_creation_wrapper();
    test_merkle_root_calculation_wrapper();
    test_block_template_empty_mempool_wrapper();
    test_block_validation_coinbase_wrapper();
    test_block_validation_no_duplicates_wrapper();
    test_subsidy_consistency_wrapper();

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
        std::cout << GREEN << "✓ ALL TESTS PASSED!" << RESET << std::endl;
        return 0;
    } else {
        std::cout << RED << "✗ SOME TESTS FAILED" << RESET << std::endl;
        return 1;
    }
}
