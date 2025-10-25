// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/pow.h>
#include <node/block_index.h>
#include <util/time.h>
#include <iostream>
#include <cassert>
#include <vector>

/**
 * Test: GetMedianTimePast() with various chain lengths
 */
void TestMedianTimePast() {
    std::cout << "Testing median-time-past calculation..." << std::endl;

    // Create a chain of 15 blocks with incrementing timestamps
    std::vector<CBlockIndex> chain(15);
    for (size_t i = 0; i < chain.size(); i++) {
        chain[i].nTime = 1000 + i * 600; // 10 minute increments
        chain[i].nHeight = i;
        if (i > 0) {
            chain[i].pprev = &chain[i - 1];
        } else {
            chain[i].pprev = nullptr;
        }
    }

    // Test median with full 11 blocks
    int64_t median = GetMedianTimePast(&chain[14]); // Block 14, uses blocks 14-4
    // Blocks 14-4 have times: 1000+14*600 to 1000+4*600
    // = 9400, 8800, 8200, 7600, 7000, 6400, 5800, 5200, 4600, 4000, 3400
    // Sorted: 3400, 4000, 4600, 5200, 5800, [6400], 7000, 7600, 8200, 8800, 9400
    assert(median == 6400);
    std::cout << "  ✓ Median-time-past with 11 blocks correct (median: " << median << ")" << std::endl;

    // Test median with fewer than 11 blocks
    median = GetMedianTimePast(&chain[5]); // Block 5, uses blocks 5-0 (6 blocks)
    // Blocks 5-0 have times: 4000, 3400, 2800, 2200, 1600, 1000
    // Sorted: 1000, 1600, 2200, [2800], 3400, 4000
    assert(median == 2800);
    std::cout << "  ✓ Median-time-past with 6 blocks correct (median: " << median << ")" << std::endl;

    // Test median with single block (genesis)
    median = GetMedianTimePast(&chain[0]);
    assert(median == 1000);
    std::cout << "  ✓ Median-time-past with 1 block (genesis) correct" << std::endl;
}

/**
 * Test: CheckBlockTimestamp() - Future timestamp validation
 */
void TestFutureTimestamp() {
    std::cout << "\nTesting future timestamp validation..." << std::endl;

    CBlockHeader block;
    int64_t now = GetTime();

    // Test 1: Block 1 hour in future (should accept)
    block.nTime = now + 1 * 60 * 60;
    assert(CheckBlockTimestamp(block, nullptr) == true);
    std::cout << "  ✓ Block 1 hour in future accepted" << std::endl;

    // Test 2: Block exactly 2 hours in future (should accept)
    block.nTime = now + 2 * 60 * 60;
    assert(CheckBlockTimestamp(block, nullptr) == true);
    std::cout << "  ✓ Block 2 hours in future accepted" << std::endl;

    // Test 3: Block 3 hours in future (should reject)
    block.nTime = now + 3 * 60 * 60;
    assert(CheckBlockTimestamp(block, nullptr) == false);
    std::cout << "  ✓ Block 3 hours in future rejected" << std::endl;

    // Test 4: Block 1 day in future (should reject)
    block.nTime = now + 24 * 60 * 60;
    assert(CheckBlockTimestamp(block, nullptr) == false);
    std::cout << "  ✓ Block 1 day in future rejected" << std::endl;
}

/**
 * Test: CheckBlockTimestamp() - Median-time-past validation
 */
void TestMedianTimePastValidation() {
    std::cout << "\nTesting median-time-past validation..." << std::endl;

    // Create a chain of 15 blocks
    std::vector<CBlockIndex> chain(15);
    int64_t baseTime = GetTime() - 10000; // Start 10000 seconds ago
    for (size_t i = 0; i < chain.size(); i++) {
        chain[i].nTime = baseTime + i * 600; // 10 minute increments
        chain[i].nHeight = i;
        if (i > 0) {
            chain[i].pprev = &chain[i - 1];
        } else {
            chain[i].pprev = nullptr;
        }
    }

    CBlockHeader block;
    CBlockIndex* pindexPrev = &chain[14];
    int64_t median = GetMedianTimePast(pindexPrev);

    // Test 1: Block time equal to median-time-past (should reject)
    block.nTime = median;
    assert(CheckBlockTimestamp(block, pindexPrev) == false);
    std::cout << "  ✓ Block time equal to median-time-past rejected" << std::endl;

    // Test 2: Block time less than median-time-past (should reject)
    block.nTime = median - 100;
    assert(CheckBlockTimestamp(block, pindexPrev) == false);
    std::cout << "  ✓ Block time less than median-time-past rejected" << std::endl;

    // Test 3: Block time greater than median-time-past (should accept)
    block.nTime = median + 1;
    assert(CheckBlockTimestamp(block, pindexPrev) == true);
    std::cout << "  ✓ Block time greater than median-time-past accepted" << std::endl;

    // Test 4: Block time much greater than median-time-past (should accept if not too far in future)
    block.nTime = median + 3600; // 1 hour ahead
    assert(CheckBlockTimestamp(block, pindexPrev) == true);
    std::cout << "  ✓ Block time 1 hour after median-time-past accepted" << std::endl;
}

/**
 * Test: CheckBlockTimestamp() - Genesis block (no previous block)
 */
void TestGenesisBlockTimestamp() {
    std::cout << "\nTesting genesis block timestamp validation..." << std::endl;

    CBlockHeader genesis;
    int64_t now = GetTime();

    // Test 1: Genesis block with current time (should accept)
    genesis.nTime = now;
    assert(CheckBlockTimestamp(genesis, nullptr) == true);
    std::cout << "  ✓ Genesis block with current time accepted" << std::endl;

    // Test 2: Genesis block with past time (should accept - no MTP check)
    genesis.nTime = now - 86400; // 1 day ago
    assert(CheckBlockTimestamp(genesis, nullptr) == true);
    std::cout << "  ✓ Genesis block with past time accepted (no MTP validation)" << std::endl;

    // Test 3: Genesis block 3 hours in future (should reject)
    genesis.nTime = now + 3 * 60 * 60;
    assert(CheckBlockTimestamp(genesis, nullptr) == false);
    std::cout << "  ✓ Genesis block 3 hours in future rejected" << std::endl;
}

/**
 * Test: Edge cases
 */
void TestEdgeCases() {
    std::cout << "\nTesting edge cases..." << std::endl;

    // Create minimal chain
    std::vector<CBlockIndex> chain(3);
    int64_t baseTime = GetTime() - 1800; // 30 minutes ago
    for (size_t i = 0; i < chain.size(); i++) {
        chain[i].nTime = baseTime + i * 600;
        chain[i].nHeight = i;
        if (i > 0) {
            chain[i].pprev = &chain[i - 1];
        } else {
            chain[i].pprev = nullptr;
        }
    }

    CBlockHeader block;

    // Test 1: Block exactly at boundary (2 hours + 1 second should reject)
    int64_t now = GetTime();
    block.nTime = now + 2 * 60 * 60 + 1;
    assert(CheckBlockTimestamp(block, &chain[2]) == false);
    std::cout << "  ✓ Block at boundary (2h + 1s) rejected" << std::endl;

    // Test 2: Block with timestamp 0 (should reject - before MTP)
    block.nTime = 0;
    assert(CheckBlockTimestamp(block, &chain[2]) == false);
    std::cout << "  ✓ Block with timestamp 0 rejected" << std::endl;

    // Test 3: Block with maximum uint32_t timestamp (should reject - too far in future)
    block.nTime = 0xFFFFFFFF;
    assert(CheckBlockTimestamp(block, &chain[2]) == false);
    std::cout << "  ✓ Block with maximum timestamp rejected" << std::endl;
}

/**
 * Test: Realistic chain scenario
 */
void TestRealisticChain() {
    std::cout << "\nTesting realistic chain scenario..." << std::endl;

    // Simulate a realistic chain with some timestamp variance
    std::vector<CBlockIndex> chain;
    int64_t baseTime = GetTime() - 7200; // Start 2 hours ago
    int64_t timestamps[] = {0, 610, 580, 615, 605, 590, 620, 595, 610, 600, 615, 605, 620};

    for (size_t i = 0; i < 13; i++) {
        CBlockIndex block;
        if (i == 0) {
            block.nTime = baseTime;
            block.pprev = nullptr;
        } else {
            block.nTime = chain[i - 1].nTime + timestamps[i];
            block.pprev = &chain[i - 1];
        }
        block.nHeight = i;
        chain.push_back(block);
    }

    CBlockHeader newBlock;
    CBlockIndex* tip = &chain.back();
    int64_t median = GetMedianTimePast(tip);

    // Test 1: New block with reasonable timestamp
    newBlock.nTime = tip->nTime + 600; // 10 minutes after tip
    assert(CheckBlockTimestamp(newBlock, tip) == true);
    std::cout << "  ✓ Realistic new block accepted (10 min after tip)" << std::endl;

    // Test 2: Miner tries to use old timestamp (attack)
    newBlock.nTime = median - 100;
    assert(CheckBlockTimestamp(newBlock, tip) == false);
    std::cout << "  ✓ Attack with old timestamp rejected" << std::endl;

    // Test 3: Miner tries future timestamp (attack)
    newBlock.nTime = GetTime() + 3 * 60 * 60;
    assert(CheckBlockTimestamp(newBlock, tip) == false);
    std::cout << "  ✓ Attack with future timestamp rejected" << std::endl;
}

int main() {
    std::cout << "======================================" << std::endl;
    std::cout << "Block Timestamp Validation Tests" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;

    try {
        TestMedianTimePast();
        TestFutureTimestamp();
        TestMedianTimePastValidation();
        TestGenesisBlockTimestamp();
        TestEdgeCases();
        TestRealisticChain();

        std::cout << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "✅ All timestamp validation tests passed!" << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << std::endl;

        std::cout << "Components Validated:" << std::endl;
        std::cout << "  ✓ Median-time-past calculation" << std::endl;
        std::cout << "  ✓ Future timestamp rejection (> 2 hours)" << std::endl;
        std::cout << "  ✓ Median-time-past comparison" << std::endl;
        std::cout << "  ✓ Genesis block handling" << std::endl;
        std::cout << "  ✓ Edge cases" << std::endl;
        std::cout << "  ✓ Realistic chain scenarios" << std::endl;
        std::cout << std::endl;

        std::cout << "Consensus Rules Enforced:" << std::endl;
        std::cout << "  ✓ Block time must not be > 2 hours in future" << std::endl;
        std::cout << "  ✓ Block time must be > median-time-past" << std::endl;
        std::cout << "  ✓ Prevents timestamp manipulation attacks" << std::endl;
        std::cout << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "❌ Test failed: " << e.what() << std::endl;
        return 1;
    }
}
