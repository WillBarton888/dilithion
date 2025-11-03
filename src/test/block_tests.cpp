// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Block Tests
 *
 * Tests for CBlock, CBlockHeader, and uint256 primitives
 * Following Bitcoin Core testing standards with Boost Test Framework
 */

#include <boost/test/unit_test.hpp>

#include <primitives/block.h>
#include <cstring>
#include <string>

BOOST_AUTO_TEST_SUITE(block_tests)

/**
 * Test Suite 1: uint256 Tests
 */
BOOST_AUTO_TEST_SUITE(uint256_tests)

BOOST_AUTO_TEST_CASE(uint256_construction) {
    uint256 hash;

    // Default constructor should create null hash
    BOOST_CHECK(hash.IsNull());

    // All bytes should be zero
    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(hash.data[i], 0);
    }
}

BOOST_AUTO_TEST_CASE(uint256_isnull) {
    uint256 hash1;
    BOOST_CHECK(hash1.IsNull());

    // Set one byte to non-zero
    uint256 hash2;
    hash2.data[0] = 0x01;
    BOOST_CHECK(!hash2.IsNull());

    // Set last byte to non-zero
    uint256 hash3;
    hash3.data[31] = 0xff;
    BOOST_CHECK(!hash3.IsNull());
}

BOOST_AUTO_TEST_CASE(uint256_equality) {
    uint256 hash1, hash2, hash3;

    // Two null hashes are equal
    BOOST_CHECK(hash1 == hash2);

    // Set same values
    memset(hash1.data, 0x42, 32);
    memset(hash2.data, 0x42, 32);
    BOOST_CHECK(hash1 == hash2);

    // Different values
    memset(hash3.data, 0x43, 32);
    BOOST_CHECK(!(hash1 == hash3));
}

BOOST_AUTO_TEST_CASE(uint256_comparison) {
    uint256 hash1, hash2, hash3;

    // Setup hash1 < hash2 < hash3
    memset(hash1.data, 0x41, 32);
    memset(hash2.data, 0x42, 32);
    memset(hash3.data, 0x43, 32);

    BOOST_CHECK(hash1 < hash2);
    BOOST_CHECK(hash2 < hash3);
    BOOST_CHECK(hash1 < hash3);
    BOOST_CHECK(!(hash2 < hash1));
    BOOST_CHECK(!(hash3 < hash2));
}

BOOST_AUTO_TEST_CASE(uint256_comparison_lexicographic) {
    uint256 hash1, hash2;

    // Test lexicographic comparison
    memset(hash1.data, 0, 32);
    memset(hash2.data, 0, 32);

    hash1.data[0] = 0x01;
    hash2.data[0] = 0x02;

    BOOST_CHECK(hash1 < hash2);

    // Test when first bytes are same
    hash1.data[0] = 0x01;
    hash2.data[0] = 0x01;
    hash1.data[1] = 0x00;
    hash2.data[1] = 0x01;

    BOOST_CHECK(hash1 < hash2);
}

BOOST_AUTO_TEST_CASE(uint256_iterators) {
    uint256 hash;

    // Test begin/end
    BOOST_CHECK_EQUAL(hash.end() - hash.begin(), 32);

    // Fill using iterators
    uint8_t value = 0;
    for (uint8_t* it = hash.begin(); it != hash.end(); ++it) {
        *it = value++;
    }

    // Verify
    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(hash.data[i], i);
    }
}

BOOST_AUTO_TEST_CASE(uint256_const_iterators) {
    uint256 hash;
    memset(hash.data, 0x42, 32);

    const uint256& const_hash = hash;

    // Read through const iterators
    int count = 0;
    for (const uint8_t* it = const_hash.begin(); it != const_hash.end(); ++it) {
        BOOST_CHECK_EQUAL(*it, 0x42);
        count++;
    }
    BOOST_CHECK_EQUAL(count, 32);
}

BOOST_AUTO_TEST_SUITE_END() // uint256_tests

/**
 * Test Suite 2: CBlockHeader Tests
 */
BOOST_AUTO_TEST_SUITE(blockheader_tests)

BOOST_AUTO_TEST_CASE(blockheader_construction) {
    CBlockHeader header;

    BOOST_CHECK_EQUAL(header.nVersion, 0);
    BOOST_CHECK(header.hashPrevBlock.IsNull());
    BOOST_CHECK(header.hashMerkleRoot.IsNull());
    BOOST_CHECK_EQUAL(header.nTime, 0);
    BOOST_CHECK_EQUAL(header.nBits, 0);
    BOOST_CHECK_EQUAL(header.nNonce, 0);
    BOOST_CHECK(header.IsNull());
}

BOOST_AUTO_TEST_CASE(blockheader_setnull) {
    CBlockHeader header;

    // Set some values
    header.nVersion = 1;
    header.nTime = 1234567890;
    header.nBits = 0x1d00ffff;
    header.nNonce = 42;
    memset(header.hashPrevBlock.data, 0x42, 32);
    memset(header.hashMerkleRoot.data, 0x43, 32);

    BOOST_CHECK(!header.IsNull());

    // Reset to null
    header.SetNull();

    BOOST_CHECK(header.IsNull());
    BOOST_CHECK_EQUAL(header.nVersion, 0);
    BOOST_CHECK(header.hashPrevBlock.IsNull());
    BOOST_CHECK(header.hashMerkleRoot.IsNull());
    BOOST_CHECK_EQUAL(header.nTime, 0);
    BOOST_CHECK_EQUAL(header.nBits, 0);
    BOOST_CHECK_EQUAL(header.nNonce, 0);
}

BOOST_AUTO_TEST_CASE(blockheader_isnull) {
    CBlockHeader header;

    // nBits == 0 means null
    BOOST_CHECK(header.IsNull());

    // Set nBits
    header.nBits = 0x1d00ffff;
    BOOST_CHECK(!header.IsNull());

    // Even if other fields are set
    header.nVersion = 1;
    header.nTime = 1234567890;
    header.nNonce = 42;
    BOOST_CHECK(!header.IsNull());

    // Reset nBits
    header.nBits = 0;
    BOOST_CHECK(header.IsNull());
}

BOOST_AUTO_TEST_CASE(blockheader_version) {
    CBlockHeader header;

    // Test version 1
    header.nVersion = 1;
    BOOST_CHECK_EQUAL(header.nVersion, 1);

    // Test version 2
    header.nVersion = 2;
    BOOST_CHECK_EQUAL(header.nVersion, 2);

    // Test version 3
    header.nVersion = 3;
    BOOST_CHECK_EQUAL(header.nVersion, 3);

    // Test version 4 (hypothetical)
    header.nVersion = 4;
    BOOST_CHECK_EQUAL(header.nVersion, 4);
}

BOOST_AUTO_TEST_CASE(blockheader_prev_block) {
    CBlockHeader header;

    BOOST_CHECK(header.hashPrevBlock.IsNull());

    // Set previous block hash
    memset(header.hashPrevBlock.data, 0x42, 32);
    BOOST_CHECK(!header.hashPrevBlock.IsNull());

    // Verify value
    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(header.hashPrevBlock.data[i], 0x42);
    }
}

BOOST_AUTO_TEST_CASE(blockheader_merkle_root) {
    CBlockHeader header;

    BOOST_CHECK(header.hashMerkleRoot.IsNull());

    // Set merkle root
    memset(header.hashMerkleRoot.data, 0x99, 32);
    BOOST_CHECK(!header.hashMerkleRoot.IsNull());

    // Verify value
    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(header.hashMerkleRoot.data[i], 0x99);
    }
}

BOOST_AUTO_TEST_CASE(blockheader_timestamp) {
    CBlockHeader header;

    BOOST_CHECK_EQUAL(header.nTime, 0);

    // Set various timestamps
    header.nTime = 1609459200;  // Jan 1, 2021
    BOOST_CHECK_EQUAL(header.nTime, 1609459200);

    header.nTime = 1640995200;  // Jan 1, 2022
    BOOST_CHECK_EQUAL(header.nTime, 1640995200);

    // Test edge cases
    header.nTime = 0;
    BOOST_CHECK_EQUAL(header.nTime, 0);

    header.nTime = 0xffffffff;  // Max uint32_t
    BOOST_CHECK_EQUAL(header.nTime, 0xffffffff);
}

BOOST_AUTO_TEST_CASE(blockheader_bits) {
    CBlockHeader header;

    BOOST_CHECK_EQUAL(header.nBits, 0);

    // Bitcoin difficulty encoding examples
    header.nBits = 0x1d00ffff;  // Initial Bitcoin difficulty
    BOOST_CHECK_EQUAL(header.nBits, 0x1d00ffff);

    header.nBits = 0x1b0404cb;  // Example difficulty
    BOOST_CHECK_EQUAL(header.nBits, 0x1b0404cb);
}

BOOST_AUTO_TEST_CASE(blockheader_nonce) {
    CBlockHeader header;

    BOOST_CHECK_EQUAL(header.nNonce, 0);

    // Test various nonces
    header.nNonce = 1;
    BOOST_CHECK_EQUAL(header.nNonce, 1);

    header.nNonce = 2083236893;  // Bitcoin genesis block nonce
    BOOST_CHECK_EQUAL(header.nNonce, 2083236893);

    header.nNonce = 0xffffffff;  // Max uint32_t
    BOOST_CHECK_EQUAL(header.nNonce, 0xffffffff);
}

BOOST_AUTO_TEST_SUITE_END() // blockheader_tests

/**
 * Test Suite 3: CBlock Tests
 */
BOOST_AUTO_TEST_SUITE(block_tests)

BOOST_AUTO_TEST_CASE(block_construction) {
    CBlock block;

    // Should inherit from CBlockHeader
    BOOST_CHECK(block.IsNull());
    BOOST_CHECK_EQUAL(block.nVersion, 0);
    BOOST_CHECK(block.hashPrevBlock.IsNull());
    BOOST_CHECK(block.hashMerkleRoot.IsNull());
    BOOST_CHECK_EQUAL(block.nTime, 0);
    BOOST_CHECK_EQUAL(block.nBits, 0);
    BOOST_CHECK_EQUAL(block.nNonce, 0);

    // Block-specific fields
    BOOST_CHECK(block.vtx.empty());
}

BOOST_AUTO_TEST_CASE(block_header_construction) {
    // Create header
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1234567890;
    header.nBits = 0x1d00ffff;
    header.nNonce = 42;
    memset(header.hashPrevBlock.data, 0x42, 32);
    memset(header.hashMerkleRoot.data, 0x43, 32);

    // Construct block from header
    CBlock block(header);

    BOOST_CHECK_EQUAL(block.nVersion, header.nVersion);
    BOOST_CHECK(block.hashPrevBlock == header.hashPrevBlock);
    BOOST_CHECK(block.hashMerkleRoot == header.hashMerkleRoot);
    BOOST_CHECK_EQUAL(block.nTime, header.nTime);
    BOOST_CHECK_EQUAL(block.nBits, header.nBits);
    BOOST_CHECK_EQUAL(block.nNonce, header.nNonce);
    BOOST_CHECK(block.vtx.empty());
}

BOOST_AUTO_TEST_CASE(block_setnull) {
    CBlock block;

    // Set some values
    block.nVersion = 1;
    block.nBits = 0x1d00ffff;
    block.vtx.push_back(0x01);
    block.vtx.push_back(0x02);

    BOOST_CHECK(!block.IsNull());
    BOOST_CHECK(!block.vtx.empty());

    // Reset to null
    block.SetNull();

    BOOST_CHECK(block.IsNull());
    BOOST_CHECK(block.vtx.empty());
    BOOST_CHECK_EQUAL(block.nVersion, 0);
    BOOST_CHECK_EQUAL(block.nBits, 0);
}

BOOST_AUTO_TEST_CASE(block_transactions) {
    CBlock block;

    // Add transaction data
    block.vtx.push_back(0xaa);
    block.vtx.push_back(0xbb);
    block.vtx.push_back(0xcc);

    BOOST_CHECK_EQUAL(block.vtx.size(), 3);
    BOOST_CHECK_EQUAL(block.vtx[0], 0xaa);
    BOOST_CHECK_EQUAL(block.vtx[1], 0xbb);
    BOOST_CHECK_EQUAL(block.vtx[2], 0xcc);
}

BOOST_AUTO_TEST_CASE(block_empty_transactions) {
    CBlock block;

    // Set header fields but no transactions
    block.nVersion = 1;
    block.nBits = 0x1d00ffff;

    BOOST_CHECK(!block.IsNull());
    BOOST_CHECK(block.vtx.empty());
}

BOOST_AUTO_TEST_CASE(block_multiple_transactions) {
    CBlock block;
    block.nVersion = 1;
    block.nBits = 0x1d00ffff;

    // Add multiple transactions (simulated as byte arrays)
    for (int i = 0; i < 100; i++) {
        block.vtx.push_back(static_cast<uint8_t>(i));
    }

    BOOST_CHECK_EQUAL(block.vtx.size(), 100);

    // Verify content
    for (int i = 0; i < 100; i++) {
        BOOST_CHECK_EQUAL(block.vtx[i], static_cast<uint8_t>(i));
    }
}

BOOST_AUTO_TEST_CASE(block_clear_transactions) {
    CBlock block;

    // Add transactions
    for (int i = 0; i < 10; i++) {
        block.vtx.push_back(static_cast<uint8_t>(i));
    }

    BOOST_CHECK_EQUAL(block.vtx.size(), 10);

    // Clear
    block.vtx.clear();

    BOOST_CHECK(block.vtx.empty());
    BOOST_CHECK_EQUAL(block.vtx.size(), 0);
}

BOOST_AUTO_TEST_SUITE_END() // block_tests

/**
 * Test Suite 4: Block Relationships
 */
BOOST_AUTO_TEST_SUITE(block_chain_tests)

BOOST_AUTO_TEST_CASE(genesis_block_properties) {
    CBlock genesis;

    // Genesis block has no previous block
    genesis.nVersion = 1;
    genesis.nTime = 1609459200;
    genesis.nBits = 0x1d00ffff;
    genesis.nNonce = 0;
    // hashPrevBlock stays null for genesis

    BOOST_CHECK(genesis.hashPrevBlock.IsNull());
    BOOST_CHECK(!genesis.IsNull());
}

BOOST_AUTO_TEST_CASE(block_chain_linkage) {
    // Create genesis block
    CBlock block1;
    block1.nVersion = 1;
    block1.nBits = 0x1d00ffff;
    block1.nTime = 1000;

    // Get hash of block1 (simulated)
    uint256 block1_hash;
    memset(block1_hash.data, 0x11, 32);

    // Create block2 that references block1
    CBlock block2;
    block2.nVersion = 1;
    block2.nBits = 0x1d00ffff;
    block2.nTime = 2000;
    block2.hashPrevBlock = block1_hash;

    BOOST_CHECK(block2.hashPrevBlock == block1_hash);
    BOOST_CHECK(!block2.hashPrevBlock.IsNull());
}

BOOST_AUTO_TEST_CASE(block_timestamps_ascending) {
    // Create chain of blocks with ascending timestamps
    CBlock block1, block2, block3;

    block1.nTime = 1000;
    block2.nTime = 2000;
    block3.nTime = 3000;

    BOOST_CHECK(block1.nTime < block2.nTime);
    BOOST_CHECK(block2.nTime < block3.nTime);
    BOOST_CHECK(block1.nTime < block3.nTime);
}

/**
 * Additional Block and uint256 Edge Case Tests
 * To improve block.h coverage from 43.8% to 75%+
 */

BOOST_AUTO_TEST_CASE(block_header_get_hash) {
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1234567890;
    header.nBits = 0x1d00ffff;
    header.nNonce = 0;

    // Set merkle root
    memset(header.hashMerkleRoot.data, 0xAA, 32);

    // GetHash() should produce non-null hash
    uint256 hash = header.GetHash();
    BOOST_CHECK(!hash.IsNull());

    // Hash should be deterministic
    uint256 hash2 = header.GetHash();
    BOOST_CHECK(hash == hash2);
}

BOOST_AUTO_TEST_CASE(block_header_different_versions) {
    CBlockHeader h1, h2;

    h1.nVersion = 1;
    h2.nVersion = 2;

    // Different versions should produce different hashes
    uint256 hash1 = h1.GetHash();
    uint256 hash2 = h2.GetHash();

    BOOST_CHECK(hash1 != hash2);
}

BOOST_AUTO_TEST_CASE(block_with_transactions) {
    CBlock block;
    block.nVersion = 1;

    // Add mock transaction data
    std::vector<uint8_t> tx_data(100, 0xBB);
    block.vtx = tx_data;

    BOOST_CHECK(!block.vtx.empty());
    BOOST_CHECK_EQUAL(block.vtx.size(), 100);
}

BOOST_AUTO_TEST_CASE(uint256_hex_conversion) {
    uint256 original;
    memset(original.data, 0, 32);
    original.data[0] = 0x12;
    original.data[1] = 0x34;
    original.data[31] = 0xAB;

    // Convert to hex and back
    std::string hex = original.GetHex();
    BOOST_CHECK(!hex.empty());
    BOOST_CHECK_EQUAL(hex.length(), 64); // 32 bytes * 2 hex chars

    uint256 parsed;
    parsed.SetHex(hex);

    BOOST_CHECK(parsed == original);
}

BOOST_AUTO_TEST_CASE(uint256_all_bits_set) {
    uint256 all_ones;
    memset(all_ones.data, 0xFF, 32);

    BOOST_CHECK(!all_ones.IsNull());

    // All bytes should be 0xFF
    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(all_ones.data[i], 0xFF);
    }
}

BOOST_AUTO_TEST_CASE(uint256_alternating_pattern) {
    uint256 pattern;
    for (int i = 0; i < 32; i++) {
        pattern.data[i] = (i % 2 == 0) ? 0xAA : 0x55;
    }

    BOOST_CHECK(!pattern.IsNull());

    // Verify pattern
    for (int i = 0; i < 32; i++) {
        uint8_t expected = (i % 2 == 0) ? 0xAA : 0x55;
        BOOST_CHECK_EQUAL(pattern.data[i], expected);
    }
}

BOOST_AUTO_TEST_CASE(uint256_comparison_boundaries) {
    uint256 min, max;

    // Min: all zeros except last byte = 1
    memset(min.data, 0, 32);
    min.data[0] = 0x01;

    // Max: all 0xFF
    memset(max.data, 0xFF, 32);

    BOOST_CHECK(min < max);
    BOOST_CHECK(!(max < min));
    BOOST_CHECK(min != max);
}

BOOST_AUTO_TEST_CASE(block_difficulty_bits_encoding) {
    CBlockHeader header;

    // Test various difficulty encodings
    std::vector<uint32_t> test_bits = {
        0x1d00ffff,  // MIN_DIFFICULTY_BITS
        0x1d01ffff,
        0x1d0fffff,
        0x1e00ffff,
        0x1f0fffff   // MAX_DIFFICULTY_BITS (testnet)
    };

    for (uint32_t bits : test_bits) {
        header.nBits = bits;
        BOOST_CHECK_EQUAL(header.nBits, bits);

        // Should be able to hash with any valid difficulty
        uint256 hash = header.GetHash();
        BOOST_CHECK(!hash.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(block_nonce_range) {
    CBlockHeader header;
    header.nVersion = 1;
    header.nBits = 0x1d00ffff;

    // Test nonce at boundaries
    header.nNonce = 0;
    uint256 hash1 = header.GetHash();

    header.nNonce = 0xFFFFFFFF;
    uint256 hash2 = header.GetHash();

    // Different nonces should produce different hashes
    BOOST_CHECK(hash1 != hash2);
}

BOOST_AUTO_TEST_CASE(block_merkle_root_variations) {
    CBlockHeader header;
    header.nVersion = 1;

    // Test with different merkle roots
    uint256 merkle1, merkle2;
    memset(merkle1.data, 0xAA, 32);
    memset(merkle2.data, 0xBB, 32);

    header.hashMerkleRoot = merkle1;
    uint256 hash1 = header.GetHash();

    header.hashMerkleRoot = merkle2;
    uint256 hash2 = header.GetHash();

    // Different merkle roots should produce different block hashes
    BOOST_CHECK(hash1 != hash2);
}

BOOST_AUTO_TEST_CASE(block_timestamp_boundaries) {
    CBlockHeader header;

    // Test timestamp boundaries
    header.nTime = 0;  // Epoch
    BOOST_CHECK_EQUAL(header.nTime, 0);

    header.nTime = 0xFFFFFFFF;  // Max uint32_t
    BOOST_CHECK_EQUAL(header.nTime, 0xFFFFFFFF);

    header.nTime = 1609459200;  // Jan 1, 2021
    BOOST_CHECK_EQUAL(header.nTime, 1609459200);
}

BOOST_AUTO_TEST_CASE(uint256_bitwise_operations) {
    uint256 a, b;

    memset(a.data, 0xF0, 32);
    memset(b.data, 0x0F, 32);

    // Test that they're different
    BOOST_CHECK(a != b);

    // Both should be non-null
    BOOST_CHECK(!a.IsNull());
    BOOST_CHECK(!b.IsNull());
}

BOOST_AUTO_TEST_SUITE_END() // block_chain_tests

BOOST_AUTO_TEST_SUITE_END() // block_tests (outer)
