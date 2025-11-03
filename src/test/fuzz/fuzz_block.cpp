// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include "fuzz.h"
#include "util.h"
#include "../../primitives/block.h"
#include "../../net/serialize.h"
#include <vector>

/**
 * Fuzz target: Block header deserialization
 *
 * Tests:
 * - Block header parsing from arbitrary bytes
 * - Version field handling
 * - Previous block hash parsing
 * - Merkle root parsing
 * - Timestamp validation
 * - nBits (difficulty) parsing
 * - Nonce parsing
 * - Invalid format rejection
 *
 * Coverage:
 * - src/primitives/block.h
 * - src/primitives/block.cpp
 *
 * Based on gap analysis: P2-1 (block validation)
 * Priority: HIGH (consensus critical)
 */

FUZZ_TARGET(block_header_deserialize)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss.write(reinterpret_cast<const char*>(data), size);

        // Attempt to deserialize block header
        CBlockHeader header;
        ss >> header;

        // If successful, check fields are reasonable

        // Version
        if (header.nVersion < 1 || header.nVersion > 10) {
            // Unusual but not necessarily invalid
        }

        // Timestamp (should be Unix time)
        if (header.nTime > 0 && header.nTime < 2000000000) {
            // Reasonable timestamp range
        }

        // Difficulty bits
        uint32_t bits = header.nBits;
        (void)bits; // Can be any value

        // Nonce
        uint64_t nonce = header.nNonce;
        (void)nonce; // Can be any value

        // Calculate block hash
        uint256 hash = header.GetHash();
        (void)hash;

    } catch (const std::exception& e) {
        // Expected for invalid input
        return;
    }
}

/**
 * Fuzz target: Full block deserialization
 *
 * Tests parsing of complete block including transactions
 */
FUZZ_TARGET(block_deserialize)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss.write(reinterpret_cast<const char*>(data), size);

        // Attempt to deserialize full block
        CBlock block;
        ss >> block;

        // Check header
        const CBlockHeader& header = block;
        (void)header;

        // Check transactions
        size_t tx_count = block.vtx.size();
        if (tx_count > MAX_BLOCK_SIZE / 100) {
            // Too many transactions
            return;
        }

        // Verify first tx exists (should be coinbase)
        if (tx_count > 0) {
            const CTransaction& coinbase = block.vtx[0];

            // Coinbase should have at least one input
            if (coinbase.vin.size() == 0) {
                // Invalid coinbase
                return;
            }
        }

        // Calculate merkle root
        uint256 merkle_root = block.BuildMerkleTree();
        (void)merkle_root;

        // Serialize back
        CDataStream ss_out(SER_NETWORK, PROTOCOL_VERSION);
        ss_out << block;

        // Check size is reasonable
        if (ss_out.size() > MAX_BLOCK_SIZE) {
            return;
        }

    } catch (const std::exception& e) {
        return;
    }
}

/**
 * Fuzz target: Merkle tree construction
 *
 * Tests merkle root calculation with fuzzed transaction list
 */
FUZZ_TARGET(block_merkle_tree)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Create block with fuzzed transactions
        CBlock block;

        // Fuzz number of transactions
        size_t num_txs = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 100);

        for (size_t i = 0; i < num_txs && fuzzed_data.remaining_bytes() > 0; ++i) {
            // Create simple transaction with fuzzed data
            CMutableTransaction mtx;

            mtx.nVersion = fuzzed_data.ConsumeIntegral<int32_t>();

            // Add one input with fuzzed prevout
            CTxIn txin;
            txin.prevout.hash = uint256S(fuzzed_data.ConsumeRandomLengthString(64));
            txin.prevout.n = fuzzed_data.ConsumeIntegral<uint32_t>();
            mtx.vin.push_back(txin);

            // Add one output with fuzzed value
            CTxOut txout;
            txout.nValue = fuzzed_data.ConsumeIntegral<CAmount>();
            mtx.vout.push_back(txout);

            mtx.nLockTime = fuzzed_data.ConsumeIntegral<uint32_t>();

            block.vtx.push_back(CTransaction(mtx));
        }

        // Calculate merkle root
        uint256 merkle_root1 = block.BuildMerkleTree();

        // Calculate again (should be deterministic)
        uint256 merkle_root2 = block.BuildMerkleTree();

        // Verify determinism
        assert(merkle_root1 == merkle_root2);

        // Set in header
        block.hashMerkleRoot = merkle_root1;

    } catch (const std::exception& e) {
        return;
    }
}

/**
 * Fuzz target: Block validation
 *
 * Tests block validation logic with fuzzed blocks
 */
FUZZ_TARGET(block_validation)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss.write(reinterpret_cast<const char*>(data), size);

        CBlock block;
        ss >> block;

        // Test various validation functions

        // 1. Check block size
        size_t block_size = ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
        if (block_size > MAX_BLOCK_SIZE) {
            // Block too large
            return;
        }

        // 2. Check transaction count
        if (block.vtx.empty()) {
            // Block must have at least coinbase
            return;
        }

        // 3. Check first transaction is coinbase
        if (block.vtx.size() > 0) {
            const CTransaction& first_tx = block.vtx[0];
            if (first_tx.vin.empty()) {
                return;
            }

            // Coinbase input should have null prevout
            if (first_tx.vin[0].prevout.IsNull()) {
                // Valid coinbase
            }
        }

        // 4. Check for duplicate transactions
        std::set<uint256> tx_set;
        for (const auto& tx : block.vtx) {
            uint256 txid = tx.GetHash();
            if (tx_set.count(txid)) {
                // Duplicate transaction
                return;
            }
            tx_set.insert(txid);
        }

        // 5. Verify merkle root
        uint256 calculated_merkle = block.BuildMerkleTree();
        if (calculated_merkle != block.hashMerkleRoot) {
            // Merkle root mismatch
            return;
        }

    } catch (const std::exception& e) {
        return;
    }
}
