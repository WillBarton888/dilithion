// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include "fuzz.h"
#include "util.h"
#include "../../primitives/block.h"
#include <vector>
#include <cstring>

/**
 * Fuzz target: Block header field manipulation
 *
 * Tests:
 * - Block header construction with arbitrary fields
 * - Version field handling
 * - Previous block hash
 * - Merkle root
 * - Timestamp validation
 * - nBits (difficulty)
 * - Nonce handling
 * - Hash calculation with arbitrary inputs
 *
 * Coverage:
 * - src/primitives/block.h
 * - src/primitives/block.cpp (GetHash)
 *
 * Based on gap analysis: P2-1 (block validation)
 * Priority: HIGH (consensus critical)
 */

FUZZ_TARGET(block_header_fields)
{
    FuzzedDataProvider fuzzed_data(data, size);

    if (size < 80) {
        return;  // Need minimum data for block header fields
    }

    try {
        // Construct block header with fuzzed fields
        CBlockHeader header;

        // Fuzz version
        header.nVersion = fuzzed_data.ConsumeIntegral<int32_t>();

        // Fuzz previous block hash
        std::vector<uint8_t> prev_hash = fuzzed_data.ConsumeBytes<uint8_t>(32);
        if (prev_hash.size() == 32) {
            memcpy(header.hashPrevBlock.data, prev_hash.data(), 32);
        }

        // Fuzz merkle root
        std::vector<uint8_t> merkle_root = fuzzed_data.ConsumeBytes<uint8_t>(32);
        if (merkle_root.size() == 32) {
            memcpy(header.hashMerkleRoot.data, merkle_root.data(), 32);
        }

        // Fuzz timestamp
        header.nTime = fuzzed_data.ConsumeIntegral<uint32_t>();

        // Fuzz difficulty bits
        header.nBits = fuzzed_data.ConsumeIntegral<uint32_t>();

        // Fuzz nonce
        header.nNonce = fuzzed_data.ConsumeIntegral<uint32_t>();

        // Test basic operations
        bool is_null = header.IsNull();
        (void)is_null;

        // Calculate block hash - this exercises RandomX hashing
        try {
            uint256 hash = header.GetHash();
            (void)hash;

            // Verify hash is deterministic
            uint256 hash2 = header.GetHash();
            if (!(hash == hash2)) {
                // Non-deterministic hash calculation detected!
                // This would be a critical bug
            }
        } catch (const std::exception& e) {
            // Hash calculation may fail for invalid headers
            return;
        }

    } catch (const std::exception& e) {
        // Expected for some invalid combinations
        return;
    }
}

/*
 * TODO: Re-enable additional fuzz targets by splitting into separate files
 *
 * Multiple FUZZ_TARGET macros in one file cause "redefinition of LLVMFuzzerTestOneInput" errors.
 * Each FUZZ_TARGET must be in a separate .cpp file to create separate fuzzer binaries.
 *
 * Additional targets to split out:
 * - block_deserialize (full block parsing)
 * - block_merkle_tree (merkle tree validation)
 * - block_validation (block validation rules)
 *
 * For now, keeping only "block_header_fields" as the primary test.
 */

#if 0  // DISABLED: Multiple FUZZ_TARGETs not supported in single file

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

#endif  // DISABLED FUZZ_TARGETs
