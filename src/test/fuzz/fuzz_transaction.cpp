// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include "fuzz.h"
#include "util.h"
#include "../../primitives/transaction.h"
#include "../../net/serialize.h"
#include <cstring>
#include <vector>

/**
 * Fuzz target: Transaction deserialization
 *
 * Tests:
 * - Transaction parsing from arbitrary bytes
 * - Version field handling
 * - Input parsing (vin)
 * - Output parsing (vout)
 * - Locktime parsing
 * - CompactSize handling for input/output counts
 * - Invalid format rejection
 * - Buffer overflow protection
 *
 * Coverage:
 * - src/primitives/transaction.h
 * - src/primitives/transaction.cpp
 * - src/net/serialize.h
 *
 * Based on gap analysis: P1-1 (transaction serialization)
 * Priority: HIGH (core protocol)
 */

FUZZ_TARGET(transaction_deserialize)
{
    FuzzedDataProvider fuzzed_data(data, size);

    // Try to deserialize transaction from fuzzed input
    try {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

        // Feed fuzzed data to stream
        ss.write(reinterpret_cast<const char*>(data), size);

        // Attempt deserialization
        CTransaction tx;
        ss >> tx;

        // If deserialization succeeded, perform basic validity checks

        // Check version is reasonable
        if (tx.nVersion < 1 || tx.nVersion > 10) {
            // Unusual but not invalid
        }

        // Check input count
        size_t vin_count = tx.vin.size();
        if (vin_count > MAX_BLOCK_SIZE / sizeof(CTxIn)) {
            // Too many inputs - should have failed earlier
            return;
        }

        // Check output count
        size_t vout_count = tx.vout.size();
        if (vout_count > MAX_BLOCK_SIZE / sizeof(CTxOut)) {
            // Too many outputs - should have failed earlier
            return;
        }

        // Check locktime
        uint32_t locktime = tx.nLockTime;
        (void)locktime; // Valid any value 0-UINT32_MAX

        // Try to serialize back
        CDataStream ss_out(SER_NETWORK, PROTOCOL_VERSION);
        ss_out << tx;

        // Check serialized size is reasonable
        if (ss_out.size() > MAX_BLOCK_SIZE) {
            // Transaction too large
            return;
        }

        // Test transaction ID calculation
        uint256 txid = tx.GetHash();
        (void)txid; // Just ensure it doesn't crash

    } catch (const std::exception& e) {
        // Deserialization failed - this is expected for most random inputs
        // The important thing is it doesn't crash
        return;
    }
}

/**
 * Fuzz target: Transaction serialization round-trip
 *
 * Creates a transaction from fuzzed data, serializes it,
 * deserializes it, and verifies consistency.
 */
FUZZ_TARGET(transaction_roundtrip)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Create transaction with fuzzed fields
        CMutableTransaction mtx;

        // Fuzz version
        mtx.nVersion = fuzzed_data.ConsumeIntegral<int32_t>();

        // Fuzz inputs
        size_t num_inputs = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 10);
        for (size_t i = 0; i < num_inputs && fuzzed_data.remaining_bytes() > 0; ++i) {
            CTxIn txin;

            // Fuzz prevout
            txin.prevout.hash = uint256S(fuzzed_data.ConsumeRandomLengthString(64));
            txin.prevout.n = fuzzed_data.ConsumeIntegral<uint32_t>();

            // Fuzz scriptSig (limited size)
            size_t script_size = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 100);
            std::vector<unsigned char> script_data = fuzzed_data.ConsumeBytes<unsigned char>(script_size);
            txin.scriptSig = CScript(script_data.begin(), script_data.end());

            // Fuzz sequence
            txin.nSequence = fuzzed_data.ConsumeIntegral<uint32_t>();

            mtx.vin.push_back(txin);
        }

        // Fuzz outputs
        size_t num_outputs = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 10);
        for (size_t i = 0; i < num_outputs && fuzzed_data.remaining_bytes() > 0; ++i) {
            CTxOut txout;

            // Fuzz value
            txout.nValue = fuzzed_data.ConsumeIntegral<CAmount>();

            // Fuzz scriptPubKey (limited size)
            size_t script_size = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 100);
            std::vector<unsigned char> script_data = fuzzed_data.ConsumeBytes<unsigned char>(script_size);
            txout.scriptPubKey = CScript(script_data.begin(), script_data.end());

            mtx.vout.push_back(txout);
        }

        // Fuzz locktime
        mtx.nLockTime = fuzzed_data.ConsumeIntegral<uint32_t>();

        // Create immutable transaction
        CTransaction tx(mtx);

        // Serialize
        CDataStream ss_out(SER_NETWORK, PROTOCOL_VERSION);
        ss_out << tx;

        // Deserialize
        CTransaction tx2;
        ss_out >> tx2;

        // Verify consistency
        assert(tx.GetHash() == tx2.GetHash());
        assert(tx.nVersion == tx2.nVersion);
        assert(tx.vin.size() == tx2.vin.size());
        assert(tx.vout.size() == tx2.vout.size());
        assert(tx.nLockTime == tx2.nLockTime);

    } catch (const std::exception& e) {
        // Expected for some inputs
        return;
    }
}

/**
 * Fuzz target: Transaction signature verification
 *
 * Tests signature verification with fuzzed transaction data
 */
FUZZ_TARGET(transaction_signature)
{
    FuzzedDataProvider fuzzed_data(data, size);

    // This would test actual Dilithium3 signature verification
    // For now, just test the signature data handling

    try {
        // Fuzz signature size (Dilithium3 signatures are 3309 bytes)
        size_t sig_size = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 5000);
        std::vector<uint8_t> signature = fuzzed_data.ConsumeBytes<uint8_t>(sig_size);

        // Fuzz public key size (Dilithium3 public keys are 1952 bytes)
        size_t pubkey_size = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 3000);
        std::vector<uint8_t> pubkey = fuzzed_data.ConsumeBytes<uint8_t>(pubkey_size);

        // Fuzz message to sign
        std::vector<uint8_t> message = fuzzed_data.ConsumeRemainingBytes<uint8_t>();

        // TODO: Call actual signature verification
        // bool valid = VerifyDilithium3Signature(message, signature, pubkey);

        // For now, just ensure data handling doesn't crash

    } catch (const std::exception& e) {
        return;
    }
}
