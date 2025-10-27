// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/tx_validation.h>
#include <consensus/fees.h>
#include <set>
#include <algorithm>
#include <cstdio>

// ============================================================================
// Basic Structural Validation
// ============================================================================

bool CTransactionValidator::CheckTransactionBasic(const CTransaction& tx, std::string& error) const
{
    // Check transaction is not null
    if (tx.IsNull()) {
        error = "Transaction is null";
        return false;
    }

    // Coinbase transactions have special rules
    if (tx.IsCoinBase()) {
        // Coinbase must have exactly one input
        if (tx.vin.size() != 1) {
            error = "Coinbase transaction must have exactly one input";
            return false;
        }

        // Coinbase input must have null prevout
        if (!tx.vin[0].prevout.IsNull()) {
            error = "Coinbase transaction input must have null prevout";
            return false;
        }

        // Coinbase scriptSig size must be between 2 and 100 bytes
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100) {
            error = "Coinbase scriptSig size must be between 2 and 100 bytes";
            return false;
        }
    } else {
        // Regular transaction must have inputs
        if (tx.vin.empty()) {
            error = "Transaction has no inputs";
            return false;
        }

        // Regular transaction inputs must not have null prevout
        for (const auto& txin : tx.vin) {
            if (txin.prevout.IsNull()) {
                error = "Transaction input has null prevout (only coinbase allowed)";
                return false;
            }
        }
    }

    // All transactions must have outputs
    if (tx.vout.empty()) {
        error = "Transaction has no outputs";
        return false;
    }

    // Check output values are positive and within range
    CAmount totalOut = 0;
    for (const auto& txout : tx.vout) {
        // Output value must be positive
        if (txout.nValue <= 0) {
            error = "Transaction output value must be positive";
            return false;
        }

        // Output value must be within monetary range
        if (!MoneyRange(txout.nValue)) {
            error = "Transaction output value out of range";
            return false;
        }

        // Check for overflow when adding outputs
        totalOut += txout.nValue;
        if (!MoneyRange(totalOut)) {
            error = "Transaction output total out of range";
            return false;
        }
    }

    // Check transaction size
    size_t txSize = tx.GetSerializedSize();
    if (txSize > TxValidation::MAX_TRANSACTION_SIZE) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Transaction size (%zu bytes) exceeds maximum (%zu bytes)",
                 txSize, TxValidation::MAX_TRANSACTION_SIZE);
        error = buf;
        return false;
    }

    // Check for duplicate inputs (same outpoint spent twice)
    if (!CheckDuplicateInputs(tx)) {
        error = "Transaction contains duplicate inputs";
        return false;
    }

    return true;
}

// ============================================================================
// Input Validation (UTXO Checks)
// ============================================================================

bool CTransactionValidator::CheckTransactionInputs(const CTransaction& tx, CUTXOSet& utxoSet,
                                                     uint32_t currentHeight, CAmount& txFee,
                                                     std::string& error) const
{
    // Coinbase transactions don't have real inputs to check
    if (tx.IsCoinBase()) {
        txFee = 0;
        return true;
    }

    // Verify all inputs exist in UTXO set
    for (const auto& txin : tx.vin) {
        if (!utxoSet.HaveUTXO(txin.prevout)) {
            char buf[256];
            snprintf(buf, sizeof(buf), "Input references non-existent UTXO (tx: %s, n: %u)",
                     txin.prevout.hash.GetHex().c_str(), txin.prevout.n);
            error = buf;
            return false;
        }
    }

    // Check coinbase maturity
    if (!CheckCoinbaseMaturity(tx, utxoSet, currentHeight, error)) {
        return false;
    }

    // Calculate total input value
    CAmount totalIn = 0;
    if (!CalculateTotalInputValue(tx, utxoSet, totalIn, error)) {
        return false;
    }

    // Calculate total output value
    CAmount totalOut = 0;
    for (const auto& txout : tx.vout) {
        totalOut += txout.nValue;
    }

    // Calculate fee (inputs - outputs)
    if (totalIn < totalOut) {
        error = "Transaction inputs less than outputs (negative fee)";
        return false;
    }

    txFee = totalIn - totalOut;

    // Verify fee is within reasonable range
    if (!MoneyRange(txFee)) {
        error = "Transaction fee out of range";
        return false;
    }

    // Check for suspiciously low fee (but allow zero for testing)
    // In production, you might want to enforce minimum fee
    if (txFee < 0) {
        error = "Transaction fee is negative";
        return false;
    }

    return true;
}

// ============================================================================
// Script Verification (Simplified P2PKH)
// ============================================================================

bool CTransactionValidator::VerifyScript(const std::vector<uint8_t>& scriptSig,
                                          const std::vector<uint8_t>& scriptPubKey,
                                          std::string& error) const
{
    // For now, we implement basic P2PKH validation
    // Full Dilithium signature verification will be added in Phase 5.2

    // P2PKH scriptPubKey format: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    // Minimum size: 25 bytes (1+1+1+20+1+1)
    if (scriptPubKey.size() < 25) {
        error = "scriptPubKey too short for P2PKH";
        return false;
    }

    // P2PKH scriptSig format: <signature> <pubKey>
    // For now, we just check it's not empty
    if (scriptSig.empty()) {
        error = "scriptSig is empty";
        return false;
    }

    // Basic structure validation for P2PKH
    // Check opcodes: OP_DUP (0x76), OP_HASH160 (0xa9), OP_EQUALVERIFY (0x88), OP_CHECKSIG (0xac)
    if (scriptPubKey.size() == 25 &&
        scriptPubKey[0] == 0x76 &&  // OP_DUP
        scriptPubKey[1] == 0xa9 &&  // OP_HASH160
        scriptPubKey[2] == 0x14 &&  // Push 20 bytes
        scriptPubKey[23] == 0x88 && // OP_EQUALVERIFY
        scriptPubKey[24] == 0xac) { // OP_CHECKSIG

        // Valid P2PKH structure
        // Placeholder: In Phase 5.2, we'll verify Dilithium signature here
        return true;
    }

    // For now, accept any non-empty scriptSig with valid scriptPubKey structure
    // This is a PLACEHOLDER for full cryptographic verification

    // TODO Phase 5.2: Implement Dilithium signature verification
    // 1. Extract signature and public key from scriptSig
    // 2. Extract public key hash from scriptPubKey
    // 3. Verify public key hashes to expected value
    // 4. Verify Dilithium signature over transaction

    return true;
}

// ============================================================================
// Complete Transaction Validation
// ============================================================================

bool CTransactionValidator::CheckTransaction(const CTransaction& tx, CUTXOSet& utxoSet,
                                              uint32_t currentHeight, CAmount& txFee,
                                              std::string& error) const
{
    // Step 1: Basic structural validation
    if (!CheckTransactionBasic(tx, error)) {
        return false;
    }

    // Step 2: Input validation against UTXO set
    if (!CheckTransactionInputs(tx, utxoSet, currentHeight, txFee, error)) {
        return false;
    }

    // Step 3: Script verification for all inputs
    if (!tx.IsCoinBase()) {
        for (const auto& txin : tx.vin) {
            CUTXOEntry entry;
            if (!utxoSet.GetUTXO(txin.prevout, entry)) {
                error = "Failed to retrieve UTXO for script verification";
                return false;
            }

            if (!VerifyScript(txin.scriptSig, entry.out.scriptPubKey, error)) {
                char buf[256];
                snprintf(buf, sizeof(buf), "Script verification failed: %s", error.c_str());
                error = buf;
                return false;
            }
        }
    }

    return true;
}

// ============================================================================
// Additional Validation Helpers
// ============================================================================

bool CTransactionValidator::IsStandardTransaction(const CTransaction& tx) const
{
    // Check transaction version (currently only version 1 is standard)
    if (tx.nVersion != 1) {
        return false;
    }

    // Check transaction size is reasonable (for relay)
    size_t txSize = tx.GetSerializedSize();
    if (txSize > TxValidation::MAX_TRANSACTION_SIZE / 10) {
        return false;  // Transactions over 100KB are not standard
    }

    // Check output values meet dust threshold (0.00001 DIL = 1000 ions)
    const CAmount dustThreshold = 1000;
    for (const auto& txout : tx.vout) {
        if (txout.nValue < dustThreshold) {
            return false;
        }
    }

    // Check scripts are standard P2PKH
    for (const auto& txout : tx.vout) {
        // P2PKH scriptPubKey should be 25 bytes
        if (txout.scriptPubKey.size() != 25) {
            return false;
        }

        // Check P2PKH structure
        if (txout.scriptPubKey[0] != 0x76 ||  // OP_DUP
            txout.scriptPubKey[1] != 0xa9 ||  // OP_HASH160
            txout.scriptPubKey[2] != 0x14 ||  // Push 20 bytes
            txout.scriptPubKey[23] != 0x88 || // OP_EQUALVERIFY
            txout.scriptPubKey[24] != 0xac) { // OP_CHECKSIG
            return false;
        }
    }

    return true;
}

size_t CTransactionValidator::GetTransactionWeight(const CTransaction& tx) const
{
    // For now, weight = serialized size
    // In the future, this could account for witness data differently
    return tx.GetSerializedSize();
}

CAmount CTransactionValidator::GetMinimumFee(const CTransaction& tx) const
{
    // Use existing fee calculation from consensus/fees.h
    size_t txSize = tx.GetSerializedSize();
    return Consensus::CalculateMinFee(txSize);
}

bool CTransactionValidator::CheckDoubleSpend(const CTransaction& tx, CUTXOSet& utxoSet) const
{
    // Check for duplicate inputs within the transaction
    if (!CheckDuplicateInputs(tx)) {
        return false;
    }

    // Check all inputs exist in UTXO set (not already spent)
    for (const auto& txin : tx.vin) {
        if (!utxoSet.HaveUTXO(txin.prevout)) {
            return false;  // UTXO doesn't exist or already spent
        }
    }

    return true;
}

// ============================================================================
// Private Helper Functions
// ============================================================================

bool CTransactionValidator::CheckDuplicateInputs(const CTransaction& tx) const
{
    std::set<COutPoint> uniqueInputs;

    for (const auto& txin : tx.vin) {
        // Try to insert into set
        auto result = uniqueInputs.insert(txin.prevout);

        // If insertion failed, we found a duplicate
        if (!result.second) {
            return false;
        }
    }

    return true;
}

bool CTransactionValidator::CalculateTotalInputValue(const CTransaction& tx, CUTXOSet& utxoSet,
                                                       CAmount& totalIn, std::string& error) const
{
    totalIn = 0;

    for (const auto& txin : tx.vin) {
        CUTXOEntry entry;
        if (!utxoSet.GetUTXO(txin.prevout, entry)) {
            error = "Failed to retrieve UTXO entry";
            return false;
        }

        // Verify value is within range
        if (!MoneyRange(entry.out.nValue)) {
            error = "UTXO value out of range";
            return false;
        }

        // Add to total, checking for overflow
        CAmount newTotal = totalIn + entry.out.nValue;
        if (!MoneyRange(newTotal)) {
            error = "Total input value overflow";
            return false;
        }

        totalIn = newTotal;
    }

    return true;
}

bool CTransactionValidator::CheckCoinbaseMaturity(const CTransaction& tx, CUTXOSet& utxoSet,
                                                   uint32_t currentHeight, std::string& error) const
{
    for (const auto& txin : tx.vin) {
        CUTXOEntry entry;
        if (!utxoSet.GetUTXO(txin.prevout, entry)) {
            error = "Failed to retrieve UTXO for maturity check";
            return false;
        }

        // If this is a coinbase output, check maturity
        if (entry.fCoinBase) {
            uint32_t confirmations = currentHeight - entry.nHeight;

            if (confirmations < TxValidation::COINBASE_MATURITY) {
                char buf[256];
                snprintf(buf, sizeof(buf),
                         "Coinbase output not mature (height: %u, current: %u, confirmations: %u, required: %u)",
                         entry.nHeight, currentHeight, confirmations, TxValidation::COINBASE_MATURITY);
                error = buf;
                return false;
            }
        }
    }

    return true;
}
