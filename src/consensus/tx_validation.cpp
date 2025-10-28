// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/tx_validation.h>
#include <consensus/fees.h>
#include <crypto/sha3.h>
#include <set>
#include <algorithm>
#include <cstdio>
#include <cstring>

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

    // Check for negative fees (should never happen with proper UTXO validation)
    if (txFee < 0) {
        error = "Transaction fee is negative";
        return false;
    }

    // CF-006: Enforce minimum transaction fees (production anti-spam)
    // Only enforce for non-coinbase transactions (coinbase has no inputs)
    if (!tx.IsCoinBase()) {
        std::string fee_error;
        if (!Consensus::CheckFee(tx, txFee, /*check_relay=*/true, &fee_error)) {
            error = "Fee requirement check failed: " + fee_error;
            return false;
        }
    }

    return true;
}

// ============================================================================
// Script Verification (Full Dilithium Signature Verification)
// ============================================================================

// Dilithium3 external API
extern "C" {
    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

bool CTransactionValidator::VerifyScript(const CTransaction& tx,
                                          size_t inputIdx,
                                          const std::vector<uint8_t>& scriptSig,
                                          const std::vector<uint8_t>& scriptPubKey,
                                          std::string& error) const
{
    // ========================================================================
    // 1. Validate P2PKH scriptPubKey structure
    // ========================================================================
    // P2PKH scriptPubKey format: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    // Standard size: 1 + 1 + 1 + 20 + 1 + 1 = 25 bytes
    // But Dilithium uses SHA3-256, so hash is 32 bytes: 1 + 1 + 1 + 32 + 1 + 1 = 37 bytes

    // First check for our SHA3-256 based P2PKH (37 bytes)
    const bool isStandardP2PKH = (scriptPubKey.size() == 37 &&
                                  scriptPubKey[0] == 0x76 &&  // OP_DUP
                                  scriptPubKey[1] == 0xa9 &&  // OP_HASH160
                                  scriptPubKey[2] == 0x20 &&  // Push 32 bytes (SHA3-256)
                                  scriptPubKey[35] == 0x88 && // OP_EQUALVERIFY
                                  scriptPubKey[36] == 0xac);  // OP_CHECKSIG

    // Also accept legacy 20-byte hash for backwards compatibility
    const bool isLegacyP2PKH = (scriptPubKey.size() == 25 &&
                                scriptPubKey[0] == 0x76 &&  // OP_DUP
                                scriptPubKey[1] == 0xa9 &&  // OP_HASH160
                                scriptPubKey[2] == 0x14 &&  // Push 20 bytes
                                scriptPubKey[23] == 0x88 && // OP_EQUALVERIFY
                                scriptPubKey[24] == 0xac);  // OP_CHECKSIG

    if (!isStandardP2PKH && !isLegacyP2PKH) {
        error = "scriptPubKey is not valid P2PKH format";
        return false;
    }

    // ========================================================================
    // 2. Parse scriptSig to extract signature and public key
    // ========================================================================
    // scriptSig format: [sig_size(2)] [signature] [pubkey_size(2)] [pubkey]

    // Expected size: 2 + DILITHIUM3_SIG_SIZE + 2 + DILITHIUM3_PK_SIZE = 5265 bytes
    const size_t DILITHIUM3_SIG_SIZE = 3309;
    const size_t DILITHIUM3_PK_SIZE = 1952;
    const size_t EXPECTED_SCRIPTSIG_SIZE = 2 + DILITHIUM3_SIG_SIZE + 2 + DILITHIUM3_PK_SIZE;

    if (scriptSig.size() != EXPECTED_SCRIPTSIG_SIZE) {
        char buf[256];
        snprintf(buf, sizeof(buf), "scriptSig must be exactly %zu bytes, got %zu",
                 EXPECTED_SCRIPTSIG_SIZE, scriptSig.size());
        error = buf;
        return false;
    }

    // Extract signature size (little-endian 16-bit)
    size_t pos = 0;
    uint16_t sig_size = scriptSig[pos] | (scriptSig[pos + 1] << 8);
    pos += 2;

    // Validate signature size
    if (sig_size != DILITHIUM3_SIG_SIZE) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Invalid Dilithium3 signature size: %u (expected %zu)",
                 sig_size, DILITHIUM3_SIG_SIZE);
        error = buf;
        return false;
    }

    // Ensure we have enough data for signature
    if (pos + sig_size + 2 > scriptSig.size()) {
        error = "scriptSig too short for signature data";
        return false;
    }

    // Extract signature
    std::vector<uint8_t> signature(scriptSig.begin() + pos, scriptSig.begin() + pos + sig_size);
    pos += sig_size;

    // Extract public key size (little-endian 16-bit)
    uint16_t pk_size = scriptSig[pos] | (scriptSig[pos + 1] << 8);
    pos += 2;

    // Validate public key size
    if (pk_size != DILITHIUM3_PK_SIZE) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Invalid Dilithium3 public key size: %u (expected %zu)",
                 pk_size, DILITHIUM3_PK_SIZE);
        error = buf;
        return false;
    }

    // Ensure we have enough data for public key
    if (pos + pk_size != scriptSig.size()) {
        error = "scriptSig size mismatch (extra or missing data)";
        return false;
    }

    // Extract public key
    std::vector<uint8_t> pubkey(scriptSig.begin() + pos, scriptSig.begin() + pos + pk_size);

    // ========================================================================
    // 3. Verify public key hash matches scriptPubKey
    // ========================================================================

    // Hash the public key with SHA3-256
    uint8_t computed_hash[32];
    SHA3_256(pubkey.data(), pubkey.size(), computed_hash);

    // Extract expected hash from scriptPubKey
    const uint8_t* expected_hash;
    size_t hash_size;

    if (isStandardP2PKH) {
        // SHA3-256 (32 bytes) starts at byte 3
        expected_hash = scriptPubKey.data() + 3;
        hash_size = 32;
    } else {
        // Legacy RIPEMD160 (20 bytes) starts at byte 3
        expected_hash = scriptPubKey.data() + 3;
        hash_size = 20;
        // Only compare first 20 bytes of computed hash for legacy
    }

    // Compare hashes
    if (memcmp(computed_hash, expected_hash, hash_size) != 0) {
        error = "Public key hash does not match scriptPubKey";
        return false;
    }

    // ========================================================================
    // 4. Construct signature message (same as signing)
    // ========================================================================

    // Get transaction hash
    uint256 tx_hash = tx.GetHash();

    // Create signature message: tx_hash + input_index
    std::vector<uint8_t> sig_message;
    sig_message.insert(sig_message.end(), tx_hash.begin(), tx_hash.end());

    // Add input index (4 bytes, little-endian)
    uint32_t input_idx = static_cast<uint32_t>(inputIdx);
    sig_message.push_back(static_cast<uint8_t>(input_idx & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((input_idx >> 8) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((input_idx >> 16) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((input_idx >> 24) & 0xFF));

    // Hash the signature message with SHA3-256
    uint8_t sig_hash[32];
    SHA3_256(sig_message.data(), sig_message.size(), sig_hash);

    // ========================================================================
    // 5. Verify Dilithium3 signature
    // ========================================================================

    int verify_result = pqcrystals_dilithium3_ref_verify(
        signature.data(), signature.size(),  // Signature
        sig_hash, 32,                        // Message (signature hash)
        nullptr, 0,                          // No context
        pubkey.data()                        // Public key
    );

    if (verify_result != 0) {
        error = "Dilithium signature verification failed";
        return false;
    }

    // Success! Signature is cryptographically valid
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
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const CTxIn& txin = tx.vin[i];

            CUTXOEntry entry;
            if (!utxoSet.GetUTXO(txin.prevout, entry)) {
                error = "Failed to retrieve UTXO for script verification";
                return false;
            }

            if (!VerifyScript(tx, i, txin.scriptSig, entry.out.scriptPubKey, error)) {
                char buf[256];
                snprintf(buf, sizeof(buf), "Script verification failed for input %zu: %s", i, error.c_str());
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
