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

    // SCRIPT-010 FIX: Transaction version validation (consensus-critical)
    // Version must be positive and within defined range.
    // Currently, only version 1 is defined in the protocol.
    // Version 0 is invalid (reserved for future use or error detection).
    // Maximum version is 255 to prevent overflow issues in signature message.
    if (tx.nVersion == 0) {
        error = "Transaction version cannot be zero";
        return false;
    }
    if (tx.nVersion > 255) {
        error = "Transaction version exceeds maximum (255)";
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
        // MEDIUM-C004: Zero-value output rejection policy (DESIGN DECISION)
        //
        // This implementation rejects ALL zero-value outputs (nValue == 0).
        //
        // Rationale:
        // - Prevents UTXO set bloat from unspendable zero-value outputs
        // - Simplifies wallet logic (no need to handle zero-value UTXOs)
        // - Unlike Bitcoin, Dilithion does NOT support OP_RETURN for data storage
        //
        // Trade-offs:
        // + Prevents bloat attacks
        // + Simpler UTXO management
        // - Cannot store arbitrary data in blockchain (OP_RETURN)
        // - Less flexible than Bitcoin's approach
        //
        // If future requirements need data storage, consider:
        // - Dedicated data layer (separate from UTXO set)
        // - Witness data field (like SegWit)
        // - Off-chain storage with on-chain hash commitments
        //
        // Current policy: ALL outputs must have nValue > 0
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

    // SCRIPT-001 FIX: Safe bounds checking for scriptPubKey validation
    // Check size first, then validate opcodes separately to avoid out-of-bounds access

    // SCRIPT-011 FIX: Comprehensive scriptPubKey size validation
    // Reject scripts that are too small, too large, or unexpected sizes
    if (scriptPubKey.size() < 25) {
        error = "scriptPubKey too small (minimum 25 bytes for P2PKH)";
        return false;
    }
    if (scriptPubKey.size() > 10000) {
        error = "scriptPubKey too large (DoS protection)";
        return false;
    }
    // Only accept standard sizes: 25 (legacy) or 37 (SHA3-256)
    if (scriptPubKey.size() != 25 && scriptPubKey.size() != 37) {
        error = "scriptPubKey has non-standard size (must be 25 or 37 bytes)";
        return false;
    }

    bool isStandardP2PKH = false;
    bool isLegacyP2PKH = false;

    // SCRIPT-011 FIX: Explicit opcode validation for standard P2PKH
    // Check for SHA3-256 based P2PKH (37 bytes)
    if (scriptPubKey.size() == 37) {
        // Validate each opcode explicitly with detailed checks
        if (scriptPubKey[0] != 0x76) {  // OP_DUP
            error = "scriptPubKey byte 0 must be OP_DUP (0x76)";
            return false;
        }
        if (scriptPubKey[1] != 0xa9) {  // OP_HASH160
            error = "scriptPubKey byte 1 must be OP_HASH160 (0xa9)";
            return false;
        }
        if (scriptPubKey[2] != 0x20) {  // Push 32 bytes
            error = "scriptPubKey byte 2 must be push-32 opcode (0x20)";
            return false;
        }
        if (scriptPubKey[35] != 0x88) {  // OP_EQUALVERIFY
            error = "scriptPubKey byte 35 must be OP_EQUALVERIFY (0x88)";
            return false;
        }
        if (scriptPubKey[36] != 0xac) {  // OP_CHECKSIG
            error = "scriptPubKey byte 36 must be OP_CHECKSIG (0xac)";
            return false;
        }
        isStandardP2PKH = true;
    }

    // SCRIPT-011 FIX: Explicit opcode validation for legacy P2PKH
    // Check for legacy 20-byte hash P2PKH (25 bytes)
    if (scriptPubKey.size() == 25) {
        // Validate each opcode explicitly with detailed checks
        if (scriptPubKey[0] != 0x76) {  // OP_DUP
            error = "scriptPubKey byte 0 must be OP_DUP (0x76)";
            return false;
        }
        if (scriptPubKey[1] != 0xa9) {  // OP_HASH160
            error = "scriptPubKey byte 1 must be OP_HASH160 (0xa9)";
            return false;
        }
        if (scriptPubKey[2] != 0x14) {  // Push 20 bytes
            error = "scriptPubKey byte 2 must be push-20 opcode (0x14)";
            return false;
        }
        if (scriptPubKey[23] != 0x88) {  // OP_EQUALVERIFY
            error = "scriptPubKey byte 23 must be OP_EQUALVERIFY (0x88)";
            return false;
        }
        if (scriptPubKey[24] != 0xac) {  // OP_CHECKSIG
            error = "scriptPubKey byte 24 must be OP_CHECKSIG (0xac)";
            return false;
        }
        isLegacyP2PKH = true;
    }

    if (!isStandardP2PKH && !isLegacyP2PKH) {
        error = "scriptPubKey is not valid P2PKH format (opcode validation failed)";
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

    // SCRIPT-012 FIX: Maximum scriptSig size check (DoS protection)
    // Reject oversized scriptSig immediately to prevent memory exhaustion attacks.
    // Maximum reasonable size is 10KB (expected is 5265 bytes).
    // This prevents attackers from submitting transactions with multi-megabyte scriptSig.
    if (scriptSig.size() > 10000) {
        error = "scriptSig exceeds maximum size (10000 bytes, DoS protection)";
        return false;
    }

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

    // SCRIPT-005 FIX: Basic signature malleability check
    // Check for obviously malformed signatures (all zeros, all ones)
    // Full canonical signature validation would require understanding Dilithium3 signature format
    bool sigAllZeros = true;
    bool sigAllOnes = true;
    for (size_t i = 0; i < signature.size() && (sigAllZeros || sigAllOnes); ++i) {
        if (signature[i] != 0x00) sigAllZeros = false;
        if (signature[i] != 0xFF) sigAllOnes = false;
    }

    if (sigAllZeros) {
        error = "Dilithium3 signature cannot be all zeros (malleability check)";
        return false;
    }

    if (sigAllOnes) {
        error = "Dilithium3 signature cannot be all ones (malleability check)";
        return false;
    }

    // NOTE: Full signature canonicalization requires:
    // - Dilithium3 signatures have (z, h, c) components
    // - z: polynomial vector with coefficients in [-gamma1, gamma1]
    // - h: hint bits indicating positions
    // - c: challenge hash
    // - Must verify z coefficients are in canonical range (not gamma1+1, etc.)
    // - Must verify hint bits h are minimally encoded
    // - This requires access to Dilithium3 signature internals
    // - Consider implementing pqcrystals_dilithium3_ref_signature_is_canonical() check

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

    // SCRIPT-004 FIX: Validate Dilithium3 public key structure
    // Check for obviously invalid keys (all zeros, all ones, etc.)
    // Full cryptographic validation would require Dilithium3 library internals
    bool allZeros = true;
    bool allOnes = true;
    for (size_t i = 0; i < pubkey.size() && (allZeros || allOnes); ++i) {
        if (pubkey[i] != 0x00) allZeros = false;
        if (pubkey[i] != 0xFF) allOnes = false;
    }

    if (allZeros) {
        error = "Dilithium3 public key cannot be all zeros";
        return false;
    }

    if (allOnes) {
        error = "Dilithium3 public key cannot be all ones";
        return false;
    }

    // Note: Full structural validation of Dilithium3 public key would require:
    // - Validating rho (seed) component
    // - Validating t1 (polynomial vector) component
    // - Checking polynomial coefficients are in valid range
    // - Verifying packing format matches specification
    // This requires access to Dilithium3 internals or a dedicated validation API

    // ========================================================================
    // 3. Verify public key hash matches scriptPubKey
    // ========================================================================

    // SCRIPT-006 FIX: Validate pubkey data before hashing
    if (pubkey.data() == nullptr || pubkey.empty()) {
        error = "Internal error: public key data is null or empty";
        return false;
    }

    // Hash the public key with SHA3-256
    uint8_t computed_hash[32];
    SHA3_256(pubkey.data(), pubkey.size(), computed_hash);

    // Extract expected hash from scriptPubKey
    const uint8_t* expected_hash;
    size_t hash_size;

    // SCRIPT-003 FIX: Validate scriptPubKey pointer and size before pointer arithmetic
    if (scriptPubKey.data() == nullptr) {
        error = "Internal error: scriptPubKey data pointer is null";
        return false;
    }

    if (isStandardP2PKH) {
        // SHA3-256 (32 bytes) starts at byte 3
        if (scriptPubKey.size() < 3 + 32) {
            error = "scriptPubKey too short for standard P2PKH hash";
            return false;
        }
        expected_hash = scriptPubKey.data() + 3;
        hash_size = 32;
    } else {
        // Legacy RIPEMD160 (20 bytes) starts at byte 3
        if (scriptPubKey.size() < 3 + 20) {
            error = "scriptPubKey too short for legacy P2PKH hash";
            return false;
        }
        expected_hash = scriptPubKey.data() + 3;
        hash_size = 20;
        // Only compare first 20 bytes of computed hash for legacy
    }

    // Compare hashes (both pointers now validated)
    if (memcmp(computed_hash, expected_hash, hash_size) != 0) {
        error = "Public key hash does not match scriptPubKey";
        return false;
    }

    // ========================================================================
    // 4. Construct signature message (same as signing)
    // ========================================================================
    //
    // SCRIPT-013: SIGNATURE COVERAGE DOCUMENTATION
    //
    // This section documents what transaction data is covered by the Dilithium3
    // signature and the security implications of the signature scheme.
    //
    // SIGNATURE MESSAGE COMPONENTS (40 bytes total):
    // ┌────────────────────┬──────────────────────────────────────────────┐
    // │ Field              │ Size  │ Coverage                               │
    // ├────────────────────┼───────┼────────────────────────────────────────┤
    // │ Transaction Hash   │ 32 B  │ Covers ALL tx data (inputs, outputs,   │
    // │                    │       │ version, locktime) via SHA3-256        │
    // ├────────────────────┼───────┼────────────────────────────────────────┤
    // │ Input Index        │  4 B  │ Binds signature to specific input      │
    // │                    │       │ (prevents cross-input replay)          │
    // ├────────────────────┼───────┼────────────────────────────────────────┤
    // │ Transaction Version│  4 B  │ Prevents signature reuse across        │
    // │                    │       │ different tx versions (upgrade safety) │
    // └────────────────────┴───────┴────────────────────────────────────────┘
    //
    // WHAT IS COVERED (via transaction hash):
    // ✓ All transaction inputs (prevout hash, index, sequence)
    // ✓ All transaction outputs (value, scriptPubKey)
    // ✓ Transaction version (nVersion)
    // ✓ Transaction locktime (nLockTime)
    // ✓ All scriptSig data (signatures and public keys of all inputs)
    //
    // WHAT IS NOT COVERED:
    // ✗ Block height or timestamp (signature is block-independent)
    // ✗ Block hash (signature can be included in any valid block)
    // ✗ Mempool state (signature doesn't commit to ordering)
    //
    // SECURITY PROPERTIES:
    // 1. **Non-malleability**: Transaction hash includes all scriptSig data,
    //    so signature cannot be modified without invalidating the hash.
    //
    // 2. **Input binding**: Input index prevents signature from being replayed
    //    to spend different inputs in the same transaction.
    //
    // 3. **Version isolation**: Transaction version prevents signatures from
    //    being reused if transaction format changes in future versions.
    //
    // 4. **SIGHASH_ALL semantics**: This signature scheme is equivalent to
    //    Bitcoin's SIGHASH_ALL - signs all inputs and outputs. No support for
    //    partial signing (SIGHASH_SINGLE, SIGHASH_ANYONECANPAY) currently.
    //
    // ATTACK MITIGATIONS:
    // - Signature replay attack: PREVENTED by input index binding
    // - Transaction malleability: PREVENTED by signing complete tx hash
    // - Cross-version attacks: PREVENTED by including tx version
    // - Cross-chain replay: NOT PREVENTED (requires chain ID in future)
    //
    // FUTURE CONSIDERATIONS:
    // - Add chain ID to signature message for cross-chain replay protection
    // - Support for partial signatures (SIGHASH flags) if needed
    // - Consider block height commitment for time-locked transactions
    //
    // ========================================================================

    // Get transaction hash
    uint256 tx_hash = tx.GetHash();

    // SCRIPT-007 FIX: Transaction hash validation
    // uint256 is guaranteed to be 32 bytes by its class definition (uint8_t data[32])
    // This ensures signature message construction uses the correct hash size

    // VULN-003 FIX: Canonical signature message construction
    // Create signature message: tx_hash + input_index + tx_version
    // Adding tx version prevents cross-transaction signature reuse
    std::vector<uint8_t> sig_message;
    sig_message.reserve(32 + 4 + 4);  // hash + index + version

    sig_message.insert(sig_message.end(), tx_hash.begin(), tx_hash.end());

    // SCRIPT-002 FIX: Validate inputIdx before casting to prevent integer truncation
    // Prevents signature replay across inputs when index exceeds uint32_t range
    if (inputIdx > UINT32_MAX) {
        error = "Input index exceeds maximum (uint32_t overflow)";
        return false;
    }

    // Add input index (4 bytes, little-endian)
    uint32_t input_idx = static_cast<uint32_t>(inputIdx);
    sig_message.push_back(static_cast<uint8_t>(input_idx & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((input_idx >> 8) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((input_idx >> 16) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((input_idx >> 24) & 0xFF));

    // SCRIPT-009 FIX: Validate transaction version before using in signature context
    // Context data validation ensures all signature message components are valid.
    // Version 0 is invalid, and version must be within consensus range (1-255).
    // This prevents malformed transactions from being used in signature verification.
    if (tx.nVersion == 0 || tx.nVersion > 255) {
        error = "Invalid transaction version in signature context";
        return false;
    }

    // VULN-003 FIX: Add transaction version to prevent signature replay across versions
    uint32_t version = tx.nVersion;
    sig_message.push_back(static_cast<uint8_t>(version & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 16) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 24) & 0xFF));

    // VULN-003 FIX: Validate message construction
    if (sig_message.size() != 40) {  // 32 (hash) + 4 (index) + 4 (version)
        error = "Internal error: Invalid signature message size";
        return false;
    }

    // SCRIPT-006 FIX: Validate sig_message data before hashing
    if (sig_message.data() == nullptr || sig_message.empty()) {
        error = "Internal error: signature message data is null or empty";
        return false;
    }

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
        // SCRIPT-008 FIX: Rate limiting for signature verification (DoS protection)
        // Dilithium3 verification takes ~2ms per input. Limiting to 10,000 inputs
        // caps verification time at ~20 seconds, preventing computational DoS.
        // Attack scenario: 22,000 inputs × 2ms = 44 seconds = node paralysis
        if (tx.vin.size() > TxValidation::MAX_INPUT_COUNT_PER_TX) {
            error = "Transaction has too many inputs (DoS protection limit exceeded)";
            return false;
        }

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

    // MEDIUM-C005 FIX: Accept both SHA3-256 (37 bytes) and legacy (25 bytes) P2PKH
    // This aligns with VerifyScript() which accepts both formats for backward compatibility
    for (const auto& txout : tx.vout) {
        size_t scriptSize = txout.scriptPubKey.size();

        // Accept both SHA3-256 P2PKH (37 bytes) and legacy P2PKH (25 bytes)
        if (scriptSize != 37 && scriptSize != 25) {
            return false;
        }

        // Validate P2PKH structure based on size
        if (scriptSize == 37) {
            // SHA3-256 P2PKH: OP_DUP OP_HASH256 <32-byte hash> OP_EQUALVERIFY OP_CHECKSIG
            if (txout.scriptPubKey[0] != 0x76 ||  // OP_DUP
                txout.scriptPubKey[1] != 0xa9 ||  // OP_HASH256 (SHA3-256)
                txout.scriptPubKey[2] != 0x20 ||  // Push 32 bytes
                txout.scriptPubKey[35] != 0x88 || // OP_EQUALVERIFY
                txout.scriptPubKey[36] != 0xac) { // OP_CHECKSIG
                return false;
            }
        } else {  // scriptSize == 25
            // Legacy P2PKH: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
            if (txout.scriptPubKey[0] != 0x76 ||  // OP_DUP
                txout.scriptPubKey[1] != 0xa9 ||  // OP_HASH160
                txout.scriptPubKey[2] != 0x14 ||  // Push 20 bytes
                txout.scriptPubKey[23] != 0x88 || // OP_EQUALVERIFY
                txout.scriptPubKey[24] != 0xac) { // OP_CHECKSIG
                return false;
            }
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
