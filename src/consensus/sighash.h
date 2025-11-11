// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_SIGHASH_H
#define DILITHION_CONSENSUS_SIGHASH_H

#include <cstdint>

/**
 * WALLET-015 FIX: SIGHASH type implementation
 *
 * SIGHASH flags control which parts of a transaction are covered by the signature.
 * This enables advanced transaction types and smart contract functionality.
 *
 * Background:
 * - Bitcoin introduced SIGHASH flags for flexible transaction signing
 * - Enables use cases like: blank checks, crowdfunding, partial signatures
 * - Critical for layer-2 protocols and advanced transaction types
 *
 * Security implications:
 * - SIGHASH_ALL: Most secure - signs everything (recommended default)
 * - SIGHASH_NONE: Dangerous - allows output modification after signing
 * - SIGHASH_SINGLE: Moderate risk - binds signature to specific output
 * - SIGHASH_ANYONECANPAY: Allows adding inputs (useful for crowdfunding)
 */

/**
 * SIGHASH flags (Bitcoin-compatible)
 *
 * Basic types (only one can be used):
 * - SIGHASH_ALL:    Sign all inputs and all outputs
 * - SIGHASH_NONE:   Sign all inputs but no outputs (outputs can be changed)
 * - SIGHASH_SINGLE: Sign all inputs and one output (same index as input)
 *
 * Modifier (can be combined with basic types):
 * - SIGHASH_ANYONECANPAY: Sign only this input (others can be added)
 *
 * Example combinations:
 * - SIGHASH_ALL | SIGHASH_ANYONECANPAY: "Anyone can pay" crowdfunding
 * - SIGHASH_NONE | SIGHASH_ANYONECANPAY: Blank check (very dangerous!)
 * - SIGHASH_SINGLE | SIGHASH_ANYONECANPAY: Partial payment with specific output
 */

enum SigHashType : uint8_t {
    /** All outputs are signed (default and recommended) */
    SIGHASH_ALL = 0x01,

    /** None of the outputs are signed (dangerous - allows output modification) */
    SIGHASH_NONE = 0x02,

    /** Only the output with the same index as this input is signed */
    SIGHASH_SINGLE = 0x03,

    /** Sign only this input, allowing others to add more inputs */
    SIGHASH_ANYONECANPAY = 0x80,
};

/**
 * Get the base SIGHASH type (without modifiers)
 */
inline SigHashType GetBaseSigHashType(uint8_t sighash_flags) {
    return static_cast<SigHashType>(sighash_flags & 0x1F);
}

/**
 * Check if ANYONECANPAY modifier is set
 */
inline bool HasAnyoneCanPay(uint8_t sighash_flags) {
    return (sighash_flags & SIGHASH_ANYONECANPAY) != 0;
}

/**
 * Validate SIGHASH flags
 *
 * @param sighash_flags Flags to validate
 * @return true if valid, false otherwise
 */
inline bool IsValidSigHashType(uint8_t sighash_flags) {
    SigHashType base = GetBaseSigHashType(sighash_flags);

    // Base type must be ALL, NONE, or SINGLE
    if (base != SIGHASH_ALL && base != SIGHASH_NONE && base != SIGHASH_SINGLE) {
        return false;
    }

    return true;
}

/**
 * Get human-readable description of SIGHASH type
 */
inline const char* SigHashTypeToString(uint8_t sighash_flags) {
    bool anyonecanpay = HasAnyoneCanPay(sighash_flags);
    SigHashType base = GetBaseSigHashType(sighash_flags);

    if (base == SIGHASH_ALL) {
        return anyonecanpay ? "ALL|ANYONECANPAY" : "ALL";
    } else if (base == SIGHASH_NONE) {
        return anyonecanpay ? "NONE|ANYONECANPAY" : "NONE";
    } else if (base == SIGHASH_SINGLE) {
        return anyonecanpay ? "SINGLE|ANYONECANPAY" : "SINGLE";
    } else {
        return "INVALID";
    }
}

#endif // DILITHION_CONSENSUS_SIGHASH_H
