// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_SCRIPT_HTLC_H
#define DILITHION_SCRIPT_HTLC_H

#include <script/script.h>
#include <cstdint>
#include <vector>
#include <string>

// ============================================================================
// HTLC (Hash Time-Locked Contract) for Cross-Chain Atomic Swaps
//
// Adapted from BIP-199 for SHA3-256 and Dilithium3 signatures.
//
// Locking script (scriptPubKey):
//   OP_IF
//       OP_SHA3_256 <hash_lock> OP_EQUALVERIFY
//       OP_DUP OP_HASH160 <claim_pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
//   OP_ELSE
//       <timeout_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
//       OP_DUP OP_HASH160 <refund_pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
//   OP_ENDIF
//
// Claim path (recipient reveals preimage):
//   <signature> <pubkey> <preimage> OP_TRUE
//
// Refund path (sender reclaims after timeout):
//   <signature> <pubkey> OP_FALSE
//
// ============================================================================

struct HTLCParameters {
    std::vector<uint8_t> hash_lock;          // SHA3-256 hash of preimage (32 bytes)
    std::vector<uint8_t> claim_pubkey_hash;  // Recipient's pubkey hash (20 bytes)
    std::vector<uint8_t> refund_pubkey_hash; // Sender's pubkey hash (20 bytes)
    uint32_t timeout_height;                  // Block height for refund eligibility
};

/**
 * Build the HTLC locking script (scriptPubKey).
 *
 * @param params   HTLC parameters (hash_lock, pubkey hashes, timeout)
 * @return CScript containing the HTLC locking script
 */
CScript CreateHTLCScript(const HTLCParameters& params);

/**
 * Build the claim scriptSig (recipient reveals preimage to claim funds).
 *
 * @param signature  Dilithium3 signature (3309 bytes)
 * @param pubkey     Dilithium3 public key (1952 bytes)
 * @param preimage   Secret preimage (32 bytes)
 * @return CScript containing the claim script
 */
CScript CreateHTLCClaimScript(const std::vector<uint8_t>& signature,
                               const std::vector<uint8_t>& pubkey,
                               const std::vector<uint8_t>& preimage);

/**
 * Build the refund scriptSig (sender reclaims after timeout).
 *
 * @param signature  Dilithium3 signature (3309 bytes)
 * @param pubkey     Dilithium3 public key (1952 bytes)
 * @return CScript containing the refund script
 */
CScript CreateHTLCRefundScript(const std::vector<uint8_t>& signature,
                                const std::vector<uint8_t>& pubkey);

/**
 * Parse an HTLC scriptPubKey into its parameters.
 *
 * @param script  The scriptPubKey to decode
 * @param params  Output: extracted HTLC parameters
 * @return true if the script is a valid HTLC
 */
bool DecodeHTLCScript(const CScript& script, HTLCParameters& params);

/**
 * Generate a cryptographically secure random preimage (32 bytes).
 *
 * Uses the platform's secure random number generator (BCryptGenRandom on
 * Windows, /dev/urandom on Unix).
 *
 * @return 32-byte random preimage
 */
std::vector<uint8_t> GeneratePreimage();

/**
 * Compute SHA3-256 hash of a preimage.
 *
 * @param preimage  The preimage to hash (should be 32 bytes)
 * @return 32-byte SHA3-256 hash
 */
std::vector<uint8_t> HashPreimage(const std::vector<uint8_t>& preimage);

#endif // DILITHION_SCRIPT_HTLC_H
