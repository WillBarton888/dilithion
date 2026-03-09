#ifndef DILITHION_CONSENSUS_VDF_VALIDATION_H
#define DILITHION_CONSENSUS_VDF_VALIDATION_H

#include <primitives/block.h>
#include <array>
#include <string>
#include <vector>

/**
 * VDF consensus validation.
 *
 * Called by the PoW dispatcher when a block has version >= 4 (VDF block).
 * Validates:
 *   1. VDF proof is present in coinbase and matches header's vdfProofHash
 *   2. VDF proof verifies against the expected challenge
 *   3. VDF output in header matches the proof's output
 *
 * Note: Cooldown was miner-side policy until dfmpCooldownConsensusHeight.
 * After that height, CheckVDFCooldown() enforces cooldown at consensus.
 */

/**
 * Full VDF block validation.
 *
 * @param block         The candidate block (must be IsVDFBlock())
 * @param height        Block height
 * @param prevHash      Hash of the previous block (for challenge derivation)
 * @param vdfIterations Expected iteration count (from chainparams)
 * @param error         Human-readable error string on failure
 * @return true if VDF proof is valid and all consensus checks pass
 */
bool CheckVDFProof(
    const CBlock& block,
    int height,
    const uint256& prevHash,
    uint64_t vdfIterations,
    std::string& error
);

/**
 * Compute the per-miner VDF challenge.
 *
 * challenge = SHA3-256( prevHash || height_le32 || minerAddress )
 *
 * Each miner gets a unique challenge derived from the previous block
 * and their payout address, ensuring independent VDF computations.
 */
std::array<uint8_t, 32> ComputeVDFChallenge(
    const uint256& prevHash,
    int height,
    const std::array<uint8_t, 20>& minerAddress
);

/**
 * Extract the miner's payout address (first 20 bytes of first output's
 * scriptPubKey) from the coinbase transaction.
 *
 * @param block  The block containing the coinbase
 * @param addr   Output: 20-byte address
 * @return true if extraction succeeded
 */
bool ExtractCoinbaseAddress(
    const CBlock& block,
    std::array<uint8_t, 20>& addr
);

/**
 * Extract the miner's MIK identity (20 bytes) from the coinbase scriptSig.
 *
 * Parses the MIK_MARKER (0xDF) section of the coinbase and returns the
 * 20-byte MIK identity.  Falls back to payout address if MIK is not present
 * (pre-MIK blocks or blocks without MIK data).
 *
 * @param block  The block containing the coinbase
 * @param mikId  Output: 20-byte MIK identity
 * @return true if extraction succeeded
 */
bool ExtractCoinbaseMIKIdentity(
    const CBlock& block,
    std::array<uint8_t, 20>& mikId
);

// Forward declarations
class CCooldownTracker;
namespace digital_dna { class IDNARegistry; }

/**
 * Check VDF cooldown consensus rule (hard fork).
 *
 * After dfmpCooldownConsensusHeight, rejects blocks where the miner's MIK
 * identity has mined within the cooldown period.
 *
 * @param block         The candidate block
 * @param height        Block height
 * @param tracker       Cooldown tracker with current chain state
 * @param error         Human-readable error string on failure
 * @return true if block passes cooldown check (or not yet enforced)
 */
bool CheckVDFCooldown(
    const CBlock& block,
    int height,
    CCooldownTracker& tracker,
    std::string& error
);

/**
 * Check DNA commitment in VDF block coinbase (Phase 3).
 *
 * After dnaCommitmentActivationHeight, VDF blocks must include a 0xDD + 32-byte
 * DNA hash in their coinbase scriptSig (after MIK data).
 *
 * @param block         The candidate VDF block
 * @param height        Block height
 * @param error         Human-readable error string on failure
 * @return true if block passes DNA commitment check (or pre-activation)
 */
bool CheckDNACommitment(
    const CBlock& block,
    int height,
    std::string& error
);

/**
 * Check DNA hash equality at consensus (Phase 5A).
 *
 * After dnaHashEnforcementHeight, the DNA hash committed in the coinbase
 * must match the hash of the DNA stored in the local registry for that MIK.
 * If the MIK has no DNA on file, the check passes (can't verify).
 *
 * @param block         The candidate VDF block
 * @param height        Block height
 * @param registry      DNA registry with stored identities
 * @param error         Human-readable error string on failure
 * @return true if hash matches or cannot be verified (no local DNA)
 */
bool CheckDNAHashEquality(
    const CBlock& block,
    int height,
    const digital_dna::IDNARegistry& registry,
    std::string& error
);

#endif // DILITHION_CONSENSUS_VDF_VALIDATION_H
