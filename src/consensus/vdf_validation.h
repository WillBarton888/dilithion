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
 *   4. Miner is not in cooldown
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

#endif // DILITHION_CONSENSUS_VDF_VALIDATION_H
