#ifndef VDF_COINBASE_VDF_H
#define VDF_COINBASE_VDF_H

#include <primitives/transaction.h>
#include <crypto/sha3.h>
#include <cstdint>
#include <vector>

/**
 * VDF proof storage in coinbase scriptSig.
 *
 * Layout of a VDF coinbase scriptSig:
 *   [height bytes] [optional extra nonce] [VDF_TAG (4 bytes)] [proof_len (2 LE)] [proof bytes]
 *
 * The 4-byte tag 0x56 0x44 0x46 0x01 ("VDF\x01") marks the start of VDF data.
 * The proof is a BQFC-serialized Wesolowski proof (~100-200 bytes).
 *
 * The header's vdfProofHash field commits to the proof:
 *   vdfProofHash = SHA3-256(proof_bytes)
 */
namespace CoinbaseVDF {

// Magic tag: "VDF\x01" (4 bytes)
static constexpr uint8_t VDF_TAG[4] = {0x56, 0x44, 0x46, 0x01};
static constexpr size_t VDF_TAG_LEN = 4;
static constexpr size_t VDF_LEN_FIELD = 2;   // uint16_t little-endian
static constexpr size_t MAX_PROOF_SIZE = 512; // generous upper bound

/**
 * Embed a VDF proof into a coinbase scriptSig.
 * Appends [VDF_TAG][len][proof] after existing scriptSig content.
 */
inline void EmbedProof(CTxIn& coinbaseIn, const std::vector<uint8_t>& proof)
{
    // Append tag
    coinbaseIn.scriptSig.insert(coinbaseIn.scriptSig.end(),
                                 VDF_TAG, VDF_TAG + VDF_TAG_LEN);

    // Append length (little-endian uint16)
    uint16_t len = static_cast<uint16_t>(proof.size());
    coinbaseIn.scriptSig.push_back(static_cast<uint8_t>(len & 0xFF));
    coinbaseIn.scriptSig.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));

    // Append proof bytes
    coinbaseIn.scriptSig.insert(coinbaseIn.scriptSig.end(),
                                 proof.begin(), proof.end());
}

/**
 * Extract VDF proof from a coinbase scriptSig.
 * Returns empty vector if no proof found or data is malformed.
 */
inline std::vector<uint8_t> ExtractProof(const std::vector<uint8_t>& scriptSig)
{
    if (scriptSig.size() < VDF_TAG_LEN + VDF_LEN_FIELD + 1)
        return {};

    // Scan for VDF_TAG
    for (size_t i = 0; i + VDF_TAG_LEN + VDF_LEN_FIELD <= scriptSig.size(); i++) {
        if (scriptSig[i]     == VDF_TAG[0] &&
            scriptSig[i + 1] == VDF_TAG[1] &&
            scriptSig[i + 2] == VDF_TAG[2] &&
            scriptSig[i + 3] == VDF_TAG[3])
        {
            size_t lenOff = i + VDF_TAG_LEN;
            if (lenOff + VDF_LEN_FIELD > scriptSig.size())
                return {};

            uint16_t proofLen = static_cast<uint16_t>(scriptSig[lenOff]) |
                                (static_cast<uint16_t>(scriptSig[lenOff + 1]) << 8);

            if (proofLen == 0 || proofLen > MAX_PROOF_SIZE)
                return {};

            size_t dataOff = lenOff + VDF_LEN_FIELD;
            if (dataOff + proofLen > scriptSig.size())
                return {};

            return std::vector<uint8_t>(scriptSig.begin() + dataOff,
                                         scriptSig.begin() + dataOff + proofLen);
        }
    }
    return {};
}

/**
 * Compute the proof hash for the block header's vdfProofHash field.
 * vdfProofHash = SHA3-256(proof_bytes)
 */
inline uint256 ComputeProofHash(const std::vector<uint8_t>& proof)
{
    uint256 result;
    SHA3_256(proof.data(), proof.size(), result.data);
    return result;
}

/**
 * Validate that a coinbase's embedded proof matches the header's vdfProofHash.
 * Returns true if proof found and hash matches.
 */
inline bool ValidateProofCommitment(const std::vector<uint8_t>& scriptSig,
                                     const uint256& expectedHash)
{
    std::vector<uint8_t> proof = ExtractProof(scriptSig);
    if (proof.empty())
        return false;
    return ComputeProofHash(proof) == expectedHash;
}

} // namespace CoinbaseVDF

#endif // VDF_COINBASE_VDF_H
