// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/vdf_validation.h>
#include <consensus/validation.h>
#include <vdf/vdf.h>
#include <vdf/coinbase_vdf.h>
#include <crypto/sha3.h>
#include <cstring>
#include <iostream>

// ---------------------------------------------------------------------------
// ComputeVDFChallenge
// ---------------------------------------------------------------------------

std::array<uint8_t, 32> ComputeVDFChallenge(
    const uint256& prevHash,
    int height,
    const std::array<uint8_t, 20>& minerAddress)
{
    // Preimage: prevHash(32) || height_le32(4) || minerAddress(20) = 56 bytes
    uint8_t preimage[56];
    std::memcpy(preimage,      prevHash.data, 32);
    uint32_t hLE = static_cast<uint32_t>(height);
    std::memcpy(preimage + 32, &hLE, 4);
    std::memcpy(preimage + 36, minerAddress.data(), 20);

    std::array<uint8_t, 32> challenge{};
    SHA3_256(preimage, sizeof(preimage), challenge.data());
    return challenge;
}

// ---------------------------------------------------------------------------
// ExtractCoinbaseAddress
// ---------------------------------------------------------------------------

bool ExtractCoinbaseAddress(
    const CBlock& block,
    std::array<uint8_t, 20>& addr)
{
    if (block.vtx.empty())
        return false;

    // Deserialize just the coinbase transaction.
    CBlockValidator validator;
    std::vector<CTransactionRef> txs;
    std::string err;
    if (!validator.DeserializeBlockTransactions(block, txs, err) || txs.empty())
        return false;

    const CTransaction& coinbase = *txs[0];
    if (!coinbase.IsCoinBase())
        return false;

    // The miner's payout address is the first 20 bytes of the first
    // output's scriptPubKey (P2PKH format: OP_DUP OP_HASH160 <20 bytes> ...).
    // In Dilithion P2PKH the address bytes start at scriptPubKey[3].
    if (coinbase.vout.empty())
        return false;

    const auto& spk = coinbase.vout[0].scriptPubKey;
    // Minimum P2PKH: OP_DUP(1) OP_HASH160(1) OP_PUSH20(1) <20> OP_EQUALVERIFY(1) OP_CHECKSIG(1) = 25
    if (spk.size() < 25)
        return false;

    std::memcpy(addr.data(), spk.data() + 3, 20);
    return true;
}

// ---------------------------------------------------------------------------
// CheckVDFProof
// ---------------------------------------------------------------------------

bool CheckVDFProof(
    const CBlock& block,
    int height,
    const uint256& prevHash,
    uint64_t vdfIterations,
    std::string& error)
{
    // 1. Block must be a VDF block.
    if (!block.IsVDFBlock()) {
        error = "CheckVDFProof: block is not version >= 4";
        return false;
    }

    // 2. vdfOutput must not be null.
    if (block.vdfOutput.IsNull()) {
        error = "CheckVDFProof: vdfOutput is null";
        return false;
    }

    // 3. vdfProofHash must not be null.
    if (block.vdfProofHash.IsNull()) {
        error = "CheckVDFProof: vdfProofHash is null";
        return false;
    }

    // 4. Extract VDF proof from coinbase scriptSig.
    CBlockValidator validator;
    std::vector<CTransactionRef> txs;
    std::string deserErr;
    if (!validator.DeserializeBlockTransactions(block, txs, deserErr) || txs.empty()) {
        error = "CheckVDFProof: failed to deserialize coinbase: " + deserErr;
        return false;
    }

    const CTransaction& coinbase = *txs[0];
    if (!coinbase.IsCoinBase()) {
        error = "CheckVDFProof: first transaction is not coinbase";
        return false;
    }

    std::vector<uint8_t> proof = CoinbaseVDF::ExtractProof(coinbase.vin[0].scriptSig);
    if (proof.empty()) {
        error = "CheckVDFProof: no VDF proof found in coinbase scriptSig";
        return false;
    }

    // 5. Verify proof hash commitment: SHA3-256(proof) == header.vdfProofHash.
    uint256 computedHash = CoinbaseVDF::ComputeProofHash(proof);
    if (computedHash != block.vdfProofHash) {
        error = "CheckVDFProof: proof hash mismatch (commitment failed)";
        return false;
    }

    // 6. Extract miner address from coinbase.
    std::array<uint8_t, 20> minerAddr{};
    if (!ExtractCoinbaseAddress(block, minerAddr)) {
        error = "CheckVDFProof: cannot extract miner address from coinbase";
        return false;
    }

    // 7. Compute expected challenge.
    std::array<uint8_t, 32> challenge = ComputeVDFChallenge(prevHash, height, minerAddr);

    // 8. Reconstruct VDFResult and verify the Wesolowski proof via chiavdf.
    vdf::VDFResult result;
    std::memcpy(result.output.data(), block.vdfOutput.data, 32);
    result.proof = proof;
    result.iterations = vdfIterations;
    result.duration_us = 0; // not needed for verification

    vdf::VDFConfig cfg;
    cfg.target_iterations = vdfIterations;

    if (!vdf::verify(challenge, result, cfg)) {
        error = "CheckVDFProof: Wesolowski proof verification failed";
        return false;
    }

    return true;
}
