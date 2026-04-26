// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 3 — concrete IHeaderProofChecker implementations for the two
// Dilithion chains. Header-only; both classes are small enough that a
// separate translation unit isn't worth the link-edit overhead.
//
// Q4 verification (2026-04-26): both chains share the SAME chain-work
// formula (`2^(256-8*size)/mantissa` driven by nBits). The only thing
// that differs is the cryptographic-proof check itself:
//   * DIL  — RandomX PoW hash <= target  (existing CheckProofOfWork)
//   * DilV — header-level VDF sanity     (full VDF check at ConnectBlock)

#ifndef DILITHION_NET_PORT_HEADER_PROOF_CHECKERS_H
#define DILITHION_NET_PORT_HEADER_PROOF_CHECKERS_H

#include <net/iheader_proof_checker.h>
#include <consensus/chain_work.h>     // Phase 3 shared helper
#include <consensus/pow.h>            // CheckProofOfWork
#include <primitives/block.h>         // CBlockHeader

namespace dilithion::net::port {

// ============================================================================
// RandomXHeaderProofChecker — DIL chain
// ============================================================================
//
// Wraps the existing PoW path. CheckHeaderProof = hash <= target via
// the existing CheckProofOfWork. ChainWorkContribution = ComputeChainWork(nBits).

class RandomXHeaderProofChecker final : public ::dilithion::net::IHeaderProofChecker {
public:
    bool CheckHeaderProof(const CBlockHeader& header) const override
    {
        // Bitcoin's pattern: hash header → compare against target. Existing
        // CheckProofOfWork(hash, nBits) does exactly this.
        return ::CheckProofOfWork(header.GetHash(), header.nBits);
    }

    uint256 ChainWorkContribution(const CBlockHeader& header) const override
    {
        return ::dilithion::consensus::ComputeChainWork(header.nBits);
    }

    bool ChainWorkGreaterThan(const uint256& a, const uint256& b) const override
    {
        // Strict greater-than (the helper provides >=; flip ordering).
        return !::dilithion::consensus::ChainWorkGreaterOrEqual(b, a);
    }
};

// ============================================================================
// VDFHeaderProofChecker — DilV chain
// ============================================================================
//
// VDF blocks have nVersion >= VDF_VERSION (=4) and carry vdfOutput +
// vdfProofHash in the extended header layout. Full VDF proof
// verification needs the coinbase transaction (where the proof bytes
// live) and stays at ConnectBlock / CheckVDFProof — not here.
//
// At header-level we only do cheap sanity: is this actually a VDF
// block, and are the VDF fields populated? A header that fails these
// checks is malformed and the peer should be punished.
class VDFHeaderProofChecker final : public ::dilithion::net::IHeaderProofChecker {
public:
    bool CheckHeaderProof(const CBlockHeader& header) const override
    {
        if (!header.IsVDFBlock()) return false;        // wrong chain type
        if (header.vdfProofHash.IsNull()) return false;
        if (header.vdfOutput.IsNull()) return false;
        // Full VDF verification deferred to CheckVDFProof at ConnectBlock —
        // the proof bytes aren't in the header layout.
        return true;
    }

    uint256 ChainWorkContribution(const CBlockHeader& header) const override
    {
        // Q4: both chains share the formula. VDF blocks set nBits for legacy
        // compatibility (existing chain-selection logic depends on it).
        return ::dilithion::consensus::ComputeChainWork(header.nBits);
    }

    bool ChainWorkGreaterThan(const uint256& a, const uint256& b) const override
    {
        return !::dilithion::consensus::ChainWorkGreaterOrEqual(b, a);
    }
};

}  // namespace dilithion::net::port

#endif  // DILITHION_NET_PORT_HEADER_PROOF_CHECKERS_H
