// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 3 interface contract for the Bitcoin Core peer/IBD/chain-selection port.
// Architecture document: .claude/contracts/bitcoin_core_port_architecture.md
//
// IHeaderProofChecker abstracts the chain-specific proof check (RandomX PoW
// for DIL, VDF for DilV) behind a single interface. HeadersSync (Phase 3)
// and chain selection (Phase 5) consume this — they never call into the
// concrete VDF or RandomX code directly. This makes the port truly
// chain-agnostic.

#ifndef DILITHION_NET_IHEADER_PROOF_CHECKER_H
#define DILITHION_NET_IHEADER_PROOF_CHECKER_H

#include <cstdint>
#include <uint256.h>

class CBlockHeader;

namespace dilithion::net {

class IHeaderProofChecker {
public:
    virtual ~IHeaderProofChecker() = default;

    // Validate the cryptographic proof in the header (PoW hash check, or
    // VDF iteration count + output check). Read-only — does not modify
    // any state. Must be deterministic.
    //
    // Returns true if the header's proof is valid given its declared
    // difficulty/iteration target. Returns false otherwise; caller may
    // mark the source peer as misbehaving.
    virtual bool CheckHeaderProof(const CBlockHeader& header) const = 0;

    // Compute the cumulative-work contribution this header makes to the
    // chain. For PoW: 2^256 / (target + 1) per Bitcoin convention. For
    // VDF: a monotone function of iteration count. The unit is opaque —
    // chain-selection only compares uint256 values pairwise via
    // ChainWorkGreaterThan, never sums across chain types.
    //
    // Must be pure and deterministic.
    virtual uint256 ChainWorkContribution(const CBlockHeader& header) const = 0;

    // Compare two cumulative chain works. Encapsulated here because for VDF
    // chains we may eventually want to add tiebreakers (lowest hash, etc.).
    // For now: simple uint256 > uint256.
    virtual bool ChainWorkGreaterThan(const uint256& a, const uint256& b) const = 0;
};

}  // namespace dilithion::net

#endif  // DILITHION_NET_IHEADER_PROOF_CHECKER_H
