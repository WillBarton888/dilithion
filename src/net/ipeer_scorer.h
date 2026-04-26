// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 2 interface contract for Misbehaving / banman alignment. Tracks
// misbehavior score per peer; bans when threshold exceeded. Bitcoin Core's
// Misbehaving() pattern (legacy v25.x scoring shape — current upstream
// has migrated to a binary "should discourage" flag, but Dilithion retains
// numeric scoring for finer-grained policy and operator visibility).
//
// Categories include both protocol-level misbehavior (invalid signatures,
// malformed messages) and Dilithion-specific (invalid MIK signature,
// invalid DFMP cooldown proof, malformed DNA Phase 1.5 envelope).
//
// Implementation: src/net/port/peer_scorer.{h,cpp} (Phase 2). Phase 0 froze
// this file's signatures per the architecture §4 freeze contract; only
// purely-additive method additions are permitted without an interface bump.

#ifndef DILITHION_NET_IPEER_SCORER_H
#define DILITHION_NET_IPEER_SCORER_H

#include <cstdint>
#include <string>

namespace dilithion::net {

using NodeId = int;

// Categories of misbehavior, each with a default weight. Per-instance
// weights configurable (Phase 6 introduces a config knob).
enum class MisbehaviorType {
    // Bitcoin Core equivalents
    InvalidSignature,             // weight 100
    InvalidBlock,                 // weight 100
    InvalidHeader,                // weight 50
    InvalidPoW,                   // weight 100  (DIL only — VDF uses InvalidVDFProof)
    OversizedMessage,             // weight 20
    UnknownMessage,               // weight 1
    NonContinuousHeaders,         // weight 20
    DuplicateVersion,             // weight 1

    // Dilithion-specific
    InvalidMIKSignature,          // weight 100
    InvalidDFMPCooldown,          // weight 50
    InvalidVDFProof,              // weight 100
    InvalidDNAEnvelope,           // weight 25
    MalformedSMP1Trailer,         // weight 5
    PrematureDNASample,           // weight 10
    GetDataRateExceeded,          // weight 10
};

class IPeerScorer {
public:
    virtual ~IPeerScorer() = default;

    // Add to peer's misbehavior score. Returns true if the peer should
    // be disconnected and banned (score crossed threshold).
    virtual bool Misbehaving(NodeId peer,
                             MisbehaviorType type,
                             const std::string& reason = "") = 0;

    // Misbehaving with explicit weight (for one-off cases).
    virtual bool Misbehaving(NodeId peer,
                             int weight,
                             const std::string& reason = "") = 0;

    // Get current score for diagnostic RPC.
    virtual int GetScore(NodeId peer) const = 0;

    // Reset score (for testing or operator override).
    virtual void ResetScore(NodeId peer) = 0;

    // Configure ban threshold (default 100). Score >= threshold => disconnect+ban.
    virtual void SetBanThreshold(int threshold) = 0;
    virtual int GetBanThreshold() const = 0;
};

}  // namespace dilithion::net

#endif  // DILITHION_NET_IPEER_SCORER_H
