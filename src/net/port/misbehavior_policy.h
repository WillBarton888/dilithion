// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 2 — Misbehaving policy table. Single source of truth for:
//   1. DefaultWeight(net::MisbehaviorType) — per-category default scoring
//      weight, used when callers invoke IPeerScorer::Misbehaving(NodeId,
//      MisbehaviorType, …) without an explicit weight override.
//   2. MapPolicyToDiagnostic(net::MisbehaviorType) → ::MisbehaviorType —
//      bridge from the FROZEN scoring-policy enum (in ipeer_scorer.h) to
//      the existing diagnostic-logging enum (in banman.h, codes 100–600
//      already baked into production banlist.dat files).
//
// Header-only by design: small, inline, no link cost. Both functions are
// `constexpr` so the compiler verifies switch coverage for any caller that
// uses them in a constant-evaluation context.

#ifndef DILITHION_NET_PORT_MISBEHAVIOR_POLICY_H
#define DILITHION_NET_PORT_MISBEHAVIOR_POLICY_H

#include <net/banman.h>          // ::MisbehaviorType + GetMisbehaviorScore
#include <net/ipeer_scorer.h>    // dilithion::net::MisbehaviorType

namespace dilithion::net::port {

// ============================================================================
// DELIBERATE DIVERGENCE: two MisbehaviorType enums coexist after Phase 2.
// ============================================================================
//
// 1. `dilithion::net::MisbehaviorType` (in ipeer_scorer.h) — FROZEN in Phase 0.
//    The scoring-policy enum: 15 values (8 Bitcoin Core equivalents, 7
//    Dilithion-specific). Used by IPeerScorer::Misbehaving and any future
//    MaybePunishNodeFor* dispatcher (deferred to Phase 3 per Phase 2 plan
//    §10 Q5 = C).
//
// 2. `::MisbehaviorType` (in banman.h) — global namespace, ALREADY in
//    production. Diagnostic-logging enum with uint16_t numeric codes
//    (100–600). Used by CBanEntry::misbehaviorType to record WHY a peer
//    was banned in banlist.dat. Renumbering would break ban-list
//    compatibility on every node, so this enum is preserved exactly.
//
// Why two enums (not one):
//   * The frozen IPeerScorer interface declares its own enum class and
//     §4 freeze contract forbids signature changes without a version bump.
//   * The legacy enum's codes are persisted on disk (banlist.dat) — can't
//     renumber without a format migration.
//   * Adding the Dilithion-specific entries (InvalidMIKSignature, etc.)
//     into the legacy enum would be possible but creates a one-way
//     coupling: anyone touching banman.h would need to remember to update
//     ipeer_scorer.h's frozen enum. The bridge function below is the
//     explicit, audit-friendly contract instead.
//
// MapPolicyToDiagnostic is the bridge. Drift detection: the unit test
// test_default_weights_match_policy_table iterates every value of the
// frozen enum and asserts both DefaultWeight() and MapPolicyToDiagnostic()
// produce non-zero / non-NONE results. A future contributor adding a new
// frozen-enum value MUST update both functions or fail the test.
// ============================================================================

// Default weight per scoring-policy category. Comments mirror those in
// ipeer_scorer.h so the source of truth for any one weight is the enum
// declaration; this function just makes the assignments executable.
//
// SCOPE NOTE (Cursor Phase 2 review Q2, 2026-04-26):
//   Production runtime today uses the *legacy* helper `::GetMisbehaviorScore(
//   ::MisbehaviorType)` from banman.h to resolve the default weight inside
//   the CPeerManager::Misbehaving forwarder. That's because all ~107
//   existing call sites pass `::MisbehaviorType` (the diagnostic enum),
//   not `dilithion::net::MisbehaviorType` (the scoring-policy enum).
//
//   `DefaultWeight()` is the source of truth for SCORING-POLICY callers —
//   the IPeerScorer interface and any future MaybePunishNodeFor* dispatcher
//   (Phase 3+). `::GetMisbehaviorScore()` is the source of truth for
//   DIAGNOSTIC-ENUM callers (the existing forwarder).
//
//   Today the two tables happen to land on the same numbers for overlapping
//   categories. If a future contributor changes one, the other won't follow
//   automatically. Drift between them is real but bounded — caught at test
//   time by `test_default_weights_match_policy_table` (frozen-enum
//   coverage) plus the existing misbehavior_scoring_tests.cpp regression
//   net (legacy-enum coverage).
//
//   When Phase 3 wires MaybePunishNodeFor* to use this table directly,
//   the forwarder also gets refactored — this comment can come down then.
constexpr int DefaultWeight(::dilithion::net::MisbehaviorType type)
{
    using Type = ::dilithion::net::MisbehaviorType;
    switch (type) {
        // Bitcoin Core equivalents
        case Type::InvalidSignature:        return 100;
        case Type::InvalidBlock:            return 100;
        case Type::InvalidHeader:           return 50;
        case Type::InvalidPoW:              return 100;
        case Type::OversizedMessage:        return 20;
        case Type::UnknownMessage:          return 1;
        case Type::NonContinuousHeaders:    return 20;
        case Type::DuplicateVersion:        return 1;
        // Dilithion-specific
        case Type::InvalidMIKSignature:     return 100;  // arch §3.6
        case Type::InvalidDFMPCooldown:     return 50;
        case Type::InvalidVDFProof:         return 100;
        case Type::InvalidDNAEnvelope:      return 25;
        case Type::MalformedSMP1Trailer:    return 5;
        case Type::PrematureDNASample:      return 10;
        case Type::GetDataRateExceeded:     return 10;
    }
    return 0;  // unknown — caller MUST detect (test enforces switch coverage)
}

// Bridge from the scoring-policy enum to the diagnostic-logging enum.
// Used by CPeerScorer at threshold-cross to populate CBanEntry::misbehaviorType
// so existing banlist.dat audit/RPC outputs continue rendering consistent
// codes. Returns ::MisbehaviorType::NONE for unknown inputs.
constexpr ::MisbehaviorType
MapPolicyToDiagnostic(::dilithion::net::MisbehaviorType type)
{
    using Type = ::dilithion::net::MisbehaviorType;
    switch (type) {
        case Type::InvalidSignature:        return ::MisbehaviorType::TX_INVALID_SIGNATURE;
        case Type::InvalidBlock:            return ::MisbehaviorType::INVALID_BLOCK_HEADER;
        case Type::InvalidHeader:           return ::MisbehaviorType::INVALID_BLOCK_HEADER;
        case Type::InvalidPoW:              return ::MisbehaviorType::INVALID_BLOCK_POW;
        case Type::OversizedMessage:        return ::MisbehaviorType::INVALID_MESSAGE_SIZE;
        case Type::UnknownMessage:          return ::MisbehaviorType::UNKNOWN_MESSAGE_TYPE;
        case Type::NonContinuousHeaders:    return ::MisbehaviorType::INVALID_BLOCK_HEADER;
        case Type::DuplicateVersion:        return ::MisbehaviorType::DUPLICATE_VERSION;
        // Dilithion-specific — no exact match in the legacy enum, route to the
        // closest semantic neighbour. Operators see the policy reason in logs;
        // banlist.dat shows the diagnostic code below.
        case Type::InvalidMIKSignature:     return ::MisbehaviorType::TX_INVALID_SIGNATURE;
        case Type::InvalidDFMPCooldown:     return ::MisbehaviorType::INVALID_BLOCK_HEADER;
        case Type::InvalidVDFProof:         return ::MisbehaviorType::INVALID_BLOCK_POW;
        case Type::InvalidDNAEnvelope:      return ::MisbehaviorType::PARSE_FAILURE;
        case Type::MalformedSMP1Trailer:    return ::MisbehaviorType::PARSE_FAILURE;
        case Type::PrematureDNASample:      return ::MisbehaviorType::PARSE_FAILURE;
        case Type::GetDataRateExceeded:     return ::MisbehaviorType::GETDATA_RATE_EXCEEDED;
    }
    return ::MisbehaviorType::NONE;
}

}  // namespace dilithion::net::port

#endif  // DILITHION_NET_PORT_MISBEHAVIOR_POLICY_H
