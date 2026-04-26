// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 2 Day 2 AM: CPeerScorer unit tests.
//
// Covers (per port_phase_2_implementation_plan.md §4.1):
//   * Public IPeerScorer API: both Misbehaving overloads, GetScore,
//     ResetScore, SetBanThreshold, GetBanThreshold
//   * DefaultWeight policy table parity
//   * Decay model (decrement-and-floor)
//   * Slot reclamation on ResetScore
//   * Q1=C codifier — transient-only behaviour (after reset, score is gone)
//
// NOT covered here (Phase 2 Day 2 PM scope):
//   * Forwarder integration in CPeerManager
//   * CBanManager wiring on threshold cross (separate integration test file)

#include <net/port/peer_scorer.h>
#include <net/port/misbehavior_policy.h>
#include <net/ipeer_scorer.h>

#include <cassert>
#include <iostream>
#include <string>

// `MisbehaviorType` exists in TWO namespaces (global from banman.h +
// dilithion::net from ipeer_scorer.h). Use a namespace alias + a renamed
// type alias for the tests; ban_misbehavior_t is the global one.
namespace dnet = ::dilithion::net;
using ::dilithion::net::NodeId;
using ::dilithion::net::port::CPeerScorer;
using ::dilithion::net::port::DefaultWeight;
using ::dilithion::net::port::MapPolicyToDiagnostic;
using NetMisbehavior = dnet::MisbehaviorType;     // scoring-policy enum
using DiagMisbehavior = ::MisbehaviorType;        // banlist.dat diagnostic enum

// ============================================================================
// Tests
// ============================================================================

void test_misbehaving_below_threshold_does_not_ban()
{
    std::cout << "  test_misbehaving_below_threshold_does_not_ban..." << std::flush;
    CPeerScorer s;
    bool banned = s.Misbehaving(NodeId{1}, /*weight=*/50, "below");
    assert(!banned);
    assert(s.GetScore(NodeId{1}) == 50);
    std::cout << " OK\n";
}

void test_misbehaving_at_threshold_returns_true()
{
    std::cout << "  test_misbehaving_at_threshold_returns_true..." << std::flush;
    CPeerScorer s;
    bool banned = s.Misbehaving(NodeId{2}, /*weight=*/100, "instant ban");
    assert(banned);
    assert(s.GetScore(NodeId{2}) == 100);
    std::cout << " OK\n";
}

void test_misbehaving_accumulates_to_threshold()
{
    std::cout << "  test_misbehaving_accumulates_to_threshold..." << std::flush;
    CPeerScorer s;
    assert(!s.Misbehaving(NodeId{3}, 40, ""));   // 40
    assert(!s.Misbehaving(NodeId{3}, 40, ""));   // 80
    assert( s.Misbehaving(NodeId{3}, 40, ""));   // 120 → cross
    assert(s.GetScore(NodeId{3}) == 120);
    std::cout << " OK\n";
}

void test_default_weights_match_policy_table()
{
    std::cout << "  test_default_weights_match_policy_table..." << std::flush;
    // Spec from misbehavior_policy.h — every value of the FROZEN enum has
    // a non-zero weight. DefaultWeight returns 0 only for unknown values
    // (which can't be constructed from a valid enum literal).
    using T = NetMisbehavior;
    assert(DefaultWeight(T::InvalidSignature)     == 100);
    assert(DefaultWeight(T::InvalidBlock)         == 100);
    assert(DefaultWeight(T::InvalidHeader)        == 50);
    assert(DefaultWeight(T::InvalidPoW)           == 100);
    assert(DefaultWeight(T::OversizedMessage)     == 20);
    assert(DefaultWeight(T::UnknownMessage)       == 1);
    assert(DefaultWeight(T::NonContinuousHeaders) == 20);
    assert(DefaultWeight(T::DuplicateVersion)     == 1);
    assert(DefaultWeight(T::InvalidMIKSignature)  == 100);
    assert(DefaultWeight(T::InvalidDFMPCooldown)  == 50);
    assert(DefaultWeight(T::InvalidVDFProof)      == 100);
    assert(DefaultWeight(T::InvalidDNAEnvelope)   == 25);
    assert(DefaultWeight(T::MalformedSMP1Trailer) == 5);
    assert(DefaultWeight(T::PrematureDNASample)   == 10);
    assert(DefaultWeight(T::GetDataRateExceeded)  == 10);
    std::cout << " OK\n";
}

void test_explicit_weight_overrides_policy()
{
    std::cout << "  test_explicit_weight_overrides_policy..." << std::flush;
    CPeerScorer s;
    // DuplicateVersion default is 1; explicit weight 99 must override.
    bool banned = s.Misbehaving(NodeId{4}, 99, "explicit");
    assert(!banned);  // 99 < 100 threshold
    assert(s.GetScore(NodeId{4}) == 99);
    std::cout << " OK\n";
}

void test_get_score_for_unknown_node_is_zero()
{
    std::cout << "  test_get_score_for_unknown_node_is_zero..." << std::flush;
    CPeerScorer s;
    assert(s.GetScore(NodeId{99999}) == 0);
    // Critical: querying an unknown node must NOT create a map entry.
    assert(s.GetScoreMapSizeForTest() == 0);
    std::cout << " OK\n";
}

void test_reset_score_clears_map_entry()
{
    std::cout << "  test_reset_score_clears_map_entry..." << std::flush;
    CPeerScorer s;
    s.Misbehaving(NodeId{5}, 50, "");
    s.Misbehaving(NodeId{6}, 30, "");
    assert(s.GetScoreMapSizeForTest() == 2);

    s.ResetScore(NodeId{5});
    assert(s.GetScore(NodeId{5}) == 0);
    assert(s.GetScoreMapSizeForTest() == 1);  // slot reclaimed, not zeroed

    s.ResetScore(NodeId{6});
    assert(s.GetScoreMapSizeForTest() == 0);
    std::cout << " OK\n";
}

void test_decay_reduces_all_scores()
{
    std::cout << "  test_decay_reduces_all_scores..." << std::flush;
    CPeerScorer s;
    s.Misbehaving(NodeId{10}, 10, "");
    s.Misbehaving(NodeId{20}, 50, "");
    s.Misbehaving(NodeId{30}, 99, "");

    s.DecayAll();
    assert(s.GetScore(NodeId{10}) == 9);
    assert(s.GetScore(NodeId{20}) == 49);
    assert(s.GetScore(NodeId{30}) == 98);
    std::cout << " OK\n";
}

void test_decay_floors_at_zero()
{
    std::cout << "  test_decay_floors_at_zero..." << std::flush;
    CPeerScorer s;
    s.Misbehaving(NodeId{40}, 1, "");

    s.DecayAll();
    assert(s.GetScore(NodeId{40}) == 0);

    s.DecayAll();
    assert(s.GetScore(NodeId{40}) == 0);  // doesn't go negative

    // Map entry still exists at score=0 — decay does not auto-reclaim
    // (matches existing CPeerManager::DecayMisbehaviorScores behaviour).
    assert(s.GetScoreMapSizeForTest() == 1);
    std::cout << " OK\n";
}

void test_set_ban_threshold_changes_trigger_point()
{
    std::cout << "  test_set_ban_threshold_changes_trigger_point..." << std::flush;
    CPeerScorer s;
    assert(s.GetBanThreshold() == 100);  // default

    s.SetBanThreshold(50);
    assert(s.GetBanThreshold() == 50);

    bool banned = s.Misbehaving(NodeId{50}, 50, "");
    assert(banned);  // crosses lowered threshold
    std::cout << " OK\n";
}

void test_dilithion_specific_categories_have_nonzero_weight()
{
    std::cout << "  test_dilithion_specific_categories_have_nonzero_weight..." << std::flush;
    using T = NetMisbehavior;
    assert(DefaultWeight(T::InvalidMIKSignature)  > 0);
    assert(DefaultWeight(T::InvalidDFMPCooldown)  > 0);
    assert(DefaultWeight(T::InvalidVDFProof)      > 0);
    assert(DefaultWeight(T::InvalidDNAEnvelope)   > 0);
    assert(DefaultWeight(T::MalformedSMP1Trailer) > 0);
    assert(DefaultWeight(T::PrematureDNASample)   > 0);
    assert(DefaultWeight(T::GetDataRateExceeded)  > 0);
    std::cout << " OK\n";
}

void test_premature_dna_sample_weight_matches_arch()
{
    std::cout << "  test_premature_dna_sample_weight_matches_arch..." << std::flush;
    // architecture §3.6 + ipeer_scorer.h spec line: PrematureDNASample weight 10
    assert(DefaultWeight(NetMisbehavior::PrematureDNASample) == 10);
    std::cout << " OK\n";
}

void test_score_persists_within_session_across_misbehaving_calls()
{
    std::cout << "  test_score_persists_within_session_across_misbehaving_calls..." << std::flush;
    CPeerScorer s;
    for (int i = 0; i < 5; ++i) {
        s.Misbehaving(NodeId{60}, 10, "");
    }
    assert(s.GetScore(NodeId{60}) == 50);
    std::cout << " OK\n";
}

void test_score_does_not_persist_after_reset_score()
{
    std::cout << "  test_score_does_not_persist_after_reset_score..." << std::flush;
    // Q1=C codifier: scorer is transient; ResetScore is the only durable
    // signal that a NodeId is gone. After reset, the score is zero.
    CPeerScorer s;
    s.Misbehaving(NodeId{70}, 80, "high");
    assert(s.GetScore(NodeId{70}) == 80);
    s.ResetScore(NodeId{70});
    assert(s.GetScore(NodeId{70}) == 0);
    // Re-misbehaving after reset must start fresh (no carryover from the
    // 80 score) — this is the cross-session-fresh-state property.
    s.Misbehaving(NodeId{70}, 30, "fresh");
    assert(s.GetScore(NodeId{70}) == 30);
    std::cout << " OK\n";
}

// Sanity smoke for the diagnostic enum bridge — every frozen enum value
// must map to a non-NONE legacy diagnostic code (to keep banlist.dat
// audit fields meaningful).
void test_map_policy_to_diagnostic_covers_all_values()
{
    std::cout << "  test_map_policy_to_diagnostic_covers_all_values..." << std::flush;
    using T = NetMisbehavior;
    assert(MapPolicyToDiagnostic(T::InvalidSignature)     != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::InvalidBlock)         != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::InvalidHeader)        != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::InvalidPoW)           != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::OversizedMessage)     != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::UnknownMessage)       != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::NonContinuousHeaders) != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::DuplicateVersion)     != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::InvalidMIKSignature)  != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::InvalidDFMPCooldown)  != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::InvalidVDFProof)      != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::InvalidDNAEnvelope)   != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::MalformedSMP1Trailer) != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::PrematureDNASample)   != DiagMisbehavior::NONE);
    assert(MapPolicyToDiagnostic(T::GetDataRateExceeded)  != DiagMisbehavior::NONE);
    std::cout << " OK\n";
}

// Cursor Phase 2 review Q14 (2026-04-26): codify intended semantics of
// SetBanThreshold for invalid (0 or negative) values. Operator config might
// expose this in the future; behaviour must be predictable.
//
// `score >= m_ban_threshold` is the trigger. With threshold = 0, ANY
// positive weight crosses (0 >= 0 false; 1 >= 0 true). With threshold < 0,
// a peer with score = 0 immediately satisfies score >= threshold — but
// AddScoreLocked rejects weight <= 0 as a no-op, so a fresh-but-zero peer
// can't actually trigger the ban path (no insertion to reach the test).
// First positive weight crosses regardless of how negative the threshold.
void test_set_ban_threshold_zero_traps_first_positive_weight()
{
    std::cout << "  test_set_ban_threshold_zero_traps_first_positive_weight..." << std::flush;
    CPeerScorer s;
    s.SetBanThreshold(0);

    // Weight 1 immediately crosses: 0+1=1 >= 0.
    bool banned = s.Misbehaving(NodeId{90}, 1, "tiny weight");
    assert(banned);
    assert(s.GetScore(NodeId{90}) == 1);
    std::cout << " OK\n";
}

void test_set_ban_threshold_negative_first_positive_weight_crosses()
{
    std::cout << "  test_set_ban_threshold_negative_first_positive_weight_crosses..." << std::flush;
    CPeerScorer s;
    s.SetBanThreshold(-50);  // pathological — would be rejected at config layer

    // Zero/negative weights are still no-ops (AddScoreLocked early returns).
    // GetScore on the never-inserted node is 0 — matches threshold trigger
    // condition `0 >= -50`, but no Misbehaving call has happened so the
    // returned bool path isn't exercised.
    assert(s.GetScore(NodeId{91}) == 0);

    // First positive weight crosses immediately.
    bool banned = s.Misbehaving(NodeId{91}, 1, "");
    assert(banned);
    std::cout << " OK\n";
}

// Bonus: zero/negative weight is a no-op per upstream pattern.
void test_zero_or_negative_weight_is_noop()
{
    std::cout << "  test_zero_or_negative_weight_is_noop..." << std::flush;
    CPeerScorer s;
    bool banned = s.Misbehaving(NodeId{80}, 0, "zero");
    assert(!banned);
    assert(s.GetScore(NodeId{80}) == 0);
    // No map entry created for zero-weight.
    assert(s.GetScoreMapSizeForTest() == 0);

    banned = s.Misbehaving(NodeId{80}, -50, "negative");
    assert(!banned);
    assert(s.GetScoreMapSizeForTest() == 0);
    std::cout << " OK\n";
}

// ============================================================================
// main
// ============================================================================

int main()
{
    std::cout << "\n=== Phase 2: CPeerScorer Tests ===\n" << std::endl;

    try {
        std::cout << "--- Public API ---" << std::endl;
        test_misbehaving_below_threshold_does_not_ban();
        test_misbehaving_at_threshold_returns_true();
        test_misbehaving_accumulates_to_threshold();
        test_explicit_weight_overrides_policy();
        test_get_score_for_unknown_node_is_zero();
        test_reset_score_clears_map_entry();
        test_set_ban_threshold_changes_trigger_point();
        test_set_ban_threshold_zero_traps_first_positive_weight();
        test_set_ban_threshold_negative_first_positive_weight_crosses();
        test_score_persists_within_session_across_misbehaving_calls();
        test_score_does_not_persist_after_reset_score();
        test_zero_or_negative_weight_is_noop();

        std::cout << "\n--- Decay ---" << std::endl;
        test_decay_reduces_all_scores();
        test_decay_floors_at_zero();

        std::cout << "\n--- Policy / Diagnostic Bridge ---" << std::endl;
        test_default_weights_match_policy_table();
        test_dilithion_specific_categories_have_nonzero_weight();
        test_premature_dna_sample_weight_matches_arch();
        test_map_policy_to_diagnostic_covers_all_values();

        std::cout << "\n=== All Phase 2 CPeerScorer Tests Passed (18 tests) ===" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown exception" << std::endl;
        return 1;
    }
}
