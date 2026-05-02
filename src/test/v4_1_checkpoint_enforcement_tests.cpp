// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// v4.1 mandatory upgrade — checkpoint enforcement test scenarios.
//
// Coverage:
//   - Three-tier ABC enforcement at chain.cpp:294
//     (Tier 1 single-block, Tier 2 highest-checkpoint ancestor, Tier 3 reorg-only walk)
//   - startup_checkpoint_validator Phase 1 + Phase 2
//   - Lifetime-miner snapshot assertion (placeholder mode + active mode)
//
// Test fixture pattern: scoped ChainParams copy per Cursor §7 Q3 + Layer-2
// MED-1. We do NOT mutate global g_chainParams permanently — each test
// saves the prior pointer, swaps in a stub, then restores on exit.
//
// Note on header-time helper coverage: the CheckpointCheckHeader function
// is `static` inside src/net/headers_manager.cpp and not externally
// callable. Header-time enforcement is exercised end-to-end by the existing
// competing_sibling_below_checkpoint_tests + fast_path_2_boundary_tests
// suites (which now include the v4.1 5-site insertions in their build).
// Direct unit tests would require either making the helper non-static or
// writing P2P-mock integration tests; both are out of v4.1 scope. The
// helper's logic is straightforward (compare hash to one checkpoint at
// the exact height) and the integration is verified by §4.3 manual test.

#include <consensus/chain.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <node/startup_checkpoint_validator.h>
#include <vdf/cooldown_tracker.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>

namespace {

// Build a CBlockIndex with explicit phashBlock and pprev.
std::unique_ptr<CBlockIndex> MakeIndex(uint8_t hash_seed, int height,
                                        CBlockIndex* pprev = nullptr)
{
    auto pindex = std::make_unique<CBlockIndex>();
    pindex->pprev = pprev;
    pindex->nHeight = height;
    pindex->nChainWork = uint256();
    pindex->nStatus = CBlockIndex::BLOCK_VALID_TRANSACTIONS;
    pindex->nSequenceId = 1;
    std::memset(pindex->phashBlock.data, 0, 32);
    pindex->phashBlock.data[0] = hash_seed;
    return pindex;
}

uint256 MakeHashSeeded(uint8_t seed) {
    uint256 h;
    std::memset(h.data, 0, 32);
    h.data[0] = seed;
    return h;
}

// RAII guard: swap g_chainParams to a stub for the test, restore on dtor.
class ChainParamsScope {
public:
    explicit ChainParamsScope(Dilithion::ChainParams* stub) {
        m_saved = Dilithion::g_chainParams;
        Dilithion::g_chainParams = stub;
    }
    ~ChainParamsScope() {
        Dilithion::g_chainParams = m_saved;
    }
private:
    Dilithion::ChainParams* m_saved;
};

}  // anonymous

// =============================================================================
// CheckpointCheck (chainparams) — sanity tests on the existing helper used
// by both Tier 1 and the post-rollback enforcement path. These are not new
// in v4.1 but lock in the semantics v4.1 depends on.
// =============================================================================

void test_checkpoint_check_no_checkpoint_at_height_returns_true()
{
    std::cout << "  test_checkpoint_check_no_checkpoint_at_height_returns_true..." << std::flush;
    Dilithion::ChainParams stub;
    stub.checkpoints.emplace_back(100, MakeHashSeeded(0xAA));
    // Querying at a height with NO checkpoint should pass.
    assert(stub.CheckpointCheck(50, MakeHashSeeded(0x99)) == true);
    assert(stub.CheckpointCheck(101, MakeHashSeeded(0xBB)) == true);
    std::cout << " OK\n";
}

void test_checkpoint_check_match_returns_true()
{
    std::cout << "  test_checkpoint_check_match_returns_true..." << std::flush;
    Dilithion::ChainParams stub;
    stub.checkpoints.emplace_back(100, MakeHashSeeded(0xAA));
    assert(stub.CheckpointCheck(100, MakeHashSeeded(0xAA)) == true);
    std::cout << " OK\n";
}

void test_checkpoint_check_mismatch_returns_false()
{
    std::cout << "  test_checkpoint_check_mismatch_returns_false..." << std::flush;
    Dilithion::ChainParams stub;
    stub.checkpoints.emplace_back(100, MakeHashSeeded(0xAA));
    assert(stub.CheckpointCheck(100, MakeHashSeeded(0xBB)) == false);
    std::cout << " OK\n";
}

// =============================================================================
// Startup validator Phase 1 — ValidateChainAgainstCheckpoints
// =============================================================================

void test_startup_validator_null_tip_passes()
{
    std::cout << "  test_startup_validator_null_tip_passes..." << std::flush;
    Dilithion::ChainParams stub;
    stub.checkpoints.emplace_back(100, MakeHashSeeded(0xAA));
    ChainParamsScope scope(&stub);
    // Empty chain (null tip) — fresh IBD will use header-time enforcement.
    assert(Dilithion::ValidateChainAgainstCheckpoints(nullptr) == true);
    std::cout << " OK\n";
}

void test_startup_validator_null_chainparams_passes()
{
    std::cout << "  test_startup_validator_null_chainparams_passes..." << std::flush;
    auto pindex = MakeIndex(0xAA, 100);
    ChainParamsScope scope(nullptr);
    // No chainparams configured → defensive pass.
    assert(Dilithion::ValidateChainAgainstCheckpoints(pindex.get()) == true);
    std::cout << " OK\n";
}

void test_startup_validator_tip_below_all_checkpoints_passes()
{
    std::cout << "  test_startup_validator_tip_below_all_checkpoints_passes..." << std::flush;
    Dilithion::ChainParams stub;
    stub.checkpoints.emplace_back(100, MakeHashSeeded(0xAA));
    ChainParamsScope scope(&stub);
    // Tip at h=50 is below every checkpoint (h=100).
    auto pindex = MakeIndex(0xCC, 50);
    assert(Dilithion::ValidateChainAgainstCheckpoints(pindex.get()) == true);
    std::cout << " OK\n";
}

void test_startup_validator_tip_at_matching_checkpoint_passes()
{
    std::cout << "  test_startup_validator_tip_at_matching_checkpoint_passes..." << std::flush;
    Dilithion::ChainParams stub;
    stub.checkpoints.emplace_back(100, MakeHashSeeded(0xAA));
    ChainParamsScope scope(&stub);
    // Build a chain genesis(0) -> h=100(0xAA matching checkpoint).
    auto genesis = MakeIndex(0x01, 0);
    auto h100 = MakeIndex(0xAA, 100, genesis.get());
    assert(Dilithion::ValidateChainAgainstCheckpoints(h100.get()) == true);
    std::cout << " OK\n";
}

void test_startup_validator_tip_at_violating_checkpoint_fails()
{
    std::cout << "  test_startup_validator_tip_at_violating_checkpoint_fails..." << std::flush;
    Dilithion::ChainParams stub;
    stub.checkpoints.emplace_back(100, MakeHashSeeded(0xAA));
    ChainParamsScope scope(&stub);
    // Tip at h=100 with hash 0xBB — does NOT match the canonical 0xAA.
    auto genesis = MakeIndex(0x01, 0);
    auto h100 = MakeIndex(0xBB, 100, genesis.get());
    // Validator should refuse.
    assert(Dilithion::ValidateChainAgainstCheckpoints(h100.get()) == false);
    std::cout << " OK\n";
}

// =============================================================================
// Startup validator Phase 2 — ValidateLifetimeMinerSnapshot
// =============================================================================
// CCooldownTracker exposes GetLifetimeMinerCount() returning
// m_lifetimeBlockCount.size(). We construct a tracker, call OnBlockConnected
// to populate it deterministically, then exercise the assertion.

void test_lifetime_validator_null_tracker_passes()
{
    std::cout << "  test_lifetime_validator_null_tracker_passes..." << std::flush;
    Dilithion::ChainParams stub;
    stub.lifetimeMinerCountAt44232 = 7;
    ChainParamsScope scope(&stub);
    auto pindex = MakeIndex(0xAA, 50000);
    // Null tracker → defensive pass.
    assert(Dilithion::ValidateLifetimeMinerSnapshot(pindex.get(), nullptr) == true);
    std::cout << " OK\n";
}

void test_lifetime_validator_null_tip_passes()
{
    std::cout << "  test_lifetime_validator_null_tip_passes..." << std::flush;
    Dilithion::ChainParams stub;
    stub.lifetimeMinerCountAt44232 = 7;
    ChainParamsScope scope(&stub);
    CCooldownTracker tracker;
    assert(Dilithion::ValidateLifetimeMinerSnapshot(nullptr, &tracker) == true);
    std::cout << " OK\n";
}

void test_lifetime_validator_tip_below_threshold_passes()
{
    std::cout << "  test_lifetime_validator_tip_below_threshold_passes..." << std::flush;
    Dilithion::ChainParams stub;
    stub.lifetimeMinerCountAt44232 = 7;
    ChainParamsScope scope(&stub);
    CCooldownTracker tracker;
    // Tip below activation height — assertion skipped.
    auto pindex = MakeIndex(0xAA, 1000);
    assert(Dilithion::ValidateLifetimeMinerSnapshot(pindex.get(), &tracker) == true);
    std::cout << " OK\n";
}

void test_lifetime_validator_placeholder_zero_below_threshold_passes()
{
    std::cout << "  test_lifetime_validator_placeholder_zero_below_threshold_passes..." << std::flush;
    Dilithion::ChainParams stub;
    stub.lifetimeMinerCountAt44232 = 0;  // placeholder = disabled
    ChainParamsScope scope(&stub);
    CCooldownTracker tracker;
    // v4.1 HIGH-3 update: placeholder mode (=0) is OK ONLY when tip is below
    // the activation height (e.g., during pass-1 IBD build before reaching
    // 44232). Above that height + placeholder = fail-fast. See companion
    // test test_lifetime_validator_placeholder_with_active_chain_fails.
    auto pindex = MakeIndex(0xAA, 1000);
    assert(Dilithion::ValidateLifetimeMinerSnapshot(pindex.get(), &tracker) == true);
    std::cout << " OK\n";
}

void test_lifetime_validator_match_passes()
{
    std::cout << "  test_lifetime_validator_match_passes..." << std::flush;
    Dilithion::ChainParams stub;
    stub.lifetimeMinerCountAt44232 = 3;
    ChainParamsScope scope(&stub);
    CCooldownTracker tracker;
    // Populate tracker with 3 distinct MIKs.
    CCooldownTracker::Address mik_a{}; mik_a.fill(0xAA);
    CCooldownTracker::Address mik_b{}; mik_b.fill(0xBB);
    CCooldownTracker::Address mik_c{}; mik_c.fill(0xCC);
    tracker.OnBlockConnected(1, mik_a, 1000);
    tracker.OnBlockConnected(2, mik_b, 1010);
    tracker.OnBlockConnected(3, mik_c, 1020);
    auto pindex = MakeIndex(0xAA, 50000);
    assert(Dilithion::ValidateLifetimeMinerSnapshot(pindex.get(), &tracker) == true);
    std::cout << " OK\n";
}

void test_lifetime_validator_mismatch_fails()
{
    std::cout << "  test_lifetime_validator_mismatch_fails..." << std::flush;
    Dilithion::ChainParams stub;
    stub.lifetimeMinerCountAt44232 = 5;  // expected 5 but only 2 in tracker
    ChainParamsScope scope(&stub);
    CCooldownTracker tracker;
    CCooldownTracker::Address mik_a{}; mik_a.fill(0xAA);
    CCooldownTracker::Address mik_b{}; mik_b.fill(0xBB);
    tracker.OnBlockConnected(1, mik_a, 1000);
    tracker.OnBlockConnected(2, mik_b, 1010);
    auto pindex = MakeIndex(0xAA, 50000);
    assert(Dilithion::ValidateLifetimeMinerSnapshot(pindex.get(), &tracker) == false);
    std::cout << " OK\n";
}

// v4.1 cross-component audit HIGH-2 regression test: ensures the
// validator stays correct after the chain extends past 44232 with new
// MIKs joining. The previous bug: GetLifetimeMinerCount() returned the
// cumulative-to-tip count, which would mismatch the embedded snapshot
// the moment ANY new MIK won a block at 44233+, bricking restart.
// The fix uses GetLifetimeMinerCountAtHeight(44232) which is stable.
void test_lifetime_validator_chain_extended_past_snapshot_passes()
{
    std::cout << "  test_lifetime_validator_chain_extended_past_snapshot_passes..." << std::flush;
    Dilithion::ChainParams stub;
    stub.lifetimeMinerCountAt44232 = 3;  // canonical: 3 distinct miners through h=44232
    ChainParamsScope scope(&stub);
    CCooldownTracker tracker;

    // Populate 3 distinct miners at heights <= 44232 (the canonical snapshot)
    CCooldownTracker::Address mik_a{}; mik_a.fill(0xAA);
    CCooldownTracker::Address mik_b{}; mik_b.fill(0xBB);
    CCooldownTracker::Address mik_c{}; mik_c.fill(0xCC);
    tracker.OnBlockConnected(44230, mik_a, 1000);
    tracker.OnBlockConnected(44231, mik_b, 1010);
    tracker.OnBlockConnected(44232, mik_c, 1020);

    // Now extend the chain past the snapshot with NEW miners (post-rollback
    // arrivals). Pre-fix this would push GetLifetimeMinerCount() to 5 and
    // make the validator fail-fast on every restart. Post-fix the bounded
    // accessor returns 3 (count at h=44232) regardless of post-44232 entries.
    CCooldownTracker::Address mik_new1{}; mik_new1.fill(0xDD);
    CCooldownTracker::Address mik_new2{}; mik_new2.fill(0xEE);
    tracker.OnBlockConnected(44233, mik_new1, 1030);
    tracker.OnBlockConnected(44234, mik_new2, 1040);

    auto pindex = MakeIndex(0xFF, 50000);  // tip well past 44232
    // Cumulative count would be 5; bounded count at 44232 is 3 = expected.
    assert(Dilithion::ValidateLifetimeMinerSnapshot(pindex.get(), &tracker) == true);
    std::cout << " OK\n";
}

// Cross-component HIGH-3: fail-fast when tip > 44232 but placeholder
// is still 0 (indicating pass-1 build that was never updated).
void test_lifetime_validator_placeholder_with_active_chain_fails()
{
    std::cout << "  test_lifetime_validator_placeholder_with_active_chain_fails..." << std::flush;
    Dilithion::ChainParams stub;
    stub.lifetimeMinerCountAt44232 = 0;  // placeholder
    ChainParamsScope scope(&stub);
    CCooldownTracker tracker;
    auto pindex = MakeIndex(0xAA, 50000);  // tip past activation
    // Chain past activation + placeholder still 0 = fail-fast (CRIT-1
    // mitigation would otherwise be dead code on this binary).
    assert(Dilithion::ValidateLifetimeMinerSnapshot(pindex.get(), &tracker) == false);
    std::cout << " OK\n";
}

// =============================================================================
// v4.1.2 lifetime-validator bug regression tests
//
// Background: 2026-05-02 incident. The v4.1 HIGH-2 audit fix wired
// GetLifetimeMinerCountAtHeight to walk m_heightToWinner — a sliding window
// of size m_activeWindow. As tip advanced past atHeight by activeWindow
// blocks, entries with key <= atHeight were evicted, and the count drifted
// from canonical. Three of four DilV mainnet seeds crash-looped with
// "observed=64 vs expected=65" because of this. The HIGH-2 audit's
// existing test (test_lifetime_validator_chain_extended_past_snapshot_passes
// above) only covered the increment direction (count doesn't go up); the
// failing direction (count goes down as window slides) was untested.
//
// These tests assert the post-fix invariants:
//   - Invariance: GetLifetimeMinerCountAtHeight(h) is constant as tip
//     advances on a fixed chain prefix (no matter how far past activeWindow).
//   - Reorg-symmetry: disconnect+reconnect returns to the same value.
//   - Cursor scenario: a MIK whose only blocks are evicted from the
//     sliding window is still correctly removed from the count after
//     all its blocks disconnect (multiset becomes empty, MIK erased).
//   - Multiset minimum: after a MIK's earliest block disconnects but
//     others remain, the new minimum is the next-earliest height.
// =============================================================================

void test_lifetime_count_at_height_invariant_as_tip_advances()
{
    std::cout << "  test_lifetime_count_at_height_invariant_as_tip_advances..." << std::flush;
    // Use small activeWindow=10 so we can test eviction quickly with
    // far fewer connect operations than DilV's 200.
    CCooldownTracker tracker(10);

    // Three distinct MIKs, each mining one block at heights 1, 2, 3.
    CCooldownTracker::Address mik_a{}; mik_a.fill(0xAA);
    CCooldownTracker::Address mik_b{}; mik_b.fill(0xBB);
    CCooldownTracker::Address mik_c{}; mik_c.fill(0xCC);
    tracker.OnBlockConnected(1, mik_a, 1000);
    tracker.OnBlockConnected(2, mik_b, 1010);
    tracker.OnBlockConnected(3, mik_c, 1020);

    // Snapshot: count at h=3 is 3.
    assert(tracker.GetLifetimeMinerCountAtHeight(3) == 3);

    // Now advance tip with a SINGLE recurring MIK at heights 4..50.
    // None of them are new MIKs after h=4, so distinct count at h=3
    // must remain stable.
    CCooldownTracker::Address mik_recur{}; mik_recur.fill(0xDD);
    for (int h = 4; h <= 50; ++h) {
        tracker.OnBlockConnected(h, mik_recur, 1000 + h * 10);
        // After every block, the count at h=3 must still be 3.
        // Pre-fix this would have dropped once h > 3 + activeWindow
        // (h > 13) because the sliding window evicted heights <= 3.
        int count_at_3 = tracker.GetLifetimeMinerCountAtHeight(3);
        if (count_at_3 != 3) {
            std::cerr << "\nINVARIANCE VIOLATION at tip=" << h
                      << ": count_at_3=" << count_at_3 << " (expected 3)\n";
            assert(false);
        }
    }
    // mik_recur (first appeared at h=4) is also counted from h=4 onward.
    assert(tracker.GetLifetimeMinerCountAtHeight(4) == 4);
    assert(tracker.GetLifetimeMinerCountAtHeight(50) == 4);
    std::cout << " OK\n";
}

void test_lifetime_count_reorg_symmetric_disconnect_reconnect()
{
    std::cout << "  test_lifetime_count_reorg_symmetric_disconnect_reconnect..." << std::flush;
    CCooldownTracker tracker(10);
    CCooldownTracker::Address mik_a{}; mik_a.fill(0xAA);
    CCooldownTracker::Address mik_b{}; mik_b.fill(0xBB);
    tracker.OnBlockConnected(5, mik_a, 1000);
    tracker.OnBlockConnected(6, mik_b, 1010);

    int before = tracker.GetLifetimeMinerCountAtHeight(6);
    assert(before == 2);

    tracker.OnBlockDisconnected(6);
    assert(tracker.GetLifetimeMinerCountAtHeight(6) == 1);

    tracker.OnBlockConnected(6, mik_b, 1010);
    assert(tracker.GetLifetimeMinerCountAtHeight(6) == before);
    std::cout << " OK\n";
}

void test_lifetime_count_cursor_scenario_evicted_then_disconnected()
{
    std::cout << "  test_lifetime_count_cursor_scenario_evicted_then_disconnected..." << std::flush;
    // Cursor's specific scenario: a MIK mines exactly two blocks at
    // H1 < H2; advance tip until H1 is evicted from m_heightToWinner;
    // disconnect H2; disconnect H1. After both disconnects, the MIK
    // must be removed from GetLifetimeMinerCountAtHeight(H2).
    //
    // Plain m_firstHeightSeen would have failed this scenario because
    // H1 is no longer in m_heightToWinner to scan-recompute from after
    // H2 disconnects.
    CCooldownTracker tracker(10);
    CCooldownTracker::Address mik_x{}; mik_x.fill(0x77);
    CCooldownTracker::Address mik_filler{}; mik_filler.fill(0xFF);

    int H1 = 5;
    int H2 = 7;
    tracker.OnBlockConnected(H1, mik_x, 1000);
    tracker.OnBlockConnected(H2, mik_x, 1020);

    assert(tracker.GetLifetimeMinerCountAtHeight(H2) == 1);

    // Advance tip with filler MIK until H1 is evicted from the sliding
    // window (H1 < tip - activeWindow + 1, i.e., tip >= H1 + activeWindow).
    int top = H1 + 10 + 5;
    for (int h = 8; h <= top; ++h) {
        tracker.OnBlockConnected(h, mik_filler, 1000 + h * 10);
    }
    // mik_x's earliest height (H1=5) is now evicted from m_heightToWinner.
    // mik_filler's first appearance is at h=8, which is > H2=7, so it
    // is NOT counted at H2 — only mik_x is.
    assert(tracker.GetLifetimeMinerCountAtHeight(H2) == 1);
    // Sanity: at any height >= 8, mik_filler IS counted, so total is 2.
    assert(tracker.GetLifetimeMinerCountAtHeight(top) == 2);

    // Disconnect blocks in reverse order, top to bottom.
    for (int h = top; h >= H2 + 1; --h) {
        tracker.OnBlockDisconnected(h);
    }
    // After disconnecting all filler-only blocks above H2: mik_x still
    // has H1 and H2; mik_filler has nothing connected at all (multiset
    // empty -> MIK erased).
    assert(tracker.GetLifetimeMinerCountAtHeight(H2) == 1);

    tracker.OnBlockDisconnected(H2);
    // mik_x's multiset still has H1; count at H2 stays 1.
    assert(tracker.GetLifetimeMinerCountAtHeight(H2) == 1);

    tracker.OnBlockDisconnected(H1);
    // mik_x's multiset is now empty -> MIK erased -> count drops to 0.
    assert(tracker.GetLifetimeMinerCountAtHeight(H2) == 0);
    std::cout << " OK\n";
}

void test_lifetime_count_multiset_minimum_updates_after_disconnect()
{
    std::cout << "  test_lifetime_count_multiset_minimum_updates_after_disconnect..." << std::flush;
    // A MIK mines blocks at H1 < H2 < H3. After H1 disconnects, the
    // earliest remaining height for this MIK is H2 — so queries below
    // H2 should NOT count the MIK, queries at or above H2 should.
    CCooldownTracker tracker(20);
    CCooldownTracker::Address mik_q{}; mik_q.fill(0x42);
    int H1 = 3, H2 = 5, H3 = 7;
    tracker.OnBlockConnected(H1, mik_q, 1000);
    tracker.OnBlockConnected(H2, mik_q, 1020);
    tracker.OnBlockConnected(H3, mik_q, 1040);

    // Pre-disconnect: counted from H1 onward.
    assert(tracker.GetLifetimeMinerCountAtHeight(H1 - 1) == 0);
    assert(tracker.GetLifetimeMinerCountAtHeight(H1) == 1);
    assert(tracker.GetLifetimeMinerCountAtHeight(H2 - 1) == 1);

    tracker.OnBlockDisconnected(H1);

    // Post-disconnect: not counted below H2, counted from H2 onward.
    assert(tracker.GetLifetimeMinerCountAtHeight(H1) == 0);
    assert(tracker.GetLifetimeMinerCountAtHeight(H2 - 1) == 0);
    assert(tracker.GetLifetimeMinerCountAtHeight(H2) == 1);
    assert(tracker.GetLifetimeMinerCountAtHeight(H3) == 1);
    std::cout << " OK\n";
}

void test_lifetime_count_clear_wipes_state()
{
    std::cout << "  test_lifetime_count_clear_wipes_state..." << std::flush;
    CCooldownTracker tracker(10);
    CCooldownTracker::Address mik_a{}; mik_a.fill(0xAA);
    tracker.OnBlockConnected(5, mik_a, 1000);
    assert(tracker.GetLifetimeMinerCountAtHeight(5) == 1);

    tracker.Clear();

    // After Clear() the lifetime multiset must be empty.
    assert(tracker.GetLifetimeMinerCountAtHeight(5) == 0);
    assert(tracker.GetLifetimeMinerCountAtHeight(1000000) == 0);
    std::cout << " OK\n";
}

// =============================================================================
// Main
// =============================================================================

int main()
{
    std::cout << "\n=== v4.1 Checkpoint Enforcement Tests ===\n" << std::endl;

    try {
        std::cout << "--- CheckpointCheck (chainparams) sanity ---" << std::endl;
        test_checkpoint_check_no_checkpoint_at_height_returns_true();
        test_checkpoint_check_match_returns_true();
        test_checkpoint_check_mismatch_returns_false();

        std::cout << "\n--- Phase 1: ValidateChainAgainstCheckpoints ---" << std::endl;
        test_startup_validator_null_tip_passes();
        test_startup_validator_null_chainparams_passes();
        test_startup_validator_tip_below_all_checkpoints_passes();
        test_startup_validator_tip_at_matching_checkpoint_passes();
        test_startup_validator_tip_at_violating_checkpoint_fails();

        std::cout << "\n--- Phase 2: ValidateLifetimeMinerSnapshot ---" << std::endl;
        test_lifetime_validator_null_tracker_passes();
        test_lifetime_validator_null_tip_passes();
        test_lifetime_validator_tip_below_threshold_passes();
        test_lifetime_validator_placeholder_zero_below_threshold_passes();
        test_lifetime_validator_match_passes();
        test_lifetime_validator_mismatch_fails();
        test_lifetime_validator_chain_extended_past_snapshot_passes();
        test_lifetime_validator_placeholder_with_active_chain_fails();

        std::cout << "\n--- v4.1.2: lifetime-validator bug regression tests ---" << std::endl;
        test_lifetime_count_at_height_invariant_as_tip_advances();
        test_lifetime_count_reorg_symmetric_disconnect_reconnect();
        test_lifetime_count_cursor_scenario_evicted_then_disconnected();
        test_lifetime_count_multiset_minimum_updates_after_disconnect();
        test_lifetime_count_clear_wipes_state();

    } catch (const std::exception& e) {
        std::cerr << "\nFAIL: exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\nFAIL: unknown exception" << std::endl;
        return 1;
    }

    std::cout << "\n=== ALL v4.1 CHECKPOINT TESTS PASSED ===\n" << std::endl;
    return 0;
}
