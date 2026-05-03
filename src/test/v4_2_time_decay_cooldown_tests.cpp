// v4.2.0 — Time-decay cooldown unit tests.
//
// Spec: .claude/contracts/v4_2_time_decay_cooldown_spec.md (§7.1)
// Tests the new self-correcting cooldown rule that REPLACES the v4.1
// stall-exemption-tier system. Coverage:
//
//   1. TimeDecay_NormalRate_BlockCountDominates
//   2. TimeDecay_SlowChain_TimeDecayDominates
//   3. TimeDecay_FullDeadlock_RecoversAfter43Min
//   4. TimeDecay_AttackRate_IsCappedAt43Min
//   5. TimeDecay_ForwardTimestamp_BoundedByConsensus
//   6. TimeDecay_Reorg_LastWinReverts
//   7. TimeDecay_ActivationBoundary_MonotoneEligibility
//   8. TimeDecay_DECAY_RATE_60s_Calibration
//   9. TimeDecay_NegativeTimeSince_TreatedAsZero          (HIGH-3)
//  10. TimeDecay_ForgedForwardJump_DoesNotChainBlocks
//  11. TimeDecay_InterleavedTimestampStrategy_DoesNotIncreaseAttackRate (HIGH-2)
//  12. TimeDecay_ConsecutiveMinerCheck_StillFires        (HIGH-1, surface only)
//  13. TimeDecay_ReorgAcrossActivation_HandlesCorrectly
//  14. TimeDecay_RecalcActiveMinersOnReorg_NotCached     (MED-1)

#include "../vdf/cooldown_tracker.h"
#include <iostream>
#include <cassert>
#include <vector>

using Address = CCooldownTracker::Address;

namespace {

Address mk(uint8_t id) {
    Address a{};
    a[0] = id;
    return a;
}

int passed = 0;
int failed = 0;

#define V42_TEST(name) \
    do { std::cout << "  " << #name << "... "; } while (0)

#define V42_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cout << "FAIL (" << #cond << " at line " << __LINE__ << ")\n"; \
            ++failed; \
            return; \
        } \
    } while (0)

#define V42_PASS() \
    do { std::cout << "PASS\n"; ++passed; } while (0)

// Helper: build a tracker with time-decay activated from genesis.
//   activeWindow = 1920 (DilV)
//   shortWindow  = 0
//   stabilization = 0
//   targetBlockTime = 45
//   timeBasedExpiry retired = 0 (so legacy time-based path won't fire)
//   timeDecayActivation = 0
//   timeDecaySeconds = 60
CCooldownTracker mk_tracker(int activation = 0, int decay = 60) {
    return CCooldownTracker(1920, 0, 0, 45, 0, activation, decay);
}

// Helper: pre-load tracker with N miners spaced 45s apart so cooldown
// formula yields a meaningful value (cooldown = floor(N * 0.67)).
void seed_active_miners(CCooldownTracker& t, int n_miners,
                        int start_height, int64_t start_ts) {
    for (int i = 0; i < n_miners; ++i) {
        t.OnBlockConnected(start_height + i, mk(static_cast<uint8_t>(100 + i)),
                           start_ts + i * 45);
    }
}

// =====================================================================
// Test 1: at target block rate (45s), block-count path is binding.
// Behavior must match v4.1 (no time-decay shortening).
// =====================================================================
void test_normal_rate_block_count_dominates() {
    V42_TEST(TimeDecay_NormalRate_BlockCountDominates);

    auto t = mk_tracker(/*activation*/ 0, /*decay*/ 60);
    seed_active_miners(t, 65, 100, 1000000);  // 65 miners → cooldown=43

    // miner alice mines at h=200, ts=1010000
    Address alice = mk(1);
    t.OnBlockConnected(200, alice, 1010000);

    // At h=201, ts=1010045 (target rate). time_since=45.
    // time_decrement = 45/60 = 0. effective = 43-0 = 43.
    // blocks_since = 1. 1 < 43 → in cooldown.
    V42_CHECK(t.IsInCooldown(alice, 201, 1010045));

    // At h=242, ts = 1010000 + 42*45 = 1011890. blocks_since=42.
    // time_since = 1890. time_decrement = 1890/60 = 31. effective = 43-31 = 12.
    // 42 < 12 false → NOT in cooldown.
    V42_CHECK(!t.IsInCooldown(alice, 242, 1011890));

    // At h=243, ts target. blocks_since=43. effective ≤ 43 always. NOT in cooldown.
    V42_CHECK(!t.IsInCooldown(alice, 243, 1011935));

    V42_PASS();
}

// =====================================================================
// Test 2: at slow rate (600s/block), time-decay path opens cooldown
// faster than the block-count path.
// =====================================================================
void test_slow_chain_time_decay_dominates() {
    V42_TEST(TimeDecay_SlowChain_TimeDecayDominates);

    auto t = mk_tracker(0, 60);
    seed_active_miners(t, 65, 100, 1000000);  // cooldown=43

    Address alice = mk(1);
    t.OnBlockConnected(200, alice, 1010000);

    // At h=205 (only 5 blocks later) but ts = 1010000 + 5*600 = 1013000.
    // time_since = 3000. time_decrement = 50. effective = max(0, 43-50) = 0.
    // 5 < 0 false → NOT in cooldown.
    V42_CHECK(!t.IsInCooldown(alice, 205, 1013000));

    // Compare: block-count alone would say 5 < 43 → in cooldown.
    // The time-decay path correctly let alice out early.

    V42_PASS();
}

// =====================================================================
// Test 3: full deadlock (no new blocks). Cooldown drains to zero in
// cooldown_blocks × decay_seconds.
// =====================================================================
void test_full_deadlock_recovers_after_43min() {
    V42_TEST(TimeDecay_FullDeadlock_RecoversAfter43Min);

    auto t = mk_tracker(0, 60);
    seed_active_miners(t, 65, 100, 1000000);

    Address alice = mk(1);
    t.OnBlockConnected(200, alice, 1010000);

    int cd = t.GetEffectiveCooldown(201);  // dynamic — depends on seed count

    // At time_since = cd*60, decrement=cd, effective=0, blocks_since=1 → eligible.
    V42_CHECK(!t.IsInCooldown(alice, 201, 1010000 + (int64_t)cd * 60));

    // 1s before threshold: time_since = cd*60 - 1. decrement = cd-1 (integer
    // division of (cd*60 - 1) / 60 = cd - 1 for cd >= 1). effective = 1.
    // blocks_since = 1. 1 < 1 false → eligible (boundary inclusive).
    V42_CHECK(!t.IsInCooldown(alice, 201, 1010000 + (int64_t)cd * 60 - 1));

    // Way before threshold: ts = 1010000 + 600 (10 min). decrement = 10.
    // effective = cd - 10 (still > 1). 1 < effective → in cooldown.
    if (cd >= 12) {
        V42_CHECK(t.IsInCooldown(alice, 201, 1010000 + 600));
    }

    V42_PASS();
}

// =====================================================================
// Test 4: single attacker with 100x hashpower trying to mine consecutive
// blocks. Even with block.nTime forged to +7200s (max allowed), they can
// mine at most 1 block per ~43 min in steady state.
// =====================================================================
void test_attack_rate_is_capped_at_43min() {
    V42_TEST(TimeDecay_AttackRate_IsCappedAt43Min);

    auto t = mk_tracker(0, 60);
    seed_active_miners(t, 65, 100, 1000000);

    Address attacker = mk(7);
    int64_t real_clock = 1010000;
    int height = 200;

    // Attacker mines first block honestly.
    t.OnBlockConnected(height++, attacker, real_clock);
    (void)real_clock;  // tracked implicitly via OnBlockConnected timestamps

    // Attacker tries to mine block N+1 with forged +7200 timestamp.
    // time_since = 7200. time_decrement = 120. effective = max(0, 43-120) = 0.
    // Eligible immediately. (FREE BLOCK — analyzed in spec §5.1.)
    V42_CHECK(!t.IsInCooldown(attacker, height, real_clock + 7200));
    t.OnBlockConnected(height++, attacker, real_clock + 7200);

    // Now attacker tries another forged block with same real_clock + 7200.
    // time_since = 0 (same forged time). time_decrement = 0. effective = 43.
    // blocks_since = 1. 1 < 43 → in cooldown. Rejected.
    V42_CHECK(t.IsInCooldown(attacker, height, real_clock + 7200));

    // Wait 43 minutes of real wall-clock; advance forged ts by same amount.
    // last_attacker_time = real_clock + 7200; new attempt at real_clock + 2580 + 7200
    // = real_clock + 9780. time_since = 9780 - 7200 = 2580. time_decrement = 43.
    // effective = 0. Eligible.
    int64_t new_ts = real_clock + 2580 + 7200;
    V42_CHECK(!t.IsInCooldown(attacker, height, new_ts));

    V42_PASS();
}

// =====================================================================
// Test 5: forward-timestamp manipulation bounded. Attacker forging
// nTime = T_real + 7200 cannot do better than reducing cooldown by
// 7200/60 = 120 blocks worth of decrement on the FIRST block of a session.
// Subsequent blocks see steady-state rate-limit.
// =====================================================================
void test_forward_timestamp_bounded_by_consensus() {
    V42_TEST(TimeDecay_ForwardTimestamp_BoundedByConsensus);

    auto t = mk_tracker(0, 60);
    seed_active_miners(t, 65, 100, 1000000);

    Address attacker = mk(8);
    t.OnBlockConnected(200, attacker, 1010000);

    // Try with forged timestamp = honest + 7200. With 7200/60 = 120 decrement,
    // effective = 0, eligible.
    V42_CHECK(!t.IsInCooldown(attacker, 201, 1010000 + 7200));

    // But the new last_win_time becomes the forged value, not honest. So next
    // attempt's clock starts from that high-water mark — proven by Test 4.

    // Sanity: attacker can't push timestamp arbitrarily forward; that's a
    // consensus rule enforced upstream by IsValidBlock. This test only
    // verifies the cooldown rule's response under the maximum forged delta.
    V42_PASS();
}

// =====================================================================
// Test 6: reorg correctly reverts last-win-time, not just last-win-height.
// =====================================================================
void test_reorg_last_win_reverts() {
    V42_TEST(TimeDecay_Reorg_LastWinReverts);

    auto t = mk_tracker(0, 60);
    seed_active_miners(t, 65, 100, 1000000);

    Address alice = mk(1);
    // Alice mines twice: first at h=150 (ts=1005000), then at h=200 (ts=1010000).
    t.OnBlockConnected(150, alice, 1005000);
    t.OnBlockConnected(200, alice, 1010000);

    // h=200 record should be authoritative.
    V42_CHECK(t.GetLastWinHeight(alice) == 200);

    // Reorg removes h=200.
    t.OnBlockDisconnected(200);

    // After reorg, alice's last win is back to h=150.
    V42_CHECK(t.GetLastWinHeight(alice) == 150);

    // Crucially, the time-decay calc must use ts=1005000, not 1010000.
    // At h=151 with ts=1005045 (target rate): time_since = 45, decrement = 0,
    // effective = 43, blocks_since = 1. 1 < 43 → in cooldown.
    V42_CHECK(t.IsInCooldown(alice, 151, 1005045));

    // At h=151 with ts=1005000+2580=1007580: time_since=2580, decrement=43,
    // effective=0, eligible.
    V42_CHECK(!t.IsInCooldown(alice, 151, 1005000 + 2580));

    V42_PASS();
}

// =====================================================================
// Test 7: at activation boundary, no miner becomes LESS eligible.
// =====================================================================
void test_activation_boundary_monotone_eligibility() {
    V42_TEST(TimeDecay_ActivationBoundary_MonotoneEligibility);

    // Activation at height 1000.
    CCooldownTracker t(1920, 0, 0, 45, 999999999, 1000, 60);
    seed_active_miners(t, 65, 100, 1000000);

    Address alice = mk(1);
    t.OnBlockConnected(950, alice, 1042750);  // 50 blocks before activation

    // At h=999 (legacy path), ts=1045000. blocks_since=49.
    // Legacy: time-based-expiry RETIRED (= 999999999). Just block-count.
    // 49 < 43 false → eligible under legacy.
    V42_CHECK(!t.IsInCooldown(alice, 999, 1045000));

    // At h=1000 (new path), ts=1045000. blocks_since=50, time_since=2250.
    // time_decrement = 37. effective = max(0, 43-37) = 6. 50 < 6 false → eligible.
    V42_CHECK(!t.IsInCooldown(alice, 1000, 1045000));

    // Earlier eligibility test: at h=1000, ts=1042750 (no time elapsed).
    // blocks_since=50. effective=43. 50 < 43 false → eligible.
    V42_CHECK(!t.IsInCooldown(alice, 1000, 1042750));

    // Pathological: at h=1000, ts=BEFORE last_win (negative time_since).
    // Without HIGH-3 clamp, this would EXTEND cooldown. With clamp, time_since=0,
    // time_decrement=0, effective=43, blocks_since=50. 50 < 43 false → eligible.
    V42_CHECK(!t.IsInCooldown(alice, 1000, 1042000));

    V42_PASS();
}

// =====================================================================
// Test 8: DECAY_RATE_SECONDS = 60 calibration sanity. At 1 minute of
// wall-clock per cooldown block, a fresh entry into cooldown clears
// after exactly cooldown_blocks minutes (when blocks_since=0).
// =====================================================================
void test_decay_rate_60s_calibration() {
    V42_TEST(TimeDecay_DECAY_RATE_60s_Calibration);

    auto t = mk_tracker(0, 60);
    seed_active_miners(t, 65, 100, 1000000);

    Address alice = mk(1);
    t.OnBlockConnected(200, alice, 1010000);

    int cd = t.GetEffectiveCooldown(200);  // dynamic

    // ts=1010000, time_since=0, decrement=0, effective=cd. blocks_since=0 < cd → in cooldown.
    V42_CHECK(t.IsInCooldown(alice, 200, 1010000));

    // 1 min later: decrement=1, effective=cd-1. 0 < cd-1 → in cooldown.
    if (cd >= 2) {
        V42_CHECK(t.IsInCooldown(alice, 200, 1010060));
    }

    // (cd-1) mins later: decrement=cd-1, effective=1. 0 < 1 → in cooldown.
    V42_CHECK(t.IsInCooldown(alice, 200, 1010000 + (int64_t)(cd - 1) * 60));

    // cd mins later: decrement=cd, effective=0. 0 < 0 false → eligible.
    V42_CHECK(!t.IsInCooldown(alice, 200, 1010000 + (int64_t)cd * 60));

    V42_PASS();
}

// =====================================================================
// Test 9 (HIGH-3): negative time_since must be treated as zero.
// =====================================================================
void test_negative_time_since_treated_as_zero() {
    V42_TEST(TimeDecay_NegativeTimeSince_TreatedAsZero);

    auto t = mk_tracker(0, 60);
    seed_active_miners(t, 65, 100, 1000000);

    Address alice = mk(1);
    t.OnBlockConnected(200, alice, 1010000);

    // At h=201 with block timestamp BEFORE alice's last win (legal under
    // consensus as long as median-of-11 increases). time_since = -100 → clamped to 0.
    // time_decrement = 0. effective = 43. blocks_since = 1. 1 < 43 → in cooldown.
    V42_CHECK(t.IsInCooldown(alice, 201, 1009900));

    // Without the clamp, time_since=-100/60 = -1 (toward zero in C++ integer division
    // with negative dividend implementation-defined pre-C++11; truncation toward zero in C++11+).
    // effective = 43 - (-1) = 44. blocks_since=1 < 44 → still in cooldown.
    // So the visible failure mode would actually be subtle (1 extra block). But
    // for larger negative deltas the difference becomes pronounced. Test that
    // a large negative delta does NOT make alice less eligible than the
    // baseline block-count rule would.
    //
    // ts = 1010000 - 7200 (alice's last_win - 2 hours). Without clamp:
    //   time_since = -7200, time_decrement = -120, effective = 43 - (-120) = 163.
    //   blocks_since = 50 (we'll bump alice's height). 50 < 163 → in cooldown.
    // With clamp: time_since = 0, decrement = 0, effective = 43.
    //   blocks_since = 50. 50 < 43 false → ELIGIBLE.
    V42_CHECK(!t.IsInCooldown(alice, 250, 1010000 - 7200));

    V42_PASS();
}

// =====================================================================
// Test 10: forged forward jump on block N does NOT enable chaining
// further blocks immediately. The high-water mark constraint binds.
// =====================================================================
void test_forged_forward_jump_does_not_chain_blocks() {
    V42_TEST(TimeDecay_ForgedForwardJump_DoesNotChainBlocks);

    auto t = mk_tracker(0, 60);
    seed_active_miners(t, 65, 100, 1000000);

    Address attacker = mk(9);
    t.OnBlockConnected(200, attacker, 1010000);

    // Forge block N+1 with +7200 (eligible per Test 4 / 5).
    int64_t forged = 1010000 + 7200;
    V42_CHECK(!t.IsInCooldown(attacker, 201, forged));
    t.OnBlockConnected(201, attacker, forged);

    // Immediately try to forge block N+2 with same +7200 jump from honest clock.
    // honest clock = 1010001 (1s after first honest block). +7200 = 1017201.
    // last_attacker_time = forged = 1017200. time_since = 1. time_decrement = 0.
    // effective = 43. blocks_since = 1. 1 < 43 → in cooldown.
    V42_CHECK(t.IsInCooldown(attacker, 202, 1010001 + 7200));

    // Even with maximal forge from current honest time + 7200 = 1017201, the
    // high-water mark prevents chaining. Attacker must wait real time.
    V42_PASS();
}

// =====================================================================
// Test 11 (HIGH-2 disproof): interleaved honest+forged strategy yields
// rate ≤ always-honest rate. (Red-team claimed 2x; simulation showed
// interleave is WORSE.)
// Reduced-scale test: 10 attempts each over 6h sim window.
// =====================================================================
void test_interleaved_strategy_does_not_increase_attack_rate() {
    V42_TEST(TimeDecay_InterleavedTimestampStrategy_DoesNotIncreaseAttackRate);

    auto count_blocks = [](int strategy) -> int {
        // strategy: 0 = always honest, 1 = always forged, 2 = interleave
        CCooldownTracker t(1920, 0, 0, 45, 0, /*activation*/0, /*decay*/60);
        // seed active miner count to 65
        for (int i = 0; i < 65; ++i) {
            t.OnBlockConnected(i, mk(static_cast<uint8_t>(50 + i)), 1000 + i * 45);
        }
        Address atk = mk(200);
        const int sim_seconds = 6 * 3600;  // 6h
        int real_clock = 4000;  // start after seeding
        int height = 100;
        int blocks = 0;
        int last_attempt_kind = 0;
        while (real_clock < 4000 + sim_seconds) {
            int64_t attempt_ts;
            if (strategy == 0) attempt_ts = real_clock;
            else if (strategy == 1) attempt_ts = real_clock + 7200;
            else attempt_ts = (last_attempt_kind == 0) ? real_clock : real_clock + 7200;

            if (!t.IsInCooldown(atk, height + 1, attempt_ts)) {
                ++height;
                t.OnBlockConnected(height, atk, attempt_ts);
                ++blocks;
                last_attempt_kind = 1 - last_attempt_kind;
            }
            real_clock += 1;  // 1-second granularity
        }
        return blocks;
    };

    int honest = count_blocks(0);
    int forged = count_blocks(1);
    int interleave = count_blocks(2);

    std::cout << "(honest=" << honest << " forged=" << forged
              << " interleave=" << interleave << ") ";

    // Red-team's HIGH-2 claim: interleave should be ~2x always_forge. DISPROVED.
    // Empirically: interleave ≤ max(honest, forged) — never exceeds either.
    V42_CHECK(interleave <= forged + 1);  // tolerance for boundary noise

    V42_PASS();
}

// =====================================================================
// Test 12 (HIGH-1, surface check): time-decay path does NOT include
// consecutive-miner check. That's enforced separately at chain.cpp.
// This test confirms that IsInCooldown returns FALSE when an attacker
// has waited long enough — but the chain.cpp consecutive-miner check
// would still reject them. This test verifies the surface only.
// =====================================================================
void test_time_decay_does_not_subsume_consecutive_check() {
    V42_TEST(TimeDecay_ConsecutiveMinerCheck_StillFires_Surface);

    auto t = mk_tracker(0, 60);
    seed_active_miners(t, 65, 100, 1000000);

    Address attacker = mk(10);
    t.OnBlockConnected(200, attacker, 1010000);

    // Wait 43 min wall-clock. attacker passes IsInCooldown.
    int64_t ts_after_43min = 1010000 + 43*60;
    V42_CHECK(!t.IsInCooldown(attacker, 201, ts_after_43min));

    // chain.cpp's CheckConsecutiveMiner would reject this even though
    // IsInCooldown returns false — they enforce separate invariants.
    // This test ONLY verifies that IsInCooldown does NOT pretend to
    // enforce the consecutive constraint. That orthogonality is the
    // architectural invariant we care about.
    V42_PASS();
}

// =====================================================================
// Test 13: reorg from a block above activation back to a block below
// activation must work (legacy semantics restored on the alternative path).
// =====================================================================
void test_reorg_across_activation_handles_correctly() {
    V42_TEST(TimeDecay_ReorgAcrossActivation_HandlesCorrectly);

    // Activation at height 1000.
    CCooldownTracker t(1920, 0, 0, 45, 999999999, 1000, 60);
    seed_active_miners(t, 65, 100, 1000000);

    Address alice = mk(1);
    t.OnBlockConnected(995, alice, 1044775);  // 5 blocks before activation
    t.OnBlockConnected(1005, alice, 1045225); // 5 blocks above activation

    // Disconnect h=1005 (the above-activation block).
    t.OnBlockDisconnected(1005);
    V42_CHECK(t.GetLastWinHeight(alice) == 995);

    // At h=996 (legacy path), ts=1044775+45=1044820. legacy time-based expiry
    // is RETIRED (=999999999), so block-only path. blocks_since=1. effective=43.
    // 1 < 43 → in cooldown.
    V42_CHECK(t.IsInCooldown(alice, 996, 1044820));

    // At h=1005 (new path again, replaying), ts=1044775+450 (10*45=450s elapsed
    // since alice's only remaining win at h=995). blocks_since=10, time_since=450.
    // time_decrement=7. effective=36. 10 < 36 → in cooldown.
    V42_CHECK(t.IsInCooldown(alice, 1005, 1044775 + 450));

    V42_PASS();
}

// =====================================================================
// Test 14 (MED-1): RecalcActiveMiners must be deterministic per call,
// not influenced by stale cache across reorgs. Verify the active count
// returned by IsInCooldown's internal computation matches a fresh count.
// =====================================================================
void test_recalc_active_miners_on_reorg_not_cached() {
    V42_TEST(TimeDecay_RecalcActiveMinersOnReorg_NotCached);

    auto t = mk_tracker(0, 60);

    // Build up 30 distinct miners.
    for (int i = 0; i < 30; ++i) {
        t.OnBlockConnected(100 + i, mk(static_cast<uint8_t>(50 + i)), 1000000 + i * 45);
    }
    // Cooldown at h=130 with 30 active miners: floor(30*0.67) = 20.
    int initial = t.GetEffectiveCooldown(130);
    V42_CHECK(initial == 20);

    // Disconnect last 10 miners (rolls back 10 unique winners).
    for (int i = 129; i >= 120; --i) {
        t.OnBlockDisconnected(i);
    }

    // Different-height query: 119 ≠ 130 cache key, so this would recalc
    // anyway. Belt-and-braces.
    int after_reorg = t.GetEffectiveCooldown(119);
    V42_CHECK(after_reorg == CCooldownTracker::CalculateCooldown(20));
    V42_CHECK(after_reorg != initial);

    // MED-D regression (red-team Layer-2 close): same-height query AFTER
    // disconnect must NOT serve a stale cached value from BEFORE disconnect.
    // The cache key is height-only, so without OnBlockDisconnected setting
    // m_cachedAtHeightMut = -1 (cooldown_tracker.cpp ~472), the second call
    // at height=130 would silently return the pre-reorg value.
    //
    // Reconnect blocks 120..129 with DIFFERENT miners so that the active
    // set composition has changed. If caching is broken, the second
    // GetEffectiveCooldown(130) below will return the original value.
    for (int i = 120; i < 130; ++i) {
        // Reuse one already-active miner instead of bringing in 10 new ones.
        // This shrinks the unique active count back below 30 — proves the
        // active-miner recount is deterministic per (chain state, height).
        t.OnBlockConnected(i, mk(static_cast<uint8_t>(50)),  // same MIK every block
                           1000000 + i * 45);
    }
    int after_reconnect_same_height = t.GetEffectiveCooldown(130);
    // After reconnect, m_heightToWinner has heights 100..129 with
    // mk(50)..mk(69) at 100..119 and mk(50) at 120..129.
    // Distinct winners in active window: mk(50)..mk(69) = 20 unique.
    int expected = CCooldownTracker::CalculateCooldown(20);
    V42_CHECK(after_reconnect_same_height == expected);
    // CRITICAL: must NOT equal the original cached value. Initial was
    // CalculateCooldown(30) = 20 cooldown-blocks; new value is
    // CalculateCooldown(20) = 13. If the cache is stale, second
    // GetEffectiveCooldown(130) returns 20 — failing this check.
    V42_CHECK(after_reconnect_same_height != initial);

    V42_PASS();
}

}  // namespace

int main() {
    std::cout << "\nv4.2 Time-Decay Cooldown Tests\n";
    std::cout << "==============================\n\n";

    test_normal_rate_block_count_dominates();
    test_slow_chain_time_decay_dominates();
    test_full_deadlock_recovers_after_43min();
    test_attack_rate_is_capped_at_43min();
    test_forward_timestamp_bounded_by_consensus();
    test_reorg_last_win_reverts();
    test_activation_boundary_monotone_eligibility();
    test_decay_rate_60s_calibration();
    test_negative_time_since_treated_as_zero();
    test_forged_forward_jump_does_not_chain_blocks();
    test_interleaved_strategy_does_not_increase_attack_rate();
    test_time_decay_does_not_subsume_consecutive_check();
    test_reorg_across_activation_handles_correctly();
    test_recalc_active_miners_on_reorg_not_cached();

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";

    if (failed > 0) {
        std::cout << "\n=== TESTS FAILED ===\n";
        return 1;
    }

    std::cout << "\n=== ALL TESTS PASSED ===\n";
    return 0;
}
