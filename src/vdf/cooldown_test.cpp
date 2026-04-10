/**
 * CCooldownTracker unit tests.
 *
 * Tests: basic cooldown, active miner counting, scaling cooldown length,
 *        sliding window eviction, reorg undo, edge cases.
 */
#include "cooldown_tracker.h"
#include <iostream>
#include <cassert>

using Address = CCooldownTracker::Address;

static Address make_addr(uint8_t id)
{
    Address a{};
    a[0] = id;
    return a;
}

static int passed = 0;
static int failed = 0;

#define TEST(name) \
    do { std::cout << "  " << #name << "... "; } while(0)

#define PASS() \
    do { std::cout << "PASS\n"; ++passed; } while(0)

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cout << "FAIL (" << #cond << ")\n"; \
            ++failed; \
            return; \
        } \
    } while(0)

// --- Tests ---

static void test_basic_cooldown()
{
    TEST(basic_cooldown);
    CCooldownTracker tracker;
    Address alice = make_addr(1);

    tracker.OnBlockConnected(100, alice);

    // 1 active miner → cooldown = floor(1*0.67) = 0, clamped to MIN_COOLDOWN (0).
    // With cooldown=0, miner is never in cooldown (solo mining).
    CHECK(!tracker.IsInCooldown(alice, 101));
    CHECK(!tracker.IsInCooldown(alice, 200));

    PASS();
}

static void test_unknown_address_not_in_cooldown()
{
    TEST(unknown_address_not_in_cooldown);
    CCooldownTracker tracker;
    Address unknown = make_addr(99);

    CHECK(!tracker.IsInCooldown(unknown, 100));
    CHECK(tracker.GetLastWinHeight(unknown) == -1);

    PASS();
}

static void test_active_miner_count()
{
    TEST(active_miner_count);
    CCooldownTracker tracker;

    // Add 5 distinct miners.
    for (uint8_t i = 1; i <= 5; i++) {
        tracker.OnBlockConnected(100 + i, make_addr(i));
    }

    CHECK(tracker.GetActiveMiners() == 5);

    // Same miner wins again — should still be 5 unique.
    tracker.OnBlockConnected(106, make_addr(1));
    CHECK(tracker.GetActiveMiners() == 5);

    PASS();
}

static void test_cooldown_scales_with_miners()
{
    TEST(cooldown_scales_with_miners);
    CCooldownTracker tracker;
    Address alice = make_addr(1);

    // Register 50 distinct miners at heights 1001-1050.
    for (uint8_t i = 1; i <= 50; i++) {
        tracker.OnBlockConnected(1000 + i, make_addr(i));
    }

    // 50 miners → cooldown = floor(50*0.67) = 33.
    CHECK(tracker.GetCooldownBlocks() == 33);

    // Have Alice win again at height 1060 (all 50 miners in window).
    tracker.OnBlockConnected(1060, alice);

    // Alice last won at 1060. At 1060+32=1092 she should still be in cooldown.
    CHECK(tracker.IsInCooldown(alice, 1092));
    // At 1060+33=1093 she's out.
    CHECK(!tracker.IsInCooldown(alice, 1093));

    PASS();
}

static void test_cooldown_clamped_min()
{
    TEST(cooldown_clamped_min);
    CCooldownTracker tracker;

    // Only 1 miner → floor(1*0.67)=0, clamped to MIN_COOLDOWN (0).
    tracker.OnBlockConnected(201, make_addr(1));

    CHECK(tracker.GetCooldownBlocks() == CCooldownTracker::MIN_COOLDOWN);

    PASS();
}

static void test_cooldown_clamped_max()
{
    TEST(cooldown_clamped_max);
    CCooldownTracker tracker;

    // 200 miners — cooldown should be MAX_COOLDOWN (100), not 200.
    for (int i = 1; i <= 200; i++) {
        Address a{};
        a[0] = static_cast<uint8_t>(i & 0xFF);
        a[1] = static_cast<uint8_t>((i >> 8) & 0xFF);
        tracker.OnBlockConnected(500 + i, a);
    }

    CHECK(tracker.GetCooldownBlocks() == CCooldownTracker::MAX_COOLDOWN);

    PASS();
}

static void test_sliding_window_eviction()
{
    TEST(sliding_window_eviction);
    CCooldownTracker tracker;

    // Alice wins at height 100.
    Address alice = make_addr(1);
    tracker.OnBlockConnected(100, alice);

    // Fill with other miners up to height 100 + ACTIVE_WINDOW.
    int end = 100 + CCooldownTracker::ACTIVE_WINDOW;
    for (int h = 101; h <= end; h++) {
        Address a{};
        a[0] = static_cast<uint8_t>(h & 0xFF);
        a[1] = static_cast<uint8_t>((h >> 8) & 0xFF);
        tracker.OnBlockConnected(h, a);
    }

    // Alice's entry at height 100 is now outside the window (cutoff = end - 360 = 100).
    // The cutoff is `height - ACTIVE_WINDOW`, and entries < cutoff are evicted.
    // At height 460 (=100+360), cutoff = 460-360 = 100, so height 100 is evicted.
    CHECK(tracker.GetLastWinHeight(alice) == -1);

    PASS();
}

static void test_reorg_undo()
{
    TEST(reorg_undo);
    CCooldownTracker tracker;
    Address alice = make_addr(1);
    Address bob = make_addr(2);

    tracker.OnBlockConnected(100, alice);
    tracker.OnBlockConnected(101, bob);
    tracker.OnBlockConnected(102, alice);  // Alice wins again at 102.

    CHECK(tracker.GetLastWinHeight(alice) == 102);

    // Disconnect block 102.
    tracker.OnBlockDisconnected(102);

    // Alice's last win should revert to 100.
    CHECK(tracker.GetLastWinHeight(alice) == 100);

    // Bob unaffected.
    CHECK(tracker.GetLastWinHeight(bob) == 101);

    PASS();
}

static void test_reorg_undo_removes_address()
{
    TEST(reorg_undo_removes_address);
    CCooldownTracker tracker;
    Address alice = make_addr(1);

    tracker.OnBlockConnected(100, alice);
    tracker.OnBlockDisconnected(100);

    // Alice should be completely gone.
    CHECK(tracker.GetLastWinHeight(alice) == -1);
    CHECK(!tracker.IsInCooldown(alice, 101));

    PASS();
}

static void test_clear()
{
    TEST(clear);
    CCooldownTracker tracker;

    for (uint8_t i = 1; i <= 10; i++) {
        tracker.OnBlockConnected(500 + i, make_addr(i));
    }

    CHECK(tracker.GetActiveMiners() == 10);

    tracker.Clear();

    CHECK(tracker.GetActiveMiners() == 0);
    CHECK(tracker.GetLastWinHeight(make_addr(1)) == -1);

    PASS();
}

static void test_consecutive_wins_same_miner()
{
    TEST(consecutive_wins_same_miner);
    CCooldownTracker tracker;
    Address alice = make_addr(1);

    tracker.OnBlockConnected(100, alice);
    tracker.OnBlockConnected(101, alice);
    tracker.OnBlockConnected(102, alice);

    // Only 1 unique miner.
    CHECK(tracker.GetActiveMiners() == 1);
    // Last win at 102, cooldown = floor(1*0.67)=0 → not in cooldown.
    CHECK(tracker.GetLastWinHeight(alice) == 102);
    CHECK(!tracker.IsInCooldown(alice, 103));

    PASS();
}

static void test_cooldown_formula_values()
{
    TEST(cooldown_formula_values);

    // Verify the formula: cooldown = floor(activeMiners * 0.67)
    CHECK(CCooldownTracker::CalculateCooldown(0) == 0);     // 0*0.67=0
    CHECK(CCooldownTracker::CalculateCooldown(1) == 0);     // 1*67/100=0
    CHECK(CCooldownTracker::CalculateCooldown(2) == 1);     // 2*67/100=1
    CHECK(CCooldownTracker::CalculateCooldown(3) == 2);     // 3*67/100=2
    CHECK(CCooldownTracker::CalculateCooldown(10) == 6);    // 10*67/100=6
    CHECK(CCooldownTracker::CalculateCooldown(22) == 14);   // 22*67/100=14
    CHECK(CCooldownTracker::CalculateCooldown(50) == 33);   // 50*67/100=33
    CHECK(CCooldownTracker::CalculateCooldown(100) == 67);  // 100*67/100=67
    CHECK(CCooldownTracker::CalculateCooldown(150) == 100); // 150*67/100=100 → clamped to MAX(100)
    CHECK(CCooldownTracker::CalculateCooldown(200) == 100); // 200*67/100=134 → clamped to MAX(100)

    PASS();
}

// --- Integration-style tests (validate the specific bugs being fixed) ---

static void test_startup_repopulation()
{
    TEST(startup_repopulation);

    // Simulate original tracker with 10 miners across 10 blocks.
    CCooldownTracker original;
    for (uint8_t i = 1; i <= 10; i++) {
        original.OnBlockConnected(1000 + i, make_addr(i));
    }

    int orig_miners = original.GetActiveMiners();
    int orig_cooldown = original.GetCooldownBlocks();
    int orig_last_win_5 = original.GetLastWinHeight(make_addr(5));

    CHECK(orig_miners == 10);
    CHECK(orig_last_win_5 == 1005);

    // Simulate node restart: create a NEW tracker and replay the same events
    // (this is what the startup population code does).
    CCooldownTracker restarted;
    restarted.Clear();
    for (uint8_t i = 1; i <= 10; i++) {
        restarted.OnBlockConnected(1000 + i, make_addr(i));
    }

    // State must match exactly.
    CHECK(restarted.GetActiveMiners() == orig_miners);
    CHECK(restarted.GetCooldownBlocks() == orig_cooldown);
    CHECK(restarted.GetLastWinHeight(make_addr(5)) == orig_last_win_5);

    // Cooldown behavior must match.
    for (uint8_t i = 1; i <= 10; i++) {
        CHECK(restarted.IsInCooldown(make_addr(i), 1011) ==
              original.IsInCooldown(make_addr(i), 1011));
    }

    PASS();
}

static void test_disconnect_reorg_multi_block()
{
    TEST(disconnect_reorg_multi_block);
    CCooldownTracker tracker;
    Address alice = make_addr(1);
    Address bob   = make_addr(2);
    Address carol = make_addr(3);

    // Connect: A@100, B@101, C@102, A@103, B@104
    tracker.OnBlockConnected(100, alice);
    tracker.OnBlockConnected(101, bob);
    tracker.OnBlockConnected(102, carol);
    tracker.OnBlockConnected(103, alice);
    tracker.OnBlockConnected(104, bob);

    CHECK(tracker.GetLastWinHeight(alice) == 103);
    CHECK(tracker.GetLastWinHeight(bob) == 104);
    CHECK(tracker.GetLastWinHeight(carol) == 102);
    CHECK(tracker.GetActiveMiners() == 3);

    // Simulate 3-block reorg: disconnect 104, 103, 102
    tracker.OnBlockDisconnected(104);
    CHECK(tracker.GetLastWinHeight(bob) == 101);   // reverts to 101

    tracker.OnBlockDisconnected(103);
    CHECK(tracker.GetLastWinHeight(alice) == 100);  // reverts to 100

    tracker.OnBlockDisconnected(102);
    CHECK(tracker.GetLastWinHeight(carol) == -1);   // carol gone entirely

    // Trigger cache recalc via IsInCooldown before checking active count.
    // (GetActiveMiners returns cached value; cache is invalidated by
    // OnBlockDisconnected but only recalculated by IsInCooldown/OnBlockConnected.)
    tracker.IsInCooldown(alice, 102);
    CHECK(tracker.GetActiveMiners() == 2);  // only alice and bob remain

    // Connect new competing chain: D@102, E@103, F@104
    Address dave  = make_addr(4);
    Address eve   = make_addr(5);
    Address frank = make_addr(6);
    tracker.OnBlockConnected(102, dave);
    tracker.OnBlockConnected(103, eve);
    tracker.OnBlockConnected(104, frank);

    CHECK(tracker.GetActiveMiners() == 5);  // alice, bob, dave, eve, frank
    CHECK(tracker.GetLastWinHeight(dave) == 102);
    CHECK(tracker.GetLastWinHeight(eve) == 103);
    CHECK(tracker.GetLastWinHeight(frank) == 104);
    // Original miners still tracked at their earlier heights
    CHECK(tracker.GetLastWinHeight(alice) == 100);
    CHECK(tracker.GetLastWinHeight(bob) == 101);

    PASS();
}

static void test_no_double_count()
{
    TEST(no_double_count);
    CCooldownTracker tracker;
    Address alice = make_addr(1);

    // Connect alice at height 100
    tracker.OnBlockConnected(100, alice);
    CHECK(tracker.GetActiveMiners() == 1);
    CHECK(tracker.GetLastWinHeight(alice) == 100);

    // Call OnBlockConnected again for the SAME height and address.
    // This simulates what would have happened if both the miner callback
    // AND the chainstate callback fired for the same self-mined block
    // (the bug we prevent by removing the miner callback).
    // The tracker uses height as map key, so duplicate calls are idempotent.
    tracker.OnBlockConnected(100, alice);
    CHECK(tracker.GetActiveMiners() == 1);   // still 1, not 2
    CHECK(tracker.GetLastWinHeight(alice) == 100);

    // Add another miner and verify counts are still correct.
    Address bob = make_addr(2);
    tracker.OnBlockConnected(101, bob);
    CHECK(tracker.GetActiveMiners() == 2);

    // Double-call bob at 101 — still 2 unique miners.
    tracker.OnBlockConnected(101, bob);
    CHECK(tracker.GetActiveMiners() == 2);

    PASS();
}

// --- Consensus-enforced cooldown tests ---

static void test_consensus_cooldown_rejects_violation()
{
    TEST(consensus_cooldown_rejects_violation);
    CCooldownTracker tracker;

    // Set up 10 active miners so cooldown = floor(10*0.67) = 6
    // All miners must be at heights BELOW the query height because
    // RecalcActiveMiners(height) only counts blocks at heights <= height.
    // Miners 2-10 at heights 991-999, miner 1 at 1000 (most recent).
    for (uint8_t i = 2; i <= 10; i++) {
        tracker.OnBlockConnected(989 + i, make_addr(i));  // 991-999
    }
    tracker.OnBlockConnected(1000, make_addr(1));

    CHECK(tracker.GetActiveMiners() == 10);
    CHECK(tracker.GetCooldownBlocks() == 6);

    // Miner 1 won at 1000.  At height 1003 (gap=3), still in cooldown (3 < 6).
    CHECK(tracker.IsInCooldown(make_addr(1), 1003));

    // At height 1006 (gap=6), cooldown expired (6 < 6 is false).
    CHECK(!tracker.IsInCooldown(make_addr(1), 1006));

    PASS();
}

static void test_consensus_cooldown_solo_miner_never_blocked()
{
    TEST(consensus_cooldown_solo_miner_never_blocked);
    CCooldownTracker tracker;
    Address alice = make_addr(1);

    // Solo miner: cooldown = floor(1*0.67) = 0
    tracker.OnBlockConnected(100, alice);
    CHECK(!tracker.IsInCooldown(alice, 101));
    CHECK(!tracker.IsInCooldown(alice, 102));

    // Even consecutive blocks are fine
    tracker.OnBlockConnected(101, alice);
    CHECK(!tracker.IsInCooldown(alice, 102));

    PASS();
}

static void test_consensus_cooldown_exact_boundary()
{
    TEST(consensus_cooldown_exact_boundary);
    CCooldownTracker tracker;

    // 3 miners, all at heights below query.  cooldown = floor(3*0.67) = 2
    // Miner 1 wins last so their last-win height is most recent.
    tracker.OnBlockConnected(98, make_addr(2));
    tracker.OnBlockConnected(99, make_addr(3));
    tracker.OnBlockConnected(100, make_addr(1));

    CHECK(tracker.GetCooldownBlocks() == 2);

    // Miner 1 won at 100. Cooldown = 2.  IsInCooldown uses strict <.
    // height 101: gap=1, 1 < 2 → in cooldown
    CHECK(tracker.IsInCooldown(make_addr(1), 101));
    // height 102: gap=2, 2 < 2 → false → NOT in cooldown (boundary)
    CHECK(!tracker.IsInCooldown(make_addr(1), 102));
    // height 103: gap=3, 3 < 2 → false → NOT in cooldown
    CHECK(!tracker.IsInCooldown(make_addr(1), 103));

    PASS();
}

static void test_consensus_cooldown_after_reorg()
{
    TEST(consensus_cooldown_after_reorg);
    CCooldownTracker tracker;

    // 3 miners: A@100, B@101, C@102
    tracker.OnBlockConnected(100, make_addr(1));
    tracker.OnBlockConnected(101, make_addr(2));
    tracker.OnBlockConnected(102, make_addr(3));

    // Cooldown = 2. Miner 1 at 100, gap at 103 = 3, 3 < 2 → false → free.
    CHECK(!tracker.IsInCooldown(make_addr(1), 103));

    // Reorg: disconnect 102, 101
    tracker.OnBlockDisconnected(102);
    tracker.OnBlockDisconnected(101);

    // Now only miner 1 at height 100. Active miners = 1, cooldown = 0.
    tracker.IsInCooldown(make_addr(1), 101); // force recalc
    CHECK(tracker.GetActiveMiners() == 1);
    CHECK(tracker.GetCooldownBlocks() == 0);
    CHECK(!tracker.IsInCooldown(make_addr(1), 101));

    // Reconnect new fork: D@101, E@102
    tracker.OnBlockConnected(101, make_addr(4));
    tracker.OnBlockConnected(102, make_addr(5));

    // 3 active miners again (A@100, D@101, E@102), cooldown = 2
    CHECK(tracker.GetActiveMiners() == 3);
    CHECK(tracker.GetCooldownBlocks() == 2);

    // Miner 5 won at 102. At height 103: all 3 miners visible,
    // cooldown=2, gap=1, 1 < 2 → IN cooldown
    CHECK(tracker.IsInCooldown(make_addr(5), 103));
    // At height 104: gap=2, 2 < 2 → false → free (boundary)
    CHECK(!tracker.IsInCooldown(make_addr(5), 104));

    // Miner 1 at 100 is free at 103 (gap=3, 3 < 2 → false)
    CHECK(!tracker.IsInCooldown(make_addr(1), 103));

    PASS();
}

// --- Dual-window cooldown tests (post-stabilization) ---

static void test_dual_window_basic()
{
    TEST(dual_window_basic);
    // Long window 360, short window 50, activation at height 100
    CCooldownTracker tracker(360, 50, 100, 45);

    // Add 20 miners in the long window (heights 1-20)
    for (uint8_t i = 1; i <= 20; i++) {
        tracker.OnBlockConnected(i, make_addr(i));
    }

    // Long: 20 miners → cooldown = floor(20*0.67) = 13
    // Short window [71..120] at height 120 — but we only have blocks 1-20,
    // so short window at height 120 would contain no blocks (cutoff = 71).
    // Let's query at height 25 instead, where all 20 blocks are in both windows.
    // Short window at height 25: [25-50+1, 25] = [-24, 25] → all 20 blocks are in window
    // Both windows see 20 miners → cooldown = 13
    // Before activation (height 25 < 100), only long window used
    CHECK(tracker.GetEffectiveCooldown(25) == 13);  // pre-activation: long only

    PASS();
}

static void test_dual_window_reduces_cooldown()
{
    TEST(dual_window_reduces_cooldown);
    // Long window 1920, short window 100, activation at height 500
    CCooldownTracker tracker(1920, 100, 500, 45);

    // Add 100 miners in the long window (heights 1-100)
    for (int i = 1; i <= 100; i++) {
        Address a{};
        a[0] = static_cast<uint8_t>(i & 0xFF);
        a[1] = static_cast<uint8_t>((i >> 8) & 0xFF);
        tracker.OnBlockConnected(i, a);
    }

    // Now only 5 miners in the short window (heights 501-505)
    for (uint8_t i = 1; i <= 5; i++) {
        tracker.OnBlockConnected(500 + i, make_addr(i));
    }

    // At height 506 (post-activation):
    // Long window [506-1920+1, 506] = includes all 105 unique miners
    // But wait, unique miners from heights 1-100 (100 unique) + 501-505 (5, some overlap with 1-5)
    // Miners 1-5 are in both sets, so total = 100 unique miners
    // Long cooldown = floor(100*0.67) = 67
    // Short window [506-100+1, 506] = [407, 506] → only heights 501-505 → 5 miners
    // Short cooldown = floor(5*0.67) = 3
    // Effective = min(67, 3) = 3
    CHECK(tracker.GetEffectiveCooldown(506) == 3);

    PASS();
}

static void test_dual_window_solo_floor()
{
    TEST(dual_window_solo_floor);
    // Short window 100, activation at height 100
    CCooldownTracker tracker(360, 100, 100, 45);

    // Add 10 miners in the long window
    for (uint8_t i = 1; i <= 10; i++) {
        tracker.OnBlockConnected(i, make_addr(i));
    }

    // Only 2 miners in the short window (at heights 200-201)
    tracker.OnBlockConnected(200, make_addr(1));
    tracker.OnBlockConnected(201, make_addr(2));

    // At height 202 (post-activation):
    // Long window: all miners still visible → depends on eviction
    // Short window [202-100+1, 202] = [103, 202] → only heights 200, 201 → 2 miners
    // Solo floor: shortMiners ≤ 2 → treated as 1 → shortCooldown = 0
    // Effective = min(longCooldown, 0) = 0
    CHECK(tracker.GetEffectiveCooldown(202) == 0);

    // Miner 1 at height 200 should NOT be in cooldown at 201 (cooldown=0)
    CHECK(!tracker.IsInCooldown(make_addr(1), 202));

    PASS();
}

static void test_dual_window_activation_gating()
{
    TEST(dual_window_activation_gating);
    // Activation at height 1000 — before that, only long window
    CCooldownTracker tracker(360, 100, 1000, 45);

    // 10 miners at heights 1-10
    for (uint8_t i = 1; i <= 10; i++) {
        tracker.OnBlockConnected(i, make_addr(i));
    }

    // Pre-activation: only long window
    // 10 miners → cooldown = 6
    CHECK(tracker.GetEffectiveCooldown(15) == 6);

    // Same miners, post-activation: both windows active
    // Short window at height 15: [15-100+1, 15] = all 10 blocks in range → 10 miners
    // Same result since both see the same miners
    // But since height 15 < activation 1000, still long-only
    CHECK(tracker.GetEffectiveCooldown(15) == 6);

    PASS();
}

static void test_dual_window_sybil_heavy()
{
    TEST(dual_window_sybil_heavy);
    // Test that flooding short window with many MIKs doesn't REDUCE cooldown
    CCooldownTracker tracker(1920, 100, 500, 45);

    // 50 legitimate miners in long window (heights 1-50)
    for (uint8_t i = 1; i <= 50; i++) {
        tracker.OnBlockConnected(i, make_addr(i));
    }

    // Attacker floods short window with 80 unique MIKs (heights 501-580)
    for (int i = 1; i <= 80; i++) {
        Address a{};
        a[0] = static_cast<uint8_t>((i + 100) & 0xFF);  // different from legitimate miners
        a[1] = static_cast<uint8_t>(((i + 100) >> 8) & 0xFF);
        tracker.OnBlockConnected(500 + i, a);
    }

    // At height 581 (post-activation):
    // Long window: 50 + 80 = 130 unique miners → cooldown = min(floor(130*0.67), 100) = 87 (clamped)
    // Short window [581-100+1, 581] = [482, 581] → heights 501-580 → 80 miners
    // Short cooldown = floor(80*0.67) = 53
    // Effective = min(87, 53) = 53
    // This is HIGHER than the long-only cooldown for 50 miners (33)
    // Key: flooding short window does NOT reduce cooldown below what legitimate miners get
    int eff = tracker.GetEffectiveCooldown(581);
    int longOnly = CCooldownTracker::CalculateCooldown(130);  // clamped to 87
    CHECK(eff <= longOnly);  // effective never exceeds long
    CHECK(eff >= 33);  // never below what 50 real miners would give

    PASS();
}

static void test_time_based_expiry()
{
    TEST(time_based_expiry);
    // shortWindow=0 (no dual-window), activation at height 100, 45s blocks
    CCooldownTracker tracker(360, 0, 100, 45);

    // 10 miners at heights 100-109 (all post-activation)
    for (uint8_t i = 1; i <= 10; i++) {
        tracker.OnBlockConnected(99 + i, make_addr(i), 50000 + i * 45);
    }

    // At height 110: 10 miners visible. Long cooldown = 6, time cooldown = 6*45 = 270s.
    // Miner 10 at height 109, ts = 50000 + 10*45 = 50450.
    // Gap at 110 = 1 < 6 → in cooldown by block-gap.

    // Time gap 250s < 270s → still in cooldown
    CHECK(tracker.IsInCooldown(make_addr(10), 110, 50700));

    // Time gap 280s >= 270s → time-based expiry!
    CHECK(!tracker.IsInCooldown(make_addr(10), 110, 50730));

    PASS();
}

static void test_time_based_pre_activation()
{
    TEST(time_based_pre_activation);
    // Activation at height 1000 — before that, timestamp ignored (fail closed)
    CCooldownTracker tracker(360, 0, 1000, 45);

    // 10 miners at heights 100-109 with timestamps
    for (uint8_t i = 1; i <= 10; i++) {
        tracker.OnBlockConnected(99 + i, make_addr(i), 50000 + i * 45);
    }

    // Pre-activation (height 110 < 1000): time-based expiry should NOT apply
    // Miner 10 at height 109, cooldown = 6. Gap at 110 = 1 < 6 → in cooldown.
    // Even with a huge timestamp that would trigger time expiry, should stay in cooldown
    CHECK(tracker.IsInCooldown(make_addr(10), 110, 999999));

    PASS();
}

static void test_time_based_both_paths()
{
    TEST(time_based_both_paths);
    // shortWindow=0, activation at height 0, 45s blocks
    CCooldownTracker tracker(360, 0, 0, 45);

    // 10 miners at heights 100-109, timestamps 50000+i*45
    for (uint8_t i = 1; i <= 10; i++) {
        tracker.OnBlockConnected(99 + i, make_addr(i), 50000 + i * 45);
    }
    // Miner 10 at height 109, ts=50450. Cooldown=6, time cooldown=270s

    // Case 1: Both expired → not in cooldown
    // height 116 (gap=7>=6), time 50750 (300>=270)
    CHECK(!tracker.IsInCooldown(make_addr(10), 116, 50750));

    // Case 2: Neither expired → in cooldown
    // height 112 (gap=3<6), time 50550 (100<270)
    CHECK(tracker.IsInCooldown(make_addr(10), 112, 50550));

    // Case 3: Block-gap expired, time not → not in cooldown (OR logic)
    // height 116 (gap=7>=6), time 50500 (50<270)
    CHECK(!tracker.IsInCooldown(make_addr(10), 116, 50500));

    // Case 4: Time expired, block-gap not → not in cooldown (OR logic)
    // height 112 (gap=3<6), time 50750 (300>=270)
    CHECK(!tracker.IsInCooldown(make_addr(10), 112, 50750));

    PASS();
}

static void test_time_based_zero_timestamp()
{
    TEST(time_based_zero_timestamp);
    // shortWindow=0, activation at height 0
    CCooldownTracker tracker(360, 0, 0, 45);

    // 10 miners at heights 100-109 with timestamps
    for (uint8_t i = 1; i <= 10; i++) {
        tracker.OnBlockConnected(99 + i, make_addr(i), 50000 + i * 45);
    }

    // Miner 10 at height 109. At height 112 (gap=3<6), in cooldown.
    // currentTimestamp=0 → time-based expiry SKIPPED (fail closed)
    CHECK(tracker.IsInCooldown(make_addr(10), 112, 0));
    CHECK(tracker.IsInCooldown(make_addr(10), 112));  // default arg = 0

    PASS();
}

static void test_dual_window_reorg()
{
    TEST(dual_window_reorg);
    // Short window 10, activation at height 0
    CCooldownTracker tracker(360, 10, 0, 45);

    // 5 miners at heights 1-5
    for (uint8_t i = 1; i <= 5; i++) {
        tracker.OnBlockConnected(i, make_addr(i));
    }

    // Short window at height 6: [6-10+1, 6] = all 5 blocks → 5 miners
    CHECK(tracker.GetEffectiveCooldown(6) == 3);  // min(long=3, short=3)

    // Disconnect heights 4, 5
    tracker.OnBlockDisconnected(5);
    tracker.OnBlockDisconnected(4);

    // Short window at height 4: [4-10+1, 4] = heights 1-3 → 3 miners
    CHECK(tracker.GetEffectiveCooldown(4) == 2);

    // Reconnect with different miners
    tracker.OnBlockConnected(4, make_addr(6));
    tracker.OnBlockConnected(5, make_addr(7));

    // Now 5 unique miners again (1,2,3,6,7)
    CHECK(tracker.GetEffectiveCooldown(6) == 3);

    PASS();
}

static void test_startup_with_timestamps()
{
    TEST(startup_with_timestamps);
    // Simulate startup population with timestamps (shortWindow=0)
    CCooldownTracker tracker(360, 0, 0, 45);

    // Populate with 5 miners + timestamps
    for (uint8_t i = 1; i <= 5; i++) {
        tracker.OnBlockConnected(99 + i, make_addr(i), 50000 + i * 45);
    }

    // 5 miners → cooldown 3, time cooldown = 3*45 = 135s
    // Miner 5 at height 104, ts = 50000 + 5*45 = 50225
    // At height 106 (gap=2<3), ts=50225+100=50325 (100<135) → in cooldown
    CHECK(tracker.IsInCooldown(make_addr(5), 106, 50325));
    // At height 106, ts=50225+140=50365 (140>=135) → time-based expiry
    CHECK(!tracker.IsInCooldown(make_addr(5), 106, 50365));

    PASS();
}

static void test_effective_cooldown_unit()
{
    TEST(effective_cooldown_unit);
    // Verify GetEffectiveCooldown returns correct values

    // Pre-activation: long window only
    CCooldownTracker tracker1(360, 100, 1000, 45);
    for (uint8_t i = 1; i <= 10; i++) {
        tracker1.OnBlockConnected(i, make_addr(i));
    }
    CHECK(tracker1.GetEffectiveCooldown(15) == 6);  // 10 miners, long only (pre-activation)

    // Post-activation: min(long, short)
    // Short window 10, long window 360, activation at 0
    CCooldownTracker tracker2(360, 10, 0, 45);
    for (uint8_t i = 1; i <= 10; i++) {
        tracker2.OnBlockConnected(i, make_addr(i));
    }
    // At height 15: long = 10 miners → 6; short [6,15] = heights 6-10 = 5 miners → 3
    // Effective = min(6, 3) = 3
    CHECK(tracker2.GetEffectiveCooldown(15) == 3);
    // At height 10 (right at last block): long = 10 → 6; short [1,10] = 10 → 6
    // Effective = min(6, 6) = 6
    CHECK(tracker2.GetEffectiveCooldown(10) == 6);

    // Short window 5 — miners only in long window
    CCooldownTracker tracker3(360, 5, 0, 45);
    for (uint8_t i = 1; i <= 10; i++) {
        tracker3.OnBlockConnected(i, make_addr(i));
    }
    // At height 15: short [11,15] → 0 miners → solo floor → cooldown 0
    CHECK(tracker3.GetEffectiveCooldown(15) == 0);

    // Add miners to short window
    for (uint8_t i = 11; i <= 15; i++) {
        tracker3.OnBlockConnected(i, make_addr(i));
    }
    // At height 16: short [12,16] → heights 12-15 = 4 miners → cooldown 2
    // Long = 15 miners → 10
    // Effective = min(10, 2) = 2
    CHECK(tracker3.GetEffectiveCooldown(16) == 2);

    PASS();
}

// --- BUG #280: Reorg must detect cooldown violations ---
// The root cause was that ConnectTip skipped cooldown during reorgs.
// These tests verify the tracker state is correct after disconnect,
// so the moved checks (now outside !skipValidation) will work.

static void test_bug280_reorg_detects_cooldown_violation()
{
    TEST(bug280_reorg_detects_cooldown_violation);
    // DilV params: activeWindow=1920, shortWindow=0, stabilization=0, target=45s
    CCooldownTracker tracker(1920, 0, 0, 45);

    // Build a chain with 14 unique miners at heights 1-14.
    // This gives cooldown = floor(14 * 0.67) = 9.
    for (uint8_t i = 1; i <= 14; i++) {
        tracker.OnBlockConnected(240 + i, make_addr(i), 1774710000 + i * 45);
    }

    // Miner 1 wins at height 256.
    tracker.OnBlockConnected(256, make_addr(1), 1774713166);

    // Fill heights 257-258 with other miners.
    tracker.OnBlockConnected(257, make_addr(2), 1774713245);
    tracker.OnBlockConnected(258, make_addr(3), 1774713368);

    // Pre-reorg state: miner 1 last won at 256, cooldown = 9.
    CHECK(tracker.GetLastWinHeight(make_addr(1)) == 256);

    // Miner 1 at height 259 has gap = 259 - 256 = 3 < 9 → should be in cooldown.
    // Time gap = 1774713414 - 1774713166 = 248s < 405s (9*45) → no time expiry.
    CHECK(tracker.IsInCooldown(make_addr(1), 259, 1774713414));

    // Now simulate a reorg: disconnect 258, 257, 256 (back to fork point 255).
    tracker.OnBlockDisconnected(258);
    tracker.OnBlockDisconnected(257);
    tracker.OnBlockDisconnected(256);

    // After disconnect: miner 1's last win should revert to height 241
    // (from the initial population). Miner 2 reverts to 242, miner 3 to 243.
    CHECK(tracker.GetLastWinHeight(make_addr(1)) == 241);
    CHECK(tracker.GetLastWinHeight(make_addr(2)) == 242);
    CHECK(tracker.GetLastWinHeight(make_addr(3)) == 243);

    // Reconnect new fork: miner 1 at 256 again, different miners at 257-258.
    tracker.OnBlockConnected(256, make_addr(1), 1774713166);
    tracker.OnBlockConnected(257, make_addr(4), 1774713245);
    tracker.OnBlockConnected(258, make_addr(5), 1774713368);

    // After reconnect: miner 1 last won at 256 (same as before reorg).
    CHECK(tracker.GetLastWinHeight(make_addr(1)) == 256);

    // KEY TEST: miner 1 at height 259 is STILL in cooldown after the reorg.
    // gap = 259 - 256 = 3 < 9 → violation. Time gap still insufficient.
    // This is what BUG #280 fix enforces — before the fix, this check was
    // skipped during reorg connects (skipValidation=true).
    CHECK(tracker.IsInCooldown(make_addr(1), 259, 1774713414));

    PASS();
}

static void test_bug280_reorg_tracker_matches_sequential()
{
    TEST(bug280_reorg_tracker_matches_sequential);
    // Verify that tracker state after disconnect+reconnect is IDENTICAL
    // to tracker state built by sequential IBD.
    CCooldownTracker tracker_reorg(1920, 0, 0, 45);
    CCooldownTracker tracker_ibd(1920, 0, 0, 45);

    // Both trackers start with the same shared prefix (heights 1-10).
    for (uint8_t i = 1; i <= 10; i++) {
        int64_t ts = 1000000 + i * 45;
        tracker_reorg.OnBlockConnected(i, make_addr(i), ts);
        tracker_ibd.OnBlockConnected(i, make_addr(i), ts);
    }

    // Reorg tracker: build OLD fork (heights 11-15, miners A-E).
    for (uint8_t i = 0; i < 5; i++) {
        tracker_reorg.OnBlockConnected(11 + i, make_addr(101 + i), 1000495 + i * 45);
    }

    // Reorg tracker: disconnect OLD fork (heights 15..11).
    for (int h = 15; h >= 11; h--) {
        tracker_reorg.OnBlockDisconnected(h);
    }

    // Reorg tracker: connect NEW fork (heights 11-15, miners F-J).
    for (uint8_t i = 0; i < 5; i++) {
        tracker_reorg.OnBlockConnected(11 + i, make_addr(201 + i), 1000495 + i * 45);
    }

    // IBD tracker: directly build NEW fork (heights 11-15, miners F-J).
    for (uint8_t i = 0; i < 5; i++) {
        tracker_ibd.OnBlockConnected(11 + i, make_addr(201 + i), 1000495 + i * 45);
    }

    // State must match exactly.
    CHECK(tracker_reorg.GetActiveMiners() == tracker_ibd.GetActiveMiners());

    // Check every miner's cooldown status at height 16.
    for (uint8_t i = 1; i <= 10; i++) {
        CHECK(tracker_reorg.IsInCooldown(make_addr(i), 16, 1000720) ==
              tracker_ibd.IsInCooldown(make_addr(i), 16, 1000720));
    }
    for (uint8_t i = 201; i <= 205; i++) {
        CHECK(tracker_reorg.IsInCooldown(make_addr(i), 16, 1000720) ==
              tracker_ibd.IsInCooldown(make_addr(i), 16, 1000720));
    }

    // Old fork miners should NOT be in either tracker.
    for (uint8_t i = 101; i <= 105; i++) {
        CHECK(tracker_reorg.GetLastWinHeight(make_addr(i)) == -1);
    }

    PASS();
}

static void test_bug280_rollback_reconnect_passes()
{
    TEST(bug280_rollback_reconnect_passes);
    // Simulate a failed reorg rollback: the OLD chain is reconnected.
    // Since the old chain was already valid, cooldown should pass.
    // Use 10 miners cycling so each miner's gap (10) >> cooldown (6).
    CCooldownTracker tracker(1920, 0, 0, 45);

    // Build valid chain: 10 miners taking turns across 30 blocks.
    // 10 miners → cooldown = floor(10 * 0.67) = 6.
    // Cycle length 10, so each miner's gap is always 10 >= 6.
    for (int h = 1; h <= 30; h++) {
        uint8_t miner = ((h - 1) % 10) + 1;
        tracker.OnBlockConnected(h, make_addr(miner), 1000000 + h * 45);
    }

    CHECK(tracker.GetActiveMiners() == 10);
    CHECK(tracker.GetCooldownBlocks() == 6);

    // Simulate reorg: disconnect blocks 30..26 (5 blocks).
    for (int h = 30; h >= 26; h--) {
        tracker.OnBlockDisconnected(h);
    }

    // After disconnect, tracker is at height 25.
    // Miners 6-10 had their last wins at 26-30 (disconnected) → revert to 16-20.
    // Miners 1-5 had last wins at 21-25 (still connected).

    // Rollback: reconnect the SAME blocks (simulating failed reorg recovery).
    for (int h = 26; h <= 30; h++) {
        uint8_t miner = ((h - 1) % 10) + 1;
        // Before connecting, verify this miner is NOT in cooldown at height h.
        // Miner's last win after disconnect is at h-10 (gap = 10 >= cooldown 6).
        CHECK(!tracker.IsInCooldown(make_addr(miner), h, 1000000 + h * 45));
        tracker.OnBlockConnected(h, make_addr(miner), 1000000 + h * 45);
    }

    // State should be back to original.
    CHECK(tracker.GetActiveMiners() == 10);
    CHECK(tracker.GetCooldownBlocks() == 6);

    PASS();
}

static void test_option_c_excluding_height_preflight()
{
    TEST(option_c_excluding_height_preflight);
    CCooldownTracker tracker(1920, 0, 0, 45);

    // Build enough active miners so cooldown is non-trivial.
    for (uint8_t i = 1; i <= 14; ++i) {
        tracker.OnBlockConnected(240 + i, make_addr(i), 1774710000 + i * 45);
    }

    // Same miner wins at 256 and tries again at 259 (normally invalid).
    tracker.OnBlockConnected(256, make_addr(1), 1774713166);
    tracker.OnBlockConnected(257, make_addr(2), 1774713245);
    tracker.OnBlockConnected(258, make_addr(3), 1774713368);
    CHECK(tracker.IsInCooldown(make_addr(1), 259, 1774713414));

    // Option C preflight should evaluate against state with 256 excluded.
    // With the tip winner removed, miner 1's last win reverts to 241, so this passes.
    CHECK(!tracker.IsInCooldownExcludingHeight(make_addr(1), 259, 1774713414, 256));
    CHECK(tracker.GetActiveMinersExcludingHeight(259, 256) <= tracker.GetActiveMiners());

    PASS();
}

int main()
{
    std::cout << "\nCCooldownTracker Unit Tests\n";
    std::cout << "==========================\n\n";

    test_basic_cooldown();
    test_unknown_address_not_in_cooldown();
    test_active_miner_count();
    test_cooldown_scales_with_miners();
    test_cooldown_clamped_min();
    test_cooldown_clamped_max();
    test_sliding_window_eviction();
    test_reorg_undo();
    test_reorg_undo_removes_address();
    test_clear();
    test_consecutive_wins_same_miner();
    test_cooldown_formula_values();
    test_startup_repopulation();
    test_disconnect_reorg_multi_block();
    test_no_double_count();
    test_consensus_cooldown_rejects_violation();
    test_consensus_cooldown_solo_miner_never_blocked();
    test_consensus_cooldown_exact_boundary();
    test_consensus_cooldown_after_reorg();

    std::cout << "\n--- Stabilization Fork Tests ---\n\n";

    test_dual_window_basic();
    test_dual_window_reduces_cooldown();
    test_dual_window_solo_floor();
    test_dual_window_activation_gating();
    test_dual_window_sybil_heavy();
    test_time_based_expiry();
    test_time_based_pre_activation();
    test_time_based_both_paths();
    test_time_based_zero_timestamp();
    test_dual_window_reorg();
    test_startup_with_timestamps();
    test_effective_cooldown_unit();

    std::cout << "\n--- BUG #280 Reorg Enforcement Tests ---\n\n";

    test_bug280_reorg_detects_cooldown_violation();
    test_bug280_reorg_tracker_matches_sequential();
    test_bug280_rollback_reconnect_passes();
    test_option_c_excluding_height_preflight();

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";

    if (failed > 0) {
        std::cout << "\n=== TESTS FAILED ===\n";
        return 1;
    }

    std::cout << "\n=== ALL TESTS PASSED ===\n";
    return 0;
}
