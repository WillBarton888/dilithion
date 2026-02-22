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

    // 1 active miner → cooldown = CalculateCooldown(1) = max(2, 1-3) = 2.
    CHECK(tracker.IsInCooldown(alice, 101));   // 101-100=1 < 2 → in cooldown

    // At height 102, exactly 2 blocks later, cooldown expires.
    CHECK(!tracker.IsInCooldown(alice, 102));
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

    // 50 miners → cooldown = 50 - max(3, 5) = 45.
    CHECK(tracker.GetCooldownBlocks() == 45);

    // Have Alice win again at height 1060 (all 50 miners in window).
    tracker.OnBlockConnected(1060, alice);

    // Alice last won at 1060. At 1060+44=1104 she should still be in cooldown.
    CHECK(tracker.IsInCooldown(alice, 1104));
    // At 1060+45=1105 she's out.
    CHECK(!tracker.IsInCooldown(alice, 1105));

    PASS();
}

static void test_cooldown_clamped_min()
{
    TEST(cooldown_clamped_min);
    CCooldownTracker tracker;

    // Only 3 miners → formula gives 3-3=0, clamped to MIN_COOLDOWN (2).
    for (uint8_t i = 1; i <= 3; i++) {
        tracker.OnBlockConnected(200 + i, make_addr(i));
    }

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
    // Last win at 102, cooldown = MIN_COOLDOWN (2).
    CHECK(tracker.GetLastWinHeight(alice) == 102);
    CHECK(tracker.IsInCooldown(alice, 103));
    CHECK(!tracker.IsInCooldown(alice, 104));

    PASS();
}

static void test_cooldown_formula_values()
{
    TEST(cooldown_formula_values);

    // Verify the formula: cooldown = miners - max(3, miners/10)
    CHECK(CCooldownTracker::CalculateCooldown(1) == 2);    // 1-3=-2 → clamped to MIN(2)
    CHECK(CCooldownTracker::CalculateCooldown(5) == 2);    // 5-3=2
    CHECK(CCooldownTracker::CalculateCooldown(10) == 7);   // 10-3=7
    CHECK(CCooldownTracker::CalculateCooldown(20) == 17);  // 20-3=17  (20/10=2, max(3,2)=3)
    CHECK(CCooldownTracker::CalculateCooldown(30) == 27);  // 30-3=27  (30/10=3, max(3,3)=3)
    CHECK(CCooldownTracker::CalculateCooldown(31) == 28);  // 31-3=28  (31/10=3, max(3,3)=3)
    CHECK(CCooldownTracker::CalculateCooldown(50) == 45);  // 50-5=45  (50/10=5)
    CHECK(CCooldownTracker::CalculateCooldown(100) == 90); // 100-10=90
    CHECK(CCooldownTracker::CalculateCooldown(200) == 100); // 200-20=180 → clamped to MAX(100)

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

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";

    if (failed > 0) {
        std::cout << "\n=== TESTS FAILED ===\n";
        return 1;
    }

    std::cout << "\n=== ALL TESTS PASSED ===\n";
    return 0;
}
