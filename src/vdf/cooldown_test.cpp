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

    // Alice should be in cooldown for MIN_COOLDOWN blocks (10).
    CHECK(tracker.IsInCooldown(alice, 101));
    CHECK(tracker.IsInCooldown(alice, 109));

    // At height 110, exactly MIN_COOLDOWN blocks later, cooldown expires.
    CHECK(!tracker.IsInCooldown(alice, 110));
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

    // Register 50 distinct miners so cooldown becomes 50.
    for (uint8_t i = 1; i <= 50; i++) {
        tracker.OnBlockConnected(1000 + i, make_addr(i));
    }

    CHECK(tracker.GetCooldownBlocks() == 50);

    // Alice won at height 1001. At 1001 + 49 she should still be in cooldown.
    CHECK(tracker.IsInCooldown(alice, 1050));
    // At 1001 + 50 she's out.
    CHECK(!tracker.IsInCooldown(alice, 1051));

    PASS();
}

static void test_cooldown_clamped_min()
{
    TEST(cooldown_clamped_min);
    CCooldownTracker tracker;

    // Only 3 miners — cooldown should be MIN_COOLDOWN (10), not 3.
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
    // Last win at 102, cooldown = MIN_COOLDOWN (10).
    CHECK(tracker.GetLastWinHeight(alice) == 102);
    CHECK(tracker.IsInCooldown(alice, 103));
    CHECK(!tracker.IsInCooldown(alice, 112));

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

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";

    if (failed > 0) {
        std::cout << "\n=== TESTS FAILED ===\n";
        return 1;
    }

    std::cout << "\n=== ALL TESTS PASSED ===\n";
    return 0;
}
