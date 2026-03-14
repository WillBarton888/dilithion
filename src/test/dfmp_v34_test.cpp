/**
 * DFMP v3.4 Verification-Aware Free Tier Tests
 *
 * Tests the split free tier introduced in v3.4:
 *   Verified MIKs:   12 free blocks (same as v3.3)
 *   Unverified MIKs:  3 free blocks (reduced)
 *
 * Linear zone ramps from 1.0x to 4.0x at heat=24.
 * Exponential zone: 4.0x * 1.58^(heat-24) for heat > 24.
 *
 * Tests:
 *  1. Verified MIK, heat 0-12: multiplier = 1.0x
 *  2. Verified MIK, heat 13: multiplier > 1.0x
 *  3. Unverified MIK, heat 0-3: multiplier = 1.0x
 *  4. Unverified MIK, heat 4: multiplier > 1.0x
 *  5. Unverified MIK, heat 12: multiplier significantly > 1.0x
 *  6. Verified vs unverified at heat 12: verified=1.0x, unverified >> 1.0x
 *  7. Both at heat 24: both reach ~4.0x
 *  8. Both at heat 25+: identical exponential growth
 *  9. Edge: heat 0 for both: both 1.0x
 * 10. Edge: negative heat: should return 1.0x
 * 11. Pending penalty (v3.4): same as v3.3/v3.2
 */

#include "../dfmp/dfmp.h"
#include <iostream>
#include <cmath>

using namespace DFMP;

static int tests_passed = 0;
static int tests_failed = 0;

static void CHECK(bool condition, const char* name) {
    if (condition) {
        std::cout << "  [PASS] " << name << std::endl;
        tests_passed++;
    } else {
        std::cout << "  [FAIL] " << name << std::endl;
        tests_failed++;
    }
}

// ============================================================================
// Test 1: Verified MIK, heat 0-12 = 1.0x (free tier)
// ============================================================================
static void test_verified_free_tier() {
    std::cout << "\n--- Verified MIK Free Tier (heat 0-12) ---" << std::endl;

    for (int heat = 0; heat <= 12; heat++) {
        int64_t mult = CalculateHeatMultiplierFP_V34(heat, true);
        char name[80];
        snprintf(name, sizeof(name), "Verified heat %d = 1.0x (got %ld)", heat, (long)mult);
        CHECK(mult == FP_SCALE, name);
    }
}

// ============================================================================
// Test 2: Verified MIK, heat 13 = penalty starts
// ============================================================================
static void test_verified_penalty_starts() {
    std::cout << "\n--- Verified MIK Penalty Starts (heat 13) ---" << std::endl;

    int64_t mult = CalculateHeatMultiplierFP_V34(13, true);
    CHECK(mult > FP_SCALE, "Verified heat 13 > 1.0x");

    // Expected: 1.0 + 1 * 3.0 / 12 = 1.25x = 1250000
    CHECK(mult == 1250000, "Verified heat 13 = 1.25x (1250000)");
}

// ============================================================================
// Test 3: Unverified MIK, heat 0-3 = 1.0x (free tier)
// ============================================================================
static void test_unverified_free_tier() {
    std::cout << "\n--- Unverified MIK Free Tier (heat 0-3) ---" << std::endl;

    for (int heat = 0; heat <= 3; heat++) {
        int64_t mult = CalculateHeatMultiplierFP_V34(heat, false);
        char name[80];
        snprintf(name, sizeof(name), "Unverified heat %d = 1.0x (got %ld)", heat, (long)mult);
        CHECK(mult == FP_SCALE, name);
    }
}

// ============================================================================
// Test 4: Unverified MIK, heat 4 = penalty starts
// ============================================================================
static void test_unverified_penalty_starts() {
    std::cout << "\n--- Unverified MIK Penalty Starts (heat 4) ---" << std::endl;

    int64_t mult = CalculateHeatMultiplierFP_V34(4, false);
    CHECK(mult > FP_SCALE, "Unverified heat 4 > 1.0x");

    // Expected: 1.0 + 1 * 3.0 / 21 = 1.142857x
    // Integer math: FP_SCALE + (1 * 3 * FP_SCALE) / 21 = 1000000 + 142857 = 1142857
    CHECK(mult == 1142857, "Unverified heat 4 = 1142857 (~1.143x)");
}

// ============================================================================
// Test 5: Unverified MIK, heat 12 = significantly above 1.0x
// ============================================================================
static void test_unverified_heat_12() {
    std::cout << "\n--- Unverified MIK at Heat 12 ---" << std::endl;

    int64_t mult = CalculateHeatMultiplierFP_V34(12, false);
    CHECK(mult > FP_SCALE, "Unverified heat 12 > 1.0x");

    // Expected: 1.0 + 9 * 3.0 / 21 = 1.0 + 1.2857 = 2.2857x
    // Integer math: FP_SCALE + (9 * 3 * FP_SCALE) / 21 = 1000000 + 1285714 = 2285714
    CHECK(mult == 2285714, "Unverified heat 12 = 2285714 (~2.286x)");

    // Should be well above 1.5x
    CHECK(mult > 1500000, "Unverified heat 12 > 1.5x");
}

// ============================================================================
// Test 6: Verified vs unverified at heat 12
// ============================================================================
static void test_verified_vs_unverified_at_12() {
    std::cout << "\n--- Verified vs Unverified at Heat 12 ---" << std::endl;

    int64_t verified = CalculateHeatMultiplierFP_V34(12, true);
    int64_t unverified = CalculateHeatMultiplierFP_V34(12, false);

    CHECK(verified == FP_SCALE, "Verified at heat 12 = 1.0x (still in free tier)");
    CHECK(unverified > FP_SCALE, "Unverified at heat 12 > 1.0x (past free tier)");
    CHECK(unverified > verified, "Unverified penalty > verified penalty at heat 12");

    // The gap should be large: unverified is ~2.286x while verified is 1.0x
    CHECK(unverified > 2 * verified, "Unverified > 2x verified at heat 12");
}

// ============================================================================
// Test 7: Both at heat 24 = ~4.0x (linear zone endpoint)
// ============================================================================
static void test_both_at_heat_24() {
    std::cout << "\n--- Both at Heat 24 (Linear Zone Endpoint) ---" << std::endl;

    int64_t verified = CalculateHeatMultiplierFP_V34(24, true);
    int64_t unverified = CalculateHeatMultiplierFP_V34(24, false);

    // Both should reach 4.0x at heat 24 (end of linear zone)
    // Verified: excess=12, span=12: 1.0 + 12*3/12 = 4.0x
    // Unverified: excess=21, span=21: 1.0 + 21*3/21 = 4.0x
    CHECK(verified == 4000000, "Verified at heat 24 = 4.0x");
    CHECK(unverified == 4000000, "Unverified at heat 24 = 4.0x");
    CHECK(verified == unverified, "Both converge to same penalty at heat 24");
}

// ============================================================================
// Test 8: Both at heat 25+ = identical exponential growth
// ============================================================================
static void test_both_exponential_zone() {
    std::cout << "\n--- Both in Exponential Zone (heat 25+) ---" << std::endl;

    // Heat 25: 4.0x * 1.58^1 = 6.32x
    int64_t v25 = CalculateHeatMultiplierFP_V34(25, true);
    int64_t u25 = CalculateHeatMultiplierFP_V34(25, false);
    CHECK(v25 == u25, "Verified == unverified at heat 25");
    // Expected: 4000000 * 158 / 100 = 6320000
    CHECK(v25 == 6320000, "Heat 25 = 6320000 (6.32x)");

    // Heat 26: 6320000 * 158 / 100 = 9985600
    int64_t v26 = CalculateHeatMultiplierFP_V34(26, true);
    int64_t u26 = CalculateHeatMultiplierFP_V34(26, false);
    CHECK(v26 == u26, "Verified == unverified at heat 26");
    CHECK(v26 == 9985600, "Heat 26 = 9985600 (~9.986x)");

    // Heat 30: verify both still equal (deep exponential)
    int64_t v30 = CalculateHeatMultiplierFP_V34(30, true);
    int64_t u30 = CalculateHeatMultiplierFP_V34(30, false);
    CHECK(v30 == u30, "Verified == unverified at heat 30");
    CHECK(v30 > u26, "Heat 30 > heat 26 (exponential growth continues)");
}

// ============================================================================
// Test 9: Edge case: heat 0 for both
// ============================================================================
static void test_heat_zero() {
    std::cout << "\n--- Edge: Heat 0 ---" << std::endl;

    int64_t verified = CalculateHeatMultiplierFP_V34(0, true);
    int64_t unverified = CalculateHeatMultiplierFP_V34(0, false);

    CHECK(verified == FP_SCALE, "Verified heat 0 = 1.0x");
    CHECK(unverified == FP_SCALE, "Unverified heat 0 = 1.0x");
}

// ============================================================================
// Test 10: Edge case: negative heat
// ============================================================================
static void test_negative_heat() {
    std::cout << "\n--- Edge: Negative Heat ---" << std::endl;

    int64_t v_neg1 = CalculateHeatMultiplierFP_V34(-1, true);
    int64_t u_neg1 = CalculateHeatMultiplierFP_V34(-1, false);
    int64_t v_neg100 = CalculateHeatMultiplierFP_V34(-100, true);
    int64_t u_neg100 = CalculateHeatMultiplierFP_V34(-100, false);

    CHECK(v_neg1 == FP_SCALE, "Verified heat -1 = 1.0x");
    CHECK(u_neg1 == FP_SCALE, "Unverified heat -1 = 1.0x");
    CHECK(v_neg100 == FP_SCALE, "Verified heat -100 = 1.0x");
    CHECK(u_neg100 == FP_SCALE, "Unverified heat -100 = 1.0x");
}

// ============================================================================
// Test 11: Pending penalty (v3.4 = same as v3.3/v3.2)
// ============================================================================
static void test_pending_penalty_v34() {
    std::cout << "\n--- Pending Penalty v3.4 (same as v3.2) ---" << std::endl;

    // New identity (firstSeenHeight = -1): 2.5x
    int64_t p_new = CalculatePendingPenaltyFP_V34(1000, -1);
    CHECK(p_new == 2500000, "New identity = 2.5x");

    // Age < 100: 2.5x
    int64_t p_age50 = CalculatePendingPenaltyFP_V34(1050, 1000);
    CHECK(p_age50 == 2500000, "Age 50 = 2.5x");

    // Age 100-199: 2.0x
    int64_t p_age150 = CalculatePendingPenaltyFP_V34(1150, 1000);
    CHECK(p_age150 == 2000000, "Age 150 = 2.0x");

    // Age 200-299: 1.5x
    int64_t p_age250 = CalculatePendingPenaltyFP_V34(1250, 1000);
    CHECK(p_age250 == 1500000, "Age 250 = 1.5x");

    // Age 300-399: 1.25x
    int64_t p_age350 = CalculatePendingPenaltyFP_V34(1350, 1000);
    CHECK(p_age350 == 1250000, "Age 350 = 1.25x");

    // Age 400-499: 1.1x
    int64_t p_age450 = CalculatePendingPenaltyFP_V34(1450, 1000);
    CHECK(p_age450 == 1100000, "Age 450 = 1.1x");

    // Age >= 500: 1.0x (mature)
    int64_t p_age500 = CalculatePendingPenaltyFP_V34(1500, 1000);
    CHECK(p_age500 == FP_SCALE, "Age 500 = 1.0x (mature)");

    int64_t p_age1000 = CalculatePendingPenaltyFP_V34(2000, 1000);
    CHECK(p_age1000 == FP_SCALE, "Age 1000 = 1.0x (mature)");

    // Verify v3.4 matches v3.2 exactly
    for (int age : {0, 50, 99, 100, 199, 200, 299, 300, 399, 400, 499, 500, 1000}) {
        int64_t v34 = CalculatePendingPenaltyFP_V34(1000 + age, 1000);
        int64_t v32 = CalculatePendingPenaltyFP_V32(1000 + age, 1000);
        char name[100];
        snprintf(name, sizeof(name), "v3.4 matches v3.2 at age %d", age);
        CHECK(v34 == v32, name);
    }
}

// ============================================================================
// Additional: Linear ramp monotonicity (verified)
// ============================================================================
static void test_linear_ramp_monotonic_verified() {
    std::cout << "\n--- Linear Ramp Monotonicity (Verified) ---" << std::endl;

    int64_t prev = FP_SCALE;
    for (int heat = 13; heat <= 24; heat++) {
        int64_t curr = CalculateHeatMultiplierFP_V34(heat, true);
        char name[100];
        snprintf(name, sizeof(name), "Verified heat %d (%ld) > heat %d (%ld)",
                 heat, (long)curr, heat - 1, (long)prev);
        CHECK(curr > prev, name);
        prev = curr;
    }
}

// ============================================================================
// Additional: Linear ramp monotonicity (unverified)
// ============================================================================
static void test_linear_ramp_monotonic_unverified() {
    std::cout << "\n--- Linear Ramp Monotonicity (Unverified) ---" << std::endl;

    int64_t prev = FP_SCALE;
    for (int heat = 4; heat <= 24; heat++) {
        int64_t curr = CalculateHeatMultiplierFP_V34(heat, false);
        char name[100];
        snprintf(name, sizeof(name), "Unverified heat %d (%ld) > heat %d (%ld)",
                 heat, (long)curr, heat - 1, (long)prev);
        CHECK(curr > prev, name);
        prev = curr;
    }
}

// ============================================================================
// Additional: Total multiplier combines pending + heat
// ============================================================================
static void test_total_multiplier_v34() {
    std::cout << "\n--- Total Multiplier v3.4 ---" << std::endl;

    // Mature identity (age 500+) with heat 0: total = 1.0x * 1.0x = 1.0x
    int64_t total_mature_cool = CalculateTotalMultiplierFP_V34(1500, 1000, 0, true);
    CHECK(total_mature_cool == FP_SCALE, "Mature + cool = 1.0x");

    // New identity with heat 0: total = 2.5x * 1.0x = 2.5x
    int64_t total_new_cool = CalculateTotalMultiplierFP_V34(1000, -1, 0, true);
    CHECK(total_new_cool == 2500000, "New + cool = 2.5x");

    // Mature identity with heat 24 (verified): total = 1.0x * 4.0x = 4.0x
    int64_t total_mature_hot = CalculateTotalMultiplierFP_V34(1500, 1000, 24, true);
    CHECK(total_mature_hot == 4000000, "Mature + hot(24, verified) = 4.0x");

    // New identity with heat 24 (unverified): total = 2.5x * 4.0x = 10.0x
    int64_t total_new_hot = CalculateTotalMultiplierFP_V34(1000, -1, 24, false);
    CHECK(total_new_hot == 10000000, "New + hot(24, unverified) = 10.0x");
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== DFMP v3.4 Verification-Aware Free Tier Tests ===" << std::endl;

    test_verified_free_tier();
    test_verified_penalty_starts();
    test_unverified_free_tier();
    test_unverified_penalty_starts();
    test_unverified_heat_12();
    test_verified_vs_unverified_at_12();
    test_both_at_heat_24();
    test_both_exponential_zone();
    test_heat_zero();
    test_negative_heat();
    test_pending_penalty_v34();
    test_linear_ramp_monotonic_verified();
    test_linear_ramp_monotonic_unverified();
    test_total_multiplier_v34();

    std::cout << "\n=== Results ===" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "  Total:  " << (tests_passed + tests_failed) << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
