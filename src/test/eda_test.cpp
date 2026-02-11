// Emergency Difficulty Adjustment (EDA) - Standalone Math Test
// Tests the EDA reduction math independently of the full node codebase
//
// Build: g++ -std=c++17 -O2 -o eda_test src/test/eda_test.cpp
// Run: ./eda_test

#include <iostream>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <algorithm>

// ============================================================================
// Copy of consensus-critical functions from pow.cpp (for isolated testing)
// These are exact copies to verify the math works correctly.
// ============================================================================

struct uint256 {
    uint8_t data[32];
    uint256() { memset(data, 0, 32); }
    bool operator==(const uint256& other) const { return memcmp(data, other.data, 32) == 0; }
    bool operator!=(const uint256& other) const { return !(*this == other); }
};

static uint256 CompactToBig(uint32_t nCompact) {
    uint256 target;
    int nSize = (nCompact >> 24) & 0xFF;
    uint32_t nWord = nCompact & 0x7FFFFF;
    if (nSize <= 3) {
        nWord >>= 8 * (3 - nSize);
        target.data[0] = nWord & 0xFF;
        if (nSize >= 2) target.data[1] = (nWord >> 8) & 0xFF;
        if (nSize >= 3) target.data[2] = (nWord >> 16) & 0xFF;
    } else {
        int shift = nSize - 3;
        if (shift < 29) {
            target.data[shift] = nWord & 0xFF;
            target.data[shift + 1] = (nWord >> 8) & 0xFF;
            target.data[shift + 2] = (nWord >> 16) & 0xFF;
        }
    }
    return target;
}

static uint32_t BigToCompact(const uint256& target) {
    int nSize = 0;
    for (int i = 31; i >= 0; i--) {
        if (target.data[i] != 0) {
            nSize = i + 1;
            break;
        }
    }
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = target.data[0];
        if (nSize >= 2) nCompact |= (uint32_t)target.data[1] << 8;
        if (nSize >= 3) nCompact |= (uint32_t)target.data[2] << 16;
        nCompact |= (uint32_t)nSize << 24;
    } else {
        nCompact = target.data[nSize - 3];
        nCompact |= (uint32_t)target.data[nSize - 2] << 8;
        nCompact |= (uint32_t)target.data[nSize - 1] << 16;
        if (nCompact & 0x00800000) {
            nCompact >>= 8;
            nSize++;
        }
        nCompact |= (uint32_t)nSize << 24;
    }
    return nCompact;
}

static bool Multiply256x64(const uint256& a, uint64_t b, uint8_t* result) {
    memset(result, 0, 40);
    uint64_t carry = 0;
    for (int i = 0; i < 32; i++) {
        uint64_t byte_val = a.data[i];
        if (byte_val != 0 && b > UINT64_MAX / byte_val) return false;
        uint64_t mul_result = byte_val * b;
        if (carry > UINT64_MAX - mul_result) return false;
        uint64_t product = mul_result + carry;
        result[i] = product & 0xFF;
        carry = product >> 8;
    }
    for (int i = 32; i < 40 && carry > 0; i++) {
        result[i] = carry & 0xFF;
        carry >>= 8;
    }
    return carry == 0;
}

static uint256 Divide320x64(const uint8_t* dividend, uint64_t divisor) {
    uint256 quotient;
    if (divisor == 0) return quotient;
    __uint128_t remainder = 0;
    for (int i = 39; i >= 0; i--) {
        remainder = (remainder << 8) | dividend[i];
        if (i < 32) {
            quotient.data[i] = static_cast<uint8_t>(remainder / divisor);
            remainder %= divisor;
        } else {
            remainder = remainder;
            uint64_t q = static_cast<uint64_t>(remainder / divisor);
            remainder %= divisor;
            (void)q;  // High bytes discarded (overflow into uint256)
        }
    }
    return quotient;
}

// ============================================================================
// EDA Constants (same as pow.h)
// ============================================================================
const int EDA_THRESHOLD_BLOCKS = 6;
const int EDA_STEP_BLOCKS = 6;
const int EDA_REDUCTION_NUMERATOR = 5;
const int EDA_REDUCTION_DENOMINATOR = 4;
const int EDA_MAX_STEPS = 20;
const uint32_t MAX_DIFFICULTY_BITS = 0x1f0fffff;
const uint32_t MIN_DIFFICULTY_BITS = 0x1d00ffff;

// ============================================================================
// EDA Calculation (same logic as in GetNextWorkRequired)
// ============================================================================
uint32_t ApplyEDA(uint32_t prevBits, int64_t gap, int64_t blockTime) {
    int64_t threshold = static_cast<int64_t>(EDA_THRESHOLD_BLOCKS) * blockTime;
    if (gap <= threshold) return prevBits;

    int64_t stepSize = static_cast<int64_t>(EDA_STEP_BLOCKS) * blockTime;
    int64_t stepsRaw = (gap - threshold) / stepSize + 1;
    int steps = static_cast<int>(std::min(stepsRaw, static_cast<int64_t>(EDA_MAX_STEPS)));

    uint256 target = CompactToBig(prevBits);

    for (int i = 0; i < steps; i++) {
        uint8_t product[40];
        if (!Multiply256x64(target, static_cast<uint64_t>(EDA_REDUCTION_NUMERATOR), product)) break;
        target = Divide320x64(product, static_cast<uint64_t>(EDA_REDUCTION_DENOMINATOR));
    }

    uint32_t edaBits = BigToCompact(target);
    if (edaBits > MAX_DIFFICULTY_BITS) edaBits = MAX_DIFFICULTY_BITS;
    if (edaBits < MIN_DIFFICULTY_BITS) edaBits = MIN_DIFFICULTY_BITS;

    return edaBits;
}

// ============================================================================
// Tests
// ============================================================================
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(condition, msg) do { \
    if (!(condition)) { \
        std::cerr << "FAIL: " << msg << std::endl; \
        tests_failed++; \
    } else { \
        std::cout << "PASS: " << msg << std::endl; \
        tests_passed++; \
    } \
} while(0)

void test_compact_roundtrip() {
    // Verify CompactToBig/BigToCompact roundtrip
    uint32_t values[] = { 0x1d00ffff, 0x1e01fffe, 0x1f0fffff, 0x1e0fffff };
    for (uint32_t v : values) {
        uint256 big = CompactToBig(v);
        uint32_t compact = BigToCompact(big);
        TEST(compact == v, "Compact roundtrip for 0x" + std::to_string(v));
    }
}

void test_no_trigger_within_threshold() {
    // Gap = 1200s < 1440s threshold (blockTime=240)
    uint32_t result = ApplyEDA(0x1d00ffff, 1200, 240);
    TEST(result == 0x1d00ffff, "No trigger within threshold (gap=1200s)");
}

void test_no_trigger_at_exact_threshold() {
    // Gap = exactly 1440s = threshold (should NOT trigger, need > threshold)
    uint32_t result = ApplyEDA(0x1d00ffff, 1440, 240);
    TEST(result == 0x1d00ffff, "No trigger at exact threshold (gap=1440s)");
}

void test_single_step() {
    // Gap = 1500s > 1440s threshold, 1 step
    uint32_t result = ApplyEDA(0x1d00ffff, 1500, 240);
    TEST(result > 0x1d00ffff, "Single step: difficulty easier (higher nBits)");
    TEST(result <= MAX_DIFFICULTY_BITS, "Single step: within max bounds");
    std::cout << "  0x" << std::hex << 0x1d00ffff << " -> 0x" << result << std::dec << std::endl;
}

void test_multiple_steps() {
    // Gap = 28800s (8 hours)
    // steps = (28800 - 1440) / 1440 + 1 = 20 (capped at max)
    uint32_t multi = ApplyEDA(0x1d00ffff, 28800, 240);
    uint32_t single = ApplyEDA(0x1d00ffff, 1500, 240);
    TEST(multi > single, "Multiple steps easier than single step");
    std::cout << "  Single: 0x" << std::hex << single << " -> Multi(8h): 0x" << multi << std::dec << std::endl;
}

void test_max_steps_cap() {
    // 24h and 48h should both cap at 20 steps
    uint32_t r24h = ApplyEDA(0x1d00ffff, 86400, 240);
    uint32_t r48h = ApplyEDA(0x1d00ffff, 172800, 240);
    TEST(r24h == r48h, "Max steps cap: 24h == 48h");
    std::cout << "  24h: 0x" << std::hex << r24h << " == 48h: 0x" << r48h << std::dec << std::endl;
}

void test_max_difficulty_bits_cap() {
    // Start with already-easy difficulty + many steps
    uint32_t result = ApplyEDA(0x1f0f0000, 86400, 240);
    TEST(result <= MAX_DIFFICULTY_BITS, "EDA capped at MAX_DIFFICULTY_BITS");
    std::cout << "  Easy start: 0x" << std::hex << 0x1f0f0000 << " -> Capped: 0x" << result << std::dec << std::endl;
}

void test_step_count_calculation() {
    int64_t blockTime = 240;
    int64_t threshold = EDA_THRESHOLD_BLOCKS * blockTime;  // 1440

    // Just past threshold: 1 step
    int64_t gap1 = 1500;
    int steps1 = static_cast<int>(std::min((gap1 - threshold) / (EDA_STEP_BLOCKS * blockTime) + 1, (int64_t)EDA_MAX_STEPS));
    TEST(steps1 == 1, "Step count: gap=1500 -> 1 step");

    // 2 step region
    int64_t gap2 = 3000;
    int steps2 = static_cast<int>(std::min((gap2 - threshold) / (EDA_STEP_BLOCKS * blockTime) + 1, (int64_t)EDA_MAX_STEPS));
    TEST(steps2 == 2, "Step count: gap=3000 -> 2 steps");

    // 5 step region
    int64_t gap5 = 7200;
    int steps5 = static_cast<int>(std::min((gap5 - threshold) / (EDA_STEP_BLOCKS * blockTime) + 1, (int64_t)EDA_MAX_STEPS));
    TEST(steps5 == 5, "Step count: gap=7200 -> 5 steps");

    // Cap at 20
    int64_t gap_huge = 86400;
    int steps_huge = static_cast<int>(std::min((gap_huge - threshold) / (EDA_STEP_BLOCKS * blockTime) + 1, (int64_t)EDA_MAX_STEPS));
    TEST(steps_huge == 20, "Step count: gap=86400 -> capped at 20");
}

void test_realistic_mainnet_scenario() {
    // Mainnet: stuck at 7033, difficulty nBits = 0x1e01fffe, 8 hour gap
    uint32_t mainnetBits = 0x1e01fffe;
    int64_t gap = 28800;  // 8 hours
    uint32_t result = ApplyEDA(mainnetBits, gap, 240);
    TEST(result > mainnetBits, "Mainnet scenario: 8h gap reduces difficulty");
    std::cout << "  Mainnet: 0x" << std::hex << mainnetBits << " -> EDA: 0x" << result << std::dec << std::endl;

    // Verify it's significantly easier
    uint256 normalTarget = CompactToBig(mainnetBits);
    uint256 edaTarget = CompactToBig(result);
    // After 20 steps of 5/4 reduction, target should be ~86x larger
    // Check that EDA target is substantially larger (at least byte-level bigger)
    bool significantly_easier = false;
    for (int i = 31; i >= 0; i--) {
        if (edaTarget.data[i] > normalTarget.data[i]) { significantly_easier = true; break; }
        if (edaTarget.data[i] < normalTarget.data[i]) break;
    }
    TEST(significantly_easier, "Mainnet scenario: EDA target significantly larger");
}

void test_testnet_timing() {
    // Testnet: blockTime=60, threshold = 6*60 = 360s
    uint32_t result = ApplyEDA(0x1f010000, 400, 60);  // gap > 360s
    TEST(result > 0x1f010000, "Testnet: EDA triggers with testnet block time");
}

void test_each_step_increases_target() {
    // Verify monotonic increase through steps
    uint32_t prev = 0x1d00ffff;
    for (int gap = 1500; gap <= 15000; gap += 1440) {
        uint32_t curr = ApplyEDA(0x1d00ffff, gap, 240);
        TEST(curr >= prev, "Monotonic: gap=" + std::to_string(gap) + " >= previous");
        prev = curr;
    }
}

int main() {
    std::cout << "=== Emergency Difficulty Adjustment (EDA) Tests ===" << std::endl;
    std::cout << "  Threshold: " << EDA_THRESHOLD_BLOCKS << " * blockTime" << std::endl;
    std::cout << "  Step size: " << EDA_STEP_BLOCKS << " * blockTime" << std::endl;
    std::cout << "  Reduction: " << EDA_REDUCTION_NUMERATOR << "/" << EDA_REDUCTION_DENOMINATOR << " per step" << std::endl;
    std::cout << "  Max steps: " << EDA_MAX_STEPS << std::endl;
    std::cout << std::endl;

    test_compact_roundtrip();
    test_no_trigger_within_threshold();
    test_no_trigger_at_exact_threshold();
    test_single_step();
    test_multiple_steps();
    test_max_steps_cap();
    test_max_difficulty_bits_cap();
    test_step_count_calculation();
    test_realistic_mainnet_scenario();
    test_testnet_timing();
    test_each_step_increases_target();

    std::cout << std::endl;
    std::cout << "=== Results: " << tests_passed << " passed, " << tests_failed << " failed ===" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
