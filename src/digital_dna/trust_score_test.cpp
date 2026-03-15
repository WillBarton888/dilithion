/**
 * TrustScore Serialization Tests
 *
 * Tests:
 *  1. Basic 41-byte roundtrip (pre-Phase 5)
 *  2. Full 53-byte roundtrip (with Phase 5 fields)
 *  3. Backward compatibility (41-byte data loads, Phase 5 fields default to 0)
 *  4. Phase 5 field values survive roundtrip
 *  5. is_stabilizing() works after deserialize
 */

#include "trust_score.h"
#include <iostream>
#include <cstring>

using namespace digital_dna;

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { std::cout << "  [PASS] " << msg << std::endl; passed++; } \
    else { std::cout << "  [FAIL] " << msg << std::endl; failed++; } \
} while(0)

static void test_basic_roundtrip() {
    std::cout << "\n--- Test 1: Basic field roundtrip ---\n";
    TrustScore ts;
    ts.current_score = 42.5;
    ts.lifetime_earned = 100.0;
    ts.registration_height = 1000;
    ts.last_heartbeat_height = 2000;
    ts.consecutive_heartbeats = 50;
    ts.total_heartbeats = 200;
    ts.missed_heartbeats = 5;
    ts.blocks_relayed = 300;
    ts.challenge_pending = true;

    auto data = ts.serialize();
    CHECK(data.size() == 53, "Serialized size is 53 bytes (41 + 12 Phase 5)");

    auto restored = TrustScore::deserialize(data);
    CHECK(restored.current_score == 42.5, "current_score preserved");
    CHECK(restored.lifetime_earned == 100.0, "lifetime_earned preserved");
    CHECK(restored.registration_height == 1000, "registration_height preserved");
    CHECK(restored.last_heartbeat_height == 2000, "last_heartbeat_height preserved");
    CHECK(restored.consecutive_heartbeats == 50, "consecutive_heartbeats preserved");
    CHECK(restored.total_heartbeats == 200, "total_heartbeats preserved");
    CHECK(restored.missed_heartbeats == 5, "missed_heartbeats preserved");
    CHECK(restored.blocks_relayed == 300, "blocks_relayed preserved");
    CHECK(restored.challenge_pending == true, "challenge_pending preserved");
}

static void test_phase5_roundtrip() {
    std::cout << "\n--- Test 2: Phase 5 fields roundtrip ---\n";
    TrustScore ts;
    ts.current_score = 55.0;
    ts.registration_height = 500;
    ts.last_dna_change_height = 9500;
    ts.dna_change_count = 3;
    ts.dna_changes_recent = 2;

    auto data = ts.serialize();
    CHECK(data.size() == 53, "Serialized size is 53 bytes");

    auto restored = TrustScore::deserialize(data);
    CHECK(restored.last_dna_change_height == 9500, "last_dna_change_height preserved");
    CHECK(restored.dna_change_count == 3, "dna_change_count preserved");
    CHECK(restored.dna_changes_recent == 2, "dna_changes_recent preserved");
}

static void test_backward_compat() {
    std::cout << "\n--- Test 3: Backward compatibility (41-byte old data) ---\n";
    TrustScore ts;
    ts.current_score = 10.0;
    ts.registration_height = 100;
    ts.last_dna_change_height = 999;  // Will be lost in 41-byte data

    auto data = ts.serialize();
    // Truncate to 41 bytes (simulating old format)
    data.resize(41);

    auto restored = TrustScore::deserialize(data);
    CHECK(restored.current_score == 10.0, "current_score loads from old data");
    CHECK(restored.registration_height == 100, "registration_height loads from old data");
    CHECK(restored.last_dna_change_height == 0, "Phase 5 field defaults to 0 from old data");
    CHECK(restored.dna_change_count == 0, "dna_change_count defaults to 0");
    CHECK(restored.dna_changes_recent == 0, "dna_changes_recent defaults to 0");
}

static void test_stabilizing_after_deserialize() {
    std::cout << "\n--- Test 4: is_stabilizing() works after deserialize ---\n";
    TrustScore ts;
    ts.last_dna_change_height = 10000;

    auto data = ts.serialize();
    auto restored = TrustScore::deserialize(data);

    CHECK(restored.is_stabilizing(10200), "is_stabilizing at height 10200 (within 500 blocks)");
    CHECK(!restored.is_stabilizing(10600), "NOT stabilizing at height 10600 (past 500 blocks)");

    // Old data: stabilization should be inactive
    data.resize(41);
    auto old_restored = TrustScore::deserialize(data);
    CHECK(!old_restored.is_stabilizing(10200), "Old data: NOT stabilizing (field defaults to 0)");
}

static void test_rapid_rotation_after_deserialize() {
    std::cout << "\n--- Test 5: Rapid rotation tracking survives restart ---\n";
    TrustScore ts;
    ts.last_dna_change_height = 8000;
    ts.dna_change_count = 7;
    ts.dna_changes_recent = 4;  // Above RAPID_ROTATION_THRESHOLD (3)

    auto data = ts.serialize();
    auto restored = TrustScore::deserialize(data);

    CHECK(restored.dna_changes_recent >= TrustScore::RAPID_ROTATION_THRESHOLD,
          "Rapid rotation flag persists (dna_changes_recent >= threshold)");
    CHECK(restored.dna_change_count == 7, "Lifetime change count persists");
}

int main() {
    std::cout << "=== TrustScore Serialization Tests ===" << std::endl;

    test_basic_roundtrip();
    test_phase5_roundtrip();
    test_backward_compat();
    test_stabilizing_after_deserialize();
    test_rapid_rotation_after_deserialize();

    std::cout << "\n=== Results ===" << std::endl;
    std::cout << "  Passed: " << passed << std::endl;
    std::cout << "  Failed: " << failed << std::endl;
    std::cout << "  Total:  " << (passed + failed) << std::endl;

    return failed > 0 ? 1 : 0;
}
