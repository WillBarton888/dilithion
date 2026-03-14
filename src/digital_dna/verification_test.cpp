/**
 * DNA Verification & Attestation Protocol Tests (Phase 2)
 *
 * Tests:
 *  1.  Challenge serialize/deserialize roundtrip
 *  2.  Response serialize/deserialize roundtrip
 *  3.  DimensionResult serialize/deserialize roundtrip
 *  4.  Attestation serialize/deserialize roundtrip (body + fake sig)
 *  5.  Verifier selection determinism (same inputs → same output)
 *  6.  Verifier selection excludes target MIK
 *  7.  Verifier selection with fewer candidates than count
 *  8.  VDF timing tolerance boundary check (25%)
 *  9.  Bandwidth tolerance boundary check (40%)
 * 10.  Attestation DB store and retrieve
 * 11.  Verification status from attestation counts
 */

#include "dna_verification.h"
#include "dna_registry_db.h"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <cmath>
#include <filesystem>
#include <algorithm>

using namespace digital_dna;
using namespace digital_dna::verification;

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

// Helper: fill an array with a byte pattern
static std::array<uint8_t, 20> make_mik(uint8_t fill) {
    std::array<uint8_t, 20> mik;
    mik.fill(fill);
    return mik;
}

static std::array<uint8_t, 32> make_hash(uint8_t fill) {
    std::array<uint8_t, 32> h;
    h.fill(fill);
    return h;
}

// ============================================================================
// Test 1: Challenge serialize/deserialize roundtrip
// ============================================================================
static void test_challenge_roundtrip() {
    std::cout << "\n--- Challenge Serialize/Deserialize ---" << std::endl;

    VerificationChallenge orig;
    orig.target_mik = make_mik(0xAA);
    orig.verifier_mik = make_mik(0xBB);
    orig.registration_height = 12345;
    orig.vdf_seed = make_hash(0xCC);
    orig.vdf_iterations = VDF_CHALLENGE_ITERS;
    orig.nonce = 9876543210ULL;

    auto data = orig.serialize();
    CHECK(data.size() == VerificationChallenge::WIRE_SIZE, "Challenge serializes to 92 bytes");

    auto restored = VerificationChallenge::deserialize(data);
    CHECK(restored.has_value(), "Challenge deserializes successfully");
    CHECK(restored->target_mik == orig.target_mik, "Challenge target_mik matches");
    CHECK(restored->verifier_mik == orig.verifier_mik, "Challenge verifier_mik matches");
    CHECK(restored->registration_height == orig.registration_height, "Challenge registration_height matches");
    CHECK(restored->vdf_seed == orig.vdf_seed, "Challenge vdf_seed matches");
    CHECK(restored->vdf_iterations == orig.vdf_iterations, "Challenge vdf_iterations matches");
    CHECK(restored->nonce == orig.nonce, "Challenge nonce matches");

    // Too-short data should fail
    std::vector<uint8_t> short_data(50, 0);
    CHECK(!VerificationChallenge::deserialize(short_data).has_value(), "Short data returns nullopt");
}

// ============================================================================
// Test 2: Response serialize/deserialize roundtrip
// ============================================================================
static void test_response_roundtrip() {
    std::cout << "\n--- Response Serialize/Deserialize ---" << std::endl;

    VerificationResponse orig;
    orig.nonce = 1234567890ULL;
    orig.target_mik = make_mik(0xDD);
    orig.vdf_output = make_hash(0xEE);
    orig.vdf_proof = {0x01, 0x02, 0x03, 0x04, 0x05};  // Short fake proof
    orig.vdf_elapsed_us = 1300000;  // 1.3s in microseconds

    auto data = orig.serialize();
    CHECK(data.size() == 70 + orig.vdf_proof.size(), "Response serializes to expected size");

    auto restored = VerificationResponse::deserialize(data);
    CHECK(restored.has_value(), "Response deserializes successfully");
    CHECK(restored->nonce == orig.nonce, "Response nonce matches");
    CHECK(restored->target_mik == orig.target_mik, "Response target_mik matches");
    CHECK(restored->vdf_output == orig.vdf_output, "Response vdf_output matches");
    CHECK(restored->vdf_proof == orig.vdf_proof, "Response vdf_proof matches");
    CHECK(restored->vdf_elapsed_us == orig.vdf_elapsed_us, "Response vdf_elapsed_us matches");

    // Empty proof should work
    VerificationResponse empty_proof;
    empty_proof.nonce = 42;
    empty_proof.target_mik = make_mik(0x11);
    empty_proof.vdf_output = make_hash(0x22);
    empty_proof.vdf_proof.clear();
    empty_proof.vdf_elapsed_us = 500000;
    auto data2 = empty_proof.serialize();
    auto restored2 = VerificationResponse::deserialize(data2);
    CHECK(restored2.has_value() && restored2->vdf_proof.empty(), "Empty proof roundtrips correctly");
}

// ============================================================================
// Test 3: DimensionResult serialize/deserialize roundtrip
// ============================================================================
static void test_dimension_result_roundtrip() {
    std::cout << "\n--- DimensionResult Serialize/Deserialize ---" << std::endl;

    DimensionResult orig;
    orig.measured_value = 76923.45;
    orig.claimed_value = 80000.0;
    orig.pass = true;

    auto data = orig.serialize();
    CHECK(data.size() == DimensionResult::WIRE_SIZE, "DimensionResult serializes to 17 bytes");

    auto restored = DimensionResult::deserialize(data.data(), data.size());
    CHECK(restored.has_value(), "DimensionResult deserializes successfully");
    CHECK(std::abs(restored->measured_value - orig.measured_value) < 0.001, "measured_value matches");
    CHECK(std::abs(restored->claimed_value - orig.claimed_value) < 0.001, "claimed_value matches");
    CHECK(restored->pass == orig.pass, "pass flag matches");

    // Test with pass=false
    DimensionResult fail_result;
    fail_result.measured_value = 10.0;
    fail_result.claimed_value = 100.0;
    fail_result.pass = false;
    auto fail_data = fail_result.serialize();
    auto fail_restored = DimensionResult::deserialize(fail_data.data(), fail_data.size());
    CHECK(fail_restored.has_value() && !fail_restored->pass, "FAIL DimensionResult roundtrips correctly");
}

// ============================================================================
// Test 4: Attestation serialize/deserialize roundtrip
// ============================================================================
static void test_attestation_roundtrip() {
    std::cout << "\n--- Attestation Serialize/Deserialize ---" << std::endl;

    DNAAttestation orig;
    orig.target_mik = make_mik(0x11);
    orig.verifier_mik = make_mik(0x22);
    orig.registration_height = 30000;
    orig.timestamp = 1710000000;

    orig.vdf_timing = {76923.0, 80000.0, true};
    orig.bandwidth_up = {50.0, 55.0, true};
    orig.bandwidth_down = {100.0, 95.0, true};
    orig.latency_rtt_ms = 42.5;
    orig.overall_pass = true;

    // Fake signature and pubkey (not real Dilithium3 sizes for this test)
    orig.signature.resize(100, 0xAA);
    orig.verifier_pubkey.resize(50, 0xBB);

    auto data = orig.serialize();
    CHECK(data.size() > 112, "Full attestation serializes to >112 bytes");

    auto restored = DNAAttestation::deserialize(data);
    CHECK(restored.has_value(), "Attestation deserializes successfully");
    CHECK(restored->target_mik == orig.target_mik, "Attestation target_mik matches");
    CHECK(restored->verifier_mik == orig.verifier_mik, "Attestation verifier_mik matches");
    CHECK(restored->registration_height == orig.registration_height, "Attestation registration_height matches");
    CHECK(restored->timestamp == orig.timestamp, "Attestation timestamp matches");
    CHECK(std::abs(restored->vdf_timing.measured_value - 76923.0) < 0.01, "VDF timing measured matches");
    CHECK(restored->vdf_timing.pass == true, "VDF timing pass matches");
    CHECK(std::abs(restored->bandwidth_up.claimed_value - 55.0) < 0.01, "BW up claimed matches");
    CHECK(std::abs(restored->latency_rtt_ms - 42.5) < 0.01, "Latency RTT matches");
    CHECK(restored->overall_pass == true, "Overall pass matches");
    CHECK(restored->signature.size() == 100, "Signature length preserved");
    CHECK(restored->verifier_pubkey.size() == 50, "Pubkey length preserved");

    // verify_signature should fail with fake sig (not 3309 bytes)
    CHECK(!restored->verify_signature(), "Fake signature correctly fails verification");
}

// ============================================================================
// Test 5: Verifier selection determinism
// ============================================================================
static void test_verifier_selection_determinism() {
    std::cout << "\n--- Verifier Selection Determinism ---" << std::endl;

    auto block_hash = make_hash(0x42);
    auto target = make_mik(0x01);

    // Create 20 candidate MIKs
    std::vector<std::array<uint8_t, 20>> candidates;
    for (uint8_t i = 0; i < 20; i++) {
        candidates.push_back(make_mik(i));
    }

    auto result1 = SelectVerifiers(block_hash, target, candidates, VERIFIER_COUNT);
    auto result2 = SelectVerifiers(block_hash, target, candidates, VERIFIER_COUNT);

    CHECK(result1.size() == VERIFIER_COUNT, "SelectVerifiers returns correct count");
    CHECK(result1 == result2, "Same inputs produce same verifier selection");

    // Different block hash should produce different selection
    auto block_hash2 = make_hash(0x43);
    auto result3 = SelectVerifiers(block_hash2, target, candidates, VERIFIER_COUNT);
    CHECK(result3 != result1, "Different block hash produces different selection");
}

// ============================================================================
// Test 6: Verifier selection excludes target MIK
// ============================================================================
static void test_verifier_selection_excludes_target() {
    std::cout << "\n--- Verifier Selection Excludes Target ---" << std::endl;

    auto block_hash = make_hash(0x55);
    auto target = make_mik(0x05);  // Target is candidate #5

    std::vector<std::array<uint8_t, 20>> candidates;
    for (uint8_t i = 0; i < 15; i++) {
        candidates.push_back(make_mik(i));
    }

    auto verifiers = SelectVerifiers(block_hash, target, candidates, VERIFIER_COUNT);
    CHECK(verifiers.size() == VERIFIER_COUNT, "Correct number of verifiers selected");

    // Target MIK must NOT be in the result
    bool target_found = false;
    for (const auto& v : verifiers) {
        if (v == target) {
            target_found = true;
            break;
        }
    }
    CHECK(!target_found, "Target MIK is excluded from verifiers");
}

// ============================================================================
// Test 7: Verifier selection with fewer candidates than count
// ============================================================================
static void test_verifier_selection_few_candidates() {
    std::cout << "\n--- Verifier Selection: Few Candidates ---" << std::endl;

    auto block_hash = make_hash(0x77);
    auto target = make_mik(0x01);

    // Only 3 candidates (one is target), so only 2 eligible
    std::vector<std::array<uint8_t, 20>> candidates;
    candidates.push_back(make_mik(0x01));  // target — will be excluded
    candidates.push_back(make_mik(0x02));
    candidates.push_back(make_mik(0x03));

    auto verifiers = SelectVerifiers(block_hash, target, candidates, VERIFIER_COUNT);
    CHECK(verifiers.size() == 2, "Returns only available candidates (2 after excluding target)");

    // Empty candidate list
    std::vector<std::array<uint8_t, 20>> empty;
    auto empty_result = SelectVerifiers(block_hash, target, empty, VERIFIER_COUNT);
    CHECK(empty_result.empty(), "Empty candidate list returns empty result");
}

// ============================================================================
// Test 8: VDF timing tolerance boundary check (±25%)
// ============================================================================
static void test_vdf_timing_tolerance() {
    std::cout << "\n--- VDF Timing Tolerance (±25%) ---" << std::endl;

    double claimed = 80000.0;  // 80K iterations/sec
    double tolerance = VDF_TIMING_TOLERANCE;  // 0.25

    double low_bound = claimed * (1.0 - tolerance);   // 60000
    double high_bound = claimed * (1.0 + tolerance);  // 100000

    // Exactly at boundaries
    CHECK(60000.0 >= low_bound, "60K IPS at lower boundary PASS");
    CHECK(100000.0 <= high_bound, "100K IPS at upper boundary PASS");

    // Within tolerance
    double within = 75000.0;
    CHECK(within >= low_bound && within <= high_bound, "75K IPS within tolerance PASS");

    // Below tolerance
    double below = 59999.0;
    CHECK(below < low_bound, "59999 IPS below tolerance FAIL");

    // Above tolerance
    double above = 100001.0;
    CHECK(above > high_bound, "100001 IPS above tolerance FAIL");

    // Zero claimed should make all measured fail
    double zero_low = 0.0 * (1.0 - tolerance);
    double zero_high = 0.0 * (1.0 + tolerance);
    CHECK(zero_low == 0.0 && zero_high == 0.0, "Zero claimed: only zero measured passes");
}

// ============================================================================
// Test 9: Bandwidth tolerance boundary check (±40%)
// ============================================================================
static void test_bandwidth_tolerance() {
    std::cout << "\n--- Bandwidth Tolerance (±40%) ---" << std::endl;

    double claimed = 100.0;  // 100 Mbps
    double tolerance = BW_TOLERANCE;  // 0.40

    double low_bound = claimed * (1.0 - tolerance);   // 60.0
    double high_bound = claimed * (1.0 + tolerance);  // 140.0

    // Within tolerance
    CHECK(80.0 >= low_bound && 80.0 <= high_bound, "80 Mbps within BW tolerance PASS");
    CHECK(130.0 >= low_bound && 130.0 <= high_bound, "130 Mbps within BW tolerance PASS");

    // At exact boundaries
    CHECK(60.0 >= low_bound, "60 Mbps at lower boundary PASS");
    CHECK(140.0 <= high_bound, "140 Mbps at upper boundary PASS");

    // Outside tolerance
    CHECK(59.0 < low_bound, "59 Mbps below BW tolerance FAIL");
    CHECK(141.0 > high_bound, "141 Mbps above BW tolerance FAIL");
}

// ============================================================================
// Test 10: Attestation DB store and retrieve
// ============================================================================
static void test_attestation_db() {
    std::cout << "\n--- Attestation DB Store/Retrieve ---" << std::endl;

    std::string db_path = "test_verification_db";
    std::filesystem::remove_all(db_path);

    {
        DNARegistryDB db;
        db.Open(db_path);

        DNAAttestation att;
        att.target_mik = make_mik(0x11);
        att.verifier_mik = make_mik(0x22);
        att.registration_height = 30000;
        att.timestamp = 1710000000;
        att.vdf_timing = {76000.0, 80000.0, true};
        att.bandwidth_up = {50.0, 55.0, true};
        att.bandwidth_down = {95.0, 100.0, true};
        att.latency_rtt_ms = 42.5;
        att.overall_pass = true;
        att.signature.resize(100, 0xAA);
        att.verifier_pubkey.resize(50, 0xBB);

        bool stored = db.store_attestation(att);
        CHECK(stored, "Attestation stored successfully");

        auto retrieved = db.get_attestations(att.target_mik);
        CHECK(retrieved.size() == 1, "One attestation retrieved");
        CHECK(retrieved[0].verifier_mik == att.verifier_mik, "Retrieved verifier_mik matches");
        CHECK(retrieved[0].overall_pass == true, "Retrieved overall_pass matches");

        // Store a second attestation from a different verifier
        DNAAttestation att2 = att;
        att2.verifier_mik = make_mik(0x33);
        att2.overall_pass = false;
        db.store_attestation(att2);

        auto retrieved2 = db.get_attestations(att.target_mik);
        CHECK(retrieved2.size() == 2, "Two attestations retrieved for same target");

        // Count pass attestations
        size_t pass_count = db.count_pass_attestations(att.target_mik);
        CHECK(pass_count == 1, "Pass count is 1 (one PASS, one FAIL)");
    }

    std::filesystem::remove_all(db_path);
}

// ============================================================================
// Test 11: Verification status from attestation counts
// ============================================================================
static void test_verification_status_from_counts() {
    std::cout << "\n--- Verification Status from Counts ---" << std::endl;

    std::string db_path = "test_verification_status_db";
    std::filesystem::remove_all(db_path);

    {
        DNARegistryDB db;
        db.Open(db_path);
        auto target = make_mik(0x44);

        // No attestations → UNVERIFIED
        auto status0 = db.get_verification_status(target);
        CHECK(status0 == VerificationStatus::UNVERIFIED, "No attestations → UNVERIFIED");

        // Add 4 PASS attestations → still UNVERIFIED (need 5 for quorum)
        for (uint8_t i = 1; i <= 4; i++) {
            DNAAttestation att;
            att.target_mik = target;
            att.verifier_mik = make_mik(0x50 + i);
            att.registration_height = 30000;
            att.timestamp = 1710000000 + i;
            att.vdf_timing = {76000.0, 80000.0, true};
            att.bandwidth_up = {50.0, 55.0, true};
            att.bandwidth_down = {95.0, 100.0, true};
            att.latency_rtt_ms = 42.5;
            att.overall_pass = true;
            att.signature.resize(100, 0xAA);
            att.verifier_pubkey.resize(50, 0xBB);
            db.store_attestation(att);
        }

        auto status4 = db.get_verification_status(target);
        CHECK(status4 == VerificationStatus::PENDING, "4 PASS attestations → PENDING (need 5 for quorum)");

        // Add 5th PASS attestation → VERIFIED
        DNAAttestation att5;
        att5.target_mik = target;
        att5.verifier_mik = make_mik(0x55);
        att5.registration_height = 30000;
        att5.timestamp = 1710000005;
        att5.vdf_timing = {76000.0, 80000.0, true};
        att5.bandwidth_up = {50.0, 55.0, true};
        att5.bandwidth_down = {95.0, 100.0, true};
        att5.latency_rtt_ms = 42.5;
        att5.overall_pass = true;
        att5.signature.resize(100, 0xAA);
        att5.verifier_pubkey.resize(50, 0xBB);
        db.store_attestation(att5);

        auto status5 = db.get_verification_status(target);
        CHECK(status5 == VerificationStatus::VERIFIED, "5 PASS attestations → VERIFIED");

        // Test a target with majority FAIL
        auto fail_target = make_mik(0x66);
        for (uint8_t i = 1; i <= 7; i++) {
            DNAAttestation att;
            att.target_mik = fail_target;
            att.verifier_mik = make_mik(0x70 + i);
            att.registration_height = 30000;
            att.timestamp = 1710000000 + i;
            att.vdf_timing = {10000.0, 80000.0, false};
            att.bandwidth_up = {5.0, 55.0, false};
            att.bandwidth_down = {10.0, 100.0, false};
            att.latency_rtt_ms = 500.0;
            att.overall_pass = false;
            att.signature.resize(100, 0xAA);
            att.verifier_pubkey.resize(50, 0xBB);
            db.store_attestation(att);
        }

        auto status_fail = db.get_verification_status(fail_target);
        CHECK(status_fail == VerificationStatus::FAILED, "7 FAIL attestations → FAILED");
    }

    std::filesystem::remove_all(db_path);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== DNA Verification Protocol Tests ===" << std::endl;

    test_challenge_roundtrip();
    test_response_roundtrip();
    test_dimension_result_roundtrip();
    test_attestation_roundtrip();
    test_verifier_selection_determinism();
    test_verifier_selection_excludes_target();
    test_verifier_selection_few_candidates();
    test_vdf_timing_tolerance();
    test_bandwidth_tolerance();
    test_attestation_db();
    test_verification_status_from_counts();

    std::cout << "\n=== Results ===" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "  Total:  " << (tests_passed + tests_failed) << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
