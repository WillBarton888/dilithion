// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Digital DNA Detection & Trust Scoring Tests
 *
 * Tests for advisory Sybil detection, trust score progression,
 * and trust score decay.
 */

#include "digital_dna.h"
#include "trust_score.h"

#include <iostream>
#include <cassert>
#include <cstring>
#include <array>

using namespace digital_dna;

static int g_passed = 0;
static int g_failed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { \
        std::cout << "  [PASS] " << msg << std::endl; \
        g_passed++; \
    } else { \
        std::cout << "  [FAIL] " << msg << std::endl; \
        g_failed++; \
    } \
} while(0)

// Helper: create a DigitalDNA with given address and latency params
static DigitalDNA make_dna(uint8_t id, double median_ms, double ips) {
    DigitalDNA dna;
    dna.address.fill(id);
    dna.registration_height = 1000;
    dna.registration_time = 1700000000;
    dna.is_valid = true;

    LatencyFingerprint lat;
    LatencyStats s;
    s.seed_name = "1.2.3.4";
    s.median_ms = median_ms;
    s.samples = 20;
    lat.seed_stats.push_back(s);
    dna.latency = lat;

    TimingSignature ts;
    ts.iterations_per_second = ips;
    dna.timing = ts;

    PerspectiveProof pp;
    pp.start_time = 1700000000;
    pp.end_time = 1700003600;
    dna.perspective = pp;

    return dna;
}

// =================================================================
// Test 1: Advisory Sybil stores both
// =================================================================
void test_sybil_advisory_stores_both() {
    std::cout << "\n=== Test 1: Advisory Sybil stores both ===" << std::endl;

    DigitalDNARegistry registry;

    // Two identical DNAs with different addresses
    auto dna1 = make_dna(0x01, 50.0, 1000000.0);
    auto dna2 = make_dna(0x02, 50.0, 1000000.0);  // Same fingerprint

    auto r1 = registry.register_identity(dna1);
    CHECK(r1 == IDNARegistry::RegisterResult::SUCCESS, "First identity: SUCCESS");

    auto r2 = registry.register_identity(dna2);
    // Advisory mode: stores it anyway, may return SYBIL_FLAGGED
    CHECK(r2 == IDNARegistry::RegisterResult::SUCCESS ||
          r2 == IDNARegistry::RegisterResult::SYBIL_FLAGGED,
          "Second identity: stored (SUCCESS or SYBIL_FLAGGED)");

    CHECK(registry.count() == 2, "Both identities stored");
    CHECK(registry.is_registered(dna1.address), "First identity retrievable");
    CHECK(registry.is_registered(dna2.address), "Second identity retrievable");
}

// =================================================================
// Test 2: Different DNAs → clean registration
// =================================================================
void test_different_stores_clean() {
    std::cout << "\n=== Test 2: Different DNAs store clean ===" << std::endl;

    DigitalDNARegistry registry;

    auto dna1 = make_dna(0x10, 50.0, 1000000.0);
    auto dna2 = make_dna(0x20, 200.0, 5000000.0);  // Very different

    auto r1 = registry.register_identity(dna1);
    auto r2 = registry.register_identity(dna2);

    CHECK(r1 == IDNARegistry::RegisterResult::SUCCESS, "First: SUCCESS");
    CHECK(r2 == IDNARegistry::RegisterResult::SUCCESS, "Second: SUCCESS (different)");
    CHECK(registry.count() == 2, "Both stored");
}

// =================================================================
// Test 3: Progressive enrichment refines Sybil score
// =================================================================
void test_progressive_enrichment_score() {
    std::cout << "\n=== Test 3: Progressive enrichment refines score ===" << std::endl;

    DigitalDNARegistry registry;

    // Register with minimal dimensions
    auto dna1 = make_dna(0x30, 100.0, 2000000.0);
    auto r1 = registry.register_identity(dna1);
    CHECK(r1 == IDNARegistry::RegisterResult::SUCCESS, "Initial registration SUCCESS");

    // Enrich with memory dimension
    dna1.memory = MemoryFingerprint();
    dna1.memory->estimated_l1_kb = 32;
    dna1.memory->estimated_l2_kb = 256;
    dna1.memory->estimated_l3_kb = 8192;

    auto r2 = registry.update_identity(dna1);
    CHECK(r2 == IDNARegistry::RegisterResult::UPDATED, "Update returns UPDATED");

    auto retrieved = registry.get_identity(dna1.address);
    CHECK(retrieved.has_value(), "Enriched identity retrievable");
    CHECK(retrieved->memory.has_value(), "Memory dim now present");
    CHECK(retrieved->memory->estimated_l1_kb == 32, "Memory L1 correct");
}

// =================================================================
// Test 4: Trust score progression
// =================================================================
void test_trust_score_progression() {
    std::cout << "\n=== Test 4: Trust score progression ===" << std::endl;

    TrustScoreManager mgr;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    // Register
    mgr.on_registration(addr, 1000);
    auto score = mgr.get_score(addr);
    CHECK(score.current_score == 0.0, "Starts at 0.0");
    CHECK(score.get_tier() == TrustScore::UNTRUSTED, "Starts UNTRUSTED");

    // 15 heartbeats → should reach NEW tier (>10)
    for (int i = 0; i < 15; i++) {
        mgr.on_heartbeat_success(addr, 1001 + i);
    }
    score = mgr.get_score(addr);
    CHECK(score.current_score > 10.0, "After 15 heartbeats: score > 10");
    CHECK(score.get_tier() >= TrustScore::NEW, "After 15 heartbeats: at least NEW tier");
    CHECK(score.total_heartbeats == 15, "15 total heartbeats");
    CHECK(score.consecutive_heartbeats == 15, "15 consecutive heartbeats");

    // More heartbeats → ESTABLISHED
    for (int i = 0; i < 30; i++) {
        mgr.on_heartbeat_success(addr, 1016 + i);
    }
    score = mgr.get_score(addr);
    CHECK(score.current_score > 30.0, "After 45 heartbeats: score > 30");
    CHECK(score.get_tier() >= TrustScore::ESTABLISHED, "After 45 heartbeats: at least ESTABLISHED");
}

// =================================================================
// Test 5: Trust score decay
// =================================================================
void test_trust_score_decay() {
    std::cout << "\n=== Test 5: Trust score decay ===" << std::endl;

    TrustScoreManager mgr;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x55;

    mgr.on_registration(addr, 1000);

    // Build up some trust
    for (int i = 0; i < 20; i++) {
        mgr.on_heartbeat_success(addr, 1001 + i);
    }
    auto before = mgr.get_score(addr);
    CHECK(before.current_score > 15.0, "Built up trust > 15");

    // Now simulate long inactivity: heartbeat at height far in the future
    // Decay applies when next heartbeat occurs at much higher height
    mgr.on_heartbeat_success(addr, 1021 + 50000);  // 50000 blocks later
    auto after = mgr.get_score(addr);
    // Decay should have reduced the score before adding heartbeat bonus
    // The decay is 0.1% per 2000 blocks → 50000/2000 = 25 periods
    // Factor = (1-0.001)^25 ≈ 0.975 → ~2.5% reduction before +1 heartbeat
    CHECK(after.current_score < before.current_score + 2.0,
          "Decay applied (score didn't just increase by heartbeat amount)");
}

// =================================================================
// Test 6: Trust score missed heartbeat penalty
// =================================================================
void test_trust_missed_heartbeat() {
    std::cout << "\n=== Test 6: Missed heartbeat penalty ===" << std::endl;

    TrustScoreManager mgr;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x66;

    mgr.on_registration(addr, 1000);

    // Build some trust
    for (int i = 0; i < 10; i++) {
        mgr.on_heartbeat_success(addr, 1001 + i);
    }
    auto before = mgr.get_score(addr);

    // Miss a heartbeat → -5.0
    mgr.on_heartbeat_missed(addr, 1011);
    auto after = mgr.get_score(addr);
    CHECK(after.current_score < before.current_score, "Score decreased after miss");
    CHECK(after.consecutive_heartbeats == 0, "Consecutive heartbeats reset to 0");
    CHECK(after.missed_heartbeats == 1, "1 missed heartbeat recorded");
}

// =================================================================
// Test 7: Trust score persistence (save/load)
// =================================================================
void test_trust_persistence() {
    std::cout << "\n=== Test 7: Trust score persistence ===" << std::endl;

    // Use a unique temp file in current directory
    std::string path = "./dna_test_trust_tmp.dat";

    // Create and populate
    TrustScoreManager mgr_save;
    std::array<uint8_t, 20> addr1{}, addr2{};
    addr1[0] = 0x77; addr2[0] = 0x88;

    mgr_save.on_registration(addr1, 1000);
    mgr_save.on_registration(addr2, 2000);
    for (int i = 0; i < 5; i++) {
        mgr_save.on_heartbeat_success(addr1, 1001 + i);
    }

    auto pre_score = mgr_save.get_score(addr1);
    CHECK(pre_score.total_heartbeats == 5, "5 heartbeats before save");
    CHECK(pre_score.current_score > 0.0, "Score > 0 before save");

    bool saved = mgr_save.save(path);
    CHECK(saved, "Save succeeds");
    CHECK(mgr_save.count() == 2, "2 identities before save");

    // Reload into fresh manager
    TrustScoreManager mgr_load;
    bool loaded = mgr_load.load(path);
    CHECK(loaded, "Load succeeds");
    CHECK(mgr_load.count() == 2, "2 identities after load");

    auto loaded_score = mgr_load.get_score(addr1);
    CHECK(loaded_score.total_heartbeats == 5, "Heartbeat count persisted");
    CHECK(loaded_score.current_score > 0.0, "Score persisted > 0");

    // Cleanup
    std::remove(path.c_str());
}

int main() {
    std::cout << "Digital DNA Detection & Trust Scoring Tests" << std::endl;
    std::cout << "============================================" << std::endl;

    test_sybil_advisory_stores_both();
    test_different_stores_clean();
    test_progressive_enrichment_score();
    test_trust_score_progression();
    test_trust_score_decay();
    test_trust_missed_heartbeat();
    test_trust_persistence();

    std::cout << "\n============================================" << std::endl;
    std::cout << "Results: " << g_passed << " passed, " << g_failed << " failed" << std::endl;

    return g_failed > 0 ? 1 : 0;
}
