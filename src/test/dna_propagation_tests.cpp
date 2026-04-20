// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * DNA Propagation Phase 1 — Unit Tests
 *
 * Covers:
 *   1. IDNARegistry::append_sample() — accept, archive, dim-loss reject
 *   2. History 100-sample cap enforced on DNARegistryDB
 *   3. DNASampleRateLimiter — per-peer bucket, per-MIK global, per-MIK-per-peer
 *
 * Wire-level receiver handler rewrite (which uses both of the above plus
 * `g_mik_peer_map` plausibility) is exercised in-process when the node binary
 * runs; end-to-end two-node scenarios are deferred to manual deploy testing.
 */

#include <digital_dna/digital_dna.h>
#include <digital_dna/dna_registry_db.h>
#include <digital_dna/sample_rate_limiter.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#define RESET_  "\033[0m"
#define GREEN_  "\033[32m"
#define RED_    "\033[31m"
#define YELLOW_ "\033[33m"
#define BLUE_   "\033[34m"

int g_tests_passed = 0;
int g_tests_failed = 0;

#define TEST(name) \
    void test_##name(); \
    void test_##name##_wrapper() { \
        std::cout << BLUE_ << "[TEST] " << #name << RESET_ << std::endl; \
        try { \
            test_##name(); \
            std::cout << GREEN_ << "  PASSED" << RESET_ << std::endl; \
            g_tests_passed++; \
        } catch (const std::exception& e) { \
            std::cout << RED_ << "  FAILED: " << e.what() << RESET_ << std::endl; \
            g_tests_failed++; \
        } catch (...) { \
            std::cout << RED_ << "  FAILED: Unknown exception" << RESET_ << std::endl; \
            g_tests_failed++; \
        } \
    } \
    void test_##name()

#define ASSERT(cond, msg) \
    if (!(cond)) throw std::runtime_error(msg);

#define ASSERT_EQ(a, b, msg) \
    if ((a) != (b)) throw std::runtime_error(std::string(msg) + " (mismatch)");

namespace fs = std::filesystem;
using digital_dna::DigitalDNA;
using digital_dna::DNARegistryDB;
using digital_dna::DNASampleRateLimiter;
using digital_dna::IDNARegistry;

// ---------------------------------------------------------------------------
// Helpers: fabricate a minimally-valid DigitalDNA with selectable dimensions.
// ---------------------------------------------------------------------------

static DigitalDNA make_dna(uint8_t addr_seed,
                           bool with_memory = false,
                           bool with_thermal = false,
                           bool with_drift = false,
                           bool with_bandwidth = false,
                           bool with_behavioral = false,
                           uint32_t reg_height = 1)
{
    DigitalDNA d;
    for (size_t i = 0; i < d.address.size(); ++i) d.address[i] = static_cast<uint8_t>(addr_seed + i);
    d.mik_identity = d.address;  // use same bytes so MIK key path runs
    d.is_valid = true;
    d.registration_height = reg_height;
    d.registration_time = 1700000000;

    // Core dims: ensure latency + timing populate (defaults are already-present
    // objects; we just set identifying values).
    d.timing.iterations_per_second = 100000.0;

    if (with_memory) {
        digital_dna::MemoryFingerprint m;
        d.memory = m;
    }
    if (with_thermal) {
        digital_dna::ThermalProfile t;
        d.thermal = t;
    }
    if (with_drift) {
        digital_dna::ClockDriftFingerprint c;
        d.clock_drift = c;
    }
    if (with_bandwidth) {
        digital_dna::BandwidthFingerprint b;
        d.bandwidth = b;
    }
    if (with_behavioral) {
        digital_dna::BehavioralProfile bp;
        bp.observation_blocks = 10;  // non-empty so the registry treats it as populated
        d.behavioral = bp;
    }
    return d;
}

struct ScratchDir {
    fs::path path;
    explicit ScratchDir(const std::string& tag) {
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                      std::chrono::steady_clock::now().time_since_epoch()).count();
        path = fs::temp_directory_path() /
               ("dilithion_prop_" + tag + "_" + std::to_string(ns));
        std::error_code ec;
        fs::remove_all(path, ec);
        fs::create_directories(path, ec);
        if (ec) throw std::runtime_error("scratch: " + ec.message());
    }
    ~ScratchDir() { std::error_code ec; fs::remove_all(path, ec); }
};

// ---------------------------------------------------------------------------
// append_sample tests
// ---------------------------------------------------------------------------

TEST(append_sample_unregistered_registers) {
    ScratchDir dir("asu");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");
    auto d = make_dna(0x11);
    auto result = reg.append_sample(d);
    ASSERT(result == IDNARegistry::RegisterResult::SUCCESS, "Expected SUCCESS on first sample");
    ASSERT(reg.is_registered(d.address), "Address should be registered");
}

TEST(append_sample_enriches_and_archives) {
    ScratchDir dir("ase");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");

    auto slim = make_dna(0x22);                                     // 2 core dims
    auto enriched = make_dna(0x22, true, true, false, false, false); // +memory +thermal

    ASSERT(reg.append_sample(slim) == IDNARegistry::RegisterResult::SUCCESS, "first sample");
    auto r = reg.append_sample(enriched);
    ASSERT(r == IDNARegistry::RegisterResult::UPDATED || r == IDNARegistry::RegisterResult::DNA_CHANGED,
           "second sample should update");

    // Canonical is now enriched.
    auto canonical = reg.get_identity(enriched.address);
    ASSERT(canonical.has_value(), "canonical present");
    ASSERT(canonical->memory.has_value(), "memory set on canonical");
    ASSERT(canonical->thermal.has_value(), "thermal set on canonical");

    // History has 1 entry (the old slim DNA).
    auto hist = reg.get_dna_history(enriched.mik_identity, 10);
    ASSERT_EQ(hist.size(), (size_t)1, "one history entry");
}

TEST(append_sample_rejects_dimension_loss) {
    ScratchDir dir("asl");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");

    auto rich = make_dna(0x33, true, true, true, true, true);  // all optional dims
    auto thin = make_dna(0x33, false, false, false, false, false);  // just core

    ASSERT(reg.append_sample(rich) == IDNARegistry::RegisterResult::SUCCESS, "first");
    auto r = reg.append_sample(thin);
    ASSERT(r == IDNARegistry::RegisterResult::INVALID_DNA, "dim-loss must be rejected");

    // Canonical still has all dims.
    auto canonical = reg.get_identity(thin.address);
    ASSERT(canonical.has_value(), "canonical still present");
    ASSERT(canonical->memory.has_value(), "memory still set");
    ASSERT(canonical->thermal.has_value(), "thermal still set");
}

TEST(append_sample_same_dim_value_change_accepted) {
    ScratchDir dir("asv");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");

    auto a = make_dna(0x44, true, true, false, false, false);
    ASSERT(reg.append_sample(a) == IDNARegistry::RegisterResult::SUCCESS, "first");

    // Same dimension set, value tweaked.
    auto b = a;
    b.timing.iterations_per_second = 110000.0;
    auto r = reg.append_sample(b);
    ASSERT(r == IDNARegistry::RegisterResult::UPDATED || r == IDNARegistry::RegisterResult::DNA_CHANGED,
           "same-dim value change accepted");

    auto canonical = reg.get_identity(a.address);
    ASSERT(canonical.has_value(), "canonical present");
    if (std::abs(canonical->timing.iterations_per_second - 110000.0) > 1.0)
        throw std::runtime_error("timing IPS not updated");
}

TEST(history_capped_at_max_per_mik) {
    ScratchDir dir("hc");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");

    auto d = make_dna(0x55);
    ASSERT(reg.append_sample(d) == IDNARegistry::RegisterResult::SUCCESS, "first");

    // Push MAX_HISTORY_PER_MIK + 20 enriched samples, each distinguishable by
    // incrementing timing IPS to force core_dimensions_changed semantics but
    // not trigger the dim-loss guard.
    const size_t extra = IDNARegistry::MAX_HISTORY_PER_MIK + 20;
    for (size_t i = 1; i <= extra; ++i) {
        auto next = d;
        next.timing.iterations_per_second = 100000.0 + static_cast<double>(i);
        // Force timestamp diversity so history keys are unique.
        reg.append_sample(next);
    }

    auto hist = reg.get_dna_history(d.mik_identity, IDNARegistry::MAX_HISTORY_PER_MIK + 50);
    // Post-write count must not exceed MAX_HISTORY_PER_MIK.
    ASSERT(hist.size() <= IDNARegistry::MAX_HISTORY_PER_MIK,
           "history must be capped at MAX_HISTORY_PER_MIK, got " + std::to_string(hist.size()));
}

// ---------------------------------------------------------------------------
// DNASampleRateLimiter tests
// ---------------------------------------------------------------------------

static std::array<uint8_t, 20> make_mik(uint8_t seed) {
    std::array<uint8_t, 20> m{};
    for (size_t i = 0; i < m.size(); ++i) m[i] = static_cast<uint8_t>(seed + i);
    return m;
}

TEST(rate_limiter_peer_bucket_burst_then_refill) {
    DNASampleRateLimiter lim;
    uint64_t t = 1000;

    // Use distinct MIKs per call so the per-MIK / per-MIK-per-peer layers
    // never block us. This isolates layer 1 (peer bucket).
    for (int i = 0; i < static_cast<int>(DNASampleRateLimiter::PEER_BUCKET_BURST); ++i) {
        auto r = lim.allow_detail(42, make_mik(static_cast<uint8_t>(i + 1)), t);
        ASSERT(r == DNASampleRateLimiter::Reject::OK,
               "burst sample " + std::to_string(i) + " should pass");
    }

    // Now bucket is empty — 6th sample in the same second rejected.
    auto r = lim.allow_detail(42, make_mik(0xAA), t);
    ASSERT(r == DNASampleRateLimiter::Reject::PEER_BUCKET,
           "post-burst sample should be PEER_BUCKET-rejected");

    // After refill interval, one token available.
    t += DNASampleRateLimiter::PEER_BUCKET_REFILL_SEC;
    r = lim.allow_detail(42, make_mik(0xBB), t);
    ASSERT(r == DNASampleRateLimiter::Reject::OK, "refilled token accepts");
}

TEST(rate_limiter_per_mik_global) {
    DNASampleRateLimiter lim;
    auto mik = make_mik(0xCC);
    uint64_t t = 2000;

    // Accept one from peer 1.
    ASSERT(lim.allow(1, mik, t), "first sample passes");

    // Different peer 2, same MIK, within 10-min window → rejected by MIK_GLOBAL.
    auto r = lim.allow_detail(2, mik, t + 60);
    ASSERT(r == DNASampleRateLimiter::Reject::MIK_GLOBAL,
           "second-peer same-MIK sample rejected by MIK_GLOBAL");

    // After 10 min + 1s, accepted.
    r = lim.allow_detail(2, mik, t + DNASampleRateLimiter::MIK_GLOBAL_MIN_SEC + 1);
    ASSERT(r == DNASampleRateLimiter::Reject::OK,
           "after MIK_GLOBAL_MIN_SEC same-MIK sample accepted");
}

TEST(rate_limiter_per_mik_per_peer) {
    DNASampleRateLimiter lim;
    auto mik = make_mik(0xDD);
    uint64_t t = 3000;

    ASSERT(lim.allow(7, mik, t), "first");

    // Same peer, same MIK, after MIK_GLOBAL window but BEFORE MIK_PEER window
    // → should be rejected by MIK_PEER.
    uint64_t t_mid = t + DNASampleRateLimiter::MIK_GLOBAL_MIN_SEC + 1;
    auto r = lim.allow_detail(7, mik, t_mid);
    ASSERT(r == DNASampleRateLimiter::Reject::MIK_PEER,
           "same peer same MIK within 30 min rejected by MIK_PEER");

    // After the 30-min per-peer window, accepted.
    uint64_t t_late = t + DNASampleRateLimiter::MIK_PEER_MIN_SEC + 1;
    r = lim.allow_detail(7, mik, t_late);
    ASSERT(r == DNASampleRateLimiter::Reject::OK,
           "after MIK_PEER_MIN_SEC same peer same MIK accepted");
}

TEST(rate_limiter_reject_leaves_state_unchanged) {
    DNASampleRateLimiter lim;
    auto mik = make_mik(0xEE);
    uint64_t t = 4000;

    // Exhaust peer bucket on MIK A.
    for (int i = 0; i < static_cast<int>(DNASampleRateLimiter::PEER_BUCKET_BURST); ++i) {
        lim.allow(10, make_mik(static_cast<uint8_t>(i + 100)), t);
    }

    // Try to push MIK sample — rejected by peer bucket.
    ASSERT(!lim.allow(10, mik, t), "rejected by peer bucket");

    // Since it was rejected, MIK should not be in the global-last-accept map.
    // We can infer this by: a different peer submitting for the same MIK in
    // the same second should pass (no MIK_GLOBAL block).
    ASSERT(lim.allow(99, mik, t),
           "after rejected attempt, MIK state must be unchanged so another peer can accept");
}

// ---------------------------------------------------------------------------
// Phase 1.1 merge-fill tests
// ---------------------------------------------------------------------------

TEST(merge_fill_fills_missing_dimension) {
    // existing has no bandwidth; incoming has bandwidth → merged has bandwidth.
    auto existing = make_dna(0xA0, true, true, false, false, false);  // mem+thermal
    auto incoming = make_dna(0xA0, true, true, false, true,  false);  // mem+thermal+bw

    int filled = -1;
    auto merged = digital_dna::merge_fill_missing_dims(existing, incoming, &filled);

    ASSERT_EQ(filled, 1, "should fill exactly one dim (bandwidth)");
    ASSERT(merged.bandwidth.has_value(), "merged has bandwidth");
    ASSERT(merged.memory.has_value(), "merged keeps memory");
    ASSERT(merged.thermal.has_value(), "merged keeps thermal");
    ASSERT(!merged.clock_drift.has_value(), "merged doesn't invent clock_drift");
    ASSERT(!merged.behavioral.has_value(), "merged doesn't invent behavioral");
}

TEST(merge_fill_no_gap_returns_existing_with_zero_filled) {
    // Both have the same populated set → filled=0.
    auto existing = make_dna(0xA1, true, true, false, false, false);
    auto incoming = make_dna(0xA1, true, true, false, false, false);

    int filled = -1;
    auto merged = digital_dna::merge_fill_missing_dims(existing, incoming, &filled);

    ASSERT_EQ(filled, 0, "no dims to fill when both have same set");
    // merged should be equivalent to existing.
    ASSERT(merged.memory.has_value() == existing.memory.has_value(), "memory preserved");
    ASSERT(merged.thermal.has_value() == existing.thermal.has_value(), "thermal preserved");
    ASSERT(!merged.bandwidth.has_value(), "bandwidth still absent");
}

TEST(merge_fill_preserves_existing_values_on_conflict) {
    // existing has memory populated; incoming has memory populated with a
    // different marker. Merge must keep existing's value.
    auto existing = make_dna(0xA2, true, true, false, false, false);
    existing.timing.iterations_per_second = 100000.0;  // distinguishing marker

    auto incoming = make_dna(0xA2, true, true, false, true, false);
    incoming.timing.iterations_per_second = 777777.0;  // different value — must NOT win

    int filled = 0;
    auto merged = digital_dna::merge_fill_missing_dims(existing, incoming, &filled);

    ASSERT_EQ(filled, 1, "only bandwidth filled");
    ASSERT(merged.bandwidth.has_value(), "bandwidth now present");
    // Core field (timing.iterations_per_second) must come from existing.
    if (std::abs(merged.timing.iterations_per_second - 100000.0) > 1.0)
        throw std::runtime_error("timing IPS must be preserved from existing, not overwritten");
}

TEST(merge_fill_multiple_missing_dims) {
    auto existing = make_dna(0xA3, false, false, false, false, false);  // only core
    auto incoming = make_dna(0xA3, true,  true,  true,  true,  true);   // all enriched

    int filled = 0;
    auto merged = digital_dna::merge_fill_missing_dims(existing, incoming, &filled);

    // Counts: memory, thermal, clock_drift, bandwidth, behavioral = 5.
    ASSERT_EQ(filled, 5, "should fill 5 dims");
    ASSERT(merged.memory.has_value(), "memory filled");
    ASSERT(merged.thermal.has_value(), "thermal filled");
    ASSERT(merged.clock_drift.has_value(), "clock_drift filled");
    ASSERT(merged.bandwidth.has_value(), "bandwidth filled");
    ASSERT(merged.behavioral.has_value(), "behavioral filled");
}

TEST(merge_fill_then_append_sample_succeeds_with_dim_loss_guard) {
    // End-to-end: seed the registry with a thin DNA (mapped-peer-equivalent,
    // via append_sample on fresh MIK), then simulate an unmapped peer
    // providing an enriched sample. Call merge + append and verify the
    // canonical record has the new dim.
    ScratchDir dir("mf_e2e");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");

    auto slim = make_dna(0xA4, true, true, false, false, false);   // 4 dims
    ASSERT(reg.append_sample(slim) == IDNARegistry::RegisterResult::SUCCESS, "seed");

    auto enriched_from_relay = make_dna(0xA4, true, true, false, true, false);  // +bw
    int filled = 0;
    auto merged = digital_dna::merge_fill_missing_dims(slim, enriched_from_relay, &filled);
    ASSERT_EQ(filled, 1, "relay fills bandwidth");

    auto r = reg.append_sample(merged);
    ASSERT(r == IDNARegistry::RegisterResult::UPDATED ||
           r == IDNARegistry::RegisterResult::DNA_CHANGED,
           "merged sample should be accepted by append_sample");

    auto canonical = reg.get_identity(slim.address);
    ASSERT(canonical.has_value(), "canonical present");
    ASSERT(canonical->bandwidth.has_value(), "canonical now has bandwidth after merge-append");
}

TEST(merge_fill_perspective_dim_is_fillable) {
    // perspective isn't optional<T> — it has its own populated predicate.
    // Verify merge treats it correctly.
    auto existing = make_dna(0xA5, false, false, false, false, false);
    // existing has zero peers in perspective by default.
    ASSERT_EQ(existing.perspective.total_unique_peers(), (size_t)0, "existing has no peer data");

    auto incoming = existing;  // same address
    // Simulate incoming perspective with a snapshot.
    digital_dna::PerspectiveSnapshot snap;
    snap.timestamp = 1700000000;
    snap.block_height = 100;
    for (size_t i = 0; i < 20; ++i) {
        std::array<uint8_t, 20> peer{};
        for (size_t j = 0; j < 20; ++j) peer[j] = static_cast<uint8_t>(i + j);
        snap.active_peers.push_back(peer);
    }
    incoming.perspective.snapshots.push_back(snap);

    int filled = 0;
    auto merged = digital_dna::merge_fill_missing_dims(existing, incoming, &filled);
    ASSERT(filled >= 1, "perspective should count as a filled dim");
    ASSERT(!merged.perspective.snapshots.empty(), "merged got the perspective snapshot");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    std::cout << "\n" << YELLOW_ << "=== DNA Propagation Phase 1 + 1.1 Tests ===" << RESET_ << "\n" << std::endl;

    test_append_sample_unregistered_registers_wrapper();
    test_append_sample_enriches_and_archives_wrapper();
    test_append_sample_rejects_dimension_loss_wrapper();
    test_append_sample_same_dim_value_change_accepted_wrapper();
    test_history_capped_at_max_per_mik_wrapper();

    test_rate_limiter_peer_bucket_burst_then_refill_wrapper();
    test_rate_limiter_per_mik_global_wrapper();
    test_rate_limiter_per_mik_per_peer_wrapper();
    test_rate_limiter_reject_leaves_state_unchanged_wrapper();

    // Phase 1.1 merge-fill tests
    test_merge_fill_fills_missing_dimension_wrapper();
    test_merge_fill_no_gap_returns_existing_with_zero_filled_wrapper();
    test_merge_fill_preserves_existing_values_on_conflict_wrapper();
    test_merge_fill_multiple_missing_dims_wrapper();
    test_merge_fill_then_append_sample_succeeds_with_dim_loss_guard_wrapper();
    test_merge_fill_perspective_dim_is_fillable_wrapper();

    std::cout << "\n" << YELLOW_ << "=== Results ===" << RESET_ << std::endl;
    std::cout << GREEN_ << "Passed: " << g_tests_passed << RESET_ << std::endl;
    if (g_tests_failed > 0) {
        std::cout << RED_ << "Failed: " << g_tests_failed << RESET_ << std::endl;
        return 1;
    }
    return 0;
}
