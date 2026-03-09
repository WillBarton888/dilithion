#include "dna_registry_db.h"
#include <iostream>
#include <filesystem>
#include <thread>
#include <chrono>

using namespace digital_dna;

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { std::cout << "  [PASS] " << msg << std::endl; passed++; } \
    else { std::cout << "  [FAIL] " << msg << std::endl; failed++; } \
} while(0)

int main() {
    std::string dbPath = "./test_dna_hist_db";
    std::filesystem::remove_all(dbPath);

    DNARegistryDB db;
    CHECK(db.Open(dbPath), "Open DB");

    // Create a DNA identity
    DigitalDNA dna1;
    dna1.address.fill(0x01);
    dna1.mik_identity.fill(0xAA);
    dna1.registration_height = 100;
    dna1.registration_time = 1000;
    dna1.is_valid = true;
    dna1.timing.iterations_per_second = 500000;

    // Register
    auto r = db.register_identity(dna1);
    CHECK(r == IDNARegistry::RegisterResult::SUCCESS, "Register identity");

    // History should be empty after initial registration
    auto hist = db.get_dna_history(dna1.mik_identity);
    CHECK(hist.size() == 0, "History empty after register");

    // Update with new DNA (different speed = new hardware)
    std::this_thread::sleep_for(std::chrono::seconds(1));
    DigitalDNA dna2 = dna1;
    dna2.timing.iterations_per_second = 750000;
    dna2.registration_height = 200;
    r = db.update_identity(dna2);
    CHECK(r == IDNARegistry::RegisterResult::UPDATED, "Update 1 succeeds");

    hist = db.get_dna_history(dna1.mik_identity);
    CHECK(hist.size() == 1, "History has 1 entry after first update");
    if (!hist.empty()) {
        CHECK(hist[0].second.timing.iterations_per_second == 500000,
              "Archived DNA has original IPS (500000)");
        CHECK(hist[0].first > 0, "Archived timestamp is nonzero");
    }

    // Update again (another hardware change)
    std::this_thread::sleep_for(std::chrono::seconds(1));
    DigitalDNA dna3 = dna1;
    dna3.timing.iterations_per_second = 1000000;
    dna3.registration_height = 300;
    r = db.update_identity(dna3);
    CHECK(r == IDNARegistry::RegisterResult::UPDATED, "Update 2 succeeds");

    hist = db.get_dna_history(dna1.mik_identity);
    CHECK(hist.size() == 2, "History has 2 entries after second update");
    if (hist.size() >= 2) {
        CHECK(hist[0].second.timing.iterations_per_second == 500000,
              "Archived[0] has IPS 500000 (first version)");
        CHECK(hist[1].second.timing.iterations_per_second == 750000,
              "Archived[1] has IPS 750000 (second version)");
        CHECK(hist[0].first < hist[1].first,
              "History is chronologically ordered");
    }

    // Verify current identity is the latest
    auto current = db.get_identity_by_mik(dna1.mik_identity);
    CHECK(current.has_value(), "Current identity exists");
    if (current) {
        CHECK(current->timing.iterations_per_second == 1000000,
              "Current DNA has latest IPS (1000000)");
    }

    // Check that a different MIK has no history
    std::array<uint8_t, 20> otherMik{};
    otherMik.fill(0xBB);
    auto otherHist = db.get_dna_history(otherMik);
    CHECK(otherHist.empty(), "Unknown MIK has empty history");

    // Test persistence: close and reopen
    db.Close();
    DNARegistryDB db2;
    CHECK(db2.Open(dbPath), "Reopen DB");

    hist = db2.get_dna_history(dna1.mik_identity);
    CHECK(hist.size() == 2, "History survives DB reopen");
    if (hist.size() >= 2) {
        CHECK(hist[0].second.timing.iterations_per_second == 500000,
              "Persisted history[0] correct after reopen");
        CHECK(hist[1].second.timing.iterations_per_second == 750000,
              "Persisted history[1] correct after reopen");
    }

    // Cleanup
    db2.Close();
    std::filesystem::remove_all(dbPath);

    std::cout << "\n=============================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed > 0 ? 1 : 0;
}
