// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * MIK Registration Persistence + Chain Reset Unit Tests
 *
 * Covers the two pieces introduced in commit c6b664e:
 *   1. mik_registration.dat save/load, checksum integrity, pubkey binding
 *   2. ResetChainState preserve/remove lists + idempotency
 */

#include <dfmp/mik.h>
#include <dfmp/mik_registration_file.h>
#include <util/chain_reset.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// ANSI color codes
#define RESET   "\033[0m"
#define GREEN   "\033[32m"
#define RED     "\033[31m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"

int g_tests_passed = 0;
int g_tests_failed = 0;

#define TEST(name) \
    void test_##name(); \
    void test_##name##_wrapper() { \
        std::cout << BLUE << "[TEST] " << #name << RESET << std::endl; \
        try { \
            test_##name(); \
            std::cout << GREEN << "  PASSED" << RESET << std::endl; \
            g_tests_passed++; \
        } catch (const std::exception& e) { \
            std::cout << RED << "  FAILED: " << e.what() << RESET << std::endl; \
            g_tests_failed++; \
        } catch (...) { \
            std::cout << RED << "  FAILED: Unknown exception" << RESET << std::endl; \
            g_tests_failed++; \
        } \
    } \
    void test_##name()

#define ASSERT(condition, message) \
    if (!(condition)) { \
        throw std::runtime_error(message); \
    }

#define ASSERT_EQ(a, b, message) \
    if ((a) != (b)) { \
        throw std::runtime_error(std::string(message) + " (mismatch)"); \
    }

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Test fixture: unique scratch directory under temp_directory_path()
// ---------------------------------------------------------------------------

struct ScratchDir {
    fs::path path;

    explicit ScratchDir(const std::string& tag) {
        // Unique-per-invocation name using high-res clock; cross-platform.
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                      std::chrono::steady_clock::now().time_since_epoch())
                      .count();
        path = fs::temp_directory_path() /
               ("dilithion_test_" + tag + "_" + std::to_string(ns));
        std::error_code ec;
        fs::remove_all(path, ec);
        fs::create_directories(path, ec);
        if (ec) throw std::runtime_error("create scratch dir: " + ec.message());
    }

    ~ScratchDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }

    std::string str() const { return path.string(); }
};

static void write_file(const fs::path& p, const std::string& contents = "x") {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

static bool file_exists(const fs::path& p) {
    std::error_code ec;
    return fs::exists(p, ec);
}

// ---------------------------------------------------------------------------
// mik_registration.dat tests
// ---------------------------------------------------------------------------

static std::vector<uint8_t> make_fake_pubkey(uint8_t seed) {
    std::vector<uint8_t> pk(DFMP::MIK_PUBKEY_SIZE, 0);
    for (size_t i = 0; i < pk.size(); ++i) {
        pk[i] = static_cast<uint8_t>((i + seed) & 0xFF);
    }
    return pk;
}

TEST(mikreg_roundtrip_save_load) {
    ScratchDir dir("mikreg_rt");

    auto pk = make_fake_pubkey(0x11);
    std::array<uint8_t, 32> dnaHash{};
    for (size_t i = 0; i < dnaHash.size(); ++i) dnaHash[i] = static_cast<uint8_t>(0xA0 + i);
    uint64_t nonce = 0xDEADBEEFCAFEBABEULL;
    int64_t ts = 1700000000;

    ASSERT(DFMP::SaveMIKRegistration(dir.str(), pk, dnaHash, nonce, ts),
           "Save should succeed");

    fs::path filePath = fs::path(dir.str()) / DFMP::MIK_REGISTRATION_FILENAME;
    ASSERT(file_exists(filePath), "mik_registration.dat should exist after save");
    ASSERT(!file_exists(fs::path(filePath.string() + ".tmp")),
           ".tmp should not persist after atomic rename");

    DFMP::MIKRegistrationFile out;
    auto result = DFMP::LoadMIKRegistration(dir.str(), pk, out);
    ASSERT(result == DFMP::MIKRegFileLoadResult::OK, "Load should return OK");
    ASSERT_EQ(out.pubkey.size(), pk.size(), "Pubkey size mismatch");
    ASSERT(out.pubkey == pk, "Pubkey bytes mismatch");
    ASSERT(out.dnaHash == dnaHash, "DNA hash mismatch");
    ASSERT_EQ(out.nonce, nonce, "Nonce mismatch");
    ASSERT_EQ(out.timestamp, ts, "Timestamp mismatch");
}

TEST(mikreg_missing_file) {
    ScratchDir dir("mikreg_missing");
    auto pk = make_fake_pubkey(0x22);
    DFMP::MIKRegistrationFile out;
    auto result = DFMP::LoadMIKRegistration(dir.str(), pk, out);
    ASSERT(result == DFMP::MIKRegFileLoadResult::Missing,
           "Load on empty dir should return Missing");
}

TEST(mikreg_corrupt_checksum_renamed) {
    ScratchDir dir("mikreg_corrupt");
    auto pk = make_fake_pubkey(0x33);
    std::array<uint8_t, 32> dnaHash{};
    ASSERT(DFMP::SaveMIKRegistration(dir.str(), pk, dnaHash, 1, 1), "Save ok");

    fs::path filePath = fs::path(dir.str()) / DFMP::MIK_REGISTRATION_FILENAME;
    // Flip the last byte of the checksum.
    {
        std::fstream f(filePath, std::ios::binary | std::ios::in | std::ios::out);
        ASSERT(f.is_open(), "Reopen file");
        f.seekg(0, std::ios::end);
        std::streampos size = f.tellp();
        f.seekp(size - std::streamoff(1));
        char b = 0;
        f.read(&b, 1);
        f.seekp(size - std::streamoff(1));
        b ^= 0x01;
        f.write(&b, 1);
    }

    DFMP::MIKRegistrationFile out;
    auto result = DFMP::LoadMIKRegistration(dir.str(), pk, out);
    ASSERT(result == DFMP::MIKRegFileLoadResult::Corrupt,
           "Tampered checksum should load Corrupt");
    ASSERT(!file_exists(filePath),
           "Corrupt file should be renamed away from primary name");
    ASSERT(file_exists(fs::path(filePath.string() + ".corrupt")),
           "Corrupt file should be renamed to .corrupt");
}

TEST(mikreg_pubkey_mismatch_renamed_stale) {
    ScratchDir dir("mikreg_stale");
    auto pkSaved = make_fake_pubkey(0x44);
    auto pkExpected = make_fake_pubkey(0x55);  // Different wallet MIK
    std::array<uint8_t, 32> dnaHash{};
    ASSERT(DFMP::SaveMIKRegistration(dir.str(), pkSaved, dnaHash, 1, 1), "Save ok");

    fs::path filePath = fs::path(dir.str()) / DFMP::MIK_REGISTRATION_FILENAME;
    DFMP::MIKRegistrationFile out;
    auto result = DFMP::LoadMIKRegistration(dir.str(), pkExpected, out);
    ASSERT(result == DFMP::MIKRegFileLoadResult::PubkeyMismatch,
           "Mismatched pubkey should return PubkeyMismatch");
    ASSERT(!file_exists(filePath),
           "Stale file should be renamed away from primary name");
    ASSERT(file_exists(fs::path(filePath.string() + ".stale")),
           "Stale file should be renamed to .stale for forensic trail");
}

TEST(mikreg_truncated_file_is_corrupt) {
    ScratchDir dir("mikreg_trunc");
    auto pk = make_fake_pubkey(0x66);
    std::array<uint8_t, 32> dnaHash{};
    ASSERT(DFMP::SaveMIKRegistration(dir.str(), pk, dnaHash, 1, 1), "Save ok");

    fs::path filePath = fs::path(dir.str()) / DFMP::MIK_REGISTRATION_FILENAME;
    // Truncate to half size.
    {
        auto sz = fs::file_size(filePath);
        fs::resize_file(filePath, sz / 2);
    }

    DFMP::MIKRegistrationFile out;
    auto result = DFMP::LoadMIKRegistration(dir.str(), pk, out);
    ASSERT(result == DFMP::MIKRegFileLoadResult::Corrupt,
           "Truncated file should load Corrupt");
    ASSERT(file_exists(fs::path(filePath.string() + ".corrupt")),
           "Truncated file should be renamed to .corrupt");
}

TEST(mikreg_overwrite_with_newer_nonce) {
    ScratchDir dir("mikreg_overwrite");
    auto pk = make_fake_pubkey(0x77);
    std::array<uint8_t, 32> dnaHash{};

    ASSERT(DFMP::SaveMIKRegistration(dir.str(), pk, dnaHash, 111, 100), "Save #1");
    ASSERT(DFMP::SaveMIKRegistration(dir.str(), pk, dnaHash, 222, 200), "Save #2");

    DFMP::MIKRegistrationFile out;
    auto result = DFMP::LoadMIKRegistration(dir.str(), pk, out);
    ASSERT(result == DFMP::MIKRegFileLoadResult::OK, "Load OK after overwrite");
    ASSERT_EQ(out.nonce, static_cast<uint64_t>(222), "Newer nonce should win");
    ASSERT_EQ(out.timestamp, static_cast<int64_t>(200), "Newer ts should win");
}

TEST(mikreg_wrong_pubkey_size_rejected) {
    ScratchDir dir("mikreg_badsize");
    std::vector<uint8_t> shortPk(100, 0xAB);  // Not MIK_PUBKEY_SIZE
    std::array<uint8_t, 32> dnaHash{};
    ASSERT(!DFMP::SaveMIKRegistration(dir.str(), shortPk, dnaHash, 1, 1),
           "Save with wrong pubkey size must fail");
    fs::path filePath = fs::path(dir.str()) / DFMP::MIK_REGISTRATION_FILENAME;
    ASSERT(!file_exists(filePath), "No file should be written on invalid input");
}

// ---------------------------------------------------------------------------
// chain_reset tests
// ---------------------------------------------------------------------------

static void populate_datadir(const fs::path& dir) {
    // Chain-derived dirs (should be removed)
    for (const char* name : {"blocks", "chainstate", "headers", "dna_registry",
                             "dfmp_identity", "dna_trust", "wal"}) {
        fs::create_directories(dir / name);
        write_file(dir / name / "marker", "present");
    }
    // Chain-derived files (should be removed)
    for (const char* name : {"mempool.dat", "auto_rebuild", "fee_estimates.dat",
                             "dfmp_heat.dat", "dfmp_payout_heat.dat"}) {
        write_file(dir / name, "present");
    }
    // Files that MUST be preserved
    for (const char* name : {"wallet.dat", "wallet.dat.bak", "mik_registration.dat",
                             "peers.dat", "banlist.json", "dilithion.conf",
                             "dilv.conf"}) {
        write_file(dir / name, "present");
    }
    // User-owned dir
    fs::create_directories(dir / "backups");
    write_file(dir / "backups" / "wallet_20260101.dat", "present");

    // Arbitrary user file not in any list — must also survive
    write_file(dir / "my_notes.txt", "private");
}

TEST(chain_reset_preserves_wallet_and_mik_reg) {
    ScratchDir dir("cr_preserve");
    populate_datadir(dir.path);

    auto report = Dilithion::ResetChainState(dir.str());

    // Preserved: wallet.dat, mik_registration.dat, peers.dat, configs, backups
    ASSERT(file_exists(dir.path / "wallet.dat"), "wallet.dat must survive");
    ASSERT(file_exists(dir.path / "wallet.dat.bak"), "wallet.dat.bak must survive");
    ASSERT(file_exists(dir.path / "mik_registration.dat"),
           "mik_registration.dat must survive");
    ASSERT(file_exists(dir.path / "peers.dat"), "peers.dat must survive");
    ASSERT(file_exists(dir.path / "banlist.json"), "banlist.json must survive");
    ASSERT(file_exists(dir.path / "dilithion.conf"), "dilithion.conf must survive");
    ASSERT(file_exists(dir.path / "dilv.conf"), "dilv.conf must survive");
    ASSERT(file_exists(dir.path / "backups" / "wallet_20260101.dat"),
           "backups/ must survive");
    ASSERT(file_exists(dir.path / "my_notes.txt"),
           "Arbitrary user file must survive (not in remove-list)");

    ASSERT(report.errors.empty(),
           "No errors expected on clean scratch dir: " +
               (report.errors.empty() ? "" : report.errors[0]));
}

TEST(chain_reset_removes_chain_state) {
    ScratchDir dir("cr_remove");
    populate_datadir(dir.path);

    auto report = Dilithion::ResetChainState(dir.str());

    // Removed dirs
    for (const char* name : {"blocks", "chainstate", "headers", "dna_registry",
                             "dfmp_identity", "dna_trust", "wal"}) {
        ASSERT(!file_exists(dir.path / name),
               std::string(name) + "/ must be removed");
    }
    // Removed files
    for (const char* name : {"mempool.dat", "auto_rebuild", "fee_estimates.dat",
                             "dfmp_heat.dat", "dfmp_payout_heat.dat"}) {
        ASSERT(!file_exists(dir.path / name),
               std::string(name) + " must be removed");
    }

    // Report contents should include what we removed.
    ASSERT(!report.removed.empty(), "Report should list removed paths");
}

TEST(chain_reset_idempotent_on_empty_dir) {
    ScratchDir dir("cr_empty");
    // Nothing in the directory; reset must not fail.
    auto report = Dilithion::ResetChainState(dir.str());
    ASSERT(report.removed.empty(), "Nothing to remove on empty dir");
    ASSERT(report.errors.empty(), "Empty dir should not produce errors");
}

TEST(chain_reset_idempotent_twice) {
    ScratchDir dir("cr_twice");
    populate_datadir(dir.path);

    auto r1 = Dilithion::ResetChainState(dir.str());
    ASSERT(r1.errors.empty(), "First reset: no errors");

    auto r2 = Dilithion::ResetChainState(dir.str());
    ASSERT(r2.errors.empty(), "Second reset: no errors");
    ASSERT(r2.removed.empty(), "Second reset: nothing left to remove");

    // Wallet still there after two resets.
    ASSERT(file_exists(dir.path / "wallet.dat"),
           "wallet.dat survives multiple resets");
    ASSERT(file_exists(dir.path / "mik_registration.dat"),
           "mik_registration.dat survives multiple resets");
}

TEST(chain_reset_partial_state_only_removes_what_exists) {
    ScratchDir dir("cr_partial");
    // Only some of the chain dirs exist.
    fs::create_directories(dir.path / "blocks");
    fs::create_directories(dir.path / "chainstate");
    write_file(dir.path / "wallet.dat");

    auto report = Dilithion::ResetChainState(dir.str());
    ASSERT(!file_exists(dir.path / "blocks"), "blocks/ removed");
    ASSERT(!file_exists(dir.path / "chainstate"), "chainstate/ removed");
    ASSERT(file_exists(dir.path / "wallet.dat"), "wallet.dat preserved");
    ASSERT(report.errors.empty(), "No errors on partial state");
}

TEST(chain_reset_report_lists_preserved_files) {
    ScratchDir dir("cr_report");
    populate_datadir(dir.path);

    auto report = Dilithion::ResetChainState(dir.str());

    // The report should list at least wallet.dat and mik_registration.dat
    // among preserved paths.
    auto contains = [&](const std::string& needle) {
        return std::any_of(report.preserved.begin(), report.preserved.end(),
                           [&](const std::string& p) {
                               return p.find(needle) != std::string::npos;
                           });
    };
    ASSERT(contains("wallet.dat"),
           "Preserved report must mention wallet.dat");
    ASSERT(contains("mik_registration.dat"),
           "Preserved report must mention mik_registration.dat");
}

// Interaction test: save mik_registration.dat, run reset, verify it survives.
TEST(chain_reset_preserves_mik_reg_after_save) {
    ScratchDir dir("cr_mikreg_flow");

    // Populate chain-derived dirs so reset has work to do.
    fs::create_directories(dir.path / "blocks");
    fs::create_directories(dir.path / "chainstate");

    // Save a real mik_registration.dat via the persistence API.
    auto pk = make_fake_pubkey(0x99);
    std::array<uint8_t, 32> dnaHash{};
    uint64_t nonce = 42;
    int64_t ts = 1700000000;
    ASSERT(DFMP::SaveMIKRegistration(dir.str(), pk, dnaHash, nonce, ts),
           "Save mik_registration.dat");

    // Run reset.
    auto report = Dilithion::ResetChainState(dir.str());
    ASSERT(!file_exists(dir.path / "blocks"), "blocks removed");
    ASSERT(!file_exists(dir.path / "chainstate"), "chainstate removed");

    // mik_registration.dat must still load cleanly with the same values.
    DFMP::MIKRegistrationFile out;
    auto result = DFMP::LoadMIKRegistration(dir.str(), pk, out);
    ASSERT(result == DFMP::MIKRegFileLoadResult::OK,
           "mik_registration.dat must load OK after --reset-chain");
    ASSERT_EQ(out.nonce, nonce, "Nonce preserved across reset");
    ASSERT_EQ(out.timestamp, ts, "Timestamp preserved across reset");
    (void)report;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    std::cout << "\n" << YELLOW
              << "=== MIK Registration Persistence + Chain Reset Tests ==="
              << RESET << "\n" << std::endl;

    test_mikreg_roundtrip_save_load_wrapper();
    test_mikreg_missing_file_wrapper();
    test_mikreg_corrupt_checksum_renamed_wrapper();
    test_mikreg_pubkey_mismatch_renamed_stale_wrapper();
    test_mikreg_truncated_file_is_corrupt_wrapper();
    test_mikreg_overwrite_with_newer_nonce_wrapper();
    test_mikreg_wrong_pubkey_size_rejected_wrapper();

    test_chain_reset_preserves_wallet_and_mik_reg_wrapper();
    test_chain_reset_removes_chain_state_wrapper();
    test_chain_reset_idempotent_on_empty_dir_wrapper();
    test_chain_reset_idempotent_twice_wrapper();
    test_chain_reset_partial_state_only_removes_what_exists_wrapper();
    test_chain_reset_report_lists_preserved_files_wrapper();
    test_chain_reset_preserves_mik_reg_after_save_wrapper();

    std::cout << "\n" << YELLOW << "=== Results ===" << RESET << std::endl;
    std::cout << GREEN << "Passed: " << g_tests_passed << RESET << std::endl;
    if (g_tests_failed > 0) {
        std::cout << RED << "Failed: " << g_tests_failed << RESET << std::endl;
        return 1;
    }
    std::cout << "All tests passed." << std::endl;
    return 0;
}
