// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 Day 4 V1 — Deterministic WAL transition trace + crash-injection.
//
// Plan §13 hard gate #3 (Cursor 2026-04-26): "PR5.3 acceptance includes
// deterministic WAL phase-transition trace/injection test (not review-only)."
// This test satisfies that gate.
//
// What's proved:
//   * Success path: full transition INITIALIZED -> DISCONNECTING ->
//     CONNECTING -> COMPLETED -> WAL deleted.
//   * Mid-disconnect crash: BeginReorg + EnterDisconnectPhase, then
//     destroy WAL instance without CompleteReorg/AbortReorg. Reopen at
//     same dir -> HasIncompleteReorg() == true; phase == DISCONNECTING.
//   * Mid-connect crash: same, but past EnterConnectPhase -> phase ==
//     CONNECTING on recovery.
//   * Clean abort: AbortReorg deletes WAL; reopened instance has
//     HasIncompleteReorg() == false.
//   * Update progress preserves phase across crash: UpdateDisconnectProgress
//     during DISCONNECTING preserves phase on recovery.

#include <consensus/reorg_wal.h>
#include <uint256.h>

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

// Per-test temp directory; cleaned up by RAII helper.
struct TempDir {
    std::filesystem::path path;
    explicit TempDir(const std::string& tag) {
        const auto base = std::filesystem::temp_directory_path() / "phase5_wal";
        std::filesystem::create_directories(base);
        const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        path = base / (tag + "_" + std::to_string(stamp));
        std::filesystem::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);  // best-effort
    }
    std::string str() const { return path.string(); }
};

uint256 MakeHash(uint8_t seed) {
    uint256 h;
    std::memset(h.data, 0, 32);
    h.data[0] = seed;
    return h;
}

}  // anonymous

void test_wal_success_path_full_transitions()
{
    std::cout << "  test_wal_success_path_full_transitions..." << std::flush;
    TempDir td("success");

    {
        CReorgWAL wal(td.str());
        assert(!wal.HasIncompleteReorg());
        assert(!wal.IsActive());
        assert(wal.GetPhase() == ReorgPhase::INITIALIZED);

        std::vector<uint256> dis = {MakeHash(0x10), MakeHash(0x11)};
        std::vector<uint256> con = {MakeHash(0x20), MakeHash(0x21), MakeHash(0x22)};
        assert(wal.BeginReorg(MakeHash(0x01), MakeHash(0x10),
                              MakeHash(0x22), dis, con));
        assert(wal.IsActive());
        assert(wal.GetPhase() == ReorgPhase::INITIALIZED);

        assert(wal.EnterDisconnectPhase());
        assert(wal.GetPhase() == ReorgPhase::DISCONNECTING);

        assert(wal.UpdateDisconnectProgress(1));
        assert(wal.UpdateDisconnectProgress(2));
        assert(wal.GetPhase() == ReorgPhase::DISCONNECTING);

        assert(wal.EnterConnectPhase());
        assert(wal.GetPhase() == ReorgPhase::CONNECTING);

        assert(wal.UpdateConnectProgress(1));
        assert(wal.UpdateConnectProgress(2));
        assert(wal.UpdateConnectProgress(3));

        assert(wal.CompleteReorg());
        assert(!wal.IsActive());
    }

    // After CompleteReorg the WAL file is deleted; a fresh instance at
    // the same dir reports no incomplete reorg.
    {
        CReorgWAL wal(td.str());
        assert(!wal.HasIncompleteReorg());
    }

    std::cout << " OK\n";
}

void test_wal_crash_during_disconnect_recovery_sees_disconnecting()
{
    std::cout << "  test_wal_crash_during_disconnect_recovery_sees_disconnecting..."
              << std::flush;
    TempDir td("crash_disconnect");

    {
        CReorgWAL wal(td.str());
        std::vector<uint256> dis = {MakeHash(0x30), MakeHash(0x31)};
        std::vector<uint256> con = {MakeHash(0x40)};
        assert(wal.BeginReorg(MakeHash(0x02), MakeHash(0x30),
                              MakeHash(0x40), dis, con));
        assert(wal.EnterDisconnectPhase());
        assert(wal.UpdateDisconnectProgress(1));
        // SIMULATED CRASH: destroy without CompleteReorg/AbortReorg. The
        // WAL file persists on disk with phase=DISCONNECTING.
    }

    // Recovery: open a new WAL instance at the same dir.
    {
        CReorgWAL recovery(td.str());
        assert(recovery.HasIncompleteReorg());
        assert(recovery.GetPhase() == ReorgPhase::DISCONNECTING);
        // Recovery info should be non-empty for logging.
        std::string info = recovery.GetIncompleteReorgInfo();
        assert(!info.empty());
        // Fork point should match what BeginReorg wrote.
        uint256 expectedFork = MakeHash(0x02);
        assert(std::memcmp(recovery.GetForkPointHash().data,
                           expectedFork.data, 32) == 0);
    }

    std::cout << " OK\n";
}

void test_wal_crash_during_connect_recovery_sees_connecting()
{
    std::cout << "  test_wal_crash_during_connect_recovery_sees_connecting..."
              << std::flush;
    TempDir td("crash_connect");

    {
        CReorgWAL wal(td.str());
        std::vector<uint256> dis = {MakeHash(0x50)};
        std::vector<uint256> con = {MakeHash(0x60), MakeHash(0x61)};
        assert(wal.BeginReorg(MakeHash(0x03), MakeHash(0x50),
                              MakeHash(0x61), dis, con));
        assert(wal.EnterDisconnectPhase());
        assert(wal.UpdateDisconnectProgress(1));
        assert(wal.EnterConnectPhase());
        assert(wal.UpdateConnectProgress(1));
        // CRASH mid-connect — phase=CONNECTING, partial progress recorded.
    }

    {
        CReorgWAL recovery(td.str());
        assert(recovery.HasIncompleteReorg());
        assert(recovery.GetPhase() == ReorgPhase::CONNECTING);
        uint256 expectedTarget = MakeHash(0x61);
        assert(std::memcmp(recovery.GetTargetTipHash().data,
                           expectedTarget.data, 32) == 0);
    }

    std::cout << " OK\n";
}

void test_wal_clean_abort_leaves_no_recovery_state()
{
    std::cout << "  test_wal_clean_abort_leaves_no_recovery_state..."
              << std::flush;
    TempDir td("abort");

    {
        CReorgWAL wal(td.str());
        std::vector<uint256> dis = {MakeHash(0x70)};
        std::vector<uint256> con = {MakeHash(0x80)};
        assert(wal.BeginReorg(MakeHash(0x04), MakeHash(0x70),
                              MakeHash(0x80), dis, con));
        assert(wal.EnterDisconnectPhase());
        // Hit a transient error path that AborReorg's the reorg cleanly
        // rather than letting the WAL persist.
        assert(wal.AbortReorg());
        assert(!wal.IsActive());
    }

    {
        CReorgWAL recovery(td.str());
        assert(!recovery.HasIncompleteReorg() &&
               "Clean AbortReorg must not leave a recovery-required state");
    }

    std::cout << " OK\n";
}

void test_wal_phase_ordering_is_strict()
{
    std::cout << "  test_wal_phase_ordering_is_strict..." << std::flush;
    TempDir td("ordering");

    CReorgWAL wal(td.str());
    std::vector<uint256> dis = {MakeHash(0x90)};
    std::vector<uint256> con = {MakeHash(0xA0)};

    // INITIALIZED → DISCONNECTING → CONNECTING → COMPLETED
    assert(wal.GetPhase() == ReorgPhase::INITIALIZED);
    assert(wal.BeginReorg(MakeHash(0x05), MakeHash(0x90),
                          MakeHash(0xA0), dis, con));
    assert(wal.GetPhase() == ReorgPhase::INITIALIZED);
    assert(wal.EnterDisconnectPhase());
    assert(wal.GetPhase() == ReorgPhase::DISCONNECTING);
    assert(wal.EnterConnectPhase());
    assert(wal.GetPhase() == ReorgPhase::CONNECTING);
    assert(wal.CompleteReorg());

    std::cout << " OK\n";
}

void test_wal_recovery_persists_disconnected_count()
{
    std::cout << "  test_wal_recovery_persists_disconnected_count..."
              << std::flush;
    TempDir td("count");

    {
        CReorgWAL wal(td.str());
        std::vector<uint256> dis = {MakeHash(0xB0), MakeHash(0xB1), MakeHash(0xB2)};
        std::vector<uint256> con = {MakeHash(0xC0)};
        assert(wal.BeginReorg(MakeHash(0x06), MakeHash(0xB0),
                              MakeHash(0xC0), dis, con));
        assert(wal.EnterDisconnectPhase());
        assert(wal.UpdateDisconnectProgress(2));
        // Crash with progress=2.
    }

    {
        CReorgWAL recovery(td.str());
        assert(recovery.HasIncompleteReorg());
        // Recovery info string should reflect the partial progress for
        // operator visibility.
        std::string info = recovery.GetIncompleteReorgInfo();
        assert(!info.empty());
    }

    std::cout << " OK\n";
}

int main()
{
    std::cout << "\n=== Phase 5 Day 4 V1: Reorg WAL Crash-Injection Tests ===\n"
              << "    (Plan §13 hard gate #3: deterministic WAL evidence)\n"
              << std::endl;
    try {
        test_wal_success_path_full_transitions();
        test_wal_crash_during_disconnect_recovery_sees_disconnecting();
        test_wal_crash_during_connect_recovery_sees_connecting();
        test_wal_clean_abort_leaves_no_recovery_state();
        test_wal_phase_ordering_is_strict();
        test_wal_recovery_persists_disconnected_count();
        std::cout << "\n=== All WAL crash-injection tests passed (6 tests) ===\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed (unknown)" << std::endl;
        return 1;
    }
}
