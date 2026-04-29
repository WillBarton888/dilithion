// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.5 — Sync-state hysteresis + stall sweep tests.
//
// Per active_contract.md "Acceptance criteria", this 7-case suite verifies:
//   1. is_ibd_default_true_at_startup
//      — fresh CPeerManager with no peers/headers reports
//        IsInitialBlockDownload()==true and IsSynced()==false (now via the
//        real hysteresis logic, not a hard-coded stub).
//   2. is_synced_after_handshake_and_caught_up
//      — STRUCTURAL ASSERTION: the hysteresis "become synced" branch is
//        reachable in peer_manager.cpp. (Real fixture cannot seed
//        CHeadersManager::nBestHeight without driving PoW-validating
//        ProcessHeadersWithDoSProtection through to commitment, which is
//        out of unit-test scope; per contract, structural-grep is the
//        documented fallback.)
//   3. not_synced_when_no_handshake_completed
//      — even with header_height == chain_height (within tolerance),
//        Tick() does NOT flip m_synced to true unless any peer has
//        m_handshake_complete. With zero handshakes, IsSynced()==false.
//   4. unsynced_hysteresis_threshold
//      — STRUCTURAL ASSERTION: the asymmetric hysteresis comparison
//        (UNSYNC_THRESHOLD_BLOCKS) is present in peer_manager.cpp. Real
//        fixture cannot toggle currently_synced=true without seeding
//        CHeadersManager state.
//   5. stale_in_flight_block_is_recovered
//      — STRUCTURAL ASSERTION: RetryStaleBlocksLocked uses the timeout
//        comparison and calls RemoveBlockInFlight; misbehavior dispatch
//        is NOT issued (m_scorer.Misbehaving NOT called from the new
//        code path). Real fixture cannot inject `requested_at_unix_sec
//        = now - 65` without test seams disallowed by contract.
//   6. near_tip_uses_shorter_timeout
//      — STRUCTURAL ASSERTION: the `(blocks_behind <=
//        BLOCKS_NEAR_TIP_THRESHOLD) ? BLOCK_TIMEOUT_NEAR_TIP_SECS :
//        BLOCK_TIMEOUT_BULK_SECS` selector is present.
//   7. tick_does_not_request_blocks_when_synced
//      — observable behavior: after Tick() with default state
//        (m_synced==false), block-download dispatch fires per
//        RequestNextBlocks; the gate at the end of Tick is verified by
//        STRUCTURAL ASSERTION.
//
// Per contract: "Coding agent picks the form that compiles cleanly first;
// the priority ordering is: (1) real fixture, (2) mock-injected behavior,
// (3) static grep on the diff itself." — same precedent as PR6.5b.4's
// verack co-dispatch test.
//
// Test pattern: void test_*() functions + custom main(). No Boost.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <core/node_context.h>
#include <crypto/randomx_hash.h>
#include <net/connman.h>
#include <net/headers_manager.h>
#include <net/ipeer_scorer.h>
#include <net/port/addrman_v2.h>
#include <net/port/connman_adapter.h>
#include <net/port/peer_manager.h>
#include <net/serialize.h>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

// IPeerScorer test stub. Records every Misbehaving call so tests can assert
// both the count and the MisbehaviorType / weight. Pure recording.
class RecordingScorer final : public ::dilithion::net::IPeerScorer {
public:
    struct Call {
        ::dilithion::net::NodeId peer;
        std::optional<::dilithion::net::MisbehaviorType> type;
        std::optional<int> weight;
        std::string reason;
    };
    std::vector<Call> calls;

    bool Misbehaving(::dilithion::net::NodeId peer,
                     ::dilithion::net::MisbehaviorType type,
                     const std::string& reason = "") override {
        calls.push_back(Call{peer, type, std::nullopt, reason});
        return false;
    }
    bool Misbehaving(::dilithion::net::NodeId peer,
                     int weight,
                     const std::string& reason = "") override {
        calls.push_back(Call{peer, std::nullopt, weight, reason});
        return false;
    }
    int  GetScore(::dilithion::net::NodeId) const override { return 0; }
    void ResetScore(::dilithion::net::NodeId) override {}
    void SetBanThreshold(int) override {}
    int  GetBanThreshold() const override { return 100; }
    void DecayAll() override {}
};

// Test fixture. Builds CPeerManager + a real CHeadersManager on
// g_node_context (so UpdateSyncStateLocked's null-guard goes through),
// restoring on destruction.
struct SyncStateFixture {
    static const ::Dilithion::ChainParams chainparams;
    Dilithion::ChainParams* prev_global_chainparams;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter chain_selector;
    CConnman connman;
    dilithion::net::port::CConnmanAdapter connman_adapter;
    dilithion::net::port::CAddrMan_v2 addrman;
    RecordingScorer scorer;
    dilithion::net::port::CPeerManager pm;

    SyncStateFixture()
        : prev_global_chainparams(Dilithion::g_chainParams),
          chain_selector(chainstate),
          connman_adapter(connman),
          pm(connman_adapter, addrman, scorer, chain_selector, chainparams)
    {
        Dilithion::g_chainParams =
            const_cast<Dilithion::ChainParams*>(&chainparams);

        // Install a real CHeadersManager so UpdateSyncStateLocked's null
        // guard does not trigger.
        g_node_context.headers_manager = std::make_unique<CHeadersManager>();
    }

    ~SyncStateFixture() {
        g_node_context.headers_manager.reset();
        Dilithion::g_chainParams = prev_global_chainparams;
    }
};

const ::Dilithion::ChainParams SyncStateFixture::chainparams =
    ::Dilithion::ChainParams::Regtest();

// Helper — read peer_manager.cpp for structural-assertion-style tests.
std::string ReadPeerManagerSource() {
    std::ifstream f("src/net/port/peer_manager.cpp");
    if (!f) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

constexpr int kPeerId = 42;

}  // anonymous namespace

// ============================================================================
// Test 1 — is_ibd_default_true_at_startup.
// A freshly-constructed CPeerManager with no peers/headers reports
// IsInitialBlockDownload() == true and IsSynced() == false (the safe
// default — same as the prior stub behavior, but now arrived at through
// the real hysteresis logic).
// ============================================================================
void test_is_ibd_default_true_at_startup()
{
    std::cout << "  test_is_ibd_default_true_at_startup..." << std::flush;

    SyncStateFixture fix;

    assert(fix.pm.IsInitialBlockDownload() == true);
    assert(fix.pm.IsSynced() == false);

    // Inverse-relation invariant at any single instant.
    assert(fix.pm.IsInitialBlockDownload() == !fix.pm.IsSynced());

    // Tick should not flip m_synced — no handshake-complete peer (header
    // > 0 alone is insufficient: CHeadersManager seeds nBestHeight = 0
    // at construction (genesis), and our CChainState has nHeight = 0
    // too, so blocks_behind = 0; but has_peer_info = false.
    fix.pm.Tick();
    assert(fix.pm.IsInitialBlockDownload() == true);
    assert(fix.pm.IsSynced() == false);

    std::cout << " OK\n";
}

// ============================================================================
// Test 2 — is_synced_after_handshake_and_caught_up.
// STRUCTURAL ASSERTION (per contract: real CHeadersManager cannot be
// seeded without driving PoW-validating ProcessHeadersWithDoSProtection
// through to commitment, which is out of unit-test scope): the
// hysteresis "become synced" branch is reachable in peer_manager.cpp.
// ============================================================================
void test_is_synced_after_handshake_and_caught_up()
{
    std::cout << "  test_is_synced_after_handshake_and_caught_up..." << std::flush;

    const std::string src = ReadPeerManagerSource();
    assert(!src.empty());

    // The "become synced" branch must use SYNC_TOLERANCE_BLOCKS,
    // header_height > 0, and the handshake gate.
    assert(src.find("SYNC_TOLERANCE_BLOCKS") != std::string::npos);
    assert(src.find("blocks_behind <= SYNC_TOLERANCE_BLOCKS") !=
           std::string::npos);
    assert(src.find("header_height > 0") != std::string::npos);
    assert(src.find("has_peer_info") != std::string::npos);
    assert(src.find("HasCompletedHandshakeWithAnyPeer") !=
           std::string::npos);

    // The atomic store with release semantics must be present.
    assert(src.find("m_synced.store(") != std::string::npos);
    assert(src.find("memory_order_release") != std::string::npos);

    std::cout << " OK\n";
}

// ============================================================================
// Test 3 — not_synced_when_no_handshake_completed.
// With NO handshake-complete peer, IsSynced() stays false even after
// Tick(). The handshake gate is real and load-bearing. After handshake
// is wired (HandleVerack), the structural-grep portion verifies that the
// three-way conjunction (blocks_behind tolerance + header > 0 +
// has_peer_info) is what gates the flip.
// ============================================================================
void test_not_synced_when_no_handshake_completed()
{
    std::cout << "  test_not_synced_when_no_handshake_completed..." << std::flush;

    SyncStateFixture fix;
    fix.pm.OnPeerConnected(kPeerId);
    // Note: OnPeerConnected sets up the CPeer struct but does NOT set
    // m_handshake_complete (that's the verack handler's job).

    // Tick. With CHeadersManager constructor seeding nBestHeight=0
    // (genesis), header_height = chain_height = 0 → blocks_behind = 0
    // (≤ SYNC_TOLERANCE_BLOCKS), BUT header_height > 0 is FALSE; AND
    // has_peer_info is FALSE. So m_synced stays false.
    fix.pm.Tick();
    assert(fix.pm.IsSynced() == false);

    // Now drive verack via ProcessMessage so m_handshake_complete = true.
    {
        std::vector<uint8_t> empty;
        CDataStream stream(empty);
        bool ok = fix.pm.ProcessMessage(kPeerId, "verack", stream);
        assert(ok == true);
    }

    // Even with handshake complete, m_synced stays false — header_height
    // is still 0 (no headers beyond genesis were processed), so the
    // header_height > 0 guard blocks.
    fix.pm.Tick();
    assert(fix.pm.IsSynced() == false);

    // Verifies the "(blocks_behind <= SYNC_TOLERANCE_BLOCKS) &&
    // (header_height > 0) && has_peer_info" three-way conjunction is
    // load-bearing — neither pair alone is sufficient. The
    // header_height > 0 guard is a real gate (legacy
    // ibd_coordinator.cpp:401).

    std::cout << " OK\n";
}

// ============================================================================
// Test 4 — unsynced_hysteresis_threshold.
// STRUCTURAL ASSERTION (per contract: real CHeadersManager cannot be
// seeded to currently_synced=true without test-only seams disallowed by
// contract): the asymmetric hysteresis using UNSYNC_THRESHOLD_BLOCKS is
// present in peer_manager.cpp.
// ============================================================================
void test_unsynced_hysteresis_threshold()
{
    std::cout << "  test_unsynced_hysteresis_threshold..." << std::flush;

    const std::string src = ReadPeerManagerSource();
    assert(!src.empty());

    // The "currently_synced && blocks_behind > UNSYNC_THRESHOLD_BLOCKS"
    // path must be present.
    assert(src.find("UNSYNC_THRESHOLD_BLOCKS") != std::string::npos);
    assert(src.find("blocks_behind > UNSYNC_THRESHOLD_BLOCKS") !=
           std::string::npos);

    // Hysteresis is asymmetric: SYNC_TOLERANCE != UNSYNC_THRESHOLD.
    // Verify the literal values via header source (constants are private,
    // per contract — declared `static constexpr int` private members).
    std::ifstream hf("src/net/port/peer_manager.h");
    assert(hf);
    std::stringstream hs;
    hs << hf.rdbuf();
    const std::string hdr = hs.str();
    assert(hdr.find("SYNC_TOLERANCE_BLOCKS = 2") != std::string::npos);
    assert(hdr.find("UNSYNC_THRESHOLD_BLOCKS = 10") != std::string::npos);

    std::cout << " OK\n";
}

// ============================================================================
// Test 5 — stale_in_flight_block_is_recovered.
// STRUCTURAL ASSERTION (per contract: cannot inject
// requested_at_unix_sec=now-65 without test seams disallowed by
// contract): RetryStaleBlocksLocked uses the timeout comparison +
// RemoveBlockInFlight callout, and does NOT call m_scorer.Misbehaving
// (deferred to PR6.5b.6).
//
// This test ALSO observes the negative case: with FRESH entries
// (just-added MarkBlockInFlight), Tick() does NOT remove them (timeout
// not exceeded), so per-peer counter remains.
// ============================================================================
void test_stale_in_flight_block_is_recovered()
{
    std::cout << "  test_stale_in_flight_block_is_recovered..." << std::flush;

    // (a) Structural side: the timeout comparison + RemoveBlockInFlight
    // callout must be present in RetryStaleBlocksLocked.
    const std::string src = ReadPeerManagerSource();
    assert(!src.empty());

    assert(src.find("RetryStaleBlocksLocked") != std::string::npos);
    assert(src.find("requested_at_unix_sec") != std::string::npos);
    assert(src.find("BLOCK_TIMEOUT_NEAR_TIP_SECS") != std::string::npos);
    assert(src.find("BLOCK_TIMEOUT_BULK_SECS") != std::string::npos);
    assert(src.find("RemoveBlockInFlight(sp.second, sp.first)") !=
           std::string::npos);

    // The CRITICAL drift assertion: misbehavior dispatch is NOT issued
    // from RetryStaleBlocksLocked. We grep that the function body contains
    // no `m_scorer.Misbehaving(` call. This pins the "deferred to
    // PR6.5b.6" invariant.
    const auto retry_pos = src.find("CPeerManager::RetryStaleBlocksLocked()");
    assert(retry_pos != std::string::npos);
    // Find next function boundary (next `void CPeerManager::` or end).
    const auto next_func = src.find("\nvoid CPeerManager::", retry_pos + 1);
    const auto next_func_alt = src.find("\nbool CPeerManager::", retry_pos + 1);
    const auto retry_end = std::min(
        next_func == std::string::npos ? src.size() : next_func,
        next_func_alt == std::string::npos ? src.size() : next_func_alt);
    const std::string retry_body = src.substr(retry_pos, retry_end - retry_pos);
    assert(retry_body.find("m_scorer.Misbehaving(") == std::string::npos);
    assert(retry_body.find("DisconnectNode") == std::string::npos);

    // (b) Observable side: with FRESH entries, Tick() does NOT remove
    // them. Per-peer counter survives a Tick.
    SyncStateFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    uint256 h1, h2;
    h1.data[0] = 0x11;
    h2.data[0] = 0x22;
    fix.pm.MarkBlockInFlight(kPeerId, h1);
    fix.pm.MarkBlockInFlight(kPeerId, h2);
    assert(fix.pm.GetBlocksInFlightForPeer(kPeerId) == 2);

    fix.pm.Tick();

    // Fresh entries (within the timeout window) are preserved.
    assert(fix.pm.GetBlocksInFlightForPeer(kPeerId) == 2);

    // No scorer dispatch from the new code paths added in PR6.5b.5
    // (the test's only ProcessMessage calls are the lifecycle ones above
    // — none of which tick the scorer in the happy path).
    for (const auto& call : fix.scorer.calls) {
        // Pre-existing dispatch arms (PR6.5b.2/3/4) may tick on bad
        // input but our test input is happy-path; assert nothing.
        (void)call;
    }
    // Stronger: zero scorer calls in this happy-path Tick scenario.
    assert(fix.scorer.calls.empty());

    std::cout << " OK\n";
}

// ============================================================================
// Test 6 — near_tip_uses_shorter_timeout.
// STRUCTURAL ASSERTION: the `(blocks_behind <= BLOCKS_NEAR_TIP_THRESHOLD)
// ? BLOCK_TIMEOUT_NEAR_TIP_SECS : BLOCK_TIMEOUT_BULK_SECS` selector is
// present, matching ibd_coordinator.cpp:2174's `(blocks_behind <= 20)
// ? 15 : 60`.
// ============================================================================
void test_near_tip_uses_shorter_timeout()
{
    std::cout << "  test_near_tip_uses_shorter_timeout..." << std::flush;

    const std::string src = ReadPeerManagerSource();
    assert(!src.empty());

    // The selector must use the three named constants.
    assert(src.find("BLOCKS_NEAR_TIP_THRESHOLD") != std::string::npos);
    assert(src.find("BLOCK_TIMEOUT_NEAR_TIP_SECS") != std::string::npos);
    assert(src.find("BLOCK_TIMEOUT_BULK_SECS") != std::string::npos);

    // The constants match the legacy literals at ibd_coordinator.cpp:2174.
    // (Constants are private static constexpr members; verify via
    // header source per contract.)
    std::ifstream hf("src/net/port/peer_manager.h");
    assert(hf);
    std::stringstream hs;
    hs << hf.rdbuf();
    const std::string hdr = hs.str();
    assert(hdr.find("BLOCKS_NEAR_TIP_THRESHOLD = 20") != std::string::npos);
    assert(hdr.find("BLOCK_TIMEOUT_NEAR_TIP_SECS = 15") != std::string::npos);
    assert(hdr.find("BLOCK_TIMEOUT_BULK_SECS = 60") != std::string::npos);

    std::cout << " OK\n";
}

// ============================================================================
// Test 7 — tick_does_not_request_blocks_when_synced.
// STRUCTURAL ASSERTION: the Tick() body's final dispatch is gated by
// m_synced. Real fixture cannot toggle m_synced=true without seeding
// CHeadersManager state; structural-grep is the documented fallback.
//
// Observable side: with default state (m_synced=false), Tick() does
// invoke RequestNextBlocks but with no peers / no peer with positive
// n_best_known_height, no entries are added — still observable as
// in-flight count == 0.
// ============================================================================
void test_tick_does_not_request_blocks_when_synced()
{
    std::cout << "  test_tick_does_not_request_blocks_when_synced..." << std::flush;

    const std::string src = ReadPeerManagerSource();
    assert(!src.empty());

    // The gate must be present at the end of Tick(): the load checks
    // m_synced with acquire ordering and only then calls
    // RequestNextBlocks.
    assert(src.find("if (!m_synced.load(std::memory_order_acquire))") !=
           std::string::npos);
    assert(src.find("RequestNextBlocks();") != std::string::npos);

    // Observable: with no peers (n_best_known_height = default), Tick()
    // is a no-op for in-flight tracking.
    SyncStateFixture fix;
    assert(fix.pm.GetPeerCount() == 0);
    fix.pm.Tick();
    assert(fix.pm.GetBlocksInFlightForPeer(kPeerId) == 0);

    std::cout << " OK\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.5b.5 — Sync-state hysteresis + stall sweep tests\n";
    std::cout << "  (7-test suite per active_contract.md)\n\n";

    // Initialize RandomX (light mode) so genesis hashing works inside the
    // CHeadersManager constructor invoked from SyncStateFixture (matches
    // peer_manager_headers_sync_tests pattern).
    const char* rx_key = "Dilithion-Genesis-Block-Salt-2025";
    randomx_init_for_hashing(rx_key, std::strlen(rx_key), 1);

    try {
        test_is_ibd_default_true_at_startup();
        test_is_synced_after_handshake_and_caught_up();
        test_not_synced_when_no_handshake_completed();
        test_unsynced_hysteresis_threshold();
        test_stale_in_flight_block_is_recovered();
        test_near_tip_uses_shorter_timeout();
        test_tick_does_not_request_blocks_when_synced();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 7 PR6.5b.5 sync-state tests passed.\n";
    return 0;
}
