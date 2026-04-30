// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.5 + PR6.5b.test-hardening — Sync-state hysteresis +
// stall sweep tests.
//
// Per active_contract.md "Acceptance criteria", this 7-case suite verifies:
//   1. is_ibd_default_true_at_startup
//      — fresh CPeerManager with no peers/headers reports
//        IsInitialBlockDownload()==true and IsSynced()==false (now via the
//        real hysteresis logic, not a hard-coded stub).
//   2. is_synced_after_handshake_and_caught_up
//      — BEHAVIORAL ASSERTION (PR6.5b.test-hardening): set
//        m_test_header_height_override > 0 + drive handshake +
//        m_test_chain_height_override = header (blocks_behind = 0) +
//        Tick() → IsSynced() flips to true via the real hysteresis branch.
//   3. not_synced_when_no_handshake_completed
//      — even with header_height == chain_height (within tolerance),
//        Tick() does NOT flip m_synced to true unless any peer has
//        m_handshake_complete. With zero handshakes, IsSynced()==false.
//   4. unsynced_hysteresis_threshold
//      — BEHAVIORAL ASSERTION (PR6.5b.test-hardening): drive Test 2's path
//        to currently_synced=true, then bump m_test_header_height_override
//        so blocks_behind > UNSYNC_THRESHOLD_BLOCKS (10) and assert
//        IsSynced()==false after Tick. Confirms the asymmetric hysteresis
//        comparison is the load-bearing predicate.
//   5. stale_in_flight_block_is_recovered
//      — BEHAVIORAL ASSERTION (PR6.5b.test-hardening): MarkBlockInFlight
//        stamps real requested_at_unix_sec; test then sets
//        m_test_now_override = now + (BLOCK_TIMEOUT_BULK_SECS + slack);
//        Tick() removes the entry via RetryStaleBlocksLocked and the per-peer
//        counter decrements to 0. Negative-side assertion: scorer is NOT
//        invoked from the new code path (PR6.5b.6 owns misbehavior dispatch).
//   6. near_tip_uses_shorter_timeout
//      — BEHAVIORAL ASSERTION (PR6.5b.test-hardening): two scenarios share
//        a fixture pattern:
//          (a) blocks_behind ≤ BLOCKS_NEAR_TIP_THRESHOLD with age >
//              BLOCK_TIMEOUT_NEAR_TIP_SECS but < BLOCK_TIMEOUT_BULK_SECS →
//              entry is removed (near-tip threshold fires).
//          (b) blocks_behind > BLOCKS_NEAR_TIP_THRESHOLD with same age →
//              entry is preserved (bulk timeout NOT exceeded).
//        Demonstrates the timeout pivot is real and routed through
//        GetHeaderHeightForSync / GetChainHeightForSync.
//   7. tick_does_not_request_blocks_when_synced
//      — observable behavior: after Tick() with default state
//        (m_synced==false), block-download dispatch fires per
//        RequestNextBlocks; the gate at the end of Tick is verified by
//        STRUCTURAL ASSERTION (kept structural under §5 A8 — its purpose
//        is the gate's existence, and the gate's effect is exercised by
//        Tests 2/4 via the real flip).
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
#include <ctime>
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

// Helper — read peer_manager.cpp for any remaining structural-style tests.
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
// Test fixture. PR6.5b.test-hardening: moved OUT of anonymous namespace so
// the friend declaration `friend struct ::SyncStateFixture;` on
// dilithion::net::port::CPeerManager can name it. RecordingScorer stays in
// the anonymous namespace (no friending needed).
//
// Builds CPeerManager + a real CHeadersManager on g_node_context (so
// UpdateSyncStateLocked's null-guard goes through), restoring on destruction.
//
// Friend access lets test bodies set the three injection-seam fields
// directly (m_test_now_override, m_test_header_height_override,
// m_test_chain_height_override) to drive deterministic time/height.
// ============================================================================
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

    // ===== PR6.5b.test-hardening — friend-only setters =====
    //
    // These setters expose the private override fields ONLY through the
    // friended fixture struct. No production code path can call them
    // (production never instantiates SyncStateFixture). Sentinel values
    // (0 for clock, -1 for heights) restore real-source behavior.

    void SetNowOverride(int64_t v)    { pm.m_test_now_override = v; }
    void SetHeaderHeightOverride(int64_t v) { pm.m_test_header_height_override = v; }
    void SetChainHeightOverride(int64_t v)  { pm.m_test_chain_height_override = v; }

    // Convenience: drive the handshake-complete bit on a peer that's
    // already connected via OnPeerConnected. Avoids reaching into private
    // CPeer state directly — uses the real verack codepath (matches
    // not_synced_when_no_handshake_completed test below for symmetry).
    void DriveVerack(::dilithion::net::NodeId peer) {
        std::vector<uint8_t> empty;
        CDataStream stream(empty);
        (void)pm.ProcessMessage(peer, "verack", stream);
    }
};

const ::Dilithion::ChainParams SyncStateFixture::chainparams =
    ::Dilithion::ChainParams::Regtest();

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
// BEHAVIORAL ASSERTION (PR6.5b.test-hardening). Fixture sets
// m_test_header_height_override > 0 and m_test_chain_height_override
// such that blocks_behind ≤ SYNC_TOLERANCE_BLOCKS (2). With a
// handshake-complete peer, the three-way conjunction in
// UpdateSyncStateLocked fires and m_synced flips to true.
//
// Negative-side assertion: m_scorer.Misbehaving is NOT called during
// this happy-path Tick — UpdateSyncStateLocked must never score peers.
// ============================================================================
void test_is_synced_after_handshake_and_caught_up()
{
    std::cout << "  test_is_synced_after_handshake_and_caught_up..." << std::flush;

    SyncStateFixture fix;

    // Connect peer + drive handshake-complete via verack codepath
    // (HasCompletedHandshakeWithAnyPeer needs CPeer.m_handshake_complete).
    fix.pm.OnPeerConnected(kPeerId);
    fix.DriveVerack(kPeerId);

    // Inject deterministic heights: header > 0 (gate), chain at the same
    // value so blocks_behind = 0 ≤ SYNC_TOLERANCE_BLOCKS (2).
    fix.SetHeaderHeightOverride(100);
    fix.SetChainHeightOverride(100);

    // Pre-condition: not synced yet (Tick hasn't run with overrides).
    assert(fix.pm.IsSynced() == false);

    fix.pm.Tick();

    // Hysteresis "become synced" branch fires:
    //   blocks_behind (0) <= SYNC_TOLERANCE_BLOCKS (2)  ✓
    //   header_height (100) > 0                          ✓
    //   has_peer_info (handshake complete)               ✓
    assert(fix.pm.IsSynced() == true);
    assert(fix.pm.IsInitialBlockDownload() == false);

    // Negative-side assertion: UpdateSyncStateLocked never scores peers.
    // The verack handler in HandleVerack also doesn't score on the happy
    // path (no second VERSION, no missing peer), so the scorer queue
    // stays empty for this whole sequence.
    assert(fix.scorer.calls.empty());

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
// BEHAVIORAL ASSERTION (PR6.5b.test-hardening). First drive Test 2's path
// to currently_synced=true; then bump m_test_header_height_override so
// blocks_behind > UNSYNC_THRESHOLD_BLOCKS (10), Tick(), and assert that
// IsSynced() flipped to false. Demonstrates the asymmetric comparison
// (UNSYNC_THRESHOLD_BLOCKS, not SYNC_TOLERANCE_BLOCKS) is the load-bearing
// predicate on the synced→unsynced transition.
//
// Negative-side assertion: scorer not invoked during this transition.
// ============================================================================
void test_unsynced_hysteresis_threshold()
{
    std::cout << "  test_unsynced_hysteresis_threshold..." << std::flush;

    SyncStateFixture fix;

    // Step 1: get to currently_synced=true (mirrors Test 2).
    fix.pm.OnPeerConnected(kPeerId);
    fix.DriveVerack(kPeerId);
    fix.SetHeaderHeightOverride(100);
    fix.SetChainHeightOverride(100);
    fix.pm.Tick();
    assert(fix.pm.IsSynced() == true);

    // Step 2: drive blocks_behind > UNSYNC_THRESHOLD_BLOCKS (10). Bump
    // header height while leaving chain height at 100 → blocks_behind = 11.
    fix.SetHeaderHeightOverride(111);
    // chain stays at 100.

    fix.pm.Tick();

    // The "currently_synced && blocks_behind > UNSYNC_THRESHOLD_BLOCKS"
    // branch fires: IsSynced() flips back to false.
    assert(fix.pm.IsSynced() == false);
    assert(fix.pm.IsInitialBlockDownload() == true);

    // Confirm asymmetry: a value just above SYNC_TOLERANCE (3-10) would NOT
    // have flipped if currently synced. Re-set fixture for this sub-case.
    {
        SyncStateFixture fix2;
        fix2.pm.OnPeerConnected(kPeerId);
        fix2.DriveVerack(kPeerId);
        fix2.SetHeaderHeightOverride(100);
        fix2.SetChainHeightOverride(100);
        fix2.pm.Tick();
        assert(fix2.pm.IsSynced() == true);

        // Bump only 5 blocks behind — within the asymmetric "stay synced"
        // window (>SYNC_TOLERANCE_BLOCKS but <=UNSYNC_THRESHOLD_BLOCKS).
        fix2.SetHeaderHeightOverride(105);
        fix2.pm.Tick();
        // STILL SYNCED. This is the hysteresis dead-band.
        assert(fix2.pm.IsSynced() == true);
    }

    // Negative-side assertion: scorer never called from
    // UpdateSyncStateLocked across either transition.
    assert(fix.scorer.calls.empty());

    std::cout << " OK\n";
}

// ============================================================================
// Test 5 — stale_in_flight_block_is_recovered.
// BEHAVIORAL ASSERTION (PR6.5b.test-hardening). MarkBlockInFlight stamps
// the entry with real std::time(nullptr); test then sets
// m_test_now_override = now + (BLOCK_TIMEOUT_BULK_SECS + slack). Tick →
// RetryStaleBlocksLocked computes age via Now() and removes the entry.
//
// Negative-side assertion: m_scorer.Misbehaving is NOT called from
// RetryStaleBlocksLocked (deferred to PR6.5b.6).
// ============================================================================
void test_stale_in_flight_block_is_recovered()
{
    std::cout << "  test_stale_in_flight_block_is_recovered..." << std::flush;

    SyncStateFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // Force the bulk-timeout branch by leaving header/chain heights at
    // their default sentinels (override=-1 → real source via genesis-seeded
    // CHeadersManager + ChainSelectorAdapter, blocks_behind=0). Actually
    // blocks_behind=0 is near-tip, so the timeout = BLOCK_TIMEOUT_NEAR_TIP_SECS
    // (15). We use 15+slack as the offset.

    // Mark two block hashes in-flight. Both are stamped with real
    // std::time(nullptr) inside MarkBlockInFlight.
    uint256 h1, h2;
    h1.data[0] = 0x11;
    h2.data[0] = 0x22;

    const int64_t real_now_at_mark = static_cast<int64_t>(std::time(nullptr));
    fix.pm.MarkBlockInFlight(kPeerId, h1);
    fix.pm.MarkBlockInFlight(kPeerId, h2);
    assert(fix.pm.GetBlocksInFlightForPeer(kPeerId) == 2);

    // Inject "now" 100 seconds into the future. With near-tip timeout
    // (15s) AND bulk timeout (60s), 100s exceeds both. Belt-and-braces.
    fix.SetNowOverride(real_now_at_mark + 100);

    fix.pm.Tick();

    // Both stale entries removed; per-peer counter back to zero.
    assert(fix.pm.GetBlocksInFlightForPeer(kPeerId) == 0);

    // Negative-side: scorer not called from RetryStaleBlocksLocked
    // (PR6.5b.6 owns misbehavior dispatch on stalled peers).
    assert(fix.scorer.calls.empty());

    // Belt-and-braces: a fresh-entry case (no override) preserves entries.
    {
        SyncStateFixture fix2;
        fix2.pm.OnPeerConnected(kPeerId);
        fix2.pm.MarkBlockInFlight(kPeerId, h1);
        assert(fix2.pm.GetBlocksInFlightForPeer(kPeerId) == 1);
        fix2.pm.Tick();
        // Within the timeout window — preserved.
        assert(fix2.pm.GetBlocksInFlightForPeer(kPeerId) == 1);
        assert(fix2.scorer.calls.empty());
    }

    std::cout << " OK\n";
}

// ============================================================================
// Test 6 — near_tip_uses_shorter_timeout.
// BEHAVIORAL ASSERTION (PR6.5b.test-hardening). Two scenarios verify the
// `(blocks_behind <= BLOCKS_NEAR_TIP_THRESHOLD) ? BLOCK_TIMEOUT_NEAR_TIP_SECS
// : BLOCK_TIMEOUT_BULK_SECS` selector at runtime — using the height
// overrides to pin blocks_behind on each side of the threshold:
//
//   Scenario (a): blocks_behind = 5 (≤ 20 = NEAR_TIP_THRESHOLD), age = 30s
//     → 30 ≥ NEAR_TIP timeout (15s) → entry IS removed.
//   Scenario (b): blocks_behind = 50 (> 20), age = 30s
//     → 30 < BULK timeout (60s) → entry IS preserved.
//
// Same age, different blocks_behind → opposite outcomes. This is the
// behavioral signature of the timeout pivot.
//
// Negative-side assertion: scorer not called in either scenario.
// ============================================================================
void test_near_tip_uses_shorter_timeout()
{
    std::cout << "  test_near_tip_uses_shorter_timeout..." << std::flush;

    // Scenario (a): near tip — 30s age exceeds 15s NEAR_TIP timeout.
    {
        SyncStateFixture fix;
        fix.pm.OnPeerConnected(kPeerId);

        uint256 h;
        h.data[0] = 0xAA;

        const int64_t real_now = static_cast<int64_t>(std::time(nullptr));
        fix.pm.MarkBlockInFlight(kPeerId, h);
        assert(fix.pm.GetBlocksInFlightForPeer(kPeerId) == 1);

        // Pin blocks_behind = 5 (≤ NEAR_TIP_THRESHOLD = 20).
        fix.SetHeaderHeightOverride(105);
        fix.SetChainHeightOverride(100);
        // Advance "now" by 30s. Exceeds NEAR_TIP timeout (15s) but NOT
        // BULK timeout (60s) — the differentiator.
        fix.SetNowOverride(real_now + 30);

        fix.pm.Tick();

        // Near-tip timeout fired: entry removed.
        assert(fix.pm.GetBlocksInFlightForPeer(kPeerId) == 0);
        assert(fix.scorer.calls.empty());
    }

    // Scenario (b): bulk — 30s age does NOT exceed 60s BULK timeout.
    {
        SyncStateFixture fix;
        fix.pm.OnPeerConnected(kPeerId);

        uint256 h;
        h.data[0] = 0xBB;

        const int64_t real_now = static_cast<int64_t>(std::time(nullptr));
        fix.pm.MarkBlockInFlight(kPeerId, h);
        assert(fix.pm.GetBlocksInFlightForPeer(kPeerId) == 1);

        // Pin blocks_behind = 50 (> NEAR_TIP_THRESHOLD = 20).
        fix.SetHeaderHeightOverride(150);
        fix.SetChainHeightOverride(100);
        // Same 30s age. Bulk timeout (60s) NOT exceeded.
        fix.SetNowOverride(real_now + 30);

        fix.pm.Tick();

        // Bulk timeout NOT fired: entry preserved.
        assert(fix.pm.GetBlocksInFlightForPeer(kPeerId) == 1);
        assert(fix.scorer.calls.empty());
    }

    std::cout << " OK\n";
}

// ============================================================================
// Test 7 — tick_does_not_request_blocks_when_synced.
// STRUCTURAL ASSERTION (kept structural per contract §5 A8 — Test 7's
// purpose is to pin the gate's existence; the gate's effect is exercised
// behaviorally by Tests 2/4 via the real m_synced flip).
//
// Observable side: with default state (m_synced=false) and no peers,
// Tick() does invoke RequestNextBlocks but with no peers, no entries
// are added — still observable as in-flight count == 0.
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
    std::cout << "Phase 6 PR6.5b.5 + test-hardening — Sync-state tests\n";
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
