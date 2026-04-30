// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.6 — Misbehavior + OnOrphan/OnBlockConnected + SendMessages
// tests.
//
// Per active_contract.md "Acceptance criteria", this 8-case suite verifies
// the four Item bodies landed in PR6.5b.6:
//
//   1. MisbehaviorOwnership_ExactlyOneScorerTicks_UnderFlag1
//      — γ topology integration invariant. Two real CPeerScorer instances
//        (port_scorer, legacy_scorer). port-CPeerManager wired to
//        port_scorer. Synthesize an "unknown command" inbound via
//        ProcessMessage(peer, "unknown_garbage", empty_stream) → assert
//        port_scorer->GetScore(peer)==1 AND legacy_scorer->GetScore(peer)==0.
//        Then proxy a legacy-side checksum failure by calling
//        legacy_scorer.Misbehaving directly → assert legacy_scorer->
//        GetScore(peer)==50 (InvalidSignature default weight) AND
//        port_scorer->GetScore(peer)==1 (unchanged). NO event scored on
//        both scorers. NON-NEGOTIABLE. The load-bearing γ test.
//
//   2. stall_misbehavior_dispatches_via_port_scorer_once_per_peer
//      — One peer with one stale m_blocks_in_flight entry. After Tick(),
//        port-scorer score for that peer == 1 AND per-peer counter == 1
//        AND entry removed.
//
//   3. stall_disconnect_after_threshold_bulk
//      — bulk-timeout regime (blocks_behind > 20). Three consecutive Tick
//        passes each with fresh stale entries from the same peer →
//        DisconnectNode called exactly once after the third Tick.
//
//   4. stall_disconnect_after_threshold_near_tip
//      — near-tip regime (blocks_behind <= 20). One Tick is sufficient →
//        DisconnectNode called exactly once.
//
//   5. on_orphan_block_received_increments_counter
//      — 5 calls to OnOrphanBlockReceived() → counter reads as 5.
//        (Internal counter exposed via a friended fixture accessor.)
//
//   6. on_block_connected_resets_counters
//      — 3 OnOrphanBlockReceived() + 1 OnBlockConnected() → counter == 0;
//        m_last_block_connected_ticks > 0.
//
//   7. on_block_connected_resets_per_peer_timeout_counters
//      — Register 3 peers; bump each one's m_consecutive_block_timeouts
//        to 2 via stall path; OnBlockConnected() once → all three reset
//        to 0.
//
//   8. send_messages_is_no_op
//      — SendMessages(peer) for known + unknown peer → no panic, no
//        PushMessage on connman, no scorer ticks, no DisconnectNode.
//
// (Item B's orphan-cluster scoring inside HandleBlock was OPTIONAL per
// the contract and is INTENTIONALLY DEFERRED — see the rationale block
// in peer_manager.cpp HandleBlock. Test 9 was removed alongside.
// The orphan COUNTER from OnOrphanBlockReceived (Test 5) remains the
// γ-port surface for orphan tracking in this PR.)
//
// Test pattern: void test_*() functions + custom main(). No Boost.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <core/node_context.h>
#include <net/connman.h>
#include <net/iconnection_manager.h>
#include <net/ipeer_scorer.h>
#include <net/port/addrman_v2.h>
#include <net/port/connman_adapter.h>
#include <net/port/peer_manager.h>
#include <net/port/peer_scorer.h>
#include <net/protocol.h>
#include <net/serialize.h>
#include <primitives/block.h>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

// ============================================================================
// MockConnectionManager — records DisconnectNode calls so the rotation path
// is observable. All other IConnectionManager virtuals stub out to safe
// defaults. ~30 LOC; per contract Test plan summary "in-test" anonymous
// namespace.
// ============================================================================
class MockConnectionManager final : public ::dilithion::net::IConnectionManager {
public:
    struct DisconnectCall {
        ::dilithion::net::NodeId peer;
        std::string reason;
    };
    std::vector<DisconnectCall> disconnect_calls;

    void DisconnectNode(::dilithion::net::NodeId peer,
                        const std::string& reason) override {
        disconnect_calls.push_back(DisconnectCall{peer, reason});
    }
    ::dilithion::net::NodeId ConnectNode(const std::string&,
                                         ::dilithion::net::OutboundClass) override {
        return -1;
    }
    std::vector<::dilithion::net::ConnectionInfo> GetConnections() const override {
        return {};
    }
    int GetOutboundTarget(::dilithion::net::OutboundClass) const override { return 0; }
    bool IsBanned(const std::string&) const override { return false; }
    int GetConnectionCount(::dilithion::net::OutboundClass) const override { return 0; }
    int GetTotalInbound() const override { return 0; }
    int GetTotalOutbound() const override { return 0; }
};

constexpr int kPeerId = 42;
constexpr int kPeerIdB = 43;
constexpr int kPeerIdC = 44;

// Build an empty wire-format message body (for ProcessMessage("unknown", ...)).
std::vector<uint8_t> MakeEmptyWire() {
    return {};
}

// (MakeOrphanBlockWire helper was removed alongside Test 9; Item B's
// orphan-cluster scoring is intentionally deferred per contract.)

}  // anonymous namespace

// ============================================================================
// Test fixture — uses MockConnectionManager (records DisconnectNode) +
// real CPeerScorer instances (port_scorer + legacy_scorer).
// ============================================================================
struct MisbehaviorFixture {
    static const ::Dilithion::ChainParams chainparams;
    Dilithion::ChainParams* prev_global_chainparams;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter chain_selector;
    MockConnectionManager mock_connman;
    dilithion::net::port::CAddrMan_v2 addrman;
    dilithion::net::port::CPeerScorer port_scorer;
    dilithion::net::port::CPeerScorer legacy_scorer;  // simulates legacy's private scorer
    dilithion::net::port::CPeerManager pm;

    MisbehaviorFixture()
        : prev_global_chainparams(Dilithion::g_chainParams),
          chain_selector(chainstate),
          pm(mock_connman, addrman, port_scorer, chain_selector, chainparams)
    {
        Dilithion::g_chainParams =
            const_cast<Dilithion::ChainParams*>(&chainparams);
    }

    ~MisbehaviorFixture() {
        Dilithion::g_chainParams = prev_global_chainparams;
    }

    // ===== PR6.5b.test-hardening — friend-only setters =====
    // Mirrors SyncStateFixture::Set*Override pattern (peer_manager_sync_state_
    // tests.cpp). Production never instantiates this fixture; setters are
    // friend-gated via the friend declaration in peer_manager.h.
    void SetNowOverride(int64_t v)          { pm.m_test_now_override = v; }
    void SetHeaderHeightOverride(int64_t v) { pm.m_test_header_height_override = v; }
    void SetChainHeightOverride(int64_t v)  { pm.m_test_chain_height_override = v; }

    // Friend-only counter accessors (counters are private atomic fields).
    int  GetOrphanCounter() const     { return pm.m_consecutive_orphan_blocks.load(); }
    int64_t GetLastBlockTicks() const { return pm.m_last_block_connected_ticks.load(); }
};

const ::Dilithion::ChainParams MisbehaviorFixture::chainparams =
    ::Dilithion::ChainParams::Regtest();

// ============================================================================
// Test 1 — MisbehaviorOwnership_ExactlyOneScorerTicks_UnderFlag1.
// THE LOAD-BEARING γ TOPOLOGY INTEGRATION INVARIANT (per active_contract.md
// MANDATORY criterion). Asserts non-overlapping event ownership: port path
// scores port_scorer only; legacy path scores legacy_scorer only.
// ============================================================================
void test_misbehavior_ownership_exactly_one_scorer_ticks_under_flag1()
{
    std::cout << "  test_misbehavior_ownership_exactly_one_scorer_ticks_under_flag1..."
              << std::flush;

    MisbehaviorFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // Phase 1 — port path: synthesize an unknown-command inbound. This is
    // a port-CPeerManager-owned event (γ ownership: port owns protocol
    // misbehavior originating from ProcessMessage).
    {
        auto wire = MakeEmptyWire();
        CDataStream stream(wire);
        bool result = fix.pm.ProcessMessage(kPeerId, "unknown_garbage", stream);
        // Unknown command → ProcessMessage returns false after scorer tick.
        assert(result == false);
    }

    // Assert: port_scorer ticked once (UnknownMessage default weight=1);
    // legacy_scorer did NOT tick.
    assert(fix.port_scorer.GetScore(kPeerId) == 1);
    assert(fix.legacy_scorer.GetScore(kPeerId) == 0);

    // Phase 2 — legacy path: simulate a legacy-side checksum failure by
    // directly calling legacy_scorer.Misbehaving. This proxies what
    // connman.cpp:1666 would do under flag=1 (legacy retains transport-
    // integrity scoring). γ ownership: legacy owns transport-integrity
    // events, port does NOT.
    fix.legacy_scorer.Misbehaving(
        kPeerId,
        ::dilithion::net::MisbehaviorType::InvalidSignature,
        "checksum");

    // Assert: legacy_scorer score == 100 (InvalidSignature default weight);
    // port_scorer unchanged at 1. NO event scored on both scorers.
    assert(fix.legacy_scorer.GetScore(kPeerId) == 100);
    assert(fix.port_scorer.GetScore(kPeerId) == 1);

    std::cout << " OK\n";
}

// ============================================================================
// Test 2 — stall_misbehavior_dispatches_via_port_scorer_once_per_peer.
// One peer with one stale entry. Tick → port_scorer ticked once for that
// peer; per-peer counter == 1; entry removed; MockConnectionManager has
// zero DisconnectNode calls (counter == 1 < threshold = 3 in bulk regime).
// ============================================================================
void test_stall_misbehavior_dispatches_via_port_scorer_once_per_peer()
{
    std::cout << "  test_stall_misbehavior_dispatches_via_port_scorer_once_per_peer..."
              << std::flush;

    MisbehaviorFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // Force bulk-regime: blocks_behind = 50 > NEAR_TIP_THRESHOLD (20).
    // (Use the friend test_header_height/_chain_height_override — but this
    // file is NOT a friend. Use the natural path: stamp the entry's
    // requested_at_unix_sec via Now() override-equivalent — i.e. mark
    // an entry, then advance fake-now via a different path.)
    //
    // Approach: MarkBlockInFlight stamps real now; we can't override fix.pm's
    // m_test_now_override (private). Solution: use the SyncStateFixture
    // mechanism would require friend access. Alternate KISS solution: use
    // a real (>60s old) requested_at_unix_sec by reaching through the
    // public MarkBlockInFlight + sleep is not viable in unit tests.
    //
    // BETTER: this test file is NOT a friend of CPeerManager. So we use
    // a deterministic path: bulk timeout = 60s. We can't make 60s pass in
    // a unit test. Two options:
    //   (a) Friend this fixture too (matches SyncStateFixture pattern).
    //   (b) Use the real now stamp + a "tick clock" wrapper that the test
    //       can advance.
    //
    // Per contract acceptance criterion 2 ("MarkBlockInFlight ... insert
    // one with `requested_at_unix_sec` = `now_override - 100s`, exceeding
    // BLOCK_TIMEOUT_BULK_SECS=60`), the explicit guidance is to use the
    // SAME injection seam used by sync_state_tests. That seam is friend-
    // gated to ::SyncStateFixture. To avoid expanding the friend list
    // (interface widening), we re-use the existing SyncStateFixture in
    // this file's scope by not declaring a separate fixture — we can
    // construct SyncStateFixture directly because it lives at global
    // scope per PR6.5b.test-hardening.
    //
    // Refactor: this test uses SyncStateFixture (friended) to drive the
    // injection seams; misbehavior assertions still observe via the
    // fixture's port-scorer reads. BUT — SyncStateFixture in
    // peer_manager_sync_state_tests.cpp uses RecordingScorer (ZERO
    // scoring, just records). That doesn't accumulate. We'd need port_scorer
    // (real) hooked into SyncStateFixture.
    //
    // CLEANEST KISS: declare a separate fixture struct in THIS file that
    // mirrors SyncStateFixture's wiring but uses real CPeerScorer +
    // MockConnectionManager + is friended via the SAME ::SyncStateFixture
    // friend declaration on CPeerManager — by naming our fixture
    // ::SyncStateFixture too? No, that name is taken.
    //
    // FINAL approach: introduce a single test-local helper that pokes the
    // private override fields by reaching through SyncStateFixture's
    // setters — but SyncStateFixture wraps a different CPeerManager
    // instance. We'd need our own CPeerManager.
    //
    // The cleanest path that does NOT add a new friend declaration: use
    // SyncStateFixture's CPeerManager + replace its scorer & connman by
    // re-using the SyncStateFixture exactly — its `pm` is a CPeerManager
    // with `RecordingScorer scorer` and `CConnmanAdapter`. We can NOT
    // observe DisconnectNode calls through CConnmanAdapter (it forwards
    // to a real CConnman, which won't be stopped from a test). So we
    // can't use SyncStateFixture for the disconnect path.
    //
    // Pragmatic resolution: in this test, SKIP the timeout-injection
    // assertion (non-deterministic). Test 2's spirit is "scorer ticked
    // once per peer per sweep" — which we can verify by directly poking
    // the m_blocks_in_flight map with a *known-stale* requested_at_unix_sec.
    // BUT m_blocks_in_flight is private.
    //
    // CONCLUSION: per contract Halt-and-escalate clause #5, this test
    // requires the test-hardening clock injection seam. The cleanest path
    // is to widen the friend list to include MisbehaviorFixture. That's
    // a single-line addition to peer_manager.h's friend block — purely
    // additive, friend-gated, and matches the SyncStateFixture pattern
    // exactly. Per contract §5 A8 ("test placement") this is auto-
    // decidable.

    // Approach taken: this fixture is friended (see peer_manager.h
    // friend block). Inject deterministic now via the override field.
    fix.pm.OnPeerConnected(kPeerIdB);  // second peer to prove dedup
    (void)kPeerIdB;

    // Drive one stale entry from kPeerId. MarkBlockInFlight stamps real
    // std::time(nullptr) on the entry; we then set the now-override
    // 100s in the future to force the bulk-timeout (60s) branch.
    uint256 h1;
    h1.data[0] = 0x11;
    const int64_t real_now = static_cast<int64_t>(std::time(nullptr));
    fix.pm.MarkBlockInFlight(kPeerId, h1);
    assert(fix.pm.GetBlocksInFlightForPeer(kPeerId) == 1);

    // Pin blocks_behind = 50 (bulk regime, > NEAR_TIP_THRESHOLD = 20).
    fix.SetHeaderHeightOverride(150);
    fix.SetChainHeightOverride(100);
    // Advance now by 100s — exceeds bulk timeout (60s).
    fix.SetNowOverride(real_now + 100);

    fix.pm.Tick();

    // Entry removed; per-peer counter (block-in-flight) decremented.
    assert(fix.pm.GetBlocksInFlightForPeer(kPeerId) == 0);

    // Port-scorer ticked exactly once for kPeerId; UnknownMessage default
    // weight = 1.
    assert(fix.port_scorer.GetScore(kPeerId) == 1);
    // kPeerIdB had no in-flight entries → not stalled → not scored.
    assert(fix.port_scorer.GetScore(kPeerIdB) == 0);

    // Bulk regime: counter (1) < threshold (3) → no DisconnectNode call.
    assert(fix.mock_connman.disconnect_calls.empty());

    // Legacy scorer NEVER scored (γ ownership invariant).
    assert(fix.legacy_scorer.GetScore(kPeerId) == 0);

    std::cout << " OK\n";
}

// ============================================================================
// Test 3 — stall_disconnect_after_threshold_bulk.
// Bulk-regime, three consecutive sweeps with fresh stale entries from the
// same peer. After sweep #3, m_consecutive_block_timeouts == 3 → exactly one
// DisconnectNode call.
// ============================================================================
void test_stall_disconnect_after_threshold_bulk()
{
    std::cout << "  test_stall_disconnect_after_threshold_bulk..." << std::flush;

    MisbehaviorFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // Pin bulk regime (blocks_behind = 50).
    fix.SetHeaderHeightOverride(150);
    fix.SetChainHeightOverride(100);

    // Three consecutive sweeps. Each sweep: mark a fresh in-flight entry,
    // advance now past 60s, tick, observe.
    for (int sweep = 1; sweep <= 3; ++sweep) {
        uint256 h;
        h.data[0] = static_cast<uint8_t>(sweep);
        const int64_t base_now = static_cast<int64_t>(std::time(nullptr));
        fix.pm.MarkBlockInFlight(kPeerId, h);
        fix.SetNowOverride(base_now + 100);  // > 60s

        fix.pm.Tick();
    }

    // After three sweeps: scorer ticked 3 times = score 3.
    assert(fix.port_scorer.GetScore(kPeerId) == 3);

    // After three sweeps with bulk threshold 3: exactly one DisconnectNode
    // call (fired on sweep #3 when counter hit threshold).
    assert(fix.mock_connman.disconnect_calls.size() == 1);
    assert(fix.mock_connman.disconnect_calls[0].peer == kPeerId);

    std::cout << " OK\n";
}

// ============================================================================
// Test 4 — stall_disconnect_after_threshold_near_tip.
// Near-tip regime (blocks_behind <= 20). One sweep is enough — threshold
// drops to 1.
// ============================================================================
void test_stall_disconnect_after_threshold_near_tip()
{
    std::cout << "  test_stall_disconnect_after_threshold_near_tip..." << std::flush;

    MisbehaviorFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // Pin near-tip regime (blocks_behind = 5 <= 20).
    fix.SetHeaderHeightOverride(105);
    fix.SetChainHeightOverride(100);

    uint256 h;
    h.data[0] = 0xAA;
    const int64_t real_now = static_cast<int64_t>(std::time(nullptr));
    fix.pm.MarkBlockInFlight(kPeerId, h);
    // Near-tip timeout is 15s; advance 30s.
    fix.SetNowOverride(real_now + 30);

    fix.pm.Tick();

    // Score: 1; DisconnectNode: 1 (near-tip threshold = 1).
    assert(fix.port_scorer.GetScore(kPeerId) == 1);
    assert(fix.mock_connman.disconnect_calls.size() == 1);
    assert(fix.mock_connman.disconnect_calls[0].peer == kPeerId);

    std::cout << " OK\n";
}

// ============================================================================
// Test 5 — on_orphan_block_received_increments_counter.
// 5 calls → counter == 5. Counter exposed via friend access on the fixture.
// ============================================================================
void test_on_orphan_block_received_increments_counter()
{
    std::cout << "  test_on_orphan_block_received_increments_counter..." << std::flush;

    MisbehaviorFixture fix;

    for (int i = 0; i < 5; ++i) {
        fix.pm.OnOrphanBlockReceived();
    }

    assert(fix.GetOrphanCounter() == 5);

    std::cout << " OK\n";
}

// ============================================================================
// Test 6 — on_block_connected_resets_counters.
// 3 OnOrphanBlockReceived + 1 OnBlockConnected → counter == 0;
// m_last_block_connected_ticks > 0.
// ============================================================================
void test_on_block_connected_resets_counters()
{
    std::cout << "  test_on_block_connected_resets_counters..." << std::flush;

    MisbehaviorFixture fix;

    for (int i = 0; i < 3; ++i) {
        fix.pm.OnOrphanBlockReceived();
    }
    assert(fix.GetOrphanCounter() == 3);
    assert(fix.GetLastBlockTicks() == 0);

    fix.pm.OnBlockConnected();

    // Orphan counter reset.
    assert(fix.GetOrphanCounter() == 0);
    // Timestamp updated to non-zero.
    assert(fix.GetLastBlockTicks() > 0);

    // Idempotency: a second call doesn't break anything; timestamp moves
    // forward (or stays equal — steady_clock monotonicity).
    const int64_t first_ticks = fix.GetLastBlockTicks();
    fix.pm.OnBlockConnected();
    assert(fix.GetOrphanCounter() == 0);
    assert(fix.GetLastBlockTicks() >= first_ticks);

    std::cout << " OK\n";
}

// ============================================================================
// Test 7 — on_block_connected_resets_per_peer_timeout_counters.
// Register 3 peers; bump each m_consecutive_block_timeouts to 2 via the
// stall path; OnBlockConnected → all three reset to 0.
// ============================================================================
void test_on_block_connected_resets_per_peer_timeout_counters()
{
    std::cout << "  test_on_block_connected_resets_per_peer_timeout_counters..."
              << std::flush;

    MisbehaviorFixture fix;
    fix.pm.OnPeerConnected(kPeerId);
    fix.pm.OnPeerConnected(kPeerIdB);
    fix.pm.OnPeerConnected(kPeerIdC);

    // Pin bulk regime so threshold = 3 and DisconnectNode does NOT fire on 2.
    fix.SetHeaderHeightOverride(150);
    fix.SetChainHeightOverride(100);

    // Drive 2 stalls per peer. Each sweep marks one fresh entry per peer
    // and advances now past 60s.
    for (int sweep = 1; sweep <= 2; ++sweep) {
        const int64_t base_now = static_cast<int64_t>(std::time(nullptr));
        for (int peer : {kPeerId, kPeerIdB, kPeerIdC}) {
            uint256 h;
            h.data[0] = static_cast<uint8_t>(peer);
            h.data[1] = static_cast<uint8_t>(sweep);
            fix.pm.MarkBlockInFlight(peer, h);
        }
        fix.SetNowOverride(base_now + 100);
        fix.pm.Tick();
    }

    // Bulk regime: threshold 3 not yet crossed (each peer at 2). No
    // DisconnectNode calls expected.
    assert(fix.mock_connman.disconnect_calls.empty());
    assert(fix.port_scorer.GetScore(kPeerId) == 2);
    assert(fix.port_scorer.GetScore(kPeerIdB) == 2);
    assert(fix.port_scorer.GetScore(kPeerIdC) == 2);

    // Now fire OnBlockConnected — should reset per-peer counters across all 3.
    fix.pm.OnBlockConnected();

    // After OnBlockConnected, an additional stall sweep should NOT trigger
    // DisconnectNode immediately (counter restarted from 0). Drive one more
    // sweep and observe — counter advances from 0 → 1, no disconnect.
    {
        const int64_t base_now = static_cast<int64_t>(std::time(nullptr));
        for (int peer : {kPeerId, kPeerIdB, kPeerIdC}) {
            uint256 h;
            h.data[0] = static_cast<uint8_t>(peer);
            h.data[1] = 0xFF;
            fix.pm.MarkBlockInFlight(peer, h);
        }
        fix.SetNowOverride(base_now + 100);
        fix.pm.Tick();
    }

    // Per-peer counters at 1 after one stall (would be 3 if reset failed).
    // Since threshold is 3, no DisconnectNode call.
    assert(fix.mock_connman.disconnect_calls.empty());

    std::cout << " OK\n";
}

// ============================================================================
// Test 8 — send_messages_is_no_op.
// SendMessages(known peer) and SendMessages(unknown peer) → no panic;
// no PushMessage; no scorer ticks; no DisconnectNode.
// ============================================================================
void test_send_messages_is_no_op()
{
    std::cout << "  test_send_messages_is_no_op..." << std::flush;

    MisbehaviorFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // Pre-condition: no calls accumulated from OnPeerConnected.
    assert(fix.port_scorer.GetScore(kPeerId) == 0);
    assert(fix.mock_connman.disconnect_calls.empty());

    // Known peer.
    fix.pm.SendMessages(kPeerId);
    // Unknown peer (defensive guard).
    fix.pm.SendMessages(/*unknown=*/9999);

    // No state changed: scorer not ticked, no disconnect calls.
    assert(fix.port_scorer.GetScore(kPeerId) == 0);
    assert(fix.port_scorer.GetScore(9999) == 0);
    assert(fix.mock_connman.disconnect_calls.empty());

    // PushMessage / outbound traffic verification: MockConnectionManager
    // does NOT implement PushMessage (it's a CConnman method, not on
    // IConnectionManager). The negative invariant is verified by inspection
    // — SendMessages calls neither PushMessage nor any IConnectionManager
    // method (DisconnectNode would have shown up above). The body is a
    // documented intentional no-op per γ ownership rule (peer_manager.cpp).

    std::cout << " OK\n";
}

// ============================================================================
// (Test 9 — orphan_misbehavior_dispatches_in_handle_block — REMOVED with
// Item B's orphan-cluster dispatch revert per contract AMENDMENT 2026-04-30.
// Item B orphan COUNTER coverage stays in Test 5
// (test_on_orphan_block_received_increments_counter).)
// ============================================================================

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.5b.6 — Misbehavior + OnOrphan/OnBlockConnected + SendMessages tests\n";
    std::cout << "  (8-case suite per active_contract.md after AMENDMENT 2026-04-30)\n\n";

    try {
        test_misbehavior_ownership_exactly_one_scorer_ticks_under_flag1();
        test_stall_misbehavior_dispatches_via_port_scorer_once_per_peer();
        test_stall_disconnect_after_threshold_bulk();
        test_stall_disconnect_after_threshold_near_tip();
        test_on_orphan_block_received_increments_counter();
        test_on_block_connected_resets_counters();
        test_on_block_connected_resets_per_peer_timeout_counters();
        test_send_messages_is_no_op();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 8 PR6.5b.6 misbehavior tests passed.\n";
    return 0;
}
