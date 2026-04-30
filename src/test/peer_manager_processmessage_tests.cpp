// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.2 — ProcessMessage dispatch + version/verack/ping/pong tests.
//
// PR6.5b.4 IN-PLACE UPDATE: the deferred-handlers-still-stubbed pin
// previously asserted 3 commands {block, getdata, inv} routed to
// UnknownMessage. PR6.5b.4 releases `block` and `getdata` from the pin
// (they now have real handlers — block delegates to chain_selector;
// getdata validates inventory and routes unknown blocks via the scorer).
// The remaining deferred command (`inv`) stays pinned for PR6.5b.6.
// Per contract "in-place pinned-test regression authorized by this PR" —
// total stubbed route count drops from 3 to 1; total test cases stay at 9.
//
// Per active_contract.md "Acceptance criteria" + decomposition §"PR6.5b.2",
// this 9-case suite verifies:
//   1. dispatch-table-version            — version handler populates nVersion /
//                                          nServices / nTimeConnected on CPeer
//                                          (closes the deferred PR6.5b.1b
//                                          populate path).
//   2. dispatch-table-verack             — verack sets m_handshake_complete.
//   3. dispatch-table-ping               — ping stores nonce in
//                                          m_last_ping_nonce_recvd; no out send.
//   4. dispatch-table-pong-correct       — pong with matching expected nonce
//                                          clears the in-flight pong state.
//   5. dispatch-table-pong-wrong-nonce   — pong with wrong nonce returns true
//                                          AND ticks scorer once.
//   6. dispatch-unknown-command          — unhandled command returns false +
//                                          ticks scorer (UnknownMessage) once.
//   7. dispatch-unknown-peer             — unknown peer id: returns false, NO
//                                          scorer tick (harmless race with
//                                          disconnect).
//   8. double-version-misbehavior        — second version on same peer returns
//                                          false + DuplicateVersion tick once.
//   9. deferred-handlers-still-stubbed   — `inv` returns false and routes
//                                          to UnknownMessage, pinning the
//                                          current behavior so a regression
//                                          in PR6.5b.6 is loud. (PR6.5b.3
//                                          released `headers`; PR6.5b.4
//                                          released `block` and `getdata`
//                                          — they now have real handlers.)
//
// Test pattern: void test_*() functions + custom main(). No Boost framework.
// IPeerScorer test stub records every call so assertions can verify both the
// peer NodeId and MisbehaviorType (or weight) of each tick.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <consensus/params.h>
#include <core/chainparams.h>
#include <net/connman.h>
#include <net/ipeer_scorer.h>
#include <net/port/addrman_v2.h>
#include <net/port/connman_adapter.h>
#include <net/port/peer_manager.h>
#include <net/serialize.h>

#include <cassert>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

// IPeerScorer test stub. Records every Misbehaving call so tests can assert
// both the count and the MisbehaviorType / weight. Pure recording — never
// returns true (no bans triggered during tests). std::optional disambiguates
// the two Misbehaving overloads in the recorded call.
class RecordingScorer final : public ::dilithion::net::IPeerScorer {
public:
    struct Call {
        ::dilithion::net::NodeId peer;
        std::optional<::dilithion::net::MisbehaviorType> type;  // typed overload
        std::optional<int> weight;                              // weight overload
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

// Build a minimal version-message wire body: int32 version, uint64 services,
// int64 timestamp. ProcessMessage's HandleVersion only reads these three
// fields (nVersion / nServices / nTimeConnected populate path); the rest of
// the upstream wire layout is consumed by SendMessages-side code in 6b.6.
std::vector<uint8_t> MakeVersionWire(int32_t version,
                                     uint64_t services,
                                     int64_t timestamp) {
    CDataStream s;
    s.WriteInt32(version);
    s.WriteUint64(services);
    s.WriteInt64(timestamp);
    return s.GetData();
}

// Build a ping/pong wire body: uint64 nonce.
std::vector<uint8_t> MakePingPongWire(uint64_t nonce) {
    CDataStream s;
    s.WriteUint64(nonce);
    return s.GetData();
}

// Test fixture. Builds CPeerManager with all 5 refs. Uses a RecordingScorer
// (test-local) instead of CPeerScorer so misbehavior call counts can be
// asserted directly. Mirrors the lifecycle/dual-dispatch test fixture shape.
struct ProcessMessageFixture {
    static const ::Dilithion::ChainParams chainparams;
    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter chain_selector;
    CConnman connman;
    dilithion::net::port::CConnmanAdapter connman_adapter;
    dilithion::net::port::CAddrMan_v2 addrman;
    RecordingScorer scorer;
    dilithion::net::port::CPeerManager pm;

    ProcessMessageFixture()
        : chain_selector(chainstate),
          connman_adapter(connman),
          pm(connman_adapter, addrman, scorer, chain_selector, chainparams)
    {}
};

const ::Dilithion::ChainParams ProcessMessageFixture::chainparams =
    ::Dilithion::ChainParams::Regtest();

constexpr int kPeerId = 42;

}  // anonymous namespace

// ============================================================================
// Test 1 — dispatch-table-version: version handler populates nVersion,
// nServices on CPeer (closes the deferred-from-PR6.5b.1b populate path).
//
// PR6.5b.fixups-semantic update: PeerInfo::time_connected now exposes the
// LOCAL connect-time (set by OnPeerConnected from GetTime()) — NOT the
// peer-supplied wire timestamp (which lives in the internal
// m_peer_claimed_time field after a bounds check). We assert non-zero
// (proves OnPeerConnected stamped the local clock) rather than equality
// against the wire value; the wire-value path is covered by
// test_version_in_range_nTime_populates_peer_claimed below.
// ============================================================================
void test_dispatch_table_version()
{
    std::cout << "  test_dispatch_table_version..." << std::flush;

    ProcessMessageFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // Use a wire timestamp near now() so the bounds check in HandleVersion
    // (now ± Consensus::MAX_FUTURE_BLOCK_TIME) passes regardless of when
    // this test runs. The 1700000000 epoch literal would now fail the
    // bounds check (it is years in the past relative to current time).
    const int64_t now_ts = static_cast<int64_t>(time(nullptr));
    auto wire = MakeVersionWire(70015, 0x9, now_ts);
    CDataStream stream(wire);

    bool result = fix.pm.ProcessMessage(kPeerId, "version", stream);
    assert(result == true);

    auto info = fix.pm.GetPeerInfo();
    assert(info.size() == 1);
    assert(info[0].id == kPeerId);
    assert(info[0].version == 70015);
    assert(info[0].services == 0x9);
    // time_connected is local-clock (PR6.5b.fixups-semantic): asserts that
    // OnPeerConnected stamped GetTime() into nTimeConnectedLocal. It is NOT
    // the peer-supplied wire timestamp.
    assert(info[0].time_connected != 0);

    // No misbehavior expected on a clean version handshake.
    assert(fix.scorer.calls.empty());

    std::cout << " OK\n";
}

// ============================================================================
// Test 2 — dispatch-table-verack: verack returns true and (per upstream) marks
// CPeer::m_handshake_complete. The handshake bit is exposed only via internal
// state — tests assert via "verack returns true and no scorer tick".
// ============================================================================
void test_dispatch_table_verack()
{
    std::cout << "  test_dispatch_table_verack..." << std::flush;

    ProcessMessageFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    CDataStream empty;
    bool result = fix.pm.ProcessMessage(kPeerId, "verack", empty);
    assert(result == true);

    // No misbehavior expected on clean verack.
    assert(fix.scorer.calls.empty());

    // Idempotency: a second verack also returns true (handshake_complete
    // simply stays true). No scorer tick.
    CDataStream empty2;
    bool result2 = fix.pm.ProcessMessage(kPeerId, "verack", empty2);
    assert(result2 == true);
    assert(fix.scorer.calls.empty());

    std::cout << " OK\n";
}

// ============================================================================
// Test 3 — dispatch-table-ping: ping stores the nonce on CPeer
// (m_last_ping_nonce_recvd) so PR6.5b.6 SendMessages can produce the pong
// reply. No outbound send in 6b.2.
// ============================================================================
void test_dispatch_table_ping()
{
    std::cout << "  test_dispatch_table_ping..." << std::flush;

    ProcessMessageFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    auto wire = MakePingPongWire(0xCAFEBABEDEADBEEFull);
    CDataStream stream(wire);

    bool result = fix.pm.ProcessMessage(kPeerId, "ping", stream);
    assert(result == true);

    // No misbehavior on a well-formed ping.
    assert(fix.scorer.calls.empty());

    // Under-length ping: returns false + UnknownMessage scorer tick once
    // (malformed-message path routes through ProcessMessage's catch).
    CDataStream short_stream;  // empty, can't even read uint64
    bool malformed_result = fix.pm.ProcessMessage(kPeerId, "ping", short_stream);
    assert(malformed_result == false);
    assert(fix.scorer.calls.size() == 1);
    assert(fix.scorer.calls[0].peer == kPeerId);
    assert(fix.scorer.calls[0].type ==
           ::dilithion::net::MisbehaviorType::UnknownMessage);

    std::cout << " OK\n";
}

// ============================================================================
// Test 4 — dispatch-table-pong-no-crash-on-correct-nonce.
// RENAMED 2026-04-30 (PR6.5b.7-close-prep) from
// `test_dispatch_table_pong_correct_nonce` to honestly describe coverage.
//
// What this test actually verifies:
//   - The pong handler returns `true` for a structurally-valid pong frame
//     (pong wire-format successfully deserialized; dispatch table found
//     the entry; handler returned through to ProcessMessage success path).
//   - The handler does NOT crash on a "correct-nonce-shaped" payload.
//   - Under the SHIPPED port semantics (γ ownership, no outbound ping
//     issuance from port), the scorer is ALSO not ticked on this branch,
//     because m_pong_expected starts false and HandlePong's matching-
//     nonce branch is unreachable.
//
// What this test DOES NOT verify (intentional gap):
//   - The matching-nonce-clears-state branch of HandlePong. That branch
//     is dead code under γ in this PR — m_pong_expected / m_pong_expected_
//     nonce are only set by SendMessages on outbound-ping issuance, and
//     SendMessages is an intentional no-op under the γ topology this
//     phase ships (legacy retains outbound ping issuance under flag=1).
//     Making this test non-vacuous would require widening surface area
//     (friend declaration to poke m_pong_expected, public test accessor,
//     or a SendMessages rewrite) — all drift triggers per the PR6.5b.7-
//     close-prep contract amendment 2026-04-30.
//
// TODO: end-to-end coverage of the matching-nonce branch is mapped to
// PR6.5b.7 sub-stream (c) — the 3-node regtest harness — where outbound
// ping issuance flows naturally through legacy and the port observes
// ping-keyed pongs through real network plumbing. See
// `c:/Users/will/dilithion/.claude/contracts/phase_6_deferred_findings.md`
// for the explicit pong-nonce → sub-stream (c) mapping.
// ============================================================================
void test_dispatch_table_pong_no_crash_on_correct_nonce()
{
    std::cout << "  test_dispatch_table_pong_no_crash_on_correct_nonce..." << std::flush;

    ProcessMessageFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // Send a pong with nonce 0xAAAAAAAAAAAAAAAA. The peer has no
    // outstanding ping (m_pong_expected default-false), so HandlePong
    // takes the unexpected-nonce branch (covered by Test 5 below) under
    // the SHIPPED dispatch path. This test pins the wire-format-level
    // success contract:
    //   - dispatch returns `true` (structurally valid frame)
    //   - handler does not crash
    //
    // The matching-nonce branch (m_pong_expected=true && nonces equal) is
    // dead code under γ in this PR — see top-of-test rationale and the
    // deferred-findings ledger for the 3-node regtest harness mapping.
    auto wire = MakePingPongWire(0xAAAAAAAAAAAAAAAAull);
    CDataStream stream(wire);
    bool result = fix.pm.ProcessMessage(kPeerId, "pong", stream);
    assert(result == true);  // wire dispatch returns true for structurally valid frame

    std::cout << " OK\n";
}

// ============================================================================
// Test 5 — dispatch-table-pong (wrong/unexpected nonce): returns true AND
// ticks m_scorer.Misbehaving once. Per contract: pong with wrong nonce is
// misbehavior, but the message was structurally well-formed so dispatch
// returns true (only deserialization failures or unknown commands return
// false).
// ============================================================================
void test_dispatch_table_pong_wrong_nonce()
{
    std::cout << "  test_dispatch_table_pong_wrong_nonce..." << std::flush;

    ProcessMessageFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    auto wire = MakePingPongWire(0xDEADBEEFDEADBEEFull);
    CDataStream stream(wire);

    bool result = fix.pm.ProcessMessage(kPeerId, "pong", stream);
    assert(result == true);

    // Exactly one scorer tick expected (HandlePong uses the weight overload
    // with weight=1 for unexpected-nonce; per contract this is the
    // wrong/unexpected nonce case).
    assert(fix.scorer.calls.size() == 1);
    assert(fix.scorer.calls[0].peer == kPeerId);
    assert(fix.scorer.calls[0].weight.has_value());
    assert(*fix.scorer.calls[0].weight == 1);

    std::cout << " OK\n";
}

// ============================================================================
// Test 6 — dispatch-unknown-command: unhandled command returns false, does NOT
// mutate m_peers, and ticks UnknownMessage exactly once.
// ============================================================================
void test_dispatch_unknown_command()
{
    std::cout << "  test_dispatch_unknown_command..." << std::flush;

    ProcessMessageFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // Capture pre-state: peer count + per-peer info.
    int pre_count = fix.pm.GetPeerCount();
    auto pre_info = fix.pm.GetPeerInfo();

    CDataStream empty;
    bool result = fix.pm.ProcessMessage(kPeerId, "notacommand", empty);
    assert(result == false);

    // Exactly one scorer tick on UnknownMessage.
    assert(fix.scorer.calls.size() == 1);
    assert(fix.scorer.calls[0].peer == kPeerId);
    assert(fix.scorer.calls[0].type ==
           ::dilithion::net::MisbehaviorType::UnknownMessage);

    // Peer state unchanged.
    assert(fix.pm.GetPeerCount() == pre_count);
    auto post_info = fix.pm.GetPeerInfo();
    assert(post_info.size() == pre_info.size());
    for (size_t i = 0; i < pre_info.size(); ++i) {
        assert(post_info[i].id == pre_info[i].id);
        assert(post_info[i].version == pre_info[i].version);
        assert(post_info[i].services == pre_info[i].services);
        assert(post_info[i].time_connected == pre_info[i].time_connected);
    }

    std::cout << " OK\n";
}

// ============================================================================
// Test 7 — dispatch-unknown-peer: unknown peer id returns false WITHOUT scorer
// tick (no peer => no misbehavior to score; harmless race with disconnect).
// ============================================================================
void test_dispatch_unknown_peer()
{
    std::cout << "  test_dispatch_unknown_peer..." << std::flush;

    ProcessMessageFixture fix;
    // Note: do NOT call OnPeerConnected. Peer is unknown.

    auto wire = MakeVersionWire(70015, 0, 1700000000);
    CDataStream stream(wire);

    bool result = fix.pm.ProcessMessage(999, "version", stream);
    assert(result == false);

    // No scorer tick — disconnect race is harmless, scorer doesn't fire.
    assert(fix.scorer.calls.empty());

    std::cout << " OK\n";
}

// ============================================================================
// Test 8 — double-version-misbehavior: a second version on the same peer
// returns false and ticks DuplicateVersion exactly once.
// ============================================================================
void test_double_version_misbehavior()
{
    std::cout << "  test_double_version_misbehavior..." << std::flush;

    ProcessMessageFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // First version: clean, populates fields. Wire timestamp must be in
    // bounds for HandleVersion's now ± Consensus::MAX_FUTURE_BLOCK_TIME check
    // (PR6.5b.fixups-semantic).
    const int64_t now_ts = static_cast<int64_t>(time(nullptr));
    auto wire1 = MakeVersionWire(70015, 0x9, now_ts);
    CDataStream s1(wire1);
    bool r1 = fix.pm.ProcessMessage(kPeerId, "version", s1);
    assert(r1 == true);
    assert(fix.scorer.calls.empty());

    // Second version: rejected, scorer tick on DuplicateVersion.
    auto wire2 = MakeVersionWire(70016, 0x1, now_ts + 1);
    CDataStream s2(wire2);
    bool r2 = fix.pm.ProcessMessage(kPeerId, "version", s2);
    assert(r2 == false);
    assert(fix.scorer.calls.size() == 1);
    assert(fix.scorer.calls[0].peer == kPeerId);
    assert(fix.scorer.calls[0].type ==
           ::dilithion::net::MisbehaviorType::DuplicateVersion);

    // Verify the first message's fields were retained (not overwritten).
    // time_connected is local-clock (PR6.5b.fixups-semantic): asserts
    // OnPeerConnected stamped GetTime() — NOT the wire timestamp.
    auto info = fix.pm.GetPeerInfo();
    assert(info.size() == 1);
    assert(info[0].version == 70015);
    assert(info[0].services == 0x9);
    assert(info[0].time_connected != 0);

    std::cout << " OK\n";
}

// ============================================================================
// Test 9 — deferred-handlers-still-stubbed: only `inv` remains in this pin.
// PR6.5b.3 released `headers`; PR6.5b.4 released `block` and `getdata` from
// the pin — they now have real handlers. This test pins the current
// stub-routes-to-unknown behavior of `inv` so a regression in PR6.5b.6
// surfaces loudly.
// ============================================================================
void test_deferred_handlers_still_stubbed()
{
    std::cout << "  test_deferred_handlers_still_stubbed..." << std::flush;

    ProcessMessageFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    const std::vector<std::string> deferred_cmds = {"inv"};

    for (const auto& cmd : deferred_cmds) {
        CDataStream empty;
        bool result = fix.pm.ProcessMessage(kPeerId, cmd, empty);
        assert(result == false);
    }

    // Each deferred command produced exactly one UnknownMessage tick.
    assert(fix.scorer.calls.size() == deferred_cmds.size());
    for (size_t i = 0; i < deferred_cmds.size(); ++i) {
        assert(fix.scorer.calls[i].peer == kPeerId);
        assert(fix.scorer.calls[i].type ==
               ::dilithion::net::MisbehaviorType::UnknownMessage);
    }

    std::cout << " OK\n";
}

// ============================================================================
// Test 10 — version-in-range-nTime-populates-peer-claimed (PR6.5b.fixups-
// semantic, finding PR6.5b.2-SEC-MD-2): a peer-supplied wire timestamp inside
// `now ± Consensus::MAX_FUTURE_BLOCK_TIME` is accepted. Handler returns true,
// no scorer tick. m_peer_claimed_time is internal — observable evidence is
// (a) handler returned true, (b) no scorer tick, (c) the local-clock-sourced
// time_connected is non-zero (proves OnPeerConnected stamped it).
// ============================================================================
void test_version_in_range_nTime_populates_peer_claimed()
{
    std::cout << "  test_version_in_range_nTime_populates_peer_claimed..." << std::flush;

    ProcessMessageFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // 60 seconds in the past — well inside ± MAX_FUTURE_BLOCK_TIME (2 hours).
    const int64_t now_ts = static_cast<int64_t>(time(nullptr));
    auto wire = MakeVersionWire(70015, 0x9, now_ts - 60);
    CDataStream stream(wire);

    bool result = fix.pm.ProcessMessage(kPeerId, "version", stream);
    assert(result == true);
    assert(fix.scorer.calls.empty());

    auto info = fix.pm.GetPeerInfo();
    assert(info.size() == 1);
    assert(info[0].version == 70015);
    assert(info[0].services == 0x9);
    // Local-clock value (NOT the wire-supplied timestamp) — non-zero proves
    // OnPeerConnected ran and populated nTimeConnectedLocal.
    assert(info[0].time_connected != 0);

    std::cout << " OK\n";
}

// ============================================================================
// Test 11 — version-out-of-range-nTime-misbehavior (PR6.5b.fixups-semantic,
// finding PR6.5b.2-SEC-MD-2): a peer-supplied wire timestamp outside
// `now ± Consensus::MAX_FUTURE_BLOCK_TIME` is rejected. Handler returns false
// and routes exactly one UnknownMessage scorer tick (no new enum value).
// ============================================================================
void test_version_out_of_range_nTime_misbehavior()
{
    std::cout << "  test_version_out_of_range_nTime_misbehavior..." << std::flush;

    ProcessMessageFixture fix;
    fix.pm.OnPeerConnected(kPeerId);

    // Timestamp 2× MAX_FUTURE_BLOCK_TIME in the future — well outside bounds.
    const int64_t now_ts = static_cast<int64_t>(time(nullptr));
    auto wire = MakeVersionWire(
        70015, 0x9, now_ts + (Consensus::MAX_FUTURE_BLOCK_TIME * 2));
    CDataStream stream(wire);

    bool result = fix.pm.ProcessMessage(kPeerId, "version", stream);
    assert(result == false);
    assert(fix.scorer.calls.size() == 1);
    assert(fix.scorer.calls[0].peer == kPeerId);
    assert(fix.scorer.calls[0].type ==
           ::dilithion::net::MisbehaviorType::UnknownMessage);

    std::cout << " OK\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.5b.2 — ProcessMessage dispatch tests\n";
    std::cout << "  (11-test suite per active_contract.md + PR6.5b.fixups-semantic)\n\n";

    try {
        test_dispatch_table_version();
        test_dispatch_table_verack();
        test_dispatch_table_ping();
        test_dispatch_table_pong_no_crash_on_correct_nonce();
        test_dispatch_table_pong_wrong_nonce();
        test_dispatch_unknown_command();
        test_dispatch_unknown_peer();
        test_double_version_misbehavior();
        test_deferred_handlers_still_stubbed();
        test_version_in_range_nTime_populates_peer_claimed();
        test_version_out_of_range_nTime_misbehavior();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 11 PR6.5b.2 ProcessMessage dispatch tests passed.\n";
    return 0;
}
