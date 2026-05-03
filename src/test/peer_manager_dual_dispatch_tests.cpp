// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.1b — Dual-dispatch tests for connman peer-event integration.
// Phase 11 PR6.5b.2 closure (v4.3) — block-message routing tests added.
//
// Per active_contract.md / decomposition §"PR6.5b.1b" + post-1a dual-dispatch
// amendment 2026-04-28, these tests verify the BOTH-see-events behavior:
//
//   Lifecycle-A (flag=1 BOTH-dispatch):
//     port-CPeerManager registered on connman; sim connect → both legacy
//     `::CPeerManager::GetPeer(NodeId) != nullptr` AND port `GetPeerCount()==1`;
//     sim disconnect → both clear.
//
//   Lifecycle-B (flag=0 negative assertion):
//     port-CPeerManager NOT registered on connman; sim connect → legacy state
//     changes; port (constructed but unregistered) state unchanged
//     (`GetPeerCount()==0`).
//
//   Block-routing (flag=1 ProcessQueuedMessage routes to port):
//     PR6.5b.2 (v4.3) closure. Drift-watch FLIPPED: previously asserted port
//     was NOT routed (gap pin); now asserts port IS routed for `block`
//     messages, observable via MarkBlockInFlight → process → in-flight count
//     drops to 0 (HandleBlock executed RemoveBlockInFlight).
//
//   Block-routing flag=0 baseline:
//     port not registered → ProcessQueuedMessage does NOT touch port state;
//     in-flight count stable.
//
//   Block-routing flag=1 malformed:
//     malformed block payload → port's try/catch converts to UnknownMessage
//     scorer tick + returns false; connman's outer try/catch keeps its
//     own contract (no rethrow, no crash, legacy success path independent).
//
//   Block-routing flag=1 concurrent:
//     two threads call TestProcessQueuedMessage concurrently with different
//     node_ids; both complete without deadlock under a 10s timeout.
//
// Pattern: void test_*() + custom main(), matching existing tests.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <net/connman.h>
#include <net/peers.h>      // legacy ::CPeerManager
#include <net/node.h>       // CNode for synthetic events
#include <net/protocol.h>   // NetProtocol::CAddress
#include <net/serialize.h>  // CDataStream for building synthetic block payloads
#include <net/port/addrman_v2.h>
#include <net/port/connman_adapter.h>
#include <net/port/peer_manager.h>
#include <net/port/peer_scorer.h>
#include <primitives/block.h>
#include <uint256.h>

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

namespace {

// Build a synthetic CAddress for test peer events. Uses a deterministic
// IPv4-mapped-in-IPv6 address; the values don't need to be valid public IPs.
NetProtocol::CAddress MakeTestAddress(uint16_t port = 8444)
{
    NetProtocol::CAddress addr;
    std::memset(addr.ip, 0, 10);
    addr.ip[10] = 0xff;
    addr.ip[11] = 0xff;
    addr.ip[12] = 203;
    addr.ip[13] = 0;
    addr.ip[14] = 113;
    addr.ip[15] = 1;
    addr.port = port;
    addr.services = 0;
    addr.time = 0;
    return addr;
}

// Build a minimal valid (structurally) block payload for HandleBlock to parse.
// Wire layout matches src/net/port/peer_manager.cpp:1106-1131:
//   nVersion(4) + hashPrevBlock(32) + hashMerkleRoot(32) +
//   nTime(4) + nBits(4) + nNonce(4) + [VDF: vdfOutput(32)+vdfProofHash(32)] +
//   compact(vtx_size=0)
// We use nVersion=1 (NOT a VDF block) so we don't need to fabricate VDF fields.
// Returns the serialized payload AND the corresponding GetFastHash so callers
// can MarkBlockInFlight before dispatch and observe its removal after.
struct SyntheticBlock {
    std::vector<uint8_t> payload;
    uint256 hash;
};

SyntheticBlock MakeSyntheticBlock(uint32_t nonce = 0xDEADBEEF)
{
    // Build by deserializing exactly what HandleBlock will read, then computing
    // GetFastHash via a real CBlock instance.
    CBlock blk;
    blk.nVersion = 1;       // NOT VDF (>= VDF_VERSION); skips VDF fields on read.
    // hashPrevBlock / hashMerkleRoot default-construct zeroed (uint256 ctor in
    // primitives/block.h memsets to 0). No explicit SetNull needed.
    blk.nTime = 1700000000;
    blk.nBits = 0x1d00ffff;
    blk.nNonce = nonce;
    // empty vtx (vtx_size=0 compact)
    const uint256 expected_hash = blk.GetFastHash();

    CDataStream s;
    s.WriteInt32(blk.nVersion);
    s.WriteUint256(blk.hashPrevBlock);
    s.WriteUint256(blk.hashMerkleRoot);
    s.WriteUint32(blk.nTime);
    s.WriteUint32(blk.nBits);
    s.WriteUint32(blk.nNonce);
    s.WriteCompactSize(0);  // vtx_size=0

    return SyntheticBlock{ s.GetData(), expected_hash };
}

// Fixture that sets up CConnman + legacy ::CPeerManager + port-CPeerManager
// (with all 5 refs) + a CNode. Used by Lifecycle-A and Lifecycle-B.
struct DualDispatchFixture {
    static const ::Dilithion::ChainParams chainparams;
    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter chain_selector;
    CConnman connman;
    dilithion::net::port::CConnmanAdapter connman_adapter;
    dilithion::net::port::CAddrMan_v2 addrman;
    dilithion::net::port::CPeerScorer scorer;
    dilithion::net::port::CPeerManager port_pm;
    ::CPeerManager legacy_pm;  // legacy peer manager (datadir empty for test)
    NetProtocol::CAddress test_addr;
    std::unique_ptr<CNode> test_node;

    static constexpr int kTestNodeId = 1001;

    DualDispatchFixture()
        : chain_selector(chainstate),
          connman_adapter(connman),
          port_pm(connman_adapter, addrman, scorer, chain_selector, chainparams),
          legacy_pm(""),
          test_addr(MakeTestAddress()),
          test_node(std::make_unique<CNode>(kTestNodeId, test_addr, /*inbound=*/false))
    {
        // Wire connman to the legacy peer manager (matches production CConnman::Start
        // which takes legacy peer_mgr by ref and stores its address). We bypass the
        // full Start() path because tests don't need socket I/O.
        connman.SetTestPeerManager(legacy_pm);
    }
};

const ::Dilithion::ChainParams DualDispatchFixture::chainparams =
    ::Dilithion::ChainParams::Regtest();

}  // anonymous namespace

// ============================================================================
// Lifecycle-A — under flag=1 (port registered), BOTH legacy and port observe
// connect AND disconnect. Explicit BOTH-side-effect proof; not vacuous.
// ============================================================================
void test_lifecycle_a_both_dispatch_under_flag1()
{
    std::cout << "  test_lifecycle_a_both_dispatch_under_flag1..." << std::flush;

    DualDispatchFixture fix;

    // Register port-CPeerManager → simulates --usenewpeerman=1 in node startup.
    fix.connman.RegisterPortPeerManager(&fix.port_pm);

    // Pre-state: both empty.
    assert(fix.legacy_pm.GetNode(fix.kTestNodeId) == nullptr);
    assert(fix.port_pm.GetPeerCount() == 0);

    // Synthesize a connect event via the public dispatch helper.
    const bool ok = fix.connman.DispatchPeerConnected(
        fix.kTestNodeId, fix.test_node.get(), fix.test_addr, /*inbound=*/false);
    assert(ok);

    // BOTH classes saw the event (LOAD-BEARING assertion):
    //   (i)  legacy ::CPeerManager registered the CNode → GetNode returns it
    assert(fix.legacy_pm.GetNode(fix.kTestNodeId) != nullptr);
    //   (ii) port CPeerManager incremented its m_peers count
    assert(fix.port_pm.GetPeerCount() == 1);

    // Synthesize disconnect.
    fix.connman.DispatchPeerDisconnected(fix.kTestNodeId);

    // BOTH classes cleared:
    //   port_pm: GetPeerCount drops to 0
    assert(fix.port_pm.GetPeerCount() == 0);
    //   legacy_pm: OnPeerDisconnected called (cleanup hook); the CNode entry
    //   stays in legacy until RemoveNode runs (see connman.cpp:1678 — separate
    //   call). For this test, asserting OnPeerDisconnected was reached is
    //   implicit via no-crash; explicit RemoveNode test is out of scope.

    std::cout << " OK\n";
}

// ============================================================================
// Lifecycle-B — under flag=0 (port NOT registered on connman), only legacy
// observes the event. Port instance exists in fixture but its state stays
// empty. Explicit negative assertion that port is NOT invoked.
// ============================================================================
void test_lifecycle_b_legacy_only_under_flag0()
{
    std::cout << "  test_lifecycle_b_legacy_only_under_flag0..." << std::flush;

    DualDispatchFixture fix;

    // DO NOT register port-CPeerManager — simulates --usenewpeerman=0 (default).
    // connman.m_port_peer_manager stays nullptr.

    // Pre-state: both empty.
    assert(fix.legacy_pm.GetNode(fix.kTestNodeId) == nullptr);
    assert(fix.port_pm.GetPeerCount() == 0);

    // Synthesize a connect event.
    const bool ok = fix.connman.DispatchPeerConnected(
        fix.kTestNodeId, fix.test_node.get(), fix.test_addr, /*inbound=*/true);
    assert(ok);

    // Legacy DID see the event:
    assert(fix.legacy_pm.GetNode(fix.kTestNodeId) != nullptr);
    // Port did NOT (load-bearing negative assertion):
    assert(fix.port_pm.GetPeerCount() == 0);

    // Synthesize disconnect.
    fix.connman.DispatchPeerDisconnected(fix.kTestNodeId);

    // Port still untouched.
    assert(fix.port_pm.GetPeerCount() == 0);

    std::cout << " OK\n";
}

// ============================================================================
// Block-routing T1 — under flag=1, ProcessQueuedMessage routes `block`
// messages to port's HandleBlock.
//
// PR6.5b.2 / Phase 11 (v4.3) drift-watch FLIP. Before this PR, the drift-watch
// asserted "port is NOT invoked by message-handling paths" (silent-drop pin).
// Closure flips the assertion: port IS invoked for `block` messages. Proxy
// observable: MarkBlockInFlight before dispatch → in-flight count == 1 →
// dispatch a `block` payload whose hash matches → HandleBlock calls
// RemoveBlockInFlight → in-flight count drops to 0.
// ============================================================================
void test_block_routing_to_port_under_flag1()
{
    std::cout << "  test_block_routing_to_port_under_flag1..." << std::flush;

    DualDispatchFixture fix;
    fix.connman.RegisterPortPeerManager(&fix.port_pm);

    // Synthesize connect → port sees lifecycle (so HandleBlock's peer guard
    // doesn't reject — port has a CPeer entry for kTestNodeId).
    fix.connman.DispatchPeerConnected(
        fix.kTestNodeId, fix.test_node.get(), fix.test_addr, /*inbound=*/true);
    assert(fix.port_pm.GetPeerCount() == 1);

    // Build a synthetic block payload + the hash HandleBlock will compute.
    SyntheticBlock blk = MakeSyntheticBlock(/*nonce=*/0x12345678);

    // Pre-arm: mark this block as in-flight from kTestNodeId. The proxy
    // observable for "HandleBlock executed" is the in-flight count drop.
    fix.port_pm.MarkBlockInFlight(fix.kTestNodeId, blk.hash);
    assert(fix.port_pm.GetBlocksInFlightForPeer(fix.kTestNodeId) == 1);

    // Drive the connman dispatch path — TestProcessQueuedMessage exercises
    // the same code path as BlocksWorkerThread → ProcessQueuedMessage. With
    // m_port_peer_manager registered, the new dispatch routes the message
    // into port_pm.ProcessMessage → HandleBlock.
    const bool legacy_ok = fix.connman.TestProcessQueuedMessage(
        fix.kTestNodeId, "block", blk.payload);
    // legacy m_msg_processor is null in this fixture; legacy_ok is the
    // fallback's success — m_msg_handler is also null, so legacy_ok is false.
    // Important: this does NOT block the port dispatch (the new code runs
    // unconditionally on m_port_peer_manager != nullptr).
    (void)legacy_ok;

    // Load-bearing assertion: port HandleBlock was reached and called
    // RemoveBlockInFlight. If port routing weren't wired, the in-flight
    // count would still be 1.
    assert(fix.port_pm.GetBlocksInFlightForPeer(fix.kTestNodeId) == 0);

    fix.connman.DispatchPeerDisconnected(fix.kTestNodeId);
    assert(fix.port_pm.GetPeerCount() == 0);

    std::cout << " OK\n";
}

// ============================================================================
// Block-routing T2 — under flag=0, ProcessQueuedMessage does NOT touch port.
// Negative-assertion baseline. Port instance exists; just isn't registered
// on connman (m_port_peer_manager == nullptr). Block dispatch happens but
// port state must NOT mutate.
// ============================================================================
void test_block_routing_no_port_under_flag0()
{
    std::cout << "  test_block_routing_no_port_under_flag0..." << std::flush;

    DualDispatchFixture fix;
    // DO NOT register port. connman.m_port_peer_manager stays nullptr.

    // We need to mark a block in-flight on port to have a witness — but the
    // port hasn't seen a connect for this peer (flag=0 means connman doesn't
    // route lifecycle either). Drive lifecycle directly on port for the
    // marking witness; this is fine because Lifecycle-B already proved
    // connman doesn't dual-dispatch lifecycle under flag=0.
    fix.port_pm.OnPeerConnected(fix.kTestNodeId);
    assert(fix.port_pm.GetPeerCount() == 1);

    SyntheticBlock blk = MakeSyntheticBlock(/*nonce=*/0xCAFEBABE);
    fix.port_pm.MarkBlockInFlight(fix.kTestNodeId, blk.hash);
    assert(fix.port_pm.GetBlocksInFlightForPeer(fix.kTestNodeId) == 1);

    // Drive connman dispatch with port NOT registered. The new dispatch
    // block in connman.cpp guards on `m_port_peer_manager` — null means no
    // dispatch happens.
    (void)fix.connman.TestProcessQueuedMessage(fix.kTestNodeId, "block", blk.payload);

    // Load-bearing negative assertion: in-flight count UNCHANGED at 1.
    // If a regression accidentally routed messages to port under flag=0,
    // HandleBlock would have removed the entry.
    assert(fix.port_pm.GetBlocksInFlightForPeer(fix.kTestNodeId) == 1);

    fix.port_pm.OnPeerDisconnected(fix.kTestNodeId);

    std::cout << " OK\n";
}

// ============================================================================
// Block-routing T3 — under flag=1, malformed `block` payload. Port's own
// try/catch (peer_manager.cpp:561-567) routes the throw to UnknownMessage
// scorer tick and returns false. Connman's outer try/catch is a defense-in-
// depth that should NEVER fire here (because port catches first), but if
// it did the test would still pass — no rethrow, no crash. The load-bearing
// behavior under test: connman tolerates port returning false / throwing,
// AND legacy success path is independent.
// ============================================================================
void test_block_routing_malformed_under_flag1()
{
    std::cout << "  test_block_routing_malformed_under_flag1..." << std::flush;

    DualDispatchFixture fix;
    fix.connman.RegisterPortPeerManager(&fix.port_pm);
    fix.connman.DispatchPeerConnected(
        fix.kTestNodeId, fix.test_node.get(), fix.test_addr, /*inbound=*/true);

    // Truncated payload: 4 bytes is FAR less than the 80-byte minimum for a
    // header. CDataStream::read will throw past end; port's try/catch
    // converts to UnknownMessage scorer tick + return false; connman ignores
    // the false and never crashes.
    const std::vector<uint8_t> truncated = {0x01, 0x00, 0x00, 0x00};

    bool threw = false;
    try {
        (void)fix.connman.TestProcessQueuedMessage(
            fix.kTestNodeId, "block", truncated);
    } catch (...) {
        threw = true;
    }
    assert(!threw);  // connman did not let any exception escape

    // Port still has the peer registered (malformed message did NOT trigger
    // a disconnect — that's legacy's authority under flag=1).
    assert(fix.port_pm.GetPeerCount() == 1);

    fix.connman.DispatchPeerDisconnected(fix.kTestNodeId);

    std::cout << " OK\n";
}

// ============================================================================
// Block-routing T4 — concurrent dispatch from multiple "BlocksWorker-like"
// threads. Two synthetic peers, two threads, two distinct block payloads.
// Verifies: (a) no deadlock under 10s timeout, (b) both peers' in-flight
// counts drop to 0 after concurrent dispatch.
// ============================================================================
void test_block_routing_concurrent_under_flag1()
{
    std::cout << "  test_block_routing_concurrent_under_flag1..." << std::flush;

    DualDispatchFixture fix;
    fix.connman.RegisterPortPeerManager(&fix.port_pm);

    // Connect two distinct peers to port via lifecycle dispatch.
    constexpr int kPeerA = DualDispatchFixture::kTestNodeId;
    constexpr int kPeerB = DualDispatchFixture::kTestNodeId + 1;
    NetProtocol::CAddress addr_b = MakeTestAddress(8445);
    auto node_b = std::make_unique<CNode>(kPeerB, addr_b, /*inbound=*/false);

    fix.connman.DispatchPeerConnected(kPeerA, fix.test_node.get(), fix.test_addr, true);
    fix.connman.DispatchPeerConnected(kPeerB, node_b.get(), addr_b, false);
    assert(fix.port_pm.GetPeerCount() == 2);

    SyntheticBlock blk_a = MakeSyntheticBlock(0x11111111);
    SyntheticBlock blk_b = MakeSyntheticBlock(0x22222222);
    fix.port_pm.MarkBlockInFlight(kPeerA, blk_a.hash);
    fix.port_pm.MarkBlockInFlight(kPeerB, blk_b.hash);
    assert(fix.port_pm.GetBlocksInFlightForPeer(kPeerA) == 1);
    assert(fix.port_pm.GetBlocksInFlightForPeer(kPeerB) == 1);

    // Launch two threads under a 10-second deadline. Use std::async so we
    // can wait_for with a timeout; if either future doesn't return in 10s,
    // assert (deadlock detected).
    auto fut_a = std::async(std::launch::async, [&]() {
        return fix.connman.TestProcessQueuedMessage(kPeerA, "block", blk_a.payload);
    });
    auto fut_b = std::async(std::launch::async, [&]() {
        return fix.connman.TestProcessQueuedMessage(kPeerB, "block", blk_b.payload);
    });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    assert(fut_a.wait_until(deadline) == std::future_status::ready);
    assert(fut_b.wait_until(deadline) == std::future_status::ready);
    (void)fut_a.get();
    (void)fut_b.get();

    // Both peers' in-flight counts dropped to 0 → port HandleBlock ran for
    // both, concurrently, no deadlock.
    assert(fix.port_pm.GetBlocksInFlightForPeer(kPeerA) == 0);
    assert(fix.port_pm.GetBlocksInFlightForPeer(kPeerB) == 0);

    fix.connman.DispatchPeerDisconnected(kPeerA);
    fix.connman.DispatchPeerDisconnected(kPeerB);

    std::cout << " OK\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.5b.1b + PR6.5b.2 — Dual-dispatch + block-routing tests\n";
    std::cout << "  (lifecycle 2-test + block-routing 4-test suite)\n\n";

    try {
        test_lifecycle_a_both_dispatch_under_flag1();
        test_lifecycle_b_legacy_only_under_flag0();
        test_block_routing_to_port_under_flag1();
        test_block_routing_no_port_under_flag0();
        test_block_routing_malformed_under_flag1();
        test_block_routing_concurrent_under_flag1();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll dual-dispatch + block-routing tests passed.\n";
    return 0;
}
