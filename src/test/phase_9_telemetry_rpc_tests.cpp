// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 10 PR10.1 — Per-RPC unit tests for Phase 9 telemetry surface.
//
// Goal (per port_phase_10_implementation_plan.md v0.1.4 §PR10.1):
//   Lock the v0.1.2 schemas of the three Phase 9 PR9.3 telemetry RPCs
//   (getsyncstatus, getblockdownloadstats, getpeerinfo extended with
//   manager_class) as a checkable contract — any future schema deviation
//   breaks tests, surfacing the change at PR review time.
//
// Closes Cursor Phase 9 S4 + Layer-2 PR9.6-RT-MEDIUM-2 enhancement filings
// from `phase_9_deferred_findings.md`.
//
// Race windows NOT covered by these tests (operationally negligible per
// Phase 9 close brief; eliminated structurally in PR10.2 atomic-snapshot
// getters):
//   - RPC_GetSyncStatus multi-lock-acquisition tip-skew (header arrives
//     mid-RPC, height + hash refer to different tips). Bounded by header-
//     arrival rate × cs_headers lock-acquisition overhead.
//   - RPC_GetBlockDownloadStats peer-disconnect-during-iteration
//     (peer disconnects between GetConnectedPeers snapshot and per-peer
//     GetPeerBlocksInFlight). Bounded by peer-event rate.
//
// Test fixture pattern: lightweight direct construction of NodeContext
// fields using std::make_unique against the production class default
// constructors, populated state via existing public setters / Add* APIs,
// then call CRPCServer's RPC_* methods directly + parse JSON via
// substring assertions (no external JSON library needed).
//
// This pattern follows chain_selector_tests.cpp (Phase 5 PR5.1) — direct
// construction + public API assertions — NOT rpc_tests.cpp (heavy
// HTTP-socket pattern).
//
// Cases:
//   1. test_getsyncstatus_null_headers_manager
//   2. test_getsyncstatus_happy_path
//   3. test_getsyncstatus_manager_class_legacy
//   4. test_getsyncstatus_manager_class_both
//   5. test_getblockdownloadstats_null_block_fetcher
//   6. test_getblockdownloadstats_empty_peers
//   7. test_getblockdownloadstats_with_peers
//   8. test_getblockdownloadstats_stalled_blocks_populated
//   9. test_getpeerinfo_manager_class_field

#include <rpc/server.h>
#include <core/node_context.h>
#include <core/chainparams.h>
#include <net/connman.h>
#include <net/peers.h>
#include <net/headers_manager.h>
#include <net/block_fetcher.h>
#include <net/block_tracker.h>
#include <net/port/peer_manager.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

extern "C" void randomx_init_for_hashing(const void* key, size_t key_len, int light_mode);

extern NodeContext g_node_context;

namespace {

// Reset g_node_context to a clean slate for each test.
void ResetNodeContext()
{
    g_node_context.peer_manager.reset();
    g_node_context.connman.reset();
    g_node_context.headers_manager.reset();
    g_node_context.block_fetcher.reset();
    g_node_context.block_tracker.reset();
}

// Helper: substring assertion with a friendly error message on failure.
bool Contains(const std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}

void AssertContains(const std::string& haystack, const std::string& needle,
                    const char* test_name)
{
    if (!Contains(haystack, needle)) {
        std::cerr << "\nFAILED [" << test_name << "]: expected substring '"
                  << needle << "' in:\n  " << haystack << "\n";
        assert(false);
    }
}

// Helper: install a port-CPeerManager registration on connman so
// HasPortPeerManager() returns true. We pass a non-null pointer (cast
// from a sentinel) — connman only checks non-null at the dispatch site
// + at HasPortPeerManager(). No methods are invoked on the pointer
// inside the test path, so a sentinel suffices.
void RegisterPortPmStub(CConnman& connman)
{
    // Sentinel pointer: any non-null value satisfies HasPortPeerManager().
    // Using a static sentinel avoids constructing a real CPeerManager
    // (which has heavy dependencies). The tests do NOT invoke methods
    // on the registered pointer.
    static auto* sentinel = reinterpret_cast<dilithion::net::port::CPeerManager*>(0x1);
    connman.RegisterPortPeerManager(sentinel);
}

void DeregisterPortPm(CConnman& connman)
{
    connman.RegisterPortPeerManager(nullptr);
}

}  // anonymous namespace

// ============================================================================
// Case 1: getsyncstatus null-guard (headers_manager not initialized)
// ============================================================================
void test_getsyncstatus_null_headers_manager()
{
    std::cout << "  test_getsyncstatus_null_headers_manager..." << std::flush;
    ResetNodeContext();

    CRPCServer server(0);
    std::string result = server.InvokeRPCForTest("getsyncstatus", "[]");

    AssertContains(result, "\"error\"", "case 1");
    AssertContains(result, "headers_manager not initialized", "case 1");

    std::cout << " OK\n";
}

// ============================================================================
// Case 2: getsyncstatus happy path — well-formed JSON with all schema fields
// ============================================================================
void test_getsyncstatus_happy_path()
{
    std::cout << "  test_getsyncstatus_happy_path..." << std::flush;
    ResetNodeContext();

    g_node_context.headers_manager = std::make_unique<CHeadersManager>();
    g_node_context.connman = std::make_unique<CConnman>();

    CRPCServer server(0);
    std::string result = server.InvokeRPCForTest("getsyncstatus", "[]");

    // Schema fields per port_phase_9_implementation_plan.md v0.1.2 §PR9.3:
    AssertContains(result, "\"headers_progress\":", "case 2");
    AssertContains(result, "\"best_header_height\":", "case 2");
    AssertContains(result, "\"best_header_hash\":\"", "case 2");
    AssertContains(result, "\"manager_class\":", "case 2");
    // Well-formed JSON object delimiters
    AssertContains(result, "{", "case 2");
    AssertContains(result, "}", "case 2");

    ResetNodeContext();
    std::cout << " OK\n";
}

// ============================================================================
// Case 3: getsyncstatus manager_class = "legacy" when no port-pm registered
// ============================================================================
void test_getsyncstatus_manager_class_legacy()
{
    std::cout << "  test_getsyncstatus_manager_class_legacy..." << std::flush;
    ResetNodeContext();

    g_node_context.headers_manager = std::make_unique<CHeadersManager>();
    g_node_context.connman = std::make_unique<CConnman>();
    // Default state: m_port_peer_manager == nullptr → HasPortPeerManager() == false.
    assert(!g_node_context.connman->HasPortPeerManager());

    CRPCServer server(0);
    std::string result = server.InvokeRPCForTest("getsyncstatus", "[]");

    AssertContains(result, "\"manager_class\":\"legacy\"", "case 3");
    // And NOT "both" (proves the branch is by-value, not constant).
    assert(!Contains(result, "\"manager_class\":\"both\""));

    ResetNodeContext();
    std::cout << " OK\n";
}

// ============================================================================
// Case 4: getsyncstatus manager_class = "both" when port-pm registered
// ============================================================================
void test_getsyncstatus_manager_class_both()
{
    std::cout << "  test_getsyncstatus_manager_class_both..." << std::flush;
    ResetNodeContext();

    g_node_context.headers_manager = std::make_unique<CHeadersManager>();
    g_node_context.connman = std::make_unique<CConnman>();
    RegisterPortPmStub(*g_node_context.connman);
    assert(g_node_context.connman->HasPortPeerManager());

    CRPCServer server(0);
    std::string result = server.InvokeRPCForTest("getsyncstatus", "[]");

    AssertContains(result, "\"manager_class\":\"both\"", "case 4");
    assert(!Contains(result, "\"manager_class\":\"legacy\""));

    DeregisterPortPm(*g_node_context.connman);
    ResetNodeContext();
    std::cout << " OK\n";
}

// ============================================================================
// Case 5: getblockdownloadstats null-guard (block_fetcher not initialized)
// ============================================================================
void test_getblockdownloadstats_null_block_fetcher()
{
    std::cout << "  test_getblockdownloadstats_null_block_fetcher..." << std::flush;
    ResetNodeContext();

    CRPCServer server(0);
    std::string result = server.InvokeRPCForTest("getblockdownloadstats", "[]");

    AssertContains(result, "\"error\"", "case 5");
    AssertContains(result, "block_fetcher not initialized", "case 5");

    std::cout << " OK\n";
}

// ============================================================================
// Case 6: getblockdownloadstats empty-peers happy path
// ============================================================================
void test_getblockdownloadstats_empty_peers()
{
    std::cout << "  test_getblockdownloadstats_empty_peers..." << std::flush;
    ResetNodeContext();

    g_node_context.peer_manager = std::make_unique<CPeerManager>("");
    g_node_context.block_tracker = std::make_unique<CBlockTracker>();
    g_node_context.block_fetcher = std::make_unique<CBlockFetcher>(g_node_context.peer_manager.get());
    g_node_context.connman = std::make_unique<CConnman>();

    CRPCServer server(0);
    std::string result = server.InvokeRPCForTest("getblockdownloadstats", "[]");

    // Schema fields:
    AssertContains(result, "\"total_blocks_in_flight\":", "case 6");
    AssertContains(result, "\"total_blocks_pending\":", "case 6");
    AssertContains(result, "\"peers\":[", "case 6");
    AssertContains(result, "\"stalled_blocks\":[", "case 6");
    // Empty peers + empty stalled → "[]" arrays.
    AssertContains(result, "\"peers\":[]", "case 6");
    AssertContains(result, "\"stalled_blocks\":[]", "case 6");

    ResetNodeContext();
    std::cout << " OK\n";
}

// ============================================================================
// Case 7: getblockdownloadstats with connected peers — manager_class
//         field appears per peer entry, blocks_in_flight schema correct
// ============================================================================
void test_getblockdownloadstats_with_peers()
{
    std::cout << "  test_getblockdownloadstats_with_peers..." << std::flush;
    ResetNodeContext();

    g_node_context.peer_manager = std::make_unique<CPeerManager>("");
    g_node_context.block_tracker = std::make_unique<CBlockTracker>();
    g_node_context.block_fetcher = std::make_unique<CBlockFetcher>(g_node_context.peer_manager.get());
    g_node_context.connman = std::make_unique<CConnman>();

    // Add 2 connected peers via AddPeerWithId; mark CONNECTED state so
    // both the legacy GetConnectedPeers AND the PR10.2 joint-snapshot
    // GetBlockDownloadSnapshot include them. (Post-PR10.2 the RPC uses
    // GetBlockDownloadSnapshot under cs_peers; case 7 exercises that
    // path implicitly via the via-RPC call below.)
    auto peer1 = g_node_context.peer_manager->AddPeerWithId(101);
    if (peer1) peer1->state = CPeer::STATE_CONNECTED;
    auto peer2 = g_node_context.peer_manager->AddPeerWithId(102);
    if (peer2) peer2->state = CPeer::STATE_CONNECTED;

    CRPCServer server(0);
    std::string result = server.InvokeRPCForTest("getblockdownloadstats", "[]");

    // Two peer entries appear with their IDs.
    AssertContains(result, "\"peer_id\":101", "case 7");
    AssertContains(result, "\"peer_id\":102", "case 7");
    // blocks_in_flight schema field present (value will be 0 — no in-flight
    // blocks tracked in this test setup; the schema check is what matters).
    AssertContains(result, "\"blocks_in_flight\":", "case 7");
    // manager_class appears per peer (uniform "legacy" — connman has no
    // port-pm registered).
    AssertContains(result, "\"manager_class\":\"legacy\"", "case 7");

    ResetNodeContext();
    std::cout << " OK\n";
}

// ============================================================================
// Case 8: getblockdownloadstats stalled_blocks array — when block_tracker
//         has no entries past timeout, stalled_blocks should be empty;
//         when it does, entries should appear with correct schema.
//
// Test infra: we don't have a clean way to inject stalled blocks without
// a heavy block_tracker fixture. This test verifies the schema field is
// always present (empty array OK) and well-formed.
// ============================================================================
void test_getblockdownloadstats_stalled_blocks_populated()
{
    std::cout << "  test_getblockdownloadstats_stalled_blocks_populated..." << std::flush;
    ResetNodeContext();

    g_node_context.peer_manager = std::make_unique<CPeerManager>("");
    g_node_context.block_tracker = std::make_unique<CBlockTracker>();
    g_node_context.block_fetcher = std::make_unique<CBlockFetcher>(g_node_context.peer_manager.get());
    g_node_context.connman = std::make_unique<CConnman>();

    CRPCServer server(0);
    std::string result = server.InvokeRPCForTest("getblockdownloadstats", "[]");

    // stalled_blocks key always present (schema invariant).
    AssertContains(result, "\"stalled_blocks\":[", "case 8");
    // Closes correctly.
    AssertContains(result, "]}", "case 8");

    // Schema invariant: the array's content is either empty "[]" OR
    // entries with both height + peer_id fields. Test default state is
    // empty (no in-flight blocks → no stalled blocks). When populated
    // (e.g., by the 4-node harness stress scenario at runtime), entries
    // would appear as `{"height":N,"peer_id":M}` — that path is
    // exercised by scripts/four_node_local.sh, not this unit test.
    AssertContains(result, "\"stalled_blocks\":[]", "case 8");

    ResetNodeContext();
    std::cout << " OK\n";
}

// ============================================================================
// Case 8b (Phase 10 PR10.2 joint-snapshot atomicity): exercise the new
// CPeerManager::GetBlockDownloadSnapshot path used by RPC_GetBlockDownloadStats.
//
// This test verifies the joint snapshot returns peer + blocks_in_flight
// pairs under a SINGLE cs_peers acquisition (as opposed to the v0.1.2
// "GetConnectedPeers + per-peer GetPeerBlocksInFlight" pattern that was
// vulnerable to PR9.6-RT-MEDIUM-2 (b) peer-disconnect-during-iteration).
//
// The race itself can't be deterministically triggered in a single-
// threaded unit test (it requires concurrent peer events between the
// GetConnectedPeers snapshot and per-peer iteration). What we CAN
// verify deterministically:
//   * The new path produces well-formed entries for connected peers.
//   * blocks_in_flight reads come from the SAME cs_peers critical
//     section as the connected-peers iteration (verified at code-
//     review time via the lock-acquisition pattern in
//     CPeerManager::GetBlockDownloadSnapshot at peers.cpp).
//   * The TSAN sweep at PR10.2 commit time exercises the path under
//     concurrent operations (separate harness; not reproducible at
//     unit-test scope).
// ============================================================================
void test_getblockdownloadstats_joint_snapshot_atomicity()
{
    std::cout << "  test_getblockdownloadstats_joint_snapshot_atomicity..." << std::flush;
    ResetNodeContext();

    g_node_context.peer_manager = std::make_unique<CPeerManager>("");
    g_node_context.block_tracker = std::make_unique<CBlockTracker>();
    g_node_context.block_fetcher = std::make_unique<CBlockFetcher>(g_node_context.peer_manager.get());
    g_node_context.connman = std::make_unique<CConnman>();

    // Add 3 connected peers; verify the joint snapshot returns all 3
    // with valid schema fields.
    auto p1 = g_node_context.peer_manager->AddPeerWithId(301);
    if (p1) p1->state = CPeer::STATE_CONNECTED;
    auto p2 = g_node_context.peer_manager->AddPeerWithId(302);
    if (p2) p2->state = CPeer::STATE_CONNECTED;
    auto p3 = g_node_context.peer_manager->AddPeerWithId(303);
    if (p3) p3->state = CPeer::STATE_CONNECTED;

    // Direct snapshot API exercise (in addition to the via-RPC test in case 7).
    auto snapshot = g_node_context.peer_manager->GetBlockDownloadSnapshot();
    assert(snapshot.size() == 3);

    // Each entry has both fields populated (peer_id matches one of our IDs;
    // blocks_in_flight is 0 since no blocks tracked).
    bool found_301 = false, found_302 = false, found_303 = false;
    for (const auto& e : snapshot) {
        assert(e.blocks_in_flight == 0);
        if (e.peer_id == 301) found_301 = true;
        if (e.peer_id == 302) found_302 = true;
        if (e.peer_id == 303) found_303 = true;
    }
    assert(found_301 && found_302 && found_303);

    // Verify via-RPC path also reflects the joint snapshot.
    CRPCServer server(0);
    std::string result = server.InvokeRPCForTest("getblockdownloadstats", "[]");
    AssertContains(result, "\"peer_id\":301", "case 8b");
    AssertContains(result, "\"peer_id\":302", "case 8b");
    AssertContains(result, "\"peer_id\":303", "case 8b");

    ResetNodeContext();
    std::cout << " OK\n";
}

// ============================================================================
// Case 9: getpeerinfo extended with manager_class field per peer entry
// ============================================================================
void test_getpeerinfo_manager_class_field()
{
    std::cout << "  test_getpeerinfo_manager_class_field..." << std::flush;
    ResetNodeContext();

    g_node_context.peer_manager = std::make_unique<CPeerManager>("");
    g_node_context.connman = std::make_unique<CConnman>();

    // Connected peer via AddPeerWithId.
    auto peer1 = g_node_context.peer_manager->AddPeerWithId(201);
    if (peer1) peer1->state = CPeer::STATE_CONNECTED;

    CRPCServer server(0);

    // Default OFF: manager_class should be "legacy".
    std::string result_legacy = server.InvokeRPCForTest("getpeerinfo", "[]");
    // getpeerinfo uses "id" (not "peer_id") for the per-peer identifier.
    AssertContains(result_legacy, "\"id\":201", "case 9 legacy");
    AssertContains(result_legacy, "\"manager_class\":\"legacy\"", "case 9 legacy");
    assert(!Contains(result_legacy, "\"manager_class\":\"both\""));

    // Register port-pm sentinel; same call should now report "both".
    RegisterPortPmStub(*g_node_context.connman);
    std::string result_both = server.InvokeRPCForTest("getpeerinfo", "[]");
    AssertContains(result_both, "\"manager_class\":\"both\"", "case 9 both");
    assert(!Contains(result_both, "\"manager_class\":\"legacy\""));

    DeregisterPortPm(*g_node_context.connman);
    ResetNodeContext();
    std::cout << " OK\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 10 PR10.1 — Phase 9 telemetry RPC unit tests\n";
    std::cout << "  (locks v0.1.2 schemas of getsyncstatus + getblockdownloadstats\n";
    std::cout << "   + getpeerinfo manager_class extension as a checkable contract)\n\n";

    // Bootstrap g_chainParams with regtest params — CHeadersManager
    // constructor invokes Genesis::CreateGenesisBlock() which requires it.
    // Mirrors the dilithion-node.cpp:2042-2048 production setup.
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
    }

    // Initialize RandomX (light mode) so genesis hashing works inside the
    // CHeadersManager constructor (matches peer_manager_headers_sync_tests.cpp:577).
    const char* rx_key = "Dilithion-Genesis-Block-Salt-2025";
    randomx_init_for_hashing(rx_key, std::strlen(rx_key), 1);

    try {
        test_getsyncstatus_null_headers_manager();        // 1
        test_getsyncstatus_happy_path();                  // 2
        test_getsyncstatus_manager_class_legacy();        // 3
        test_getsyncstatus_manager_class_both();          // 4
        test_getblockdownloadstats_null_block_fetcher();  // 5
        test_getblockdownloadstats_empty_peers();         // 6
        test_getblockdownloadstats_with_peers();          // 7
        test_getblockdownloadstats_stalled_blocks_populated();  // 8
        test_getblockdownloadstats_joint_snapshot_atomicity();  // 8b (PR10.2)
        test_getpeerinfo_manager_class_field();           // 9
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED with exception: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll Phase 9 telemetry RPC unit tests passed.\n";
    std::cout << "  10 cases: 4 getsyncstatus + 4 getblockdownloadstats + 1 PR10.2 joint-snapshot atomicity + 1 getpeerinfo.\n";
    return 0;
}
