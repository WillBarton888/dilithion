// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.4 — fast_path_2_boundary_tests (5 cases per v1.5 §4 PR6.4).
//
// Why this file exists:
//   PR5.6 (Patch H deletion) was reverted because Patch H covers a
//   boundary class that generic competing-sibling tests miss — the
//   FAST PATH 2 mechanism in headers_manager.cpp:192–204 (where
//   the comment "if mapHeightIndex already had ANY header at this
//   height, the incoming header was silently dropped via
//   *heightIt->second.begin()" describes the bug).
//
//   PR6.4's gate is: these 5 tests stay green WITHOUT Patch H. Tests
//   focus on chain_selector::ProcessNewHeader behavior because PR6.1
//   wires HeadersManager's mapHeaders writes to chain_selector — the
//   structural-coverage property is enforced at chain_selector level
//   regardless of Patch H's HeadersManager safeguard.
//
// Tests (per v1.5):
//   1. Sibling whose ancestry crosses the checkpoint boundary
//   2. FAST PATH 2 invocation with mapBlockIndex pre-populated
//   3. Off-by-one at checkpoint boundary
//   4. Concurrent header arrival across boundary (std::thread + barrier)
//   5. Parent invalidation after initial acceptance (Cursor v1.2)

#include <consensus/chain.h>
#include <consensus/port/chain_selector_impl.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace {

// VDF-style header (SHA3-256 hash, no RandomX in tests). Different `tag`
// produces different vdfOutput → different hash → distinct sibling.
CBlockHeader MakeHeader(const uint256& parent_hash, uint32_t nBits,
                        uint32_t nTime, uint8_t tag = 0)
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::VDF_VERSION;
    h.hashPrevBlock = parent_hash;
    std::memset(h.hashMerkleRoot.data, 0, 32);
    h.nTime = nTime;
    h.nBits = nBits;
    h.nNonce = 0;
    for (int i = 0; i < 32; ++i) h.vdfProofHash.data[i] = 0;
    for (int i = 0; i < 32; ++i) h.vdfOutput.data[i] = tag;
    return h;
}

uint256 NullHash()
{
    uint256 h;
    std::memset(h.data, 0, 32);
    return h;
}

}  // anonymous

// ============================================================================
// Test 1 — Sibling fork extends across a multi-block boundary.
// Topology: genesis -> A1 -> A2 -> A3
//                        \-> B1 (sibling at h=1) -> B2 -> B3
// Both branches must coexist in mapBlockIndex regardless of where the
// (conceptual) checkpoint sits — chain_selector enforces no runtime
// checkpoint check in ProcessNewHeader; this test verifies structural
// coverage of the multi-block-boundary case. Renamed v1.5+ per subagent
// (prior name "crosses checkpoint boundary" oversold the test scope).
// ============================================================================
void test_pr64_sibling_fork_extends_across_multi_block_boundary()
{
    std::cout << "  test_pr64_sibling_fork_extends_across_multi_block_boundary..." << std::flush;

    CChainState cs;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(cs);

    // Build canonical chain genesis -> A0 -> A1 -> A2 -> A3.
    auto h_gen = MakeHeader(NullHash(), 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(h_gen));

    auto h_A1 = MakeHeader(h_gen.GetHash(), 0x1d00ffff, 1700000060, 1);
    assert(adapter.ProcessNewHeader(h_A1));
    auto h_A2 = MakeHeader(h_A1.GetHash(), 0x1d00ffff, 1700000120, 2);
    assert(adapter.ProcessNewHeader(h_A2));
    auto h_A3 = MakeHeader(h_A2.GetHash(), 0x1d00ffff, 1700000180, 3);
    assert(adapter.ProcessNewHeader(h_A3));

    // Sibling chain forks at height 1 (below "checkpoint" at A2 conceptually)
    // and extends across to height 3.
    auto h_B1 = MakeHeader(h_gen.GetHash(), 0x1d00ffff, 1700000060, 0xB1);
    assert(adapter.ProcessNewHeader(h_B1));
    auto h_B2 = MakeHeader(h_B1.GetHash(), 0x1d00ffff, 1700000120, 0xB2);
    assert(adapter.ProcessNewHeader(h_B2));
    auto h_B3 = MakeHeader(h_B2.GetHash(), 0x1d00ffff, 1700000180, 0xB3);
    assert(adapter.ProcessNewHeader(h_B3));

    // STRUCTURAL PROPERTY: both A and B siblings are in mapBlockIndex,
    // including the ones that cross the conceptual boundary.
    assert(cs.GetBlockIndex(h_A1.GetHash()) != nullptr);
    assert(cs.GetBlockIndex(h_A2.GetHash()) != nullptr);
    assert(cs.GetBlockIndex(h_A3.GetHash()) != nullptr);
    assert(cs.GetBlockIndex(h_B1.GetHash()) != nullptr);
    assert(cs.GetBlockIndex(h_B2.GetHash()) != nullptr);
    assert(cs.GetBlockIndex(h_B3.GetHash()) != nullptr);

    // No orphans, no double-counting: 7 entries (genesis + A1-A3 + B1-B3).
    assert(cs.GetBlockIndexSize() == 7);

    std::cout << " OK\n";
}

// ============================================================================
// Test 2 — FAST PATH 2 replay: mapBlockIndex pre-populated, second sibling
// arrives. Patch H originally protected the case where mapHeightIndex
// already had an entry at the height — the second-arrived was dropped.
// PR6.1 wiring + chain_selector::ProcessNewHeader's idempotency property
// MUST handle this without dropping the second sibling.
// ============================================================================
void test_pr64_fast_path_2_replay_second_sibling_not_dropped()
{
    std::cout << "  test_pr64_fast_path_2_replay_second_sibling_not_dropped..." << std::flush;

    CChainState cs;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(cs);

    auto h_gen = MakeHeader(NullHash(), 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(h_gen));

    // First sibling at height 1 — populates mapBlockIndex first.
    auto h_X = MakeHeader(h_gen.GetHash(), 0x1d00ffff, 1700000060, 0xAA);
    assert(adapter.ProcessNewHeader(h_X));

    // Second sibling at height 1 (the legacy "drop me" case under
    // FAST PATH 2 without Patch H). chain_selector accepts it — both
    // entries coexist in mapBlockIndex.
    auto h_Y = MakeHeader(h_gen.GetHash(), 0x1d00ffff, 1700000060, 0xBB);
    assert(adapter.ProcessNewHeader(h_Y));

    // BOTH siblings in index — exact PR5.6 revert scenario, handled
    // structurally without Patch H.
    assert(cs.GetBlockIndex(h_X.GetHash()) != nullptr);
    assert(cs.GetBlockIndex(h_Y.GetHash()) != nullptr);
    assert(cs.GetBlockIndexSize() == 3);  // genesis + X + Y

    std::cout << " OK\n";
}

// ============================================================================
// Test 3 — Off-by-one boundary: siblings at h=N, h=N-1, h=N+1.
// Verifies chain_selector accepts siblings at adjacent heights without
// drops or off-by-one errors. ("Checkpoint" remains conceptual — the
// chain_selector path has no runtime checkpoint enforcement; renamed
// v1.5+ per subagent.)
// ============================================================================
void test_pr64_off_by_one_boundary_siblings()
{
    std::cout << "  test_pr64_off_by_one_boundary_siblings..." << std::flush;

    CChainState cs;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(cs);

    // Build a chain genesis -> H1 -> H2 (the "checkpoint") -> H3.
    auto h_gen = MakeHeader(NullHash(), 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(h_gen));
    auto h_1 = MakeHeader(h_gen.GetHash(), 0x1d00ffff, 1700000060, 1);
    assert(adapter.ProcessNewHeader(h_1));
    auto h_2 = MakeHeader(h_1.GetHash(), 0x1d00ffff, 1700000120, 2);  // "checkpoint"
    assert(adapter.ProcessNewHeader(h_2));
    auto h_3 = MakeHeader(h_2.GetHash(), 0x1d00ffff, 1700000180, 3);
    assert(adapter.ProcessNewHeader(h_3));

    // Sibling at checkpoint height (H2's competitor).
    auto h_2b = MakeHeader(h_1.GetHash(), 0x1d00ffff, 1700000120, 0x2B);
    assert(adapter.ProcessNewHeader(h_2b));

    // Sibling at checkpoint - 1 (H1's competitor).
    auto h_1b = MakeHeader(h_gen.GetHash(), 0x1d00ffff, 1700000060, 0x1B);
    assert(adapter.ProcessNewHeader(h_1b));

    // Sibling at checkpoint + 1 (H3's competitor).
    auto h_3b = MakeHeader(h_2.GetHash(), 0x1d00ffff, 1700000180, 0x3B);
    assert(adapter.ProcessNewHeader(h_3b));

    // All 7 entries in mapBlockIndex (genesis + main3 + 3 siblings).
    assert(cs.GetBlockIndexSize() == 7);
    assert(cs.GetBlockIndex(h_2.GetHash()) != nullptr);
    assert(cs.GetBlockIndex(h_2b.GetHash()) != nullptr);

    std::cout << " OK\n";
}

// ============================================================================
// Test 4 — Concurrent header arrival across boundary.
// Two threads insert headers at boundary height simultaneously.
// std::barrier (C++20) for sync; verify no race / no drop / no dup.
// ============================================================================
void test_pr64_concurrent_header_arrival_at_boundary()
{
    std::cout << "  test_pr64_concurrent_header_arrival_at_boundary..." << std::flush;

    CChainState cs;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(cs);

    // Genesis + parent at height 1 (so siblings at height 2 share parent).
    auto h_gen = MakeHeader(NullHash(), 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(h_gen));
    auto h_p = MakeHeader(h_gen.GetHash(), 0x1d00ffff, 1700000060, 0xFF);
    assert(adapter.ProcessNewHeader(h_p));

    // Pre-build 200 distinct sibling headers all at height 2.
    constexpr int kHeaders = 200;
    std::vector<CBlockHeader> siblings;
    siblings.reserve(kHeaders);
    for (int i = 0; i < kHeaders; ++i) {
        siblings.push_back(MakeHeader(h_p.GetHash(), 0x1d00ffff,
                                      1700000120,
                                      static_cast<uint8_t>(i & 0xFF)));
    }

    // 4 threads insert in parallel via cyclic distribution.
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    std::vector<std::thread> threads;
    constexpr int kThreads = 4;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t] {
            ready.fetch_add(1);
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (int i = t; i < kHeaders; i += kThreads) {
                (void)adapter.ProcessNewHeader(siblings[i]);
            }
        });
    }
    while (ready.load() < kThreads) std::this_thread::yield();
    go.store(true, std::memory_order_release);
    for (auto& th : threads) th.join();

    // All 200 distinct siblings should be in mapBlockIndex (plus genesis + parent).
    // Note: due to hash collisions in the synthetic tag, some may be duplicates
    // (tag wraps at 256). Allow some tolerance — the property is "no drop".
    const size_t final_size = cs.GetBlockIndexSize();
    // genesis + parent = 2; plus up to kHeaders distinct siblings (some may
    // share a synthetic hash if tag % 256 collides — for kHeaders=200 there
    // are no collisions because tag = i & 0xFF and i < 200 < 256).
    assert(final_size == 2 + kHeaders);

    std::cout << " OK (no race; " << final_size << " entries)\n";
}

// ============================================================================
// Test 5 — Parent invalidation after initial acceptance (Cursor v1.2;
// HARDENED v1.5+ per subagent: use InvalidateBlock for cascade, assert
// single-outcome rejection).
//
// Descendant chain initially accepted; parent later invalidated via
// adapter.InvalidateBlock (which cascades BLOCK_FAILED_CHILD to all
// descendants). New descendant arriving AFTER invalidation must be
// rejected (single-outcome contract).
// ============================================================================
void test_pr64_parent_invalidation_after_acceptance()
{
    std::cout << "  test_pr64_parent_invalidation_after_acceptance..." << std::flush;

    CChainState cs;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(cs);

    auto h_gen = MakeHeader(NullHash(), 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(h_gen));

    // Parent that will later be invalidated.
    auto h_P = MakeHeader(h_gen.GetHash(), 0x1d00ffff, 1700000060, 0x7F);
    assert(adapter.ProcessNewHeader(h_P));

    // Descendant chain.
    auto h_C1 = MakeHeader(h_P.GetHash(), 0x1d00ffff, 1700000120, 0xC1);
    assert(adapter.ProcessNewHeader(h_C1));
    auto h_C2 = MakeHeader(h_C1.GetHash(), 0x1d00ffff, 1700000180, 0xC2);
    assert(adapter.ProcessNewHeader(h_C2));

    // All 4 entries pre-invalidation.
    assert(cs.GetBlockIndexSize() == 4);

    // HARDENED v1.5+ per subagent: use adapter.InvalidateBlock to mark P
    // failed AND cascade BLOCK_FAILED_CHILD to C1 + C2. Direct nStatus
    // mutation (the prior version) skipped the cascade, so C3's parent
    // C2 was never marked invalid and the test had to allow either
    // outcome. With proper cascade, the contract is single-valued.
    bool inv_ok = adapter.InvalidateBlock(h_P.GetHash());
    assert(inv_ok);

    // New descendant arriving NOW MUST be rejected — its parent (C2) is
    // now marked BLOCK_FAILED_CHILD via cascade from P.
    auto h_C3 = MakeHeader(h_C2.GetHash(), 0x1d00ffff, 1700000240, 0xC3);
    bool ok = adapter.ProcessNewHeader(h_C3);

    // SINGLE-OUTCOME contract: C3 rejected; mapBlockIndex unchanged.
    assert(!ok && "C3 must be rejected: parent C2 has BLOCK_FAILED_CHILD via cascade from invalid P");
    assert(cs.GetBlockIndexSize() == 4);

    std::cout << " OK\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.4 — fast_path_2_boundary_tests\n";
    std::cout << "  (5-case suite per v1.5 plan §4 PR6.4; gates Patch H deletion)\n\n";

    try {
        test_pr64_sibling_fork_extends_across_multi_block_boundary();
        test_pr64_fast_path_2_replay_second_sibling_not_dropped();
        test_pr64_off_by_one_boundary_siblings();
        test_pr64_concurrent_header_arrival_at_boundary();
        test_pr64_parent_invalidation_after_acceptance();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 5 PR6.4 boundary tests passed.\n";
    std::cout << "PR6.4 hard gate (in-process structural-coverage): GREEN\n";
    return 0;
}
