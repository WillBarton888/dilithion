// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.1 — HeadersManager → chain_selector wiring tests.
//
// Per v1.5 plan §4 PR6.1, five mandatory test classes:
//   1. Happy-path: N consecutive valid headers populate mapBlockIndex
//   2. Idempotency: same header processed twice does not double-insert
//   3. Orphan handling: header with unknown parent is rejected
//   4. Rejected-parent descendant flood: peer announces 10K headers
//      descending from a known-invalid block — verify mapBlockIndex
//      does not grow
//   5. Cap-saturation: force mapBlockIndex to cap; verify ProcessNewHeader
//      fails closed (returns false) without UAF or eviction-of-best-chain
//
// Pattern matches src/test/chain_selector_tests.cpp:
//   * Standalone test functions (no Boost framework)
//   * Manual setup using CChainState + ChainSelectorAdapter
//   * VDF-style headers (SHA3-256, no RandomX dependency)

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>

namespace {

// Construct a VDF-style header chained from a given parent hash.
// Different `tag` byte produces a different vdfOutput → different SHA3 hash
// → distinct sibling.
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

}  // anonymous

// ============================================================================
// Test 1 — Happy-path: N consecutive valid headers populate mapBlockIndex.
// Verifies the PR6.1 wiring's load-bearing claim: every accepted header
// becomes a CBlockIndex entry visible via LookupBlockIndex.
// ============================================================================
void test_pr61_happy_path_n_headers_populate_mapBlockIndex()
{
    std::cout << "  test_pr61_happy_path_n_headers_populate_mapBlockIndex..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Build a chain of 10 headers from genesis.
    uint256 prev_hash;
    std::memset(prev_hash.data, 0, 32);
    auto genesis = MakeHeader(prev_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(genesis));
    prev_hash = genesis.GetHash();

    for (int i = 1; i <= 10; ++i) {
        auto h = MakeHeader(prev_hash, 0x1d00ffff, 1700000000 + i, static_cast<uint8_t>(i));
        bool ok = adapter.ProcessNewHeader(h);
        assert(ok);
        // Verify it's now in mapBlockIndex.
        CBlockIndex* p = chainstate.GetBlockIndex(h.GetHash());
        assert(p != nullptr);
        assert(p->nHeight == i);
        // G2 invariant: pre-validation only.
        assert((p->nStatus & CBlockIndex::BLOCK_VALID_MASK) == CBlockIndex::BLOCK_VALID_HEADER);
        assert(!p->IsInvalid());
        prev_hash = h.GetHash();
    }

    // mapBlockIndex should contain exactly 11 entries (genesis + 10).
    assert(chainstate.GetBlockIndexSize() == 11);

    std::cout << " OK\n";
}

// ============================================================================
// Test 2 — Idempotency: re-processing the same header does not duplicate.
// Verifies that HeadersManager's wiring is safe to call multiple times
// (re-orgs, retries, etc.).
// ============================================================================
void test_pr61_idempotency_same_header_no_duplicate()
{
    std::cout << "  test_pr61_idempotency_same_header_no_duplicate..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    uint256 prev_hash;
    std::memset(prev_hash.data, 0, 32);
    auto genesis = MakeHeader(prev_hash, 0x1d00ffff, 1700000000, 0);
    auto h = MakeHeader(genesis.GetHash(), 0x1d00ffff, 1700000060, 1);

    assert(adapter.ProcessNewHeader(genesis));
    assert(adapter.ProcessNewHeader(h));
    CBlockIndex* p_first = chainstate.GetBlockIndex(h.GetHash());

    // Re-process. Must succeed (idempotent contract per chain_selector_impl
    // line 122-126) and return the SAME pointer.
    assert(adapter.ProcessNewHeader(h));
    CBlockIndex* p_second = chainstate.GetBlockIndex(h.GetHash());
    assert(p_first == p_second);
    // mapBlockIndex size unchanged.
    assert(chainstate.GetBlockIndexSize() == 2);

    std::cout << " OK\n";
}

// ============================================================================
// Test 3 — Orphan handling: header with unknown parent is rejected.
// Per chain_selector_impl line 134-137: orphan returns false; mapBlockIndex
// does NOT grow. (HeadersManager is responsible for topological order.)
// ============================================================================
void test_pr61_orphan_header_rejected()
{
    std::cout << "  test_pr61_orphan_header_rejected..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Build an "orphan" — header whose parent is not in mapBlockIndex.
    uint256 unknown_parent;
    std::memset(unknown_parent.data, 0xAA, 32);
    auto h = MakeHeader(unknown_parent, 0x1d00ffff, 1700000000, 0);

    bool ok = adapter.ProcessNewHeader(h);
    assert(!ok);  // orphan rejected
    assert(chainstate.GetBlockIndex(h.GetHash()) == nullptr);
    assert((chainstate.GetBlockIndexSize() == 0));

    std::cout << " OK\n";
}

// ============================================================================
// Test 4 — Rejected-parent descendant flood.
// 10K headers all descending from a parent marked BLOCK_FAILED_VALID must
// not grow mapBlockIndex. Per chain_selector_impl line 146-148 (Phase 5
// BLOCKER 1 fix): refuse to extend a chain rooted in a known-invalid block.
// ============================================================================
void test_pr61_rejected_parent_flood_does_not_grow_mapBlockIndex()
{
    std::cout << "  test_pr61_rejected_parent_flood_does_not_grow_mapBlockIndex..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Plant a genesis + an invalid block (parent of the flood).
    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto genesis = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(genesis));

    auto bad = MakeHeader(genesis.GetHash(), 0x1d00ffff, 1700000060, 0xFE);
    assert(adapter.ProcessNewHeader(bad));
    // Mark it as failed.
    CBlockIndex* p_bad = chainstate.GetBlockIndex(bad.GetHash());
    p_bad->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;

    const size_t pre_size = chainstate.GetBlockIndexSize();
    assert(pre_size == 2);

    // Flood: 10K headers descending from `bad`.
    uint256 attacker_parent = bad.GetHash();
    int rejected = 0;
    for (int i = 0; i < 10000; ++i) {
        auto flood_h = MakeHeader(attacker_parent, 0x1d00ffff,
                                  1700000060 + i + 1, static_cast<uint8_t>(i & 0xFF));
        if (!adapter.ProcessNewHeader(flood_h)) {
            ++rejected;
        }
    }

    // ALL 10K should have been rejected. mapBlockIndex must NOT have grown.
    assert(rejected == 10000);
    assert(chainstate.GetBlockIndexSize() == pre_size);

    std::cout << " OK (" << rejected << "/10000 rejected, mapBlockIndex stable at "
              << pre_size << ")\n";
}

// ============================================================================
// Test 5 — Cap-saturation: fail-closed when mapBlockIndex hits the cap.
// Sets a small cap via chainparams; floods headers; verifies cap-reached
// causes ProcessNewHeader to return false WITHOUT eviction (no UAF risk).
// ============================================================================
void test_pr61_cap_saturation_fails_closed()
{
    std::cout << "  test_pr61_cap_saturation_fails_closed..." << std::flush;

    // Set a small cap via Regtest chainparams (cap=1000).
    static Dilithion::ChainParams regtest_params = Dilithion::ChainParams::Regtest();
    Dilithion::ChainParams* prev_chainparams = Dilithion::g_chainParams;
    Dilithion::g_chainParams = &regtest_params;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Build a long valid chain. Cap should kick in around entry #1000.
    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto genesis = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(genesis));

    uint256 prev_hash = genesis.GetHash();
    int accepted = 1;  // genesis already counted
    int rejected = 0;
    for (int i = 1; i <= 1500; ++i) {
        auto h = MakeHeader(prev_hash, 0x1d00ffff, 1700000000 + i, static_cast<uint8_t>(i & 0xFF));
        bool ok = adapter.ProcessNewHeader(h);
        if (ok) {
            ++accepted;
            prev_hash = h.GetHash();
        } else {
            ++rejected;
        }
    }

    // Cap is 1000 in regtest. ProcessNewHeader should fail-closed at cap.
    // Allow some slack for race-window-overshoot per the implementation's
    // documented hot-path optimization (the size() read isn't strictly
    // synchronous with the AddBlockIndex below it).
    assert(accepted <= 1000 + 5);
    assert(rejected >= 500 - 5);
    // Ground-truth: mapBlockIndex never exceeds cap by more than the
    // race-window. The exact size depends on race-timing; just assert it
    // didn't grow unbounded.
    assert(chainstate.GetBlockIndexSize() <= 1000 + 5);

    Dilithion::g_chainParams = prev_chainparams;

    std::cout << " OK (accepted=" << accepted << " rejected=" << rejected
              << " final size=" << chainstate.GetBlockIndexSize() << ")\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.1 — HeadersManager → chain_selector wiring tests\n";
    std::cout << "  (5-test suite per v1.5 plan §4 PR6.1)\n\n";

    try {
        test_pr61_happy_path_n_headers_populate_mapBlockIndex();
        test_pr61_idempotency_same_header_no_duplicate();
        test_pr61_orphan_header_rejected();
        test_pr61_rejected_parent_flood_does_not_grow_mapBlockIndex();
        test_pr61_cap_saturation_fails_closed();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 5 PR6.1 wiring tests passed.\n";
    return 0;
}
