// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 PR5.1 — ChainSelectorAdapter trivial-getter tests.
//
// Scope (PR5.1): 4 tests covering the four trivial getters wired through
// CChainState in chain_selector_impl.cpp:
//   * GetActiveTip
//   * GetActiveHeight
//   * GetActiveTipHash
//   * LookupBlockIndex
//
// Real algorithm tests (FindMostWorkChain, ProcessNewBlock, etc.) are
// PR5.3 territory — the corresponding adapter methods are still
// assert(false) at this point.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <node/block_index.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>

namespace {

// Build a CBlockIndex with an explicitly-set phashBlock and pprev=nullptr,
// nHeight=0 (genesis-like) so it satisfies CChainState::AddBlockIndex's
// invariants without needing real-block construction. The phashBlock is
// the only thing GetBlockHash() returns post-Bug #10 fix.
std::unique_ptr<CBlockIndex> MakeGenesisLikeIndex(uint8_t hash_seed)
{
    auto pindex = std::make_unique<CBlockIndex>();
    pindex->pprev = nullptr;
    pindex->nHeight = 0;
    pindex->nChainWork = uint256();
    pindex->nStatus = CBlockIndex::BLOCK_VALID_TRANSACTIONS;
    pindex->nSequenceId = 1;
    // Synthetic deterministic hash: byte 0 = seed, rest zeros.
    std::memset(pindex->phashBlock.data, 0, 32);
    pindex->phashBlock.data[0] = hash_seed;
    return pindex;
}

}  // anonymous

void test_get_active_tip_null_on_fresh_chainstate()
{
    std::cout << "  test_get_active_tip_null_on_fresh_chainstate..." << std::flush;
    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    assert(adapter.GetActiveTip() == nullptr);
    assert(adapter.GetActiveTipHash().IsNull());
    std::cout << " OK\n";
}

void test_get_active_tip_after_set_tip_for_test()
{
    std::cout << "  test_get_active_tip_after_set_tip_for_test..." << std::flush;
    CChainState chainstate;
    auto pindex = MakeGenesisLikeIndex(0xAA);
    CBlockIndex* raw = pindex.get();
    chainstate.SetTipForTest(raw);

    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    assert(adapter.GetActiveTip() == raw);
    std::cout << " OK\n";
}

void test_get_active_height_and_hash_match_tip()
{
    std::cout << "  test_get_active_height_and_hash_match_tip..." << std::flush;
    // GetActiveHeight reads the m_cachedHeight atomic which is only
    // updated through CChainState::SetTip — and SetTip enforces the
    // invariant that the tip must live in mapBlockIndex. So the test
    // path is: AddBlockIndex (genesis-like) -> SetTip -> verify.
    CChainState chainstate;
    auto pindex = MakeGenesisLikeIndex(0xBB);
    uint256 hash = pindex->GetBlockHash();
    bool added = chainstate.AddBlockIndex(hash, std::move(pindex));
    assert(added);
    CBlockIndex* tip = chainstate.GetBlockIndex(hash);
    chainstate.SetTip(tip);

    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    assert(adapter.GetActiveHeight() == 0);  // genesis-like
    uint256 actual = adapter.GetActiveTipHash();
    assert(std::memcmp(hash.data, actual.data, 32) == 0);
    std::cout << " OK\n";
}

void test_lookup_block_index_returns_added_block()
{
    std::cout << "  test_lookup_block_index_returns_added_block..." << std::flush;
    CChainState chainstate;
    auto pindex = MakeGenesisLikeIndex(0xCC);
    uint256 hash = pindex->GetBlockHash();
    CBlockIndex* raw_before_move = pindex.get();
    bool added = chainstate.AddBlockIndex(hash, std::move(pindex));
    assert(added);

    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    CBlockIndex* found = adapter.LookupBlockIndex(hash);
    assert(found == raw_before_move);

    // Negative case: unknown hash returns nullptr.
    uint256 unknown;
    std::memset(unknown.data, 0, 32);
    unknown.data[0] = 0xFF;
    assert(adapter.LookupBlockIndex(unknown) == nullptr);
    std::cout << " OK\n";
}

int main()
{
    std::cout << "\n=== Phase 5 PR5.1: ChainSelectorAdapter Trivial-Getter Tests ===\n"
              << std::endl;

    try {
        test_get_active_tip_null_on_fresh_chainstate();
        test_get_active_tip_after_set_tip_for_test();
        test_get_active_height_and_hash_match_tip();
        test_lookup_block_index_returns_added_block();

        std::cout << "\n=== All Phase 5 PR5.1 chain_selector_tests passed (4 tests) ==="
                  << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown exception" << std::endl;
        return 1;
    }
}
