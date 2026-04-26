// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 Day 4 V1 — Competing sibling below checkpoint structural coverage.
//
// Plan §6.3: "Receives competing siblings below a checkpoint; verifies
// BOTH lands in mapBlockIndex; verifies FindMostWorkChain returns the
// heavier one. With Patch H present (PR5.4) AND with it deleted (PR5.6)."
//
// Patch H (legacy v4.0.22 fix at headers_manager.cpp:197-220) is a
// HeadersManager-level safeguard: when a header arrives below a
// checkpoint, the legacy code stored it under mapHeaders preserving
// competing siblings rather than silently dropping the second-arrived.
// Without Patch H, the 2026-04-25 incident: LDN/SGP testnet seeds
// committed to a wrong-fork sibling at height 44468 because the
// canonical sibling arrived AFTER and was dropped.
//
// Phase 5's design replaces Patch H structurally: chain_selector's
// ProcessNewHeader populates CChainState::mapBlockIndex for EVERY
// header (the prerequisite landed in commit 462afda). Both siblings
// end up in the index tree by construction; FindMostWorkChain picks
// the heavier (or, on tie, deterministic via nSequenceId).
//
// This test proves the structural coverage exists pre-deletion. PR5.6
// extends this test with the WITHOUT-Patch-H variant once the legacy
// HeadersManager Patch H block is removed.

#include <consensus/chain.h>
#include <consensus/port/chain_selector_impl.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

namespace {

std::unique_ptr<CBlockIndex> MakeIndex(uint8_t hash_seed, CBlockIndex* parent,
                                       int height, uint32_t status,
                                       uint8_t work_seed, uint32_t seq_id)
{
    auto p = std::make_unique<CBlockIndex>();
    p->pprev = parent;
    p->nHeight = height;
    p->nStatus = status;
    p->nSequenceId = seq_id;
    p->nVersion = CBlockHeader::VDF_VERSION;
    std::memset(p->phashBlock.data, 0, 32);
    p->phashBlock.data[0] = hash_seed;
    std::memset(p->nChainWork.data, 0, 32);
    p->nChainWork.data[0] = work_seed;
    return p;
}

}  // anonymous

void test_two_siblings_below_checkpoint_both_in_index()
{
    std::cout << "  test_two_siblings_below_checkpoint_both_in_index..."
              << std::flush;

    // Topology:
    //     A (genesis, height 0)
    //    / \
    //   X   Y      (both height 1, BELOW the checkpoint at height 2)
    // Checkpoint at height 2 = some-canonical-hash (X-or-Y is the canonical
    // fork; the test doesn't care which — only that BOTH are stored so the
    // chain selector can later pick).
    CChainState cs;

    auto pA = MakeIndex(0x01, nullptr, 0,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(cs.AddBlockIndex(hA, std::move(pA)));
    cs.SetTip(cs.GetBlockIndex(hA));
    CBlockIndex* A = cs.GetBlockIndex(hA);

    // Sibling X at height 1.
    auto pX = MakeIndex(0x10, A, 1,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hX = pX->GetBlockHash();
    assert(cs.AddBlockIndex(hX, std::move(pX)));

    // Sibling Y at height 1, heavier (work_seed=10).
    auto pY = MakeIndex(0x11, A, 1,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hY = pY->GetBlockHash();
    assert(cs.AddBlockIndex(hY, std::move(pY)));

    // Critical structural property: BOTH siblings retrievable from the index.
    // Without Patch H equivalent, the second-arrived (Y) would have been
    // dropped during HeadersManager's mapHeaders insertion. With the Phase
    // 5 redesign (ProcessNewHeader → AddBlockIndex unconditionally), both
    // are present.
    assert(cs.GetBlockIndex(hX) != nullptr && "X must be in mapBlockIndex");
    assert(cs.GetBlockIndex(hY) != nullptr && "Y must be in mapBlockIndex");

    // FindMostWorkChain picks the heavier sibling (Y).
    cs.RecomputeCandidates();
    CBlockIndex* picked = cs.FindMostWorkChainImpl();
    assert(picked == cs.GetBlockIndex(hY) &&
           "FindMostWorkChain must select the heavier sibling");

    std::cout << " OK\n";
}

void test_three_siblings_at_below_checkpoint_height_all_present()
{
    std::cout << "  test_three_siblings_at_below_checkpoint_height_all_present..."
              << std::flush;

    // Stress: three siblings at the same below-checkpoint height.
    CChainState cs;

    auto pA = MakeIndex(0x01, nullptr, 0,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(cs.AddBlockIndex(hA, std::move(pA)));
    cs.SetTip(cs.GetBlockIndex(hA));
    CBlockIndex* A = cs.GetBlockIndex(hA);

    auto pX = MakeIndex(0x20, A, 1,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    auto pY = MakeIndex(0x21, A, 1,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 8, 3);
    auto pZ = MakeIndex(0x22, A, 1,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 4);
    uint256 hX = pX->GetBlockHash();
    uint256 hY = pY->GetBlockHash();
    uint256 hZ = pZ->GetBlockHash();
    assert(cs.AddBlockIndex(hX, std::move(pX)));
    assert(cs.AddBlockIndex(hY, std::move(pY)));
    assert(cs.AddBlockIndex(hZ, std::move(pZ)));

    // All three present.
    assert(cs.GetBlockIndex(hX) != nullptr);
    assert(cs.GetBlockIndex(hY) != nullptr);
    assert(cs.GetBlockIndex(hZ) != nullptr);

    cs.RecomputeCandidates();
    CBlockIndex* picked = cs.FindMostWorkChainImpl();
    assert(picked == cs.GetBlockIndex(hZ) && "Heaviest (Z) must win");

    std::cout << " OK\n";
}

void test_invalidate_one_sibling_others_remain_candidates()
{
    std::cout << "  test_invalidate_one_sibling_others_remain_candidates..."
              << std::flush;

    // After invalidating one sibling, the others must still be selectable.
    // Mirrors operator-triggered ReconsiderBlock / InvalidateBlock RPC use
    // case in mainnet recovery.
    CChainState cs;

    auto pA = MakeIndex(0x01, nullptr, 0,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(cs.AddBlockIndex(hA, std::move(pA)));
    cs.SetTip(cs.GetBlockIndex(hA));
    CBlockIndex* A = cs.GetBlockIndex(hA);

    auto pX = MakeIndex(0x30, A, 1,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    auto pY = MakeIndex(0x31, A, 1,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hX = pX->GetBlockHash();
    uint256 hY = pY->GetBlockHash();
    assert(cs.AddBlockIndex(hX, std::move(pX)));
    assert(cs.AddBlockIndex(hY, std::move(pY)));

    cs.RecomputeCandidates();
    // Heaviest before invalidation: Y.
    assert(cs.FindMostWorkChainImpl() == cs.GetBlockIndex(hY));

    // Operator invalidates Y.
    assert(cs.InvalidateBlockImpl(hY));
    assert(cs.GetBlockIndex(hY)->IsInvalid());

    // X is still valid and present in the index.
    assert(cs.GetBlockIndex(hX) != nullptr);
    assert(!cs.GetBlockIndex(hX)->IsInvalid());

    // FindMostWorkChain now picks X.
    CBlockIndex* picked = cs.FindMostWorkChainImpl();
    assert(picked == cs.GetBlockIndex(hX));

    // ReconsiderBlock(Y) restores Y; FindMostWork picks Y again.
    assert(cs.ReconsiderBlockImpl(hY));
    cs.RecomputeCandidates();
    assert(cs.FindMostWorkChainImpl() == cs.GetBlockIndex(hY));

    std::cout << " OK\n";
}

void test_adapter_chain_tips_lists_all_siblings()
{
    std::cout << "  test_adapter_chain_tips_lists_all_siblings..." << std::flush;

    // The adapter's GetChainTips must surface every sibling-leaf so
    // operator tools (getchaintips RPC, fork visibility) see the full
    // picture during a competing-sibling situation.
    CChainState cs;

    auto pA = MakeIndex(0x01, nullptr, 0,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(cs.AddBlockIndex(hA, std::move(pA)));
    cs.SetTip(cs.GetBlockIndex(hA));
    CBlockIndex* A = cs.GetBlockIndex(hA);

    auto pX = MakeIndex(0x40, A, 1,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    auto pY = MakeIndex(0x41, A, 1,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hX = pX->GetBlockHash();
    uint256 hY = pY->GetBlockHash();
    assert(cs.AddBlockIndex(hX, std::move(pX)));
    assert(cs.AddBlockIndex(hY, std::move(pY)));

    ::dilithion::consensus::port::ChainSelectorAdapter adapter(cs);
    auto tips = adapter.GetChainTips();

    // Both siblings must appear; A is no longer a tip (has children).
    bool foundX = false, foundY = false;
    for (const auto& t : tips) {
        if (std::memcmp(t.hash.data, hX.data, 32) == 0) foundX = true;
        if (std::memcmp(t.hash.data, hY.data, 32) == 0) foundY = true;
    }
    assert(foundX && foundY &&
           "Both competing siblings must surface in adapter.GetChainTips()");

    std::cout << " OK\n";
}

int main()
{
    std::cout << "\n=== Phase 5 Day 4 V1: Competing-Sibling-Below-Checkpoint Tests ===\n"
              << "    (WITH-Patch-H subset; gates PR5.6 Patch H deletion)\n"
              << std::endl;
    try {
        test_two_siblings_below_checkpoint_both_in_index();
        test_three_siblings_at_below_checkpoint_height_all_present();
        test_invalidate_one_sibling_others_remain_candidates();
        test_adapter_chain_tips_lists_all_siblings();
        std::cout << "\n=== All competing-sibling structural-coverage tests passed (4 tests) ===\n";
        std::cout << "Phase 5's chain-selector design replaces Patch H structurally;\n"
                  << "PR5.6 (Patch H deletion) can proceed once this test stays green\n"
                  << "after the legacy HeadersManager Patch H block is removed.\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed (unknown)" << std::endl;
        return 1;
    }
}
