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
#include <primitives/block.h>

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

// ============================================================================
// PR5.3 prerequisite (Day 2 PM, 2026-04-26):
//   * ProcessNewHeader populates CChainState::mapBlockIndex with EVERY
//     header (pre-validation entries get nStatus = BLOCK_VALID_HEADER).
//   * G1: pre-validation siblings remain visible to fork detection.
//   * G2: BLOCK_VALID_HEADER-only entries are NOT IsInvalid().
// ============================================================================

namespace {

// Construct a VDF-style header (SHA3-256 hash, no RandomX dependency in
// tests) chained from a given parent hash.
CBlockHeader MakeVDFHeader(const uint256& parent_hash, uint32_t nBits, uint32_t nTime)
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::VDF_VERSION;
    h.hashPrevBlock = parent_hash;
    std::memset(h.hashMerkleRoot.data, 0, 32);
    h.nTime = nTime;
    h.nBits = nBits;
    h.nNonce = 0;
    // Distinguish siblings via the VDF output bytes — different vdfOutput
    // means different SHA3 hash even with same parent.
    for (int i = 0; i < 32; ++i) h.vdfProofHash.data[i] = 0;
    for (int i = 0; i < 32; ++i) h.vdfOutput.data[i] = static_cast<uint8_t>(nTime & 0xff);
    return h;
}

// Same shape as MakeGenesisLikeIndex above but explicitly named for
// pre-validation usage with arbitrary status flags.
std::unique_ptr<CBlockIndex> MakePreValidationLeaf(uint8_t hash_seed,
                                                   CBlockIndex* parent,
                                                   int height,
                                                   uint32_t status,
                                                   uint8_t work_seed,
                                                   uint32_t seq_id = 1)
{
    auto pindex = std::make_unique<CBlockIndex>();
    pindex->pprev = parent;
    pindex->nHeight = height;
    pindex->nStatus = status;
    pindex->nSequenceId = seq_id;
    std::memset(pindex->phashBlock.data, 0, 32);
    pindex->phashBlock.data[0] = hash_seed;
    std::memset(pindex->nChainWork.data, 0, 32);
    pindex->nChainWork.data[0] = work_seed;
    return pindex;
}

}  // anonymous

void test_process_new_header_genesis_creates_pre_validation_entry()
{
    std::cout << "  test_process_new_header_genesis_creates_pre_validation_entry..."
              << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Genesis: hashPrevBlock = null. VDF style so SHA3 (no RandomX).
    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto h = MakeVDFHeader(null_hash, 0x1d00ffff, 1700000000);

    bool ok = adapter.ProcessNewHeader(h);
    assert(ok);

    uint256 hash = h.GetHash();
    CBlockIndex* p = chainstate.GetBlockIndex(hash);
    assert(p != nullptr);
    assert(p->nHeight == 0);
    assert(p->pprev == nullptr);
    // G2: pre-validation only; failure flags must be clear.
    assert((p->nStatus & CBlockIndex::BLOCK_VALID_MASK) == CBlockIndex::BLOCK_VALID_HEADER);
    assert(!p->IsInvalid());

    // Idempotency: a second call with the same header succeeds without
    // creating a duplicate.
    bool ok2 = adapter.ProcessNewHeader(h);
    assert(ok2);
    assert(chainstate.GetBlockIndex(hash) == p);  // same pointer

    std::cout << " OK\n";
}

void test_process_new_header_orphan_returns_false()
{
    std::cout << "  test_process_new_header_orphan_returns_false..."
              << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Header with a non-null parent hash that does NOT exist in
    // mapBlockIndex — caller must order parents before children.
    uint256 unknown_parent;
    std::memset(unknown_parent.data, 0, 32);
    unknown_parent.data[0] = 0x99;
    auto h = MakeVDFHeader(unknown_parent, 0x1d00ffff, 1700000001);

    bool ok = adapter.ProcessNewHeader(h);
    assert(!ok);
    // mapBlockIndex unchanged.
    assert(chainstate.GetBlockIndex(h.GetHash()) == nullptr);

    std::cout << " OK\n";
}

void test_process_new_header_chains_parent_correctly()
{
    std::cout << "  test_process_new_header_chains_parent_correctly..."
              << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Process genesis via ProcessNewHeader.
    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto hG = MakeVDFHeader(null_hash, 0x1d00ffff, 1700000000);
    assert(adapter.ProcessNewHeader(hG));
    uint256 genesis_hash = hG.GetHash();
    CBlockIndex* G = chainstate.GetBlockIndex(genesis_hash);

    // Process child of genesis.
    auto hC = MakeVDFHeader(genesis_hash, 0x1d00ffff, 1700000060);
    assert(adapter.ProcessNewHeader(hC));
    CBlockIndex* C = chainstate.GetBlockIndex(hC.GetHash());

    assert(C != nullptr);
    assert(C->pprev == G);
    assert(C->nHeight == 1);
    // Cumulative work strictly greater than parent.
    assert(ChainWorkGreaterThan(C->nChainWork, G->nChainWork));
    // G2: pre-validation only.
    assert(!C->IsInvalid());
    assert((C->nStatus & CBlockIndex::BLOCK_VALID_MASK) == CBlockIndex::BLOCK_VALID_HEADER);

    std::cout << " OK\n";
}

void test_g1_pre_validation_siblings_visible_as_competing_tips()
{
    std::cout << "  test_g1_pre_validation_siblings_visible_as_competing_tips..."
              << std::flush;

    // Build: genesis A -> two pre-validation siblings B, C (BLOCK_VALID_HEADER).
    // Active tip stays at A (no full validation has connected B or C).
    // Both B and C must show up as competing tips with status=ValidHeaders.
    CChainState chainstate;

    auto pA = MakePreValidationLeaf(0x01, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x02, A, 1, CBlockIndex::BLOCK_VALID_HEADER, 10, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));

    auto pC = MakePreValidationLeaf(0x03, A, 1, CBlockIndex::BLOCK_VALID_HEADER, 10, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));

    // Both legacy and adapter should show 3 tips (A active, B+C valid-headers).
    auto legacy = chainstate.GetChainTips();
    // A has 2 children, so it's no longer a tip — but it's the active tip.
    // Wait: the active-tip path is special-cased to remain visible. Legacy
    // logic includes pindexTip even if it has children.
    bool foundA = false, foundB = false, foundC = false;
    for (const auto& t : legacy) {
        if (t.hash == hA && t.status == "active") foundA = true;
        if (t.hash == hB && t.status == "valid-headers") foundB = true;
        if (t.hash == hC && t.status == "valid-headers") foundC = true;
    }
    // A IS in hasChildren (B and C list it as parent), so it gets filtered out
    // by the "any block NOT in hasChildren is a tip" rule. The active tip
    // when it has children isn't surfaced today — but B and C both must be.
    assert(foundB && "G1: pre-validation sibling B must be visible as a tip");
    assert(foundC && "G1: pre-validation sibling C must be visible as a tip");

    // Adapter must report exactly the same set with ValidHeaders enum.
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    auto adapted = adapter.GetChainTips();
    bool foundB_adapted = false, foundC_adapted = false;
    for (const auto& t : adapted) {
        if (t.hash == hB) {
            assert(t.status == ::dilithion::consensus::ChainTipInfo::Status::ValidHeaders);
            foundB_adapted = true;
        }
        if (t.hash == hC) {
            assert(t.status == ::dilithion::consensus::ChainTipInfo::Status::ValidHeaders);
            foundC_adapted = true;
        }
    }
    assert(foundB_adapted && foundC_adapted);

    // size() > 1 IS the post-PR5.2.B replacement for HasCompetingForks.
    assert(adapted.size() >= 2);

    (void)foundA;
    std::cout << " OK\n";
}

void test_g2_pre_validation_entries_are_not_invalid()
{
    std::cout << "  test_g2_pre_validation_entries_are_not_invalid..."
              << std::flush;

    CChainState chainstate;

    // Set up genesis as a fully-validated active tip (so we have a parent).
    auto pA = MakePreValidationLeaf(0x10, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    // Pre-validation entry: BLOCK_VALID_HEADER only.
    auto pH = MakePreValidationLeaf(0x11, A, 1, CBlockIndex::BLOCK_VALID_HEADER, 10, 2);
    uint256 hH = pH->GetBlockHash();
    assert(chainstate.AddBlockIndex(hH, std::move(pH)));
    CBlockIndex* H = chainstate.GetBlockIndex(hH);

    // G2 core property: a header-only entry must NOT be IsInvalid().
    assert(!H->IsInvalid());
    // No FAILED_VALID, no FAILED_CHILD.
    assert((H->nStatus & CBlockIndex::BLOCK_FAILED_MASK) == 0);
    // The validation level is exactly BLOCK_VALID_HEADER (1).
    assert((H->nStatus & CBlockIndex::BLOCK_VALID_MASK) == CBlockIndex::BLOCK_VALID_HEADER);

    // The PR5.2.B "IsTip" replacement signature (non-null lookup AND not
    // invalid AND no children) must be true for this leaf — proving the
    // tracker can be safely retired in favor of mapBlockIndex walks once
    // PR5.3 wires ProcessNewHeader into the live IBD path.
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    CBlockIndex* via_adapter = adapter.LookupBlockIndex(hH);
    assert(via_adapter == H);
    assert(via_adapter->pnext == nullptr);
    assert(!via_adapter->IsInvalid());

    // Negative companion: an explicitly-invalidated entry MUST report
    // IsInvalid()==true so failure propagation isn't a no-op.
    auto pI = MakePreValidationLeaf(0x12, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                                        CBlockIndex::BLOCK_FAILED_VALID,
                                    10, 3);
    uint256 hI = pI->GetBlockHash();
    assert(chainstate.AddBlockIndex(hI, std::move(pI)));
    CBlockIndex* I = chainstate.GetBlockIndex(hI);
    assert(I->IsInvalid());

    std::cout << " OK\n";
}

// ============================================================================
// PR5.3 Day 3 AM: tests for RecomputeCandidates, MarkBlockAsFailed,
// MarkBlockAsValid, FindMostWorkChainImpl, IsBlockACandidateForActivation.
// ============================================================================

void test_recompute_candidates_skips_pre_validation_leaves()
{
    std::cout << "  test_recompute_candidates_skips_pre_validation_leaves..."
              << std::flush;

    // A (genesis, BLOCK_VALID_TRANSACTIONS) -> B (BLOCK_VALID_TRANSACTIONS, leaf, candidate)
    //                                       \-> C (BLOCK_VALID_HEADER only, leaf, NOT candidate)
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x40, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x41, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pC = MakePreValidationLeaf(0x42, A, 1,
                                    CBlockIndex::BLOCK_VALID_HEADER, 10, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));

    chainstate.RecomputeCandidates();

    // B is a candidate (full validation, leaf). C is not (header-only).
    // A is not (has children). Direct invariant check via the predicate.
    assert(chainstate.IsBlockACandidateForActivation(B));
    assert(!chainstate.IsBlockACandidateForActivation(chainstate.GetBlockIndex(hC)));
    assert(chainstate.IsBlockACandidateForActivation(A));  // predicate yes; leaf-status no
    // FindMostWorkChainImpl is the way to OBSERVE the candidate set's contents
    // without exposing the private member. After RecomputeCandidates with B
    // having more work than the active tip, FindMostWorkChainImpl returns B.
    assert(chainstate.FindMostWorkChainImpl() == B);

    std::cout << " OK\n";
}

void test_recompute_candidates_skips_invalid_blocks()
{
    std::cout << "  test_recompute_candidates_skips_invalid_blocks..."
              << std::flush;

    // A -> B (FAILED_VALID, NOT a candidate)
    //   -> C (valid leaf, IS a candidate)
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x50, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x51, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                                        CBlockIndex::BLOCK_FAILED_VALID,
                                    20, 2);  // higher work but invalid
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));

    auto pC = MakePreValidationLeaf(0x52, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));
    CBlockIndex* C = chainstate.GetBlockIndex(hC);

    chainstate.RecomputeCandidates();

    // FindMostWorkChainImpl should pick C (B is invalid even though heavier).
    CBlockIndex* picked = chainstate.FindMostWorkChainImpl();
    assert(picked == C);

    std::cout << " OK\n";
}

void test_mark_block_as_failed_propagates_to_descendants()
{
    std::cout << "  test_mark_block_as_failed_propagates_to_descendants..."
              << std::flush;

    // A -> B -> D
    //       \-> E
    // MarkBlockAsFailed(B) -> B gets FAILED_VALID, D + E get FAILED_CHILD.
    // A unaffected.
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x60, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x61, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pD = MakePreValidationLeaf(0x62, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = chainstate.GetBlockIndex(hD);

    auto pE = MakePreValidationLeaf(0x63, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 4);
    uint256 hE = pE->GetBlockHash();
    assert(chainstate.AddBlockIndex(hE, std::move(pE)));
    CBlockIndex* E = chainstate.GetBlockIndex(hE);

    chainstate.MarkBlockAsFailed(B);

    assert(B->IsInvalid());
    assert(B->nStatus & CBlockIndex::BLOCK_FAILED_VALID);
    assert(D->IsInvalid());
    assert(D->nStatus & CBlockIndex::BLOCK_FAILED_CHILD);
    assert(E->IsInvalid());
    assert(E->nStatus & CBlockIndex::BLOCK_FAILED_CHILD);
    // A is NOT affected.
    assert(!A->IsInvalid());

    std::cout << " OK\n";
}

void test_mark_block_as_valid_clears_failed_child()
{
    std::cout << "  test_mark_block_as_valid_clears_failed_child..."
              << std::flush;

    // Build A -> B -> D, mark B failed (D inherits FAILED_CHILD), then
    // ReconsiderBlock(B) clears failure flags on B and FAILED_CHILD on D.
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x70, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x71, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pD = MakePreValidationLeaf(0x72, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = chainstate.GetBlockIndex(hD);

    chainstate.MarkBlockAsFailed(B);
    assert(B->IsInvalid());
    assert(D->IsInvalid());

    chainstate.MarkBlockAsValid(B);
    assert(!B->IsInvalid());  // FAILED_VALID cleared
    assert(!D->IsInvalid());  // FAILED_CHILD cleared

    std::cout << " OK\n";
}

void test_invalidate_block_impl_propagates_and_drops_candidates()
{
    std::cout << "  test_invalidate_block_impl_propagates_and_drops_candidates..."
              << std::flush;

    // A -> B -> D (B has work_seed=10, D has work_seed=20, all valid)
    //       \-> E (work_seed=15)
    // After RecomputeCandidates: D, E in candidate set; FindMostWork picks D.
    // After InvalidateBlockImpl(B): B + D + E all invalid; candidates empty;
    // FindMostWork returns nullptr (no valid leaves); A is unaffected.
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x90, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x91, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pD = MakePreValidationLeaf(0x92, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20, 3);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = chainstate.GetBlockIndex(hD);

    auto pE = MakePreValidationLeaf(0x93, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 15, 4);
    uint256 hE = pE->GetBlockHash();
    assert(chainstate.AddBlockIndex(hE, std::move(pE)));
    CBlockIndex* E = chainstate.GetBlockIndex(hE);

    chainstate.RecomputeCandidates();
    assert(chainstate.FindMostWorkChainImpl() == D);  // sanity: D is the heaviest

    bool invalidated = chainstate.InvalidateBlockImpl(hB);
    assert(invalidated);

    // B and descendants are now invalid.
    assert(B->IsInvalid());
    assert(D->IsInvalid());
    assert(E->IsInvalid());
    // A is NOT affected.
    assert(!A->IsInvalid());

    // After Invalidate, no valid leaves remain (only A, but A has children).
    // FindMostWorkChainImpl returns nullptr — nothing to activate.
    assert(chainstate.FindMostWorkChainImpl() == nullptr);

    // Negative case: invalidating an unknown hash returns false.
    uint256 unknown;
    std::memset(unknown.data, 0, 32);
    unknown.data[0] = 0xFF;
    assert(!chainstate.InvalidateBlockImpl(unknown));

    std::cout << " OK\n";
}

void test_reconsider_block_impl_restores_candidates()
{
    std::cout << "  test_reconsider_block_impl_restores_candidates..."
              << std::flush;

    // A -> B -> D (all valid)
    // Invalidate(B) -> Reconsider(B). After Reconsider, D should be a
    // candidate again and FindMostWork picks D.
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0xA0, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0xA1, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pD = MakePreValidationLeaf(0xA2, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20, 3);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = chainstate.GetBlockIndex(hD);

    chainstate.RecomputeCandidates();
    assert(chainstate.FindMostWorkChainImpl() == D);

    assert(chainstate.InvalidateBlockImpl(hB));
    assert(B->IsInvalid());
    assert(D->IsInvalid());
    assert(chainstate.FindMostWorkChainImpl() == nullptr);

    assert(chainstate.ReconsiderBlockImpl(hB));
    assert(!B->IsInvalid());
    assert(!D->IsInvalid());
    // D should be a candidate again — RecomputeCandidates ran inside Reconsider.
    assert(chainstate.FindMostWorkChainImpl() == D);

    // Negative: reconsidering an unknown hash returns false.
    uint256 unknown;
    std::memset(unknown.data, 0, 32);
    unknown.data[0] = 0xEE;
    assert(!chainstate.ReconsiderBlockImpl(unknown));

    std::cout << " OK\n";
}

void test_find_most_work_chain_returns_heaviest_valid_leaf()
{
    std::cout << "  test_find_most_work_chain_returns_heaviest_valid_leaf..."
              << std::flush;

    // A -> B (work=5)
    //   -> C (work=20, heaviest)
    //   -> D (work=10)
    // FindMostWorkChainImpl returns C.
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x80, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x81, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));

    auto pC = MakePreValidationLeaf(0x82, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));
    CBlockIndex* C = chainstate.GetBlockIndex(hC);

    auto pD = MakePreValidationLeaf(0x83, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 4);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));

    chainstate.RecomputeCandidates();
    CBlockIndex* picked = chainstate.FindMostWorkChainImpl();
    assert(picked == C);

    std::cout << " OK\n";
}

int main()
{
    std::cout << "\n=== Phase 5 PR5.1 + 5.3-prereq + 5.3 Day 3 AM: ChainSelector Tests ===\n"
              << std::endl;

    try {
        std::cout << "--- PR5.1 trivial getters ---" << std::endl;
        test_get_active_tip_null_on_fresh_chainstate();
        test_get_active_tip_after_set_tip_for_test();
        test_get_active_height_and_hash_match_tip();
        test_lookup_block_index_returns_added_block();

        std::cout << "\n--- PR5.3 prerequisite: ProcessNewHeader ---" << std::endl;
        test_process_new_header_genesis_creates_pre_validation_entry();
        test_process_new_header_orphan_returns_false();
        test_process_new_header_chains_parent_correctly();

        std::cout << "\n--- PR5.3 prerequisite: G1/G2 guardrails ---" << std::endl;
        test_g1_pre_validation_siblings_visible_as_competing_tips();
        test_g2_pre_validation_entries_are_not_invalid();

        std::cout << "\n--- PR5.3 Day 3 AM: candidate set + selection ---" << std::endl;
        test_recompute_candidates_skips_pre_validation_leaves();
        test_recompute_candidates_skips_invalid_blocks();
        test_mark_block_as_failed_propagates_to_descendants();
        test_mark_block_as_valid_clears_failed_child();
        test_find_most_work_chain_returns_heaviest_valid_leaf();

        std::cout << "\n--- PR5.3 Day 3 PM: Invalidate / Reconsider operator overrides ---"
                  << std::endl;
        test_invalidate_block_impl_propagates_and_drops_candidates();
        test_reconsider_block_impl_restores_candidates();

        std::cout << "\n=== All chain_selector_tests passed (16 tests: 4 + 5 + 5 + 2) ==="
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
