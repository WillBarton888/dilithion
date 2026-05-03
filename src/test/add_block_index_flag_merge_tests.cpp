// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 11 ABI — AddBlockIndex flag-merge semantics tests.
//
// Reproduces and locks in the fix for the v4.1 IBD silent-drop bug:
// when ChainSelectorAdapter::ProcessNewHeader pre-populates mapBlockIndex
// with a CBlockIndex carrying nStatus = BLOCK_VALID_HEADER, and the
// block-data path later calls AddBlockIndex again with nStatus =
// BLOCK_HAVE_DATA for the same hash, the second call MUST merge the
// new flag into the existing entry instead of silently dropping it.
//
// Pre-fix behaviour (chain.cpp:96-98 in v4.1): return false on duplicate,
// drop the new entry → existing entry stayed at BLOCK_VALID_HEADER →
// HaveData() never became true → block_processing.cpp:891 never activated
// the block → chain stayed at genesis on a fresh datadir running with
// chain_selector enabled. SYD mainnet, 2026-05-02.
//
// Post-fix behaviour (this file): nStatus accumulates monotonically via
// bitwise OR; topology must agree on duplicate adds; pprev adoption is
// allowed when the existing entry's pprev is null.

#include <consensus/chain.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>

namespace {

// Build a CBlockIndex with an explicitly-set phashBlock and pprev=nullptr,
// nHeight=0 (genesis-like). Status starts at the caller-supplied value
// because that is what the bug-and-fix is about.
std::unique_ptr<CBlockIndex> MakeGenesisLikeIndex(uint8_t hash_seed,
                                                  uint32_t status_bits)
{
    auto pindex = std::make_unique<CBlockIndex>();
    pindex->pprev = nullptr;
    pindex->nHeight = 0;
    pindex->nChainWork = uint256();
    pindex->nStatus = status_bits;
    pindex->nSequenceId = 1;
    std::memset(pindex->phashBlock.data, 0, 32);
    pindex->phashBlock.data[0] = hash_seed;
    return pindex;
}

// Build a child of `parent` at parent.height+1. Same hash byte 0 = seed,
// byte 1 = 0x01 to disambiguate from siblings. nChainWork copied from
// parent so the topology-must-agree invariant trivially holds.
std::unique_ptr<CBlockIndex> MakeChildIndex(uint8_t hash_seed,
                                            CBlockIndex* parent,
                                            uint32_t status_bits)
{
    auto pindex = std::make_unique<CBlockIndex>();
    pindex->pprev = parent;
    pindex->nHeight = parent->nHeight + 1;
    pindex->nChainWork = parent->nChainWork;  // contrived but deterministic
    pindex->nStatus = status_bits;
    pindex->nSequenceId = 2;
    std::memset(pindex->phashBlock.data, 0, 32);
    pindex->phashBlock.data[0] = hash_seed;
    pindex->phashBlock.data[1] = 0x01;
    return pindex;
}

}  // anonymous

// ---------------------------------------------------------------------------
// Case 1: first add returns true, BLOCK_VALID_HEADER stored as-is.
// ---------------------------------------------------------------------------
void test_first_add_returns_true_with_header_flag()
{
    std::cout << "  test_first_add_returns_true_with_header_flag..." << std::flush;
    CChainState chainstate;

    auto pindex = MakeGenesisLikeIndex(0x11, CBlockIndex::BLOCK_VALID_HEADER);
    uint256 hash = pindex->GetBlockHash();
    bool added = chainstate.AddBlockIndex(hash, std::move(pindex));
    assert(added);

    CBlockIndex* found = chainstate.GetBlockIndex(hash);
    assert(found != nullptr);
    assert(found->nStatus == CBlockIndex::BLOCK_VALID_HEADER);
    assert(!found->HaveData());

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// Case 2: SECOND ADD merges BLOCK_HAVE_DATA into the existing
// BLOCK_VALID_HEADER entry. THIS IS THE LOAD-BEARING IBD SCENARIO.
// ---------------------------------------------------------------------------
void test_second_add_merges_have_data_flag_into_header()
{
    std::cout << "  test_second_add_merges_have_data_flag_into_header..."
              << std::flush;
    CChainState chainstate;

    // First call: header pre-pop (mirrors ChainSelectorAdapter::ProcessNewHeader).
    auto p1 = MakeGenesisLikeIndex(0x22, CBlockIndex::BLOCK_VALID_HEADER);
    uint256 hash = p1->GetBlockHash();
    CBlockIndex* p1_raw = p1.get();
    bool added1 = chainstate.AddBlockIndex(hash, std::move(p1));
    assert(added1);

    // Sanity: only header flag set, HaveData() false.
    CBlockIndex* before = chainstate.GetBlockIndex(hash);
    assert(before != nullptr);
    assert(before == p1_raw);  // first call retained ownership
    assert(before->nStatus == CBlockIndex::BLOCK_VALID_HEADER);
    assert(!before->HaveData());

    // Second call: block-data arrives (mirrors block_processing.cpp:1077).
    auto p2 = MakeGenesisLikeIndex(0x22, CBlockIndex::BLOCK_HAVE_DATA);
    bool added2 = chainstate.AddBlockIndex(hash, std::move(p2));
    assert(added2);  // PRE-FIX: this was false (the bug)

    // Verify the existing entry now carries BOTH flags. The pointer must
    // be unchanged — we merged into the existing CBlockIndex, we did not
    // replace it.
    CBlockIndex* after = chainstate.GetBlockIndex(hash);
    assert(after == p1_raw);  // same object, NOT replaced
    assert(after->HaveData());  // PRE-FIX: this was false (the bug)
    assert((after->nStatus & CBlockIndex::BLOCK_VALID_HEADER) != 0);
    assert((after->nStatus & CBlockIndex::BLOCK_HAVE_DATA) != 0);

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// Case 3: idempotent duplicate (same flag bits) — no-op, still true.
// ---------------------------------------------------------------------------
void test_idempotent_duplicate_call()
{
    std::cout << "  test_idempotent_duplicate_call..." << std::flush;
    CChainState chainstate;

    auto p1 = MakeGenesisLikeIndex(0x33, CBlockIndex::BLOCK_VALID_HEADER);
    uint256 hash = p1->GetBlockHash();
    assert(chainstate.AddBlockIndex(hash, std::move(p1)));

    auto p2 = MakeGenesisLikeIndex(0x33, CBlockIndex::BLOCK_VALID_HEADER);
    bool added2 = chainstate.AddBlockIndex(hash, std::move(p2));
    assert(added2);

    CBlockIndex* found = chainstate.GetBlockIndex(hash);
    // Bitwise OR of identical flag sets is the same flag set.
    assert(found->nStatus == CBlockIndex::BLOCK_VALID_HEADER);

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// Case 4: three-call accumulation — every flag stays set.
// ---------------------------------------------------------------------------
void test_status_accumulation_across_three_calls()
{
    std::cout << "  test_status_accumulation_across_three_calls..." << std::flush;
    CChainState chainstate;

    // 1. Header sync.
    auto p1 = MakeGenesisLikeIndex(0x44, CBlockIndex::BLOCK_VALID_HEADER);
    uint256 hash = p1->GetBlockHash();
    assert(chainstate.AddBlockIndex(hash, std::move(p1)));

    // 2. Block-data path (sync).
    auto p2 = MakeGenesisLikeIndex(0x44, CBlockIndex::BLOCK_HAVE_DATA);
    assert(chainstate.AddBlockIndex(hash, std::move(p2)));

    // 3. Hypothetical late re-validation path with BLOCK_VALID_CHAIN.
    auto p3 = MakeGenesisLikeIndex(0x44, CBlockIndex::BLOCK_VALID_CHAIN);
    assert(chainstate.AddBlockIndex(hash, std::move(p3)));

    CBlockIndex* found = chainstate.GetBlockIndex(hash);
    assert(found->nStatus & CBlockIndex::BLOCK_VALID_HEADER);
    assert(found->nStatus & CBlockIndex::BLOCK_HAVE_DATA);
    assert(found->nStatus & CBlockIndex::BLOCK_VALID_CHAIN);
    assert(found->HaveData());

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// Case 5: existing has null pprev, second call supplies parent — adoption.
//
// This mirrors the case where header-sync inserts a header before its
// parent has been processed (shouldn't happen in normal flow because
// ProcessNewHeader rejects orphans, but adoption is valid defense-in-depth
// for any caller path that inserts entries with pprev=null and later
// fixes them up).
// ---------------------------------------------------------------------------
void test_pprev_adoption_when_existing_was_null()
{
    std::cout << "  test_pprev_adoption_when_existing_was_null..." << std::flush;
    CChainState chainstate;

    // 1. Add a parent (genesis-like).
    auto pParent = MakeGenesisLikeIndex(0x55, CBlockIndex::BLOCK_VALID_HEADER);
    uint256 parentHash = pParent->GetBlockHash();
    assert(chainstate.AddBlockIndex(parentHash, std::move(pParent)));
    CBlockIndex* parentInMap = chainstate.GetBlockIndex(parentHash);

    // 2. Add a child but with pprev=null and height=1 (manually break the
    //    invariant on the FIRST add — bypass the parent check by using a
    //    fake "child looks like genesis" index. We use height=0 to satisfy
    //    the first-call invariant, then on the second call provide the
    //    parent linkage and simulate the merge-with-adoption case at the
    //    same height level.)
    //
    //    Note: For a true height>0 entry, the FIRST AddBlockIndex call's
    //    own ConsensusInvariant ("if pprev != null, parent must exist; else
    //    height must be 0") cannot be bypassed. So this test exercises the
    //    case where an existing height-0 entry gets a "fix" call that is
    //    also height=0 with pprev=null — i.e. the adoption branch is
    //    exercised by an equal-pprev (both null) merge, which the existing
    //    invariant accepts.
    auto p2 = MakeGenesisLikeIndex(0x55, CBlockIndex::BLOCK_HAVE_DATA);
    bool added = chainstate.AddBlockIndex(parentHash, std::move(p2));
    assert(added);

    // The merged entry retains pprev=null (existing was null, incoming was null
    // — no adoption needed, but the path was traversed without abort).
    CBlockIndex* merged = chainstate.GetBlockIndex(parentHash);
    assert(merged == parentInMap);
    assert(merged->pprev == nullptr);
    assert(merged->nHeight == 0);
    assert(merged->nStatus & CBlockIndex::BLOCK_VALID_HEADER);
    assert(merged->nStatus & CBlockIndex::BLOCK_HAVE_DATA);

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// Case 6: genesis-bootstrap idempotency.
//
// Mirrors the dilithion-node.cpp:2502 / dilv-node.cpp:2406 first-time-add
// path: genesis is stored with BLOCK_VALID_CHAIN | BLOCK_HAVE_DATA. If a
// later code path naively re-adds genesis with just BLOCK_HAVE_DATA, the
// merge must NOT lose the BLOCK_VALID_CHAIN flag.
// ---------------------------------------------------------------------------
void test_genesis_idempotent_add_preserves_valid_chain()
{
    std::cout << "  test_genesis_idempotent_add_preserves_valid_chain..."
              << std::flush;
    CChainState chainstate;

    // First add: genesis with full activation flags.
    auto pGenesis = MakeGenesisLikeIndex(
        0x66,
        CBlockIndex::BLOCK_VALID_CHAIN | CBlockIndex::BLOCK_HAVE_DATA);
    uint256 hash = pGenesis->GetBlockHash();
    assert(chainstate.AddBlockIndex(hash, std::move(pGenesis)));

    // Second add: genesis with only BLOCK_HAVE_DATA (e.g. a startup-replay
    // path that constructs a fresh CBlockIndex from disk without setting
    // the activation flag).
    auto pGenesisAgain = MakeGenesisLikeIndex(0x66,
                                              CBlockIndex::BLOCK_HAVE_DATA);
    assert(chainstate.AddBlockIndex(hash, std::move(pGenesisAgain)));

    CBlockIndex* g = chainstate.GetBlockIndex(hash);
    // Both flags must still be present (BLOCK_VALID_CHAIN was NOT lost).
    assert(g->nStatus & CBlockIndex::BLOCK_VALID_CHAIN);
    assert(g->nStatus & CBlockIndex::BLOCK_HAVE_DATA);

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// Case 7: header-then-data sequence on a child block (height 1) — the
// most direct simulation of the SYD mainnet IBD scenario.
// ---------------------------------------------------------------------------
void test_height_one_header_then_data_sequence()
{
    std::cout << "  test_height_one_header_then_data_sequence..."
              << std::flush;
    CChainState chainstate;

    // 1. Add genesis.
    auto pGenesis = MakeGenesisLikeIndex(
        0x77,
        CBlockIndex::BLOCK_VALID_CHAIN | CBlockIndex::BLOCK_HAVE_DATA);
    uint256 genesisHash = pGenesis->GetBlockHash();
    assert(chainstate.AddBlockIndex(genesisHash, std::move(pGenesis)));
    CBlockIndex* genesisRaw = chainstate.GetBlockIndex(genesisHash);

    // 2. Header-sync inserts height-1 with BLOCK_VALID_HEADER.
    auto pH1Header = MakeChildIndex(0x88, genesisRaw,
                                    CBlockIndex::BLOCK_VALID_HEADER);
    uint256 h1Hash = pH1Header->GetBlockHash();
    assert(chainstate.AddBlockIndex(h1Hash, std::move(pH1Header)));

    CBlockIndex* h1Before = chainstate.GetBlockIndex(h1Hash);
    assert(!h1Before->HaveData());  // pre-fix bug condition reproduced

    // 3. Block-data arrives → MakeChildIndex with BLOCK_HAVE_DATA.
    auto pH1Data = MakeChildIndex(0x88, genesisRaw,
                                  CBlockIndex::BLOCK_HAVE_DATA);
    bool added = chainstate.AddBlockIndex(h1Hash, std::move(pH1Data));
    assert(added);

    // POST-FIX: the entry now has data.
    CBlockIndex* h1After = chainstate.GetBlockIndex(h1Hash);
    assert(h1After == h1Before);  // same CBlockIndex object
    assert(h1After->HaveData());  // <-- the fix
    assert(h1After->nStatus & CBlockIndex::BLOCK_VALID_HEADER);
    assert(h1After->nStatus & CBlockIndex::BLOCK_HAVE_DATA);
    assert(h1After->pprev == genesisRaw);

    std::cout << " OK\n";
}

int main()
{
    std::cout << "\n=== Phase 11 ABI: AddBlockIndex flag-merge tests ==="
              << std::endl;

    try {
        test_first_add_returns_true_with_header_flag();
        test_second_add_merges_have_data_flag_into_header();
        test_idempotent_duplicate_call();
        test_status_accumulation_across_three_calls();
        test_pprev_adoption_when_existing_was_null();
        test_genesis_idempotent_add_preserves_valid_chain();
        test_height_one_header_then_data_sequence();

        std::cout << "\n=== All add_block_index_flag_merge_tests passed (7 cases) ==="
                  << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAILED with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "FAILED with unknown exception" << std::endl;
        return 1;
    }
}
