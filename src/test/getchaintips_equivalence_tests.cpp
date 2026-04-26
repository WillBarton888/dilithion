// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 PR5.2.A — getchaintips equivalence proof.
//
// Verifies that ChainSelectorAdapter::GetChainTips (vector<ChainTipInfo>
// with enum Status) describes the SAME tree as the legacy
// CChainState::GetChainTips (vector<ChainTip> with std::string status).
//
// This test is the gate before PR5.2.B retires CChainTipsTracker. If this
// proof holds, the headers-manager's separate "competing tips" cache is
// redundant — the block index tree already carries the full picture.
//
// Fixture: a hand-built block index tree with FIVE tips, one for each
// status value the frozen enum supports:
//   active        — main chain tip
//   valid-fork    — competing leaf, BLOCK_VALID_TRANSACTIONS
//   valid-headers — competing leaf, BLOCK_VALID_HEADER only
//   invalid       — competing leaf, BLOCK_FAILED_VALID set
//   unknown       — competing leaf, BLOCK_VALID_UNKNOWN (no validation)

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <node/block_index.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>

namespace consensus_port = ::dilithion::consensus::port;
using ChainTipInfo = ::dilithion::consensus::ChainTipInfo;

namespace {

// Build a CBlockIndex with explicitly-set phashBlock, parent linkage,
// height, status, and chain_work. Genesis path is pprev=nullptr/height=0.
std::unique_ptr<CBlockIndex> MakeIndex(uint8_t hash_seed,
                                       CBlockIndex* parent,
                                       int height,
                                       uint32_t status,
                                       uint8_t work_seed)
{
    auto pindex = std::make_unique<CBlockIndex>();
    pindex->pprev = parent;
    pindex->nHeight = height;
    pindex->nStatus = status;
    pindex->nSequenceId = static_cast<uint32_t>(hash_seed);

    std::memset(pindex->phashBlock.data, 0, 32);
    pindex->phashBlock.data[0] = hash_seed;

    std::memset(pindex->nChainWork.data, 0, 32);
    pindex->nChainWork.data[0] = work_seed;

    return pindex;
}

const char* StatusName(ChainTipInfo::Status s)
{
    switch (s) {
        case ChainTipInfo::Status::Active:        return "Active";
        case ChainTipInfo::Status::ValidFork:     return "ValidFork";
        case ChainTipInfo::Status::ValidHeaders:  return "ValidHeaders";
        case ChainTipInfo::Status::InvalidBlock:  return "InvalidBlock";
        case ChainTipInfo::Status::Unknown:       return "Unknown";
    }
    return "?";
}

}  // anonymous namespace

void test_chaintips_legacy_and_adapter_describe_same_tree()
{
    std::cout << "  test_chaintips_legacy_and_adapter_describe_same_tree..."
              << std::flush;

    CChainState chainstate;

    // Genesis A.
    auto pA = MakeIndex(/*hash_seed=*/0x01, /*parent=*/nullptr, /*height=*/0,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS, /*work=*/1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    // B from A — main chain extension; full block validated.
    auto pB = MakeIndex(0x02, A, 1, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    // C from A — competing fork; full block validated.
    auto pC = MakeIndex(0x03, A, 1, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));

    // E from A — header validated, block data NOT yet here.
    auto pE = MakeIndex(0x05, A, 1, CBlockIndex::BLOCK_VALID_HEADER, 10);
    uint256 hE = pE->GetBlockHash();
    assert(chainstate.AddBlockIndex(hE, std::move(pE)));

    // F from A — block validated then invalidated.
    auto pF = MakeIndex(0x06, A, 1,
                        CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                            CBlockIndex::BLOCK_FAILED_VALID,
                        10);
    uint256 hF = pF->GetBlockHash();
    assert(chainstate.AddBlockIndex(hF, std::move(pF)));

    // G from A — VALID_UNKNOWN (status=0, no validation level).
    auto pG = MakeIndex(0x07, A, 1, CBlockIndex::BLOCK_VALID_UNKNOWN, 10);
    uint256 hG = pG->GetBlockHash();
    assert(chainstate.AddBlockIndex(hG, std::move(pG)));

    // D from B — extends main chain to height 2.
    auto pD = MakeIndex(0x04, B, 2, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));

    chainstate.SetTip(chainstate.GetBlockIndex(hD));

    // ====== Legacy (string status) ======
    auto legacy = chainstate.GetChainTips();
    // Five expected tips: A is no longer a tip (it has 5 children); B has D
    // as child so not a tip; D, C, E, F, G are all leaves.
    assert(legacy.size() == 5);

    // Index legacy by hash for cross-check.
    std::map<uint256, const CChainState::ChainTip*> legacy_by_hash;
    for (const auto& t : legacy) legacy_by_hash[t.hash] = &t;

    assert(legacy_by_hash.count(hD) && legacy_by_hash[hD]->status == "active");
    assert(legacy_by_hash.count(hC) && legacy_by_hash[hC]->status == "valid-fork");
    assert(legacy_by_hash.count(hE) && legacy_by_hash[hE]->status == "valid-headers");
    assert(legacy_by_hash.count(hF) && legacy_by_hash[hF]->status == "invalid");
    assert(legacy_by_hash.count(hG) && legacy_by_hash[hG]->status == "unknown");

    // ====== Adapter (enum status) ======
    consensus_port::ChainSelectorAdapter adapter(chainstate);
    auto adapted = adapter.GetChainTips();
    assert(adapted.size() == legacy.size());

    std::map<uint256, const ChainTipInfo*> adapted_by_hash;
    for (const auto& t : adapted) adapted_by_hash[t.hash] = &t;

    // Same tip set.
    for (const auto& kv : legacy_by_hash) {
        assert(adapted_by_hash.count(kv.first));
    }

    // Per-tip equivalence: enum must map to legacy string; height,
    // branchlen, chain_work must all match.
    auto check = [&](uint256 h, ChainTipInfo::Status expected) {
        const auto& L = *legacy_by_hash[h];
        const auto& A = *adapted_by_hash[h];
        if (A.status != expected) {
            std::cerr << "\n    Status mismatch at hash byte0=" << static_cast<int>(h.data[0])
                      << ": expected=" << StatusName(expected)
                      << " got=" << StatusName(A.status) << " legacy='" << L.status << "'";
            assert(false);
        }
        assert(A.height == L.height);
        assert(A.branchlen == L.branchlen);
        assert(std::memcmp(A.chain_work.data, L.chain_work.data, 32) == 0);
    };

    check(hD, ChainTipInfo::Status::Active);
    check(hC, ChainTipInfo::Status::ValidFork);
    check(hE, ChainTipInfo::Status::ValidHeaders);
    check(hF, ChainTipInfo::Status::InvalidBlock);
    check(hG, ChainTipInfo::Status::Unknown);

    std::cout << " OK\n";
}

void test_chaintips_empty_chain()
{
    std::cout << "  test_chaintips_empty_chain..." << std::flush;
    CChainState chainstate;
    auto legacy = chainstate.GetChainTips();
    assert(legacy.empty());

    consensus_port::ChainSelectorAdapter adapter(chainstate);
    auto adapted = adapter.GetChainTips();
    assert(adapted.empty());
    std::cout << " OK\n";
}

void test_chaintips_single_active_tip_only()
{
    std::cout << "  test_chaintips_single_active_tip_only..." << std::flush;

    CChainState chainstate;
    auto pA = MakeIndex(0x11, nullptr, 0, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));

    auto legacy = chainstate.GetChainTips();
    assert(legacy.size() == 1);
    assert(legacy[0].status == "active");
    assert(legacy[0].branchlen == 0);

    consensus_port::ChainSelectorAdapter adapter(chainstate);
    auto adapted = adapter.GetChainTips();
    assert(adapted.size() == 1);
    assert(adapted[0].status == ChainTipInfo::Status::Active);
    assert(adapted[0].branchlen == 0);
    assert(std::memcmp(adapted[0].hash.data, hA.data, 32) == 0);

    std::cout << " OK\n";
}

void test_chaintips_branchlen_walks_to_fork_point()
{
    std::cout << "  test_chaintips_branchlen_walks_to_fork_point..."
              << std::flush;

    // A -> B -> D (active, height 2)
    //       \-> X (fork at height 2, branchlen should be 1)
    CChainState chainstate;

    auto pA = MakeIndex(0x21, nullptr, 0, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakeIndex(0x22, A, 1, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pD = MakeIndex(0x23, B, 2, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));

    auto pX = MakeIndex(0x24, B, 2, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10);
    uint256 hX = pX->GetBlockHash();
    assert(chainstate.AddBlockIndex(hX, std::move(pX)));

    chainstate.SetTip(chainstate.GetBlockIndex(hD));

    auto legacy = chainstate.GetChainTips();
    assert(legacy.size() == 2);

    consensus_port::ChainSelectorAdapter adapter(chainstate);
    auto adapted = adapter.GetChainTips();
    assert(adapted.size() == 2);

    // X is a fork at height 2; common ancestor is B (height 1); branchlen = 1.
    for (const auto& t : adapted) {
        if (std::memcmp(t.hash.data, hX.data, 32) == 0) {
            assert(t.status == ChainTipInfo::Status::ValidFork);
            assert(t.branchlen == 1);
        } else {
            assert(t.status == ChainTipInfo::Status::Active);
            assert(t.branchlen == 0);
        }
    }

    std::cout << " OK\n";
}

int main()
{
    std::cout << "\n=== Phase 5 PR5.2.A: GetChainTips Equivalence Tests ===\n"
              << std::endl;

    try {
        test_chaintips_empty_chain();
        test_chaintips_single_active_tip_only();
        test_chaintips_branchlen_walks_to_fork_point();
        test_chaintips_legacy_and_adapter_describe_same_tree();

        std::cout << "\n=== All Phase 5 PR5.2.A tests passed (4 tests) ==="
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
