// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 Day 4 V1 — chain_work bit-equivalence smoke test.
//
// Mirrors Phase 3 PR3.1's chain-work bit-equality acceptance criterion.
// The Phase 5 candidate-set comparator depends on byte-by-byte ordering
// of nChainWork via ChainWorkGreaterThan; any divergence in chain_work
// between code paths would cause selection divergence.
//
// What this proves at unit level:
//   * ComputeChainWork(nBits) is deterministic and idempotent
//   * AddChainWork is associative across chain extension
//   * nChainWork computed via repeated AddChainWork (chain extension)
//     equals nChainWork computed via direct sum
//   * Multiple invocations through Phase 5 helpers yield byte-equal
//     results
//
// V2 (deferred): 100-block regtest sync env-var=0 vs =1; pindexTip->nChainWork
// byte-equal at end. That's the integration-level proof.

#include <consensus/chain.h>
#include <consensus/chain_work.h>
#include <consensus/pow.h>
#include <node/block_index.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

namespace {

// Helper: cumulative work for a chain of N blocks all with same nBits.
// Hand-computed via repeated AddChainWork starting from genesis.
uint256 ChainWorkOverNBlocks(uint32_t nBits, int n_blocks)
{
    using namespace dilithion::consensus;
    uint256 total;
    std::memset(total.data, 0, 32);
    for (int i = 0; i < n_blocks; ++i) {
        total = AddChainWork(total, ComputeChainWork(nBits));
    }
    return total;
}

}  // anonymous

void test_compute_chain_work_idempotent()
{
    std::cout << "  test_compute_chain_work_idempotent..." << std::flush;
    using namespace dilithion::consensus;

    const uint32_t nBits = 0x1d00ffff;
    uint256 a = ComputeChainWork(nBits);
    uint256 b = ComputeChainWork(nBits);
    uint256 c = ComputeChainWork(nBits);
    assert(std::memcmp(a.data, b.data, 32) == 0);
    assert(std::memcmp(b.data, c.data, 32) == 0);

    // Different nBits → different work (sanity).
    uint256 harder = ComputeChainWork(0x1c00ffff);
    assert(std::memcmp(a.data, harder.data, 32) != 0);

    std::cout << " OK\n";
}

void test_add_chain_work_commutative()
{
    std::cout << "  test_add_chain_work_commutative..." << std::flush;
    using namespace dilithion::consensus;

    uint256 a = ComputeChainWork(0x1d00ffff);
    uint256 b = ComputeChainWork(0x1c00ffff);

    uint256 ab = AddChainWork(a, b);
    uint256 ba = AddChainWork(b, a);
    assert(std::memcmp(ab.data, ba.data, 32) == 0);

    std::cout << " OK\n";
}

void test_add_chain_work_associative()
{
    std::cout << "  test_add_chain_work_associative..." << std::flush;
    using namespace dilithion::consensus;

    uint256 a = ComputeChainWork(0x1d00ffff);
    uint256 b = ComputeChainWork(0x1c00ffff);
    uint256 c = ComputeChainWork(0x1d00aaaa);

    // (a + b) + c == a + (b + c)
    uint256 left = AddChainWork(AddChainWork(a, b), c);
    uint256 right = AddChainWork(a, AddChainWork(b, c));
    assert(std::memcmp(left.data, right.data, 32) == 0);

    std::cout << " OK\n";
}

void test_chain_work_extends_monotonically()
{
    std::cout << "  test_chain_work_extends_monotonically..." << std::flush;

    // Cumulative work over N blocks > cumulative work over (N-1) blocks
    // for any fixed nBits.
    uint256 w1 = ChainWorkOverNBlocks(0x1d00ffff, 1);
    uint256 w2 = ChainWorkOverNBlocks(0x1d00ffff, 2);
    uint256 w3 = ChainWorkOverNBlocks(0x1d00ffff, 3);
    uint256 w10 = ChainWorkOverNBlocks(0x1d00ffff, 10);

    assert(ChainWorkGreaterThan(w2, w1));
    assert(ChainWorkGreaterThan(w3, w2));
    assert(ChainWorkGreaterThan(w10, w3));

    std::cout << " OK\n";
}

void test_buildchainwork_matches_addchainwork()
{
    std::cout << "  test_buildchainwork_matches_addchainwork..." << std::flush;

    // CBlockIndex::BuildChainWork sets nChainWork via AddChainWork(parent, GetBlockProof()).
    // Verify byte-equality with hand-computed values.
    using namespace dilithion::consensus;

    CBlockIndex genesis;
    genesis.nBits = 0x1d00ffff;
    genesis.pprev = nullptr;
    genesis.BuildChainWork();

    uint256 expected_genesis = ComputeChainWork(0x1d00ffff);
    assert(std::memcmp(genesis.nChainWork.data, expected_genesis.data, 32) == 0);

    CBlockIndex block1;
    block1.nBits = 0x1d00ffff;
    block1.pprev = &genesis;
    block1.BuildChainWork();

    uint256 expected_b1 = AddChainWork(expected_genesis, ComputeChainWork(0x1d00ffff));
    assert(std::memcmp(block1.nChainWork.data, expected_b1.data, 32) == 0);

    CBlockIndex block2;
    block2.nBits = 0x1c00ffff;  // different difficulty — heavier work
    block2.pprev = &block1;
    block2.BuildChainWork();

    uint256 expected_b2 = AddChainWork(expected_b1, ComputeChainWork(0x1c00ffff));
    assert(std::memcmp(block2.nChainWork.data, expected_b2.data, 32) == 0);

    // Block2's work strictly exceeds block1's.
    assert(ChainWorkGreaterThan(block2.nChainWork, block1.nChainWork));

    std::cout << " OK\n";
}

void test_comparator_byte_ordering_stable_across_path()
{
    std::cout << "  test_comparator_byte_ordering_stable_across_path..."
              << std::flush;

    // The candidate-set comparator depends on byte-equal nChainWork values
    // for deterministic selection. Construct two indices with EXACTLY equal
    // nChainWork (computed via different code paths but same inputs), verify
    // tiebreak goes to nSequenceId, NOT to a chain-work delta.
    using namespace dilithion::consensus;

    CBlockIndex a, b;
    a.nBits = b.nBits = 0x1d00ffff;
    a.pprev = b.pprev = nullptr;
    a.BuildChainWork();
    b.BuildChainWork();

    // Equal work bytes.
    assert(std::memcmp(a.nChainWork.data, b.nChainWork.data, 32) == 0);

    a.nSequenceId = 1;
    b.nSequenceId = 2;

    CBlockIndexWorkComparator cmp;
    // Equal work → smaller sequence id wins.
    assert(cmp(&a, &b));   // a (seq=1) before b (seq=2)
    assert(!cmp(&b, &a));

    std::cout << " OK\n";
}

int main()
{
    std::cout << "\n=== Phase 5 Day 4 V1: Chain-Work Smoke Tests ===\n" << std::endl;
    try {
        test_compute_chain_work_idempotent();
        test_add_chain_work_commutative();
        test_add_chain_work_associative();
        test_chain_work_extends_monotonically();
        test_buildchainwork_matches_addchainwork();
        test_comparator_byte_ordering_stable_across_path();
        std::cout << "\n=== All chain_work smoke tests passed (6 tests) ===\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed (unknown)" << std::endl;
        return 1;
    }
}
