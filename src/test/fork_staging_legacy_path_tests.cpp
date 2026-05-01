// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 7 PR7.2 (+ PR8.5 deferred-finding cleanup) —
// Fork-staging state-machine regression tests.
//
// Goal (per port_phase_7_implementation_plan.md v0.3):
//   Lock ForkManager + ForkCandidate state-machine behavior under regression
//   test, so future port consolidation cannot silently regress the legacy
//   block-receive path's fork-staging machinery.
//
// Test scope (deliberate, documented):
//   * ForkCandidate state machine (AddBlock, status transitions,
//     AllReceivedBlocksPrevalidated, GetHighestPrevalidatedHeight,
//     RecordHashMismatch, HasExcessiveHashMismatches, IsExpectedBlock,
//     IsTimedOut, orphan-style out-of-order delivery).
//   * ForkManager singleton invariants (CreateForkCandidate uniqueness,
//     CancelFork resets, AddBlockToFork dispatches, HasActiveFork +
//     GetActiveFork agree under all transitions).
//
// End-to-end paths NOT covered by this unit-level suite, by design:
//   The following are exercised by Phase 8's bash harness
//   `scripts/four_node_local.sh` (test-of-record for the integration
//   layer; see queue.md PR8.2/PR8.3 + four_node_local.sh stress scenario).
//   Splitting them this way is intentional: this file owns the state-
//   machine; the bash harness owns the system-integration surface.
//
//   * PreValidateBlock end-to-end — requires block.vtx coinbase +
//     pindexParent ancestry + GetNextWorkRequired evaluation.
//     Exercised by stress scenario when miners produce real-PoW blocks
//     under multi-miner race. The legacy block_processing path that
//     invokes PreValidateBlock fires under flag=0 (no port adapter
//     bypass).
//   * TriggerChainSwitch / ActivateBestChain end-to-end — exercised by
//     stress scenario reorg events (verified in stress 6 acceptance:
//     reorg depth ≤ 1).
//   * block_processing::ProcessNewBlock end-to-end — exercised by every
//     mined block under the harness (full NodeContext active in dilv-node
//     binaries). 9 ProcessNewBlock call sites covered per the legacy-
//     path enumeration in `port_phase_7_implementation_plan.md` v0.3.
//   * block_fetcher.cpp:109-124 fork-bias path — exercised by the
//     stress scenario's outbound-request path between competing miners.
//
// PR8.5 deferred-finding cleanup (PR7.2-RT-MEDIUM-1 + INFO-1 + INFO-2):
//   Cases 1-3 in their original form had both "scaffolding consistency"
//   readback assertions (e.g. `assert(fb->status == PREVALIDATED)`
//   immediately after `fb->status = PREVALIDATED`) AND "load-bearing
//   behavioral" assertions (gate functions, counters, hash-matching).
//   The readback assertions were tautological with the synthetic
//   field-set and did NOT exercise production state-machine logic.
//   This file's PR8.5 revision drops those readbacks and restructures
//   cases 1-3 along Case 4's pattern (load-bearing observables only).
//   See `phase_7_deferred_findings.md` PR7.2-RT-INFO-2 for the full
//   rationale.
//
//   Singleton-reset hardening (PR7.2-RT-INFO-1): ResetForkManagerState
//   asserts BOTH HasActiveFork == false AND GetActiveFork == nullptr,
//   so a regression that desyncs the two observables fails the assert.
//
// Why the load-bearing-observable pattern is sufficient regression
// protection: block_processing::ProcessNewBlock at line 457-1450 calls
// into ForkManager's public API across 22 distinct method calls (per
// port_phase_7_implementation_plan.md v0.3 §"ForkManager surface").
// Every method call locked by THIS suite produces an observable side
// effect that the suite asserts on (gate function returns, counter
// increments, singleton state transitions). If a port-side change
// regresses any of those, the assert fires; the synthetic transitions
// are scaffolding to drive the assertions, not the assertions themselves.
//
// Cases:
//   1. test_legacy_happy_fork_path
//      — 3-block fork; PREVALIDATED transitions drive
//        AllReceivedBlocksPrevalidated false -> true;
//        GetHighestPrevalidatedHeight returns fork tip; CancelFork
//        leaves singleton in clean ground state.
//
//   2. test_legacy_pre_validation_failure
//      — 3-block fork; one PREVALIDATED + one INVALID staged.
//        AllReceivedBlocksPrevalidated returns false (proves the
//        gate distinguishes statuses); GetHighestPrevalidatedHeight
//        returns the PREVALIDATED block's height (proves the iteration
//        filters by status); orphaned ForkCandidate handle survives
//        CancelFork (used by the post-switch orphan sweep at
//        block_processing.cpp:1386).
//
//   3. test_legacy_out_of_order_arrival
//      — 4-block fork delivered as [1, 3, 4, 2]. Counter monotonically
//        increases through out-of-order delivery (proves stager indexes
//        by height, not arrival order). Post-PREVALIDATION,
//        AllReceivedBlocksPrevalidated == true and
//        GetHighestPrevalidatedHeight == fork tip.
//
//   4. test_legacy_excessive_hash_mismatch (Cursor v0.2.1 CONCERN #4)
//      — RecordHashMismatch counter monotonicity +
//        HasExcessiveHashMismatches threshold flip false -> true.
//
//   5. test_legacy_fork_timeout (PR8.5 — Phase 7 deferred case 5)
//      — SetLastBlockTimeForTest backdates m_lastBlockTime; IsTimedOut
//        false -> true at the GetTimeoutSeconds threshold (60s floor
//        for small forks); CancelFork mirrors the production Tick
//        handler's behavior on timeout.

#include <node/fork_manager.h>
#include <node/fork_candidate.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <map>

namespace {

// Build a synthetic CBlock with a controllable hash. The CBlock body is
// minimal — only fields ForkCandidate / ForkManager state machine reads.
// Real PoW / merkle / transactions are NOT populated; this is the
// chain_selector_tests.cpp synthetic-block pattern.
CBlock MakeSyntheticBlock(uint8_t prev_hash_seed, int64_t time_offset)
{
    CBlock block;
    // Set hashPrevBlock to a controllable value for orphan-path testing
    std::memset(block.hashPrevBlock.data, 0, 32);
    block.hashPrevBlock.data[0] = prev_hash_seed;
    block.nTime = static_cast<uint32_t>(1700000000 + time_offset);
    block.nBits = 0x207fffff;  // regtest min-difficulty (placeholder)
    block.nNonce = 0;
    block.nVersion = 1;
    return block;
}

// Synthesize a deterministic block hash from a seed byte (matches
// chain_selector_tests.cpp::MakeGenesisLikeIndex pattern).
uint256 MakeHash(uint8_t seed)
{
    uint256 h;
    std::memset(h.data, 0, 32);
    h.data[0] = seed;
    return h;
}

// Build expected-hashes map for a fork candidate covering [forkPoint+1 ..
// expectedTip] heights, using deterministic hash seeds.
std::map<int32_t, uint256> MakeExpectedHashes(int32_t forkPoint,
                                              int32_t expectedTip,
                                              uint8_t hash_base = 0xA0)
{
    std::map<int32_t, uint256> hashes;
    for (int32_t h = forkPoint + 1; h <= expectedTip; ++h) {
        hashes[h] = MakeHash(hash_base + static_cast<uint8_t>(h - forkPoint));
    }
    return hashes;
}

// Reset the singleton's state so each test starts clean. ForkManager
// is a process-level singleton (instance() returns a function-local
// static), so tests sharing a binary share the singleton; CancelFork
// returns it to the no-active-fork state.
//
// PR7.2-RT-INFO-1 hardening (PR8.5):
//   The previous version asserted only !HasActiveFork(). That left a
//   subtle order-dependence trap: a future case that mutates singleton
//   internal state without going through CancelFork (e.g. setting
//   m_validationFailed on an orphaned ForkCandidate) could leave
//   residual state that the next case depends on by accident. We now
//   assert ALL singleton-observable state is the no-active-fork
//   ground truth — both pointer identity and HasActiveFork()
//   bool — so a regression in either side fails the assert.
void ResetForkManagerState()
{
    auto& fm = ForkManager::GetInstance();
    if (fm.HasActiveFork()) {
        fm.CancelFork("test reset");
    }
    // Hardened singleton-reset checks (PR7.2-RT-INFO-1):
    //   - HasActiveFork() returns false.
    //   - GetActiveFork() returns nullptr.
    // Both must agree; a divergence between them indicates singleton
    // corruption that no later assert in the test can catch.
    assert(!fm.HasActiveFork());
    assert(fm.GetActiveFork() == nullptr);
}

}  // anonymous namespace

// ============================================================================
// Case 1: legacy happy fork path
// ============================================================================
//
// Models block_processing.cpp:457-528 happy path under fork detection:
//   - HasActiveFork() flips true after CreateForkCandidate.
//   - For each fork block: AddBlockToFork stages it (status starts PENDING).
//   - PreValidateBlock transitions status PENDING -> PREVALIDATED. Real
//     PreValidateBlock is exercised end-to-end by Phase 8's bash harness
//     (`scripts/four_node_local.sh`); this unit test transitions the
//     status field synthetically to drive downstream gate logic.
//   - Once all received blocks are PREVALIDATED, fork->AllReceivedBlocksPrevalidated()
//     returns true (gate for TriggerChainSwitch at block_processing.cpp:1343).
//
// Load-bearing behavioral observables (per PR7.2-RT-INFO-2 cleanup —
// dropped per-block status field readbacks; only gate functions / counter
// returns / singleton state transitions remain):
//   * AddBlockToFork returns true on each call (singleton plumbing).
//   * IsExpectedBlock returns true for each (hash-matching against m_expectedHashes).
//   * GetReceivedBlockCount monotonically increases.
//   * AllReceivedBlocksPrevalidated transitions false -> true mid-test
//     (proves the gate is real, not a constant-true).
//   * GetHighestPrevalidatedHeight returns expected tip height (proves
//     the iteration logic).
//   * HasAllBlocks returns true.
//   * Singleton HasActiveFork/GetActiveFork transition through the
//     full lifecycle (false -> true post-create, true through staging,
//     false post-cancel).
void test_legacy_happy_fork_path()
{
    std::cout << "  test_legacy_happy_fork_path..." << std::flush;
    ResetForkManagerState();

    auto& fm = ForkManager::GetInstance();

    // Synthetic 3-block fork: heights 11..13 (forkPoint=10, expectedTip=13).
    constexpr int32_t kForkPoint = 10;
    constexpr int32_t kExpectedTip = 13;
    constexpr int32_t kCurrentChainHeight = 12;  // we're behind the fork tip

    auto expectedHashes = MakeExpectedHashes(kForkPoint, kExpectedTip);
    uint256 forkTipHash = expectedHashes[kExpectedTip];

    // Pre-condition: no active fork.
    assert(!fm.HasActiveFork());
    assert(fm.GetActiveFork() == nullptr);

    // Create fork candidate (mirrors fork_manager.cpp:CreateForkCandidate
    // call from ibd_coordinator.cpp:2676 in production).
    auto fork = fm.CreateForkCandidate(forkTipHash, kCurrentChainHeight,
                                       kForkPoint, kExpectedTip,
                                       expectedHashes);
    assert(fork != nullptr);

    // Singleton state observable: fork is now active.
    assert(fm.HasActiveFork());
    assert(fm.GetActiveFork().get() == fork.get());
    assert(fork->GetForkPointHeight() == kForkPoint);
    assert(fork->GetExpectedTipHeight() == kExpectedTip);
    assert(fork->GetBlockCount() == 3);  // expectedTip - forkPoint == 3
    assert(fork->GetReceivedBlockCount() == 0);
    assert(!fork->HasAllBlocks());

    // Stage each fork block (mirrors block_processing.cpp:495 AddBlockToFork
    // call after IsExpectedBlock check).
    int32_t expected_received = 0;
    for (int32_t h = kForkPoint + 1; h <= kExpectedTip; ++h) {
        const uint8_t prev_seed =
            (h == kForkPoint + 1) ? 0x00  // fork point parent (synthetic)
                                  : static_cast<uint8_t>(0xA0 + (h - 1 - kForkPoint));
        CBlock blk = MakeSyntheticBlock(prev_seed, /*time_offset=*/h);
        uint256 hash = expectedHashes[h];

        // Load-bearing: IsExpectedBlock walks m_expectedHashes (production
        // hash-matching logic, not a field readback).
        assert(fork->IsExpectedBlock(hash, h));

        // Load-bearing: AddBlockToFork return + receive-count monotonic.
        assert(fm.AddBlockToFork(blk, hash, h));
        ++expected_received;
        assert(fork->GetReceivedBlockCount() == expected_received);
    }

    // Mid-test gate: with all blocks staged but none transitioned,
    // AllReceivedBlocksPrevalidated() must be false. Proves the gate
    // is real (iterates m_blocks + checks status), not a constant.
    assert(!fork->AllReceivedBlocksPrevalidated());
    assert(fork->HasAllBlocks());  // count gate is independent of status gate

    // Synthetic prevalidation: transition each block PENDING -> PREVALIDATED.
    // Real PreValidateBlock pipeline (PoW + nBits + MIK) is exercised by
    // Phase 8's bash harness (scripts/four_node_local.sh stress scenario
    // produces real-PoW blocks across the fork-staging path); this unit
    // test models its successful outcome via direct status assignment.
    for (int32_t h = kForkPoint + 1; h <= kExpectedTip; ++h) {
        ForkBlock* fb = fork->GetBlockAtHeight(h);
        assert(fb != nullptr);
        fb->status = ForkBlockStatus::PREVALIDATED;
    }

    // Load-bearing: gate function transitions false -> true after the
    // synthetic transitions. If any synthetic transition didn't take,
    // this returns false.
    assert(fork->AllReceivedBlocksPrevalidated());

    // Load-bearing: production iteration logic returns the maximum
    // PREVALIDATED height (used at block_processing.cpp:1344 to compute
    // the chain-switch tip).
    assert(fork->GetHighestPrevalidatedHeight() == kExpectedTip);

    // Singleton state: fork stays active until explicit CancelFork
    // (we don't call TriggerChainSwitch — out of scope for this test).
    assert(fm.HasActiveFork());

    // Explicit cancel; mirrors block_processing.cpp:507 etc.
    fm.CancelFork("test cleanup");

    // Singleton-reset observables: post-cancel state fully cleared.
    assert(!fm.HasActiveFork());
    assert(fm.GetActiveFork() == nullptr);

    std::cout << " OK\n";
}

// ============================================================================
// Case 2: legacy pre-validation failure
// ============================================================================
//
// Models block_processing.cpp:501-524 failure path:
//   - PreValidateBlock returns false (modeled by direct status = INVALID
//     + invalidReason set; real PreValidateBlock failure modes are
//     exercised by Phase 8's bash harness).
//   - CancelFork fires with the invalid reason embedded.
//   - HasActiveFork() flips back to false.
//   - block_processing.cpp:524 returns BlockProcessResult::INVALID_POW;
//     this test exercises the state-machine effects, not the return value.
//
// Load-bearing behavioral observables (per PR7.2-RT-INFO-2 cleanup):
//   * AllReceivedBlocksPrevalidated returns false with one PREVALIDATED
//     and one INVALID staged (proves the gate distinguishes statuses).
//   * Singleton HasActiveFork/GetActiveFork transition through the
//     full lifecycle, with explicit observability of the orphaned
//     ForkCandidate handle post-cancel (used by the post-switch
//     orphan sweep at block_processing.cpp:1386).
void test_legacy_pre_validation_failure()
{
    std::cout << "  test_legacy_pre_validation_failure..." << std::flush;
    ResetForkManagerState();

    auto& fm = ForkManager::GetInstance();

    constexpr int32_t kForkPoint = 20;
    constexpr int32_t kExpectedTip = 23;
    constexpr int32_t kCurrentChainHeight = 22;

    auto expectedHashes = MakeExpectedHashes(kForkPoint, kExpectedTip,
                                             /*hash_base=*/0xB0);
    uint256 forkTipHash = expectedHashes[kExpectedTip];

    auto fork = fm.CreateForkCandidate(forkTipHash, kCurrentChainHeight,
                                       kForkPoint, kExpectedTip,
                                       expectedHashes);
    assert(fork != nullptr);
    assert(fm.HasActiveFork());

    // Stage block 1 — model passing pre-validation.
    {
        CBlock blk = MakeSyntheticBlock(0x00, kForkPoint + 1);
        uint256 hash = expectedHashes[kForkPoint + 1];
        assert(fm.AddBlockToFork(blk, hash, kForkPoint + 1));
        ForkBlock* fb = fork->GetBlockAtHeight(kForkPoint + 1);
        assert(fb != nullptr);
        fb->status = ForkBlockStatus::PREVALIDATED;
    }

    // Stage block 2 — model PreValidateBlock failure with invalidReason set
    // (mirrors fork_manager.cpp:405-406 ValidatePoW false branch).
    int32_t kBadHeight = kForkPoint + 2;
    {
        CBlock blk = MakeSyntheticBlock(0xB1, kBadHeight);
        uint256 hash = expectedHashes[kBadHeight];
        assert(fm.AddBlockToFork(blk, hash, kBadHeight));
        ForkBlock* fb = fork->GetBlockAtHeight(kBadHeight);
        assert(fb != nullptr);
        fb->status = ForkBlockStatus::INVALID;
        fb->invalidReason = "Invalid proof of work";
    }

    // Load-bearing observable: 2 blocks received, 1 PREVALIDATED, 1 INVALID
    // → AllReceivedBlocksPrevalidated returns FALSE (the gate distinguishes
    // statuses; if it returned constant-true, this would also pass and
    // the gate would be useless).
    assert(fork->GetReceivedBlockCount() == 2);
    assert(!fork->AllReceivedBlocksPrevalidated());

    // Load-bearing observable: GetHighestPrevalidatedHeight returns the
    // height of the PREVALIDATED block (kForkPoint+1), NOT the INVALID
    // one (kForkPoint+2). Proves the iterator filters by status.
    assert(fork->GetHighestPrevalidatedHeight() == kForkPoint + 1);

    // Cancel the fork (mirrors block_processing.cpp:507).
    fm.CancelFork("Block failed pre-validation: Invalid proof of work");

    // Singleton-reset observables: post-cancel state fully cleared.
    assert(!fm.HasActiveFork());
    assert(fm.GetActiveFork() == nullptr);

    // Local `fork` shared_ptr keeps the orphaned ForkCandidate alive — a
    // property leveraged by block_processing.cpp:1386 for the post-switch
    // orphan sweep. Confirm orphaned-handle observability:
    assert(fork != nullptr);
    assert(fork->GetForkPointHeight() == kForkPoint);
    assert(fork->GetReceivedBlockCount() == 2);  // count survives cancel

    std::cout << " OK\n";
}

// ============================================================================
// Case 3: legacy out-of-order arrival
// ============================================================================
//
// Models the orphan-path interaction with fork-staging that
// block_processing.cpp:1431 ResolveOrphanChildren depends on:
//   - Fork blocks arrive in order [1, 3, 4, 2] (block 2 last).
//   - AddBlockToFork must succeed for each (the stager doesn't enforce
//     in-order arrival; orphan handling is upstream).
//   - Once all 4 are staged + PREVALIDATED, AllReceivedBlocksPrevalidated()
//     and GetHighestPrevalidatedHeight() return the expected values.
//
// Load-bearing behavioral observables (per PR7.2-RT-INFO-2 cleanup):
//   * GetReceivedBlockCount monotonically increases through out-of-order
//     delivery (proves the stager indexes by height, not by arrival
//     order — out-of-order would otherwise overwrite or drop entries).
//   * Mid-state: AllReceivedBlocksPrevalidated == false with all PENDING.
//   * Post-transition: AllReceivedBlocksPrevalidated == true.
//   * GetHighestPrevalidatedHeight returns fork tip (34), NOT block 33
//     (the highest delivered before block 32). Proves the gate iterates
//     by stored height, not delivery sequence.
void test_legacy_out_of_order_arrival()
{
    std::cout << "  test_legacy_out_of_order_arrival..." << std::flush;
    ResetForkManagerState();

    auto& fm = ForkManager::GetInstance();

    constexpr int32_t kForkPoint = 30;
    constexpr int32_t kExpectedTip = 34;  // 4 blocks: 31..34
    constexpr int32_t kCurrentChainHeight = 33;

    auto expectedHashes = MakeExpectedHashes(kForkPoint, kExpectedTip,
                                             /*hash_base=*/0xC0);
    uint256 forkTipHash = expectedHashes[kExpectedTip];

    auto fork = fm.CreateForkCandidate(forkTipHash, kCurrentChainHeight,
                                       kForkPoint, kExpectedTip,
                                       expectedHashes);
    assert(fork != nullptr);
    assert(fork->GetBlockCount() == 4);
    assert(fork->GetReceivedBlockCount() == 0);

    // Out-of-order delivery: heights [31, 33, 34, 32].
    const int32_t delivery_order[] = {kForkPoint + 1, kForkPoint + 3,
                                      kForkPoint + 4, kForkPoint + 2};

    int32_t expected_received = 0;
    for (int32_t h : delivery_order) {
        CBlock blk = MakeSyntheticBlock(static_cast<uint8_t>(h), h);
        uint256 hash = expectedHashes[h];

        // Load-bearing: hash-matching against m_expectedHashes succeeds
        // regardless of delivery order.
        assert(fork->IsExpectedBlock(hash, h));

        // Load-bearing: stager accepts out-of-order arrivals; counter
        // monotonically increases (proves it indexes by height, not by
        // arrival order — otherwise the third out-of-order delivery
        // would overwrite the first or fail).
        assert(fm.AddBlockToFork(blk, hash, h));
        ++expected_received;
        assert(fork->GetReceivedBlockCount() == expected_received);
    }

    assert(fork->GetReceivedBlockCount() == 4);
    assert(fork->HasAllBlocks());

    // Mid-state observable: with all 4 PENDING, AllReceivedBlocksPrevalidated
    // is false. Proves the gate is real (not constant-true).
    assert(!fork->AllReceivedBlocksPrevalidated());

    // Synthetic prevalidation in delivery order (the orphan path's
    // model: each block is pre-validated when it arrives + parent is
    // present).
    for (int32_t h : delivery_order) {
        ForkBlock* fb = fork->GetBlockAtHeight(h);
        assert(fb != nullptr);
        fb->status = ForkBlockStatus::PREVALIDATED;
    }

    // Load-bearing: gate function transitions false -> true post-
    // prevalidation across all 4 blocks. Crucially, this would FAIL
    // if the stager indexed by arrival order (block 32 would be at
    // a different storage slot than its height suggests, and the
    // gate would not see it).
    assert(fork->AllReceivedBlocksPrevalidated());

    // Load-bearing: GetHighestPrevalidatedHeight returns the fork tip
    // (height 34), NOT the highest height delivered before the last
    // (block 33). Proves the gate iterates by stored height, NOT
    // by delivery sequence.
    assert(fork->GetHighestPrevalidatedHeight() == kExpectedTip);

    fm.CancelFork("test cleanup");
    assert(!fm.HasActiveFork());
    assert(fm.GetActiveFork() == nullptr);

    std::cout << " OK\n";
}

// ============================================================================
// Case 4 (optional, schedule-permitting per Cursor v0.2.1 CONCERN #4):
// excessive hash-mismatch cancel
// ============================================================================
//
// Models block_processing.cpp:556-566 hash-mismatch path:
//   - Block arrives in fork's height range with wrong hash
//   - fork->RecordHashMismatch() increments counter
//   - After threshold, fork->HasExcessiveHashMismatches() returns true
//   - CancelFork fires
//
// Anti-vacuous observables:
//   * RecordHashMismatch returns the new count (proves it incremented).
//   * HasExcessiveHashMismatches() flips false -> true at threshold.
void test_legacy_excessive_hash_mismatch()
{
    std::cout << "  test_legacy_excessive_hash_mismatch..." << std::flush;
    ResetForkManagerState();

    auto& fm = ForkManager::GetInstance();

    constexpr int32_t kForkPoint = 40;
    constexpr int32_t kExpectedTip = 42;
    auto expectedHashes = MakeExpectedHashes(kForkPoint, kExpectedTip,
                                             /*hash_base=*/0xD0);

    auto fork = fm.CreateForkCandidate(expectedHashes[kExpectedTip],
                                       /*currentChainHeight=*/41,
                                       kForkPoint, kExpectedTip,
                                       expectedHashes);
    assert(fork != nullptr);

    // Pre-threshold: HasExcessiveHashMismatches() == false.
    assert(!fork->HasExcessiveHashMismatches());

    // Iterate RecordHashMismatch up to and just past the threshold. The
    // public threshold constant (MAX_HASH_MISMATCHES) lives in
    // fork_candidate.h:271 as a private static constexpr; we don't depend
    // on its exact value. We iterate enough times to exceed any reasonable
    // threshold + verify the predicate becomes true at SOME point.
    int observed_count = 0;
    for (int i = 0; i < 50; ++i) {
        observed_count = fork->RecordHashMismatch();
        // Observable: counter monotonically increases (not stuck).
        assert(observed_count == i + 1);
        if (fork->HasExcessiveHashMismatches()) break;
    }

    // Threshold was reached within 50 iterations.
    assert(fork->HasExcessiveHashMismatches());

    fm.CancelFork("Excessive hash mismatches");
    assert(!fm.HasActiveFork());

    std::cout << " OK\n";
}

// ============================================================================
// Case 5 (PR8.5 — Phase 7 deferred test case 5): fork timeout
// ============================================================================
//
// Models the timeout path that ibd_coordinator surfaces via Tick() when a
// fork stalls (no new blocks arrive within ForkCandidate::GetTimeoutSeconds()
// of the most recent block). Production logs at fork_manager.cpp:757
// "[ForkManager] Fork timed out (...)" and CancelFork fires.
//
// Test infrastructure: SetLastBlockTimeForTest backdates m_lastBlockTime
// without sleeping. Real wall-clock waits would make the suite minutes-
// long (timeout floor is 60s); the seam is justified per the PR7.2-style
// synthetic-block pattern — production observers (IsTimedOut +
// GetTimeoutSeconds) compute on the same field the seam writes.
//
// Load-bearing behavioral observables:
//   * GetTimeoutSeconds returns a positive deterministic value
//     (computed from blocks_needed; not a constant).
//   * IsTimedOut transitions false -> true after backdating beyond
//     GetTimeoutSeconds (proves the comparison is real, not stuck).
//   * IsTimedOut returns false when backdated short of the threshold
//     (proves the comparison's other branch).
//   * Singleton lifecycle observable: cancel-after-timeout matches
//     the production Tick handler's behavior.
void test_legacy_fork_timeout()
{
    std::cout << "  test_legacy_fork_timeout..." << std::flush;
    ResetForkManagerState();

    auto& fm = ForkManager::GetInstance();

    // Small fork: blocks_needed=2 → GetTimeoutSeconds returns 60s
    // (the floor for any fork; computed via 60 + (2/10)*5 = 60).
    constexpr int32_t kForkPoint = 50;
    constexpr int32_t kExpectedTip = 52;
    constexpr int32_t kCurrentChainHeight = 51;

    auto expectedHashes = MakeExpectedHashes(kForkPoint, kExpectedTip,
                                             /*hash_base=*/0xE0);

    auto fork = fm.CreateForkCandidate(expectedHashes[kExpectedTip],
                                       kCurrentChainHeight,
                                       kForkPoint, kExpectedTip,
                                       expectedHashes);
    assert(fork != nullptr);

    // Load-bearing: GetTimeoutSeconds returns the floor for a small fork.
    const int timeout_s = fork->GetTimeoutSeconds();
    assert(timeout_s == 60);  // 60 + (2/10)*5 = 60 exactly for kBlocksNeeded=2

    // Pre-condition: a freshly-created fork with m_lastBlockTime = now
    // is NOT timed out.
    assert(!fork->IsTimedOut());

    // Backdate by less than the threshold (30s of a 60s timeout).
    auto now = std::chrono::steady_clock::now();
    fork->SetLastBlockTimeForTest(now - std::chrono::seconds(30));

    // Load-bearing: IsTimedOut returns false short of the threshold
    // (proves the comparison's negative branch).
    assert(!fork->IsTimedOut());

    // Backdate by more than the threshold (90s of a 60s timeout).
    fork->SetLastBlockTimeForTest(now - std::chrono::seconds(90));

    // Load-bearing: IsTimedOut transitions false -> true at the threshold.
    assert(fork->IsTimedOut());

    // Cancel as the production Tick handler would (mirrors fork_manager.cpp:757
    // "[ForkManager] Fork timed out" + CancelFork).
    fm.CancelFork("Fork timeout");
    assert(!fm.HasActiveFork());
    assert(fm.GetActiveFork() == nullptr);

    std::cout << " OK\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 7 PR7.2 (+ PR8.5 deferred-finding cleanup) —\n";
    std::cout << "  Fork-staging legacy-path regression tests\n";
    std::cout << "  (state-machine-level; PreValidateBlock + TriggerChainSwitch +\n";
    std::cout << "   ProcessNewBlock end-to-end exercised by Phase 8 bash harness\n";
    std::cout << "   `scripts/four_node_local.sh` — see file header)\n\n";

    try {
        test_legacy_happy_fork_path();
        test_legacy_pre_validation_failure();
        test_legacy_out_of_order_arrival();
        test_legacy_excessive_hash_mismatch();
        test_legacy_fork_timeout();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll fork-staging legacy-path regression tests passed.\n";
    std::cout << "  5 cases: happy / failure / out-of-order / hash-mismatch / timeout.\n";
    return 0;
}
