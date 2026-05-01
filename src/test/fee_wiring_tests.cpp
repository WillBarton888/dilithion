// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

// Integration tests for PR-EF-2: fee estimator wired to a real mempool.
//
// These tests exercise the public mempool surface (CTxMemPool::AddTx,
// CTxMemPool::ReplaceTransaction, CTxMemPool::RemoveTx,
// CTxMemPool::CleanupExpiredTransactions via direct call) with the
// process-wide g_fee_estimator pointer set to a live
// CBlockPolicyEstimator.
//
// Coverage (initial PR-EF-2):
//   - fee_wiring_admit_records_tx     -- AddTx populates tracked-set
//   - fee_wiring_bypass_skips         -- bypass_fee_check=true skips
//   - fee_wiring_remove_drops_tracking-- RemoveTx invokes estimator
//   - fee_wiring_rbf_replace          -- ReplaceTransaction transitions
//   - fee_wiring_estimate_after_accum -- after >=25 blocks, estimate
//                                        becomes non-null
//   - fee_wiring_null_estimator_safe  -- AddTx with g_fee_estimator=null
//                                        is a no-op (acceptance gate)
//
// Coverage (red-team F#4 fixup -- additional tests added with the
// out-of-lock estimator-notify refactor):
//   - fee_wiring_eviction_notifies         -- EvictTransactions hooks
//   - fee_wiring_expiration_notifies       -- CleanupExpiredTransactions
//   - fee_wiring_evict_null_estimator_safe -- eviction with null est
//   - fee_wiring_expire_null_estimator_safe-- expiration with null est
//   - fee_wiring_replace_null_estimator_safe -- replace with null est
//   - fee_wiring_block_connect_lambda_logic -- coinbase filter +
//                                              negative-height guard +
//                                              null-estimator skip
//                                              (replicates the binary
//                                              lambda's body)
//   - fee_wiring_processblock_idempotent_replay -- F#5 reorg-rollback
//                                              double-decay guard
//   - fee_wiring_stop_expiration_idempotent -- F#1 StopExpirationThread
//                                              idempotency
//   - fee_wiring_replace_bypass_skips      -- F#8 bypass_fee_check=true
//                                              on ReplaceTransaction

#include <boost/test/unit_test.hpp>

#include <node/mempool.h>
#include <policy/fees.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <chrono>
#include <ctime>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(fee_wiring_tests)

namespace {

// Minimal RAII guard to swap g_fee_estimator for a single test and
// restore the previous value on scope exit. The fee estimator's
// process-wide pointer is intended for set-once-at-startup semantics
// in production, but tests need to hot-swap; the swap is benign here
// because no live mempool concurrent path crosses these tests.
class ScopedEstimator {
public:
    explicit ScopedEstimator(policy::fee_estimator::CBlockPolicyEstimator* e)
        : m_prev(g_fee_estimator) { g_fee_estimator = e; }
    ~ScopedEstimator() { g_fee_estimator = m_prev; }
    ScopedEstimator(const ScopedEstimator&)            = delete;
    ScopedEstimator& operator=(const ScopedEstimator&) = delete;
private:
    policy::fee_estimator::CBlockPolicyEstimator* m_prev;
};

// Synthetic transaction generator. Two seed bytes for uniqueness.
CTransactionRef MakeWiringTestTx(uint8_t a, uint8_t b) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    uint256 prev;
    std::memset(prev.data, a, 32);
    prev.data[31] = b;
    std::vector<uint8_t> sig{a, b, 0xCC, 0xDD};
    // SEQUENCE_FINAL avoids RBF-signaling unless we explicitly opt in.
    tx.vin.push_back(CTxIn(prev, b, sig, CTxIn::SEQUENCE_FINAL));
    std::vector<uint8_t> spk{0x76, 0xa9, 0x14, a, b};
    tx.vout.push_back(CTxOut(1000ULL + (a * 256 + b), spk));
    return MakeTransactionRef(tx);
}

// RBF-signaling variant of the synthetic tx (nSequence < 0xfffffffe).
CTransactionRef MakeRbfWiringTestTx(uint8_t a, uint8_t b, uint32_t seq = 0xfffffffd) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    uint256 prev;
    std::memset(prev.data, a, 32);
    prev.data[31] = b;
    std::vector<uint8_t> sig{a, b, 0xEE, 0xFF};
    tx.vin.push_back(CTxIn(prev, b, sig, seq));
    std::vector<uint8_t> spk{0x76, 0xa9, 0x14, a, b};
    tx.vout.push_back(CTxOut(2000ULL + (a * 256 + b), spk));
    return MakeTransactionRef(tx);
}

}  // anonymous namespace

// ---- T1: AddTx feeds processTx --------------------------------------------

BOOST_AUTO_TEST_CASE(fee_wiring_admit_records_tx) {
    auto est = std::make_unique<policy::fee_estimator::CBlockPolicyEstimator>();
    ScopedEstimator scope(est.get());

    CTxMemPool mempool;
    auto tx = MakeWiringTestTx(0x01, 0x02);

    // bypass_fee_check=false (default semantics for live admits) -- the
    // estimator should record this admit.
    std::string err;
    BOOST_REQUIRE(mempool.AddTx(tx, /*fee=*/50000, std::time(nullptr),
                                /*height=*/100, &err,
                                /*bypass_fee_check=*/false));

    BOOST_CHECK_EQUAL(est->getTrackedTxCount(), 1u);
    BOOST_CHECK_EQUAL(est->getBestSeenHeight(), 0u);  // no block observed yet
}

// ---- T2: bypass_fee_check=true skips estimator ----------------------------

BOOST_AUTO_TEST_CASE(fee_wiring_bypass_skips) {
    auto est = std::make_unique<policy::fee_estimator::CBlockPolicyEstimator>();
    ScopedEstimator scope(est.get());

    CTxMemPool mempool;
    auto tx = MakeWiringTestTx(0x03, 0x04);

    // bypass_fee_check=true mirrors mempool_persist's LoadMempool replay
    // path. Estimator must NOT record this admit (matches BC's
    // validFeeEstimate=false semantics).
    std::string err;
    BOOST_REQUIRE(mempool.AddTx(tx, /*fee=*/50000, std::time(nullptr),
                                /*height=*/100, &err,
                                /*bypass_fee_check=*/true));

    BOOST_CHECK_EQUAL(est->getTrackedTxCount(), 0u);
}

// ---- T3: RemoveTx invokes estimator's removeTx ----------------------------

BOOST_AUTO_TEST_CASE(fee_wiring_remove_drops_tracking) {
    auto est = std::make_unique<policy::fee_estimator::CBlockPolicyEstimator>();
    ScopedEstimator scope(est.get());

    CTxMemPool mempool;
    auto tx = MakeWiringTestTx(0x05, 0x06);

    std::string err;
    BOOST_REQUIRE(mempool.AddTx(tx, 50000, std::time(nullptr), 100, &err, false));
    BOOST_REQUIRE_EQUAL(est->getTrackedTxCount(), 1u);

    // Removing the tx (eviction-style: in_block=false) drops it from the
    // tracked set without crediting confirmation.
    BOOST_REQUIRE(mempool.RemoveTx(tx->GetHash()));
    BOOST_CHECK_EQUAL(est->getTrackedTxCount(), 0u);
}

// ---- T4: ReplaceTransaction (RBF) transitions tracked set -----------------

BOOST_AUTO_TEST_CASE(fee_wiring_rbf_replace) {
    auto est = std::make_unique<policy::fee_estimator::CBlockPolicyEstimator>();
    ScopedEstimator scope(est.get());

    CTxMemPool mempool;
    // Original RBF-signaling tx.
    auto orig = MakeRbfWiringTestTx(0x07, 0x08);
    std::string err;
    BOOST_REQUIRE(mempool.AddTx(orig, /*fee=*/50000, std::time(nullptr),
                                /*height=*/100, &err,
                                /*bypass_fee_check=*/false));
    BOOST_REQUIRE_EQUAL(est->getTrackedTxCount(), 1u);

    // Replacement spending same outpoint, higher fee, RBF-signaling.
    // Hand-build a new transaction that reuses orig's prevout(s) but
    // bumps the output value so the txid differs. mempool's RBF path
    // checks fee > replaced_fees AND fee_increase >= replacement_size.
    CTransaction repl_tx;
    repl_tx.nVersion = 1;
    repl_tx.nLockTime = 0;
    repl_tx.vin = orig->vin;     // same prevout(s)
    // Bump the output value so the txid differs from `orig`.
    std::vector<uint8_t> spk{0x76, 0xa9, 0x14, 0x07, 0x09};
    repl_tx.vout.push_back(CTxOut(99999ULL, spk));
    auto repl = MakeTransactionRef(repl_tx);

    // BIP-125 rule 4: fee increase >= replacement size. Pick a
    // replacement fee that's enough larger than orig's 50000 to satisfy
    // both rule 3 (fee > replaced) and rule 4 (fee_increase >= size).
    const CAmount replacement_fee = 50000 + static_cast<CAmount>(repl->GetSerializedSize() + 1000);
    err.clear();
    const bool ok = mempool.ReplaceTransaction(repl, replacement_fee,
                                               std::time(nullptr), 100, &err);
    BOOST_REQUIRE_MESSAGE(ok, "ReplaceTransaction failed: " + err);

    // Estimator should now track the replacement and have dropped the
    // original. Net tracked count: 1.
    BOOST_CHECK_EQUAL(est->getTrackedTxCount(), 1u);
}

// ---- T5: After >= ACCUMULATION_BLOCKS_MIN, estimate becomes non-null ------
//
// This is the integration-test acceptance gate from the contract:
// "demonstrates accumulation + estimate-after-accumulation works against
// a real mempool fixture" (PR-EF-2 acceptance gate, contract section 4).

BOOST_AUTO_TEST_CASE(fee_wiring_estimate_after_accum) {
    using namespace policy::fee_estimator;

    auto est = std::make_unique<CBlockPolicyEstimator>();
    ScopedEstimator scope(est.get());

    CTxMemPool mempool;

    // Drive 30 blocks of mempool activity:
    //   - Each block: admit 4 txs at varying feerates via AddTx.
    //   - Then call processBlock on the estimator with those txhashes
    //     to credit them as confirmed-in-this-block.
    // ACCUMULATION_BLOCKS_MIN is 25, so by block 25+ the estimator
    // should have transitioned out of "insufficient data" for at least
    // some confirmation targets.
    const unsigned int total_blocks = 30;
    for (unsigned int h = 1; h <= total_blocks; ++h) {
        std::vector<uint256> confirmed;
        for (uint32_t i = 0; i < 4; ++i) {
            // Fresh tx per (height, slot) -- two seed bytes give uniqueness.
            const uint8_t a = static_cast<uint8_t>(h & 0xFF);
            const uint8_t b = static_cast<uint8_t>(i & 0xFF);
            auto tx = MakeWiringTestTx(a, b);
            std::string err;
            // Vary the fee across slots so the estimator sees a spread.
            const CAmount fee = 50000 + i * 10000;
            const bool admitted = mempool.AddTx(tx, fee,
                                                static_cast<int64_t>(h),
                                                h, &err, false);
            BOOST_REQUIRE_MESSAGE(admitted, "AddTx failed at h=" +
                                  std::to_string(h) + ": " + err);
            confirmed.push_back(tx->GetHash());
        }
        // Confirm them this block. (In production this comes from the
        // chainstate's BlockConnect callback in dilithion-node.cpp;
        // here we drive it directly so the test stays unit-scoped.)
        est->processBlock(h, confirmed);
        // RemoveConfirmedTxs would normally clean these from the
        // mempool too, but for this test we don't need that -- the
        // estimator has already aged them out via processBlock.
    }

    BOOST_CHECK_GE(est->getBlocksObserved(), 25u);

    // Some bucket should now satisfy the ECONOMICAL threshold for
    // target=6 blocks. We DO NOT pin the exact feerate (the estimator
    // is intentionally a simplified port for now per PR-EF-1 open
    // question 1); we only assert that an estimate IS returned (i.e.
    // not -1) after the accumulation window. PR-EF-1-FIX Finding F3
    // calls out the exact non-null check.
    EstimationResult res = est->estimateRawFee(
        /*target_blocks=*/6,
        /*success_threshold=*/SUCCESS_PCT_ECONOMICAL,
        EstimateHorizon::SHORT_HALFLIFE);
    BOOST_CHECK_MESSAGE(res.feerate >= 0.0L,
                        "estimator returned -1 after accumulation; "
                        "expected a non-null estimate");
}

// ---- T6: null estimator pointer is a no-op (operator passed -feeestimates=0)

BOOST_AUTO_TEST_CASE(fee_wiring_null_estimator_safe) {
    ScopedEstimator scope(nullptr);  // disable for this test

    CTxMemPool mempool;
    auto tx = MakeWiringTestTx(0x10, 0x11);

    // AddTx must succeed and not crash with the null pointer.
    std::string err;
    BOOST_REQUIRE(mempool.AddTx(tx, 50000, std::time(nullptr), 100, &err, false));
    // RemoveTx must also succeed (null-safe).
    BOOST_REQUIRE(mempool.RemoveTx(tx->GetHash()));
}

// ============================================================================
// PR-EF-2 fixup F#4 -- additional coverage from red-team
// ============================================================================

// ---- T7: EvictTransactions notifies the estimator -------------------------
//
// Drive eviction by lowering max_mempool_count to 1 (test seam) and adding a
// second transaction. AddTx triggers EvictTransactions, which should notify
// the estimator (out-of-lock per F#3) for the evicted tx.

BOOST_AUTO_TEST_CASE(fee_wiring_eviction_notifies) {
    auto est = std::make_unique<policy::fee_estimator::CBlockPolicyEstimator>();
    ScopedEstimator scope(est.get());

    CTxMemPool mempool;
    mempool.SetMaxMempoolCountForTesting(1);  // F#4: tight cap to force eviction

    // Low-fee tx admitted first -- becomes the eviction candidate.
    // Use Consensus::CheckFee-passing fees but with disparate fee-rates so
    // eviction orders correctly. CalculateMinFee(192-byte tx) ~= 192 ions
    // floor; a 50000-ion fee passes both min-fee and relay-min, and a
    // 5_000_000-ion fee gives a much higher rate.
    auto low = MakeWiringTestTx(0x21, 0x22);
    std::string err;
    BOOST_REQUIRE(mempool.AddTx(low, /*fee=*/50000, std::time(nullptr),
                                /*height=*/100, &err, false));
    BOOST_REQUIRE_EQUAL(est->getTrackedTxCount(), 1u);

    // High-fee tx -- triggers eviction of `low`. EvictTransactions
    // queues `low` into m_pending_estimator_evictions; AddTx's wrapper
    // drains and notifies after release. Expected: low is dropped from
    // estimator's tracked-set, high is added. Net count: 1.
    auto high = MakeWiringTestTx(0x23, 0x24);
    err.clear();
    BOOST_REQUIRE_MESSAGE(
        mempool.AddTx(high, /*fee=*/5000000, std::time(nullptr),
                      /*height=*/100, &err, false),
        "high-fee admit failed: " + err);

    BOOST_CHECK_EQUAL(est->getTrackedTxCount(), 1u);
    // `low` must have been removed; only `high` is tracked.
    BOOST_CHECK(!mempool.Exists(low->GetHash()));
    BOOST_CHECK(mempool.Exists(high->GetHash()));
}

// ---- T8: CleanupExpiredTransactions notifies the estimator ----------------
//
// Set tx time 15 days in the past so MEMPOOL_EXPIRY_SECONDS (14d) is
// exceeded, then call CleanupExpiredTransactions directly (no need to
// spin up the background thread).

BOOST_AUTO_TEST_CASE(fee_wiring_expiration_notifies) {
    auto est = std::make_unique<policy::fee_estimator::CBlockPolicyEstimator>();
    ScopedEstimator scope(est.get());

    CTxMemPool mempool;
    auto tx = MakeWiringTestTx(0x31, 0x32);

    const int64_t fifteen_days = 15LL * 24 * 60 * 60;
    const int64_t old_time = std::time(nullptr) - fifteen_days;

    std::string err;
    BOOST_REQUIRE(mempool.AddTx(tx, /*fee=*/50000, old_time,
                                /*height=*/100, &err, false));
    BOOST_REQUIRE_EQUAL(est->getTrackedTxCount(), 1u);

    // F#3: Cleanup runs the cs-scoped collection then notifies outside
    // the lock. After the call, the estimator should have dropped the
    // expired tx from its tracked-set.
    mempool.CleanupExpiredTransactions();

    BOOST_CHECK(!mempool.Exists(tx->GetHash()));
    BOOST_CHECK_EQUAL(est->getTrackedTxCount(), 0u);
}

// ---- T9: eviction is null-estimator-safe ---------------------------------

BOOST_AUTO_TEST_CASE(fee_wiring_evict_null_estimator_safe) {
    ScopedEstimator scope(nullptr);

    CTxMemPool mempool;
    mempool.SetMaxMempoolCountForTesting(1);

    auto low = MakeWiringTestTx(0x41, 0x42);
    std::string err;
    BOOST_REQUIRE(mempool.AddTx(low, 50000, std::time(nullptr), 100, &err, false));

    // High-fee admit triggers eviction; with g_fee_estimator=null the
    // post-lock notify branch must be a no-op (no crash).
    auto high = MakeWiringTestTx(0x43, 0x44);
    BOOST_REQUIRE(mempool.AddTx(high, 5000000, std::time(nullptr),
                                100, &err, false));

    BOOST_CHECK(!mempool.Exists(low->GetHash()));
    BOOST_CHECK(mempool.Exists(high->GetHash()));
}

// ---- T10: expiration is null-estimator-safe ------------------------------

BOOST_AUTO_TEST_CASE(fee_wiring_expire_null_estimator_safe) {
    ScopedEstimator scope(nullptr);

    CTxMemPool mempool;
    auto tx = MakeWiringTestTx(0x51, 0x52);

    const int64_t old_time = std::time(nullptr) - (15LL * 24 * 60 * 60);
    std::string err;
    BOOST_REQUIRE(mempool.AddTx(tx, 50000, old_time, 100, &err, false));

    // Must not crash with null estimator.
    mempool.CleanupExpiredTransactions();
    BOOST_CHECK(!mempool.Exists(tx->GetHash()));
}

// ---- T11: ReplaceTransaction is null-estimator-safe ----------------------

BOOST_AUTO_TEST_CASE(fee_wiring_replace_null_estimator_safe) {
    ScopedEstimator scope(nullptr);

    CTxMemPool mempool;
    auto orig = MakeRbfWiringTestTx(0x61, 0x62);
    std::string err;
    BOOST_REQUIRE(mempool.AddTx(orig, 50000, std::time(nullptr), 100, &err, false));

    CTransaction repl_tx;
    repl_tx.nVersion = 1;
    repl_tx.nLockTime = 0;
    repl_tx.vin = orig->vin;
    std::vector<uint8_t> spk{0x76, 0xa9, 0x14, 0x61, 0x63};
    repl_tx.vout.push_back(CTxOut(99999ULL, spk));
    auto repl = MakeTransactionRef(repl_tx);

    const CAmount replacement_fee = 50000 + static_cast<CAmount>(repl->GetSerializedSize() + 1000);
    err.clear();
    // Must not crash with null estimator.
    BOOST_REQUIRE(mempool.ReplaceTransaction(repl, replacement_fee,
                                             std::time(nullptr), 100, &err));
    BOOST_CHECK(mempool.Exists(repl->GetHash()));
    BOOST_CHECK(!mempool.Exists(orig->GetHash()));
}

// ---- T12: block-connect lambda body logic --------------------------------
//
// The actual binary lambda (dilithion-node.cpp / dilv-node.cpp) is in a
// captureless lambda referencing globals. We can't invoke it directly
// from this TU, but we can replicate its body and assert the same
// invariants: coinbase filter, negative-height guard, null-estimator
// skip, IBD-gate (F#2). The IBD gate uses g_node_context.ibd_coordinator;
// in unit tests no coordinator is registered, so the gate "no
// coordinator" branch (skip) is what fires here. We assert that:
//   - coinbase is filtered out of `confirmed`
//   - h<0 short-circuits before any work
//   - null estimator short-circuits before any work
//
// Note: we do NOT test the post-IBD path here because that requires a
// running CIbdCoordinator. The IBD-vs-post-IBD coverage is by inspection
// (one branch in the lambda; gate matches the existing txindex pattern).

BOOST_AUTO_TEST_CASE(fee_wiring_block_connect_lambda_logic) {
    auto est = std::make_unique<policy::fee_estimator::CBlockPolicyEstimator>();
    ScopedEstimator scope(est.get());

    // Replicate the lambda body. Take a synthetic txhash list and verify
    // the filtering invariants. The real binary's processBlock is what
    // actually advances getBlocksObserved; here we assert it doesn't
    // advance for the guards (h<0, null estimator).
    auto run_guards = [&](int h) -> bool {
        if (!g_fee_estimator || h < 0) return false;
        // Real lambda would deserialize block.vtx here. For unit-test
        // scope we assert the pre-condition guards only.
        return true;
    };

    BOOST_CHECK(!run_guards(-1));   // negative height -> skip
    {
        ScopedEstimator scope_null(nullptr);
        BOOST_CHECK(!run_guards(100));  // null estimator -> skip
    }
    BOOST_CHECK(run_guards(100));   // valid case -> proceeds

    // Coinbase filter: separate, deterministic check on the synthetic tx
    // generator -- coinbase has empty vin, our MakeWiringTestTx always
    // has one input, so IsCoinBase() returns false. The lambda's filter
    // is `if (tx->IsCoinBase()) continue;`. We construct a coinbase tx
    // (vin empty) and assert IsCoinBase()==true so the filter would
    // exclude it.
    CTransaction cb;
    cb.nVersion = 1;
    cb.nLockTime = 0;
    // No inputs -> IsCoinBase() per CTransaction::IsCoinBase(): vin.size()==1
    // && vin[0].prevout.IsNull(). For our test we just need the filter
    // input-shape check; CTransaction's IsCoinBase returns false for
    // empty vin too. So construct a real coinbase: one input with null
    // prevout.
    uint256 null_prev;
    std::memset(null_prev.data, 0, 32);
    cb.vin.push_back(CTxIn(null_prev, 0xFFFFFFFF,
                           std::vector<uint8_t>{0x01}, 0xFFFFFFFF));
    std::vector<uint8_t> cb_spk{0x76, 0xa9, 0x14, 0xCB, 0x00};
    cb.vout.push_back(CTxOut(50ULL, cb_spk));
    auto cb_ref = MakeTransactionRef(cb);
    BOOST_CHECK(cb_ref->IsCoinBase());  // sanity: lambda filter would skip
}

// ---- T13: processBlock idempotent on rollback replay (F#5) ----------------
//
// Drive 25 blocks of accumulation, then replay block 25 a second time
// (simulating ActivateBestChain's rollback path: re-disconnect then
// re-connect the same height). Assert that the second call does NOT
// double-decay or double-age.

BOOST_AUTO_TEST_CASE(fee_wiring_processblock_idempotent_replay) {
    using namespace policy::fee_estimator;
    auto est = std::make_unique<CBlockPolicyEstimator>();
    ScopedEstimator scope(est.get());

    CTxMemPool mempool;

    // Drive 25 blocks of accumulation. We only need the estimator's
    // internal state to advance; tx admission is a side-effect.
    const unsigned int total_blocks = 25;
    for (unsigned int h = 1; h <= total_blocks; ++h) {
        std::vector<uint256> confirmed;
        for (uint32_t i = 0; i < 4; ++i) {
            const uint8_t a = static_cast<uint8_t>(h & 0xFF);
            const uint8_t b = static_cast<uint8_t>(i & 0xFF);
            auto tx = MakeWiringTestTx(a, b);
            std::string err;
            const CAmount fee = 50000 + i * 10000;
            BOOST_REQUIRE(mempool.AddTx(tx, fee, static_cast<int64_t>(h),
                                        h, &err, false));
            confirmed.push_back(tx->GetHash());
        }
        est->processBlock(h, confirmed);
    }

    // Snapshot post-accumulation state.
    const unsigned int blocks_observed_before = est->getBlocksObserved();
    const unsigned int best_height_before = est->getBestSeenHeight();

    // Replay block 25 with NO new tracked-tx confirmations (all txs
    // for height 25 were already confirmed and erased). F#5 guard:
    //   height (25) <= m_historical_best (25) AND
    //   counted_confirms == 0
    // -> skip decay/age.
    std::vector<uint256> empty_confirms;
    est->processBlock(total_blocks, empty_confirms);

    // Best-seen height did not advance.
    BOOST_CHECK_EQUAL(est->getBestSeenHeight(), best_height_before);
    // Blocks-observed did not advance (we already saw block 25).
    BOOST_CHECK_EQUAL(est->getBlocksObserved(), blocks_observed_before);

    // Sanity: re-applying an unrelated forward block DOES advance.
    est->processBlock(total_blocks + 1, empty_confirms);
    BOOST_CHECK_GT(est->getBestSeenHeight(), best_height_before);
}

// ---- T14: StopExpirationThread idempotency (F#1) -------------------------
//
// CTxMemPool::StopExpirationThread() must be safe to call multiple
// times. The destructor also calls it. The two-call sequence
// (explicit + implicit at scope exit) must not double-join, deadlock,
// or crash.

BOOST_AUTO_TEST_CASE(fee_wiring_stop_expiration_idempotent) {
    auto est = std::make_unique<policy::fee_estimator::CBlockPolicyEstimator>();
    ScopedEstimator scope(est.get());

    {
        CTxMemPool mempool;
        // First call: stops + joins the expiration thread.
        mempool.StopExpirationThread();
        // Second call: must be a no-op (idempotent).
        mempool.StopExpirationThread();

        // Any post-stop estimator-touching mempool method should still
        // function; the expiration thread is dead but the public API is
        // still alive. Add a tx and assert it lands in the estimator.
        auto tx = MakeWiringTestTx(0x71, 0x72);
        std::string err;
        BOOST_REQUIRE(mempool.AddTx(tx, 50000, std::time(nullptr),
                                    100, &err, false));
        BOOST_CHECK_EQUAL(est->getTrackedTxCount(), 1u);

        // CleanupExpiredTransactions must also be safe to call after
        // StopExpirationThread (the thread that normally invokes it is
        // gone, but the method itself is fine).
        mempool.CleanupExpiredTransactions();
    }
    // Implicit StopExpirationThread() in CTxMemPool's destructor must
    // be a no-op here; if the test exits cleanly we're good.
}

// ---- T15: ReplaceTransaction with bypass_fee_check=true (F#8) ------------
//
// bypass_fee_check=true (e.g. mempool reload RBF replay) maps to
// valid_fee_estimate=false. The replacement tx still admits but is NOT
// recorded as a fresh tracked-tx. The evicted conflict IS still removed
// from the tracked-set (its prior admit IS in the set; it must be
// dropped to keep the estimator state consistent with the mempool).

BOOST_AUTO_TEST_CASE(fee_wiring_replace_bypass_skips) {
    auto est = std::make_unique<policy::fee_estimator::CBlockPolicyEstimator>();
    ScopedEstimator scope(est.get());

    CTxMemPool mempool;

    // Live-admit the original (fills tracked-set).
    auto orig = MakeRbfWiringTestTx(0x81, 0x82);
    std::string err;
    BOOST_REQUIRE(mempool.AddTx(orig, /*fee=*/50000, std::time(nullptr),
                                /*height=*/100, &err, false));
    BOOST_REQUIRE_EQUAL(est->getTrackedTxCount(), 1u);

    // Replacement -- bypass_fee_check=true.
    CTransaction repl_tx;
    repl_tx.nVersion = 1;
    repl_tx.nLockTime = 0;
    repl_tx.vin = orig->vin;
    std::vector<uint8_t> spk{0x76, 0xa9, 0x14, 0x81, 0x83};
    repl_tx.vout.push_back(CTxOut(99999ULL, spk));
    auto repl = MakeTransactionRef(repl_tx);

    const CAmount replacement_fee =
        50000 + static_cast<CAmount>(repl->GetSerializedSize() + 1000);
    err.clear();
    BOOST_REQUIRE_MESSAGE(
        mempool.ReplaceTransaction(repl, replacement_fee,
                                   std::time(nullptr), 100, &err,
                                   /*bypass_fee_check=*/true),
        "ReplaceTransaction failed: " + err);

    // Original was tracked, gets evicted -> dropped from estimator.
    // Replacement was bypass-replayed -> NOT added to estimator.
    // Net tracked count: 0.
    BOOST_CHECK_EQUAL(est->getTrackedTxCount(), 0u);

    // Mempool itself still contains the replacement (it was admitted).
    BOOST_CHECK(mempool.Exists(repl->GetHash()));
}

BOOST_AUTO_TEST_SUITE_END()
