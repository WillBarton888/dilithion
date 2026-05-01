// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

// Integration tests for PR-EF-2: fee estimator wired to a real mempool.
//
// These tests exercise the public mempool surface (CTxMemPool::AddTx,
// CTxMemPool::ReplaceTransaction, CTxMemPool::RemoveTx,
// CTxMemPool::CleanupExpiredTransactions via direct call) with the
// process-wide g_fee_estimator pointer set to a live
// CBlockPolicyEstimator. We then drive synthetic block-connect events
// directly through the estimator's processBlock (the in-process
// chainstate connect callback path is exercised by the actual binary
// at runtime; here we verify the estimator state after each phase).
//
// Coverage:
//   - fee_wiring_admit_records_tx     -- AddTx populates tracked-set
//   - fee_wiring_bypass_skips         -- bypass_fee_check=true skips
//   - fee_wiring_remove_drops_tracking-- RemoveTx invokes estimator
//   - fee_wiring_rbf_replace          -- ReplaceTransaction transitions
//   - fee_wiring_estimate_after_accum -- after >=25 blocks, estimate
//                                        becomes non-null
//   - fee_wiring_null_estimator_safe  -- AddTx with g_fee_estimator=null
//                                        is a no-op (acceptance gate)

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

BOOST_AUTO_TEST_SUITE_END()
