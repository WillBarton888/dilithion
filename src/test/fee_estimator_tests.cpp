// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <boost/test/unit_test.hpp>

#include <policy/fees.h>
#include <uint256.h>

#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(fee_estimator_tests)

namespace {

// Make a unique deterministic txhash from a seed.
uint256 MakeTxHash(uint32_t seed) {
    uint256 h;
    std::memset(h.data, 0, 32);
    h.data[0] = static_cast<uint8_t>(seed & 0xFF);
    h.data[1] = static_cast<uint8_t>((seed >> 8) & 0xFF);
    h.data[2] = static_cast<uint8_t>((seed >> 16) & 0xFF);
    h.data[3] = static_cast<uint8_t>((seed >> 24) & 0xFF);
    // Spread some entropy to avoid map-collision pathologies.
    h.data[31] = static_cast<uint8_t>(seed * 0x9E + 0x37);
    return h;
}

}  // anonymous namespace

// ---- Bucket ladder shape -----------------------------------------------

BOOST_AUTO_TEST_CASE(bucket_ladder_shape) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;
    auto buckets = est.getBuckets();

    // First bucket is MIN_BUCKET_FEERATE; last is INF_FEERATE sentinel.
    BOOST_REQUIRE_GT(buckets.size(), 2u);
    BOOST_CHECK(static_cast<double>(buckets.front()) ==
                static_cast<double>(MIN_BUCKET_FEERATE));
    BOOST_CHECK(static_cast<double>(buckets.back()) ==
                static_cast<double>(INF_FEERATE));

    // Each bucket strictly greater than previous.
    for (size_t i = 1; i < buckets.size(); ++i) {
        BOOST_CHECK(static_cast<double>(buckets[i]) >
                    static_cast<double>(buckets[i - 1]));
    }

    // Estimator starts in accumulation window.
    BOOST_CHECK_EQUAL(est.getBlocksObserved(), 0u);
    BOOST_CHECK_EQUAL(est.getBestSeenHeight(), 0u);
    BOOST_CHECK_EQUAL(est.getTrackedTxCount(), 0u);
}

// ---- Insufficient-data path ---------------------------------------------

BOOST_AUTO_TEST_CASE(insufficient_data_returns_error) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;

    // No blocks observed -> raw and smart return error.
    auto raw = est.estimateRawFee(6, 0.85,
                                  EstimateHorizon::MED_HALFLIFE);
    BOOST_CHECK(raw.feerate < 0.0L);
    BOOST_CHECK(!raw.error.empty());
    BOOST_CHECK(raw.error.find("insufficient data") != std::string::npos);

    auto smart = est.estimateSmartFee(6, EstimateMode::CONSERVATIVE);
    BOOST_CHECK(smart.feerate < 0.0L);
    BOOST_CHECK(!smart.error.empty());

    // Even after a few blocks (< ACCUMULATION_BLOCKS_MIN) we still error.
    for (unsigned int h = 1; h <= 10; ++h) {
        est.processBlock(h, /*confirmed=*/{});
    }
    auto still = est.estimateSmartFee(6, EstimateMode::CONSERVATIVE);
    BOOST_CHECK(still.feerate < 0.0L);
}

// ---- Accumulation crosses the threshold ---------------------------------

BOOST_AUTO_TEST_CASE(crosses_accumulation_threshold) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;
    for (unsigned int h = 1; h <= ACCUMULATION_BLOCKS_MIN + 5; ++h) {
        est.processBlock(h, /*confirmed=*/{});
    }
    BOOST_CHECK_GE(est.getBlocksObserved(), ACCUMULATION_BLOCKS_MIN);
    BOOST_CHECK_EQUAL(est.getBestSeenHeight(), ACCUMULATION_BLOCKS_MIN + 5);
    // Even with no tx data we may not yet have a bucket meeting threshold;
    // that's an "insufficient bucket data" error, not the accumulation error.
    auto r = est.estimateSmartFee(6, EstimateMode::CONSERVATIVE);
    BOOST_CHECK(r.feerate < 0.0L);
    // Error MUST NOT mention "accumulation" anymore.
    BOOST_CHECK(r.error.find("accumulation") == std::string::npos);
}

// ---- Synthetic mempool driver: high-fee txs confirm fast ---------------

BOOST_AUTO_TEST_CASE(high_fee_confirms_fast) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;

    // Drive 30 blocks. In each block:
    //   - admit 5 high-fee txs (50000 ions/250 vsize = 200_000 ions/kB)
    //   - admit 5 low-fee txs (5000 ions/250 vsize  =  20_000 ions/kB)
    //   - confirm all 5 high-fee txs in this same block (1-block confirm)
    //   - confirm low-fee txs only in next block (2-block confirm)
    constexpr CAmount kHighFee = 50000;
    constexpr CAmount kLowFee  = 5000;
    constexpr size_t  kVsize   = 250;
    std::vector<uint256> last_low;

    for (unsigned int h = 1; h <= 30; ++h) {
        std::vector<uint256> high_hashes, low_hashes;
        for (uint32_t i = 0; i < 5; ++i) {
            uint256 hh = MakeTxHash(h * 1000 + i);
            est.processTx(hh, h, kHighFee, kVsize, true);
            high_hashes.push_back(hh);
            uint256 lh = MakeTxHash(h * 1000 + 100 + i);
            est.processTx(lh, h, kLowFee, kVsize, true);
            low_hashes.push_back(lh);
        }
        // Confirm last block's low-fee txs + this block's high-fee txs.
        std::vector<uint256> confirmed = last_low;
        confirmed.insert(confirmed.end(), high_hashes.begin(), high_hashes.end());
        est.processBlock(h, confirmed);
        last_low = low_hashes;
    }

    // After 30 blocks of consistent behavior we should have:
    //   - some bucket showing a strong confirm-rate at target=1 around 200k
    //   - a lower bucket showing strong confirm-rate at target=2 around 20k
    // Because our estimator returns the LOWEST feerate that meets threshold,
    // target=1 estimate should pick up the lowest bucket whose cumulative
    // (from-top-down) success rate exceeds the threshold.
    auto r1 = est.estimateRawFee(1, 0.80,
                                 EstimateHorizon::SHORT_HALFLIFE);
    BOOST_TEST_MESSAGE("target=1 r1.feerate=" << static_cast<double>(r1.feerate)
                       << " err='" << r1.error << "'");
    BOOST_CHECK(r1.feerate > 0.0L);

    auto r2 = est.estimateRawFee(2, 0.80,
                                 EstimateHorizon::MED_HALFLIFE);
    BOOST_TEST_MESSAGE("target=2 r2.feerate=" << static_cast<double>(r2.feerate)
                       << " err='" << r2.error << "'");
    BOOST_CHECK(r2.feerate > 0.0L);

    // Smart estimate must succeed too (CONSERVATIVE picks max across horizons).
    auto smart = est.estimateSmartFee(2, EstimateMode::CONSERVATIVE);
    BOOST_TEST_MESSAGE("smart target=2 feerate=" << static_cast<double>(smart.feerate)
                       << " err='" << smart.error << "'");
    BOOST_CHECK(smart.feerate > 0.0L);
}

// ---- valid_fee_estimate=false is ignored -------------------------------

BOOST_AUTO_TEST_CASE(invalid_fee_estimate_flag_ignored) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;
    uint256 h = MakeTxHash(42);
    est.processTx(h, /*height=*/1, /*fee=*/100000,
                  /*vsize=*/250, /*valid_fee_estimate=*/false);
    BOOST_CHECK_EQUAL(est.getTrackedTxCount(), 0u);
    // processBlockTx for an untracked hash must return false cleanly.
    BOOST_CHECK(!est.processBlockTx(2, h));
}

// ---- Zero-vsize tx is dropped -----------------------------------------

BOOST_AUTO_TEST_CASE(zero_vsize_dropped) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;
    est.processTx(MakeTxHash(1), 1, 100000, 0, true);
    BOOST_CHECK_EQUAL(est.getTrackedTxCount(), 0u);
}

// ---- Negative fee dropped ----------------------------------------------

BOOST_AUTO_TEST_CASE(negative_fee_dropped) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;
    est.processTx(MakeTxHash(1), 1, -1, 250, true);
    BOOST_CHECK_EQUAL(est.getTrackedTxCount(), 0u);
}

// ---- Saturating fee at INF bucket --------------------------------------

BOOST_AUTO_TEST_CASE(massive_fee_saturates_to_inf_bucket) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;
    // Fee = MAX_MONEY, vsize = 250 -> feerate = MAX_MONEY * 1000 / 250
    // = 8.4e15 ions/kB, far above MAX_BUCKET_FEERATE=1e7. Should bucket
    // into the INF sentinel rather than wrap or crash.
    est.processTx(MakeTxHash(1), 1, MAX_MONEY, 250, true);
    BOOST_CHECK_EQUAL(est.getTrackedTxCount(), 1u);
    BOOST_CHECK(est.processBlockTx(1, MakeTxHash(1)));
}

// ---- Anti-replay: later-tx with earlier-than-best height is dropped ----

BOOST_AUTO_TEST_CASE(anti_replay_drops_older_height) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;
    for (unsigned int h = 1; h <= 30; ++h) {
        est.processBlock(h, /*confirmed=*/{});
    }
    BOOST_REQUIRE_EQUAL(est.getBestSeenHeight(), 30u);
    // Now feed a tx with height=10 -- before our best-seen.
    est.processTx(MakeTxHash(99), /*height=*/10, 100000, 250, true);
    BOOST_CHECK_EQUAL(est.getTrackedTxCount(), 0u);
}

// ---- Reorg behavior: subsequent confirmations self-correct -------------

BOOST_AUTO_TEST_CASE(reorg_self_corrects) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;

    // Phase 1: feed 30 blocks with consistent fees.
    for (unsigned int h = 1; h <= 30; ++h) {
        std::vector<uint256> confirmed;
        for (uint32_t i = 0; i < 5; ++i) {
            uint256 t = MakeTxHash(h * 100 + i);
            est.processTx(t, h, 50000, 250, true);
            confirmed.push_back(t);
        }
        est.processBlock(h, confirmed);
    }
    const auto baseline_height = est.getBestSeenHeight();
    BOOST_CHECK_EQUAL(baseline_height, 30u);
    auto raw_pre = est.estimateRawFee(2, 0.80,
                                      EstimateHorizon::MED_HALFLIFE);
    BOOST_CHECK(raw_pre.feerate > 0.0L);

    // Phase 2: simulate a reorg by replaying processBlock for blocks 28-30
    // with different (replayed) confirms. The estimator's state should not
    // crash, NaN, or wrap; subsequent observations on a higher height
    // should still produce sensible estimates.
    for (unsigned int h = 28; h <= 30; ++h) {
        est.processBlock(h, /*confirmed=*/{});  // reorg-out
    }
    // Now extend on a fresh fork at heights 31-50 with consistent fees.
    for (unsigned int h = 31; h <= 50; ++h) {
        std::vector<uint256> confirmed;
        for (uint32_t i = 0; i < 5; ++i) {
            uint256 t = MakeTxHash(h * 100 + i + 99999);
            est.processTx(t, h, 80000, 250, true);
            confirmed.push_back(t);
        }
        est.processBlock(h, confirmed);
    }
    auto raw_post = est.estimateRawFee(2, 0.80,
                                       EstimateHorizon::MED_HALFLIFE);
    BOOST_CHECK(raw_post.feerate > 0.0L);
    // Sanity bound: must not wrap to negative, must be within bucket range.
    BOOST_CHECK(raw_post.feerate >= MIN_BUCKET_FEERATE);
    BOOST_CHECK(raw_post.feerate <= INF_FEERATE);
}

// ---- removeTx (eviction) drops without affecting fail counters ---------

BOOST_AUTO_TEST_CASE(remove_tx_eviction) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;
    uint256 h = MakeTxHash(7);
    est.processTx(h, 1, 100000, 250, true);
    BOOST_CHECK_EQUAL(est.getTrackedTxCount(), 1u);
    est.removeTx(h, /*in_block=*/false);
    BOOST_CHECK_EQUAL(est.getTrackedTxCount(), 0u);
    // No-op for an already-removed tx.
    est.removeTx(h, /*in_block=*/false);
    BOOST_CHECK_EQUAL(est.getTrackedTxCount(), 0u);
}

// ---- Snapshot / restore round-trip preserves state ---------------------

BOOST_AUTO_TEST_CASE(snapshot_restore_roundtrip) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator a;

    // Drive 30 blocks of activity into 'a'.
    for (unsigned int h = 1; h <= 30; ++h) {
        std::vector<uint256> confirmed;
        for (uint32_t i = 0; i < 3; ++i) {
            uint256 t = MakeTxHash(h * 1000 + i);
            a.processTx(t, h, 80000 + i * 1000, 250, true);
            confirmed.push_back(t);
        }
        a.processBlock(h, confirmed);
    }
    // Leave a few unconfirmed in 'a'.
    a.processTx(MakeTxHash(7777), 30, 30000, 250, true);
    a.processTx(MakeTxHash(7778), 30, 60000, 250, true);

    auto snap = a.snapshot();
    BOOST_CHECK_EQUAL(snap.tracked_txs.size(), 2u);
    BOOST_CHECK_EQUAL(snap.best_seen_height, 30u);

    CBlockPolicyEstimator b;
    BOOST_REQUIRE(b.restore(snap));

    BOOST_CHECK_EQUAL(a.getBestSeenHeight(), b.getBestSeenHeight());
    BOOST_CHECK_EQUAL(a.getTrackedTxCount(), b.getTrackedTxCount());
    BOOST_CHECK_EQUAL(a.getBlocksObserved(), b.getBlocksObserved());

    // Estimates should match modulo encoding noise.
    auto ra = a.estimateRawFee(2, 0.80,
                               EstimateHorizon::MED_HALFLIFE);
    auto rb = b.estimateRawFee(2, 0.80,
                               EstimateHorizon::MED_HALFLIFE);
    BOOST_TEST_MESSAGE("a feerate=" << static_cast<double>(ra.feerate)
                       << " b feerate=" << static_cast<double>(rb.feerate));
    if (ra.feerate > 0.0L) {
        BOOST_REQUIRE(rb.feerate > 0.0L);
        // After Q32.32 round-trip, exact equality.
        BOOST_CHECK_EQUAL(static_cast<double>(ra.feerate),
                          static_cast<double>(rb.feerate));
    }
}

// ---- Restore with bucket-shape mismatch returns false ------------------

BOOST_AUTO_TEST_CASE(restore_rejects_bad_bucket_shape) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator a;
    auto snap = a.snapshot();
    // Truncate buckets vector -- restore must reject.
    snap.buckets.pop_back();
    BOOST_CHECK(!a.restore(std::move(snap)));
}

BOOST_AUTO_TEST_CASE(restore_rejects_mangled_bucket_value) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator a;
    auto snap = a.snapshot();
    BOOST_REQUIRE(!snap.buckets.empty());
    // Flip a bucket boundary far outside tolerance.
    snap.buckets[0] = snap.buckets[0] * 2.0L;
    BOOST_CHECK(!a.restore(std::move(snap)));
}

// ---- Restore with bad stats shape returns false -----------------------

BOOST_AUTO_TEST_CASE(restore_rejects_bad_stats_shape) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator a;
    auto snap = a.snapshot();
    snap.short_stats.tx_ct_avg.pop_back();
    BOOST_CHECK(!a.restore(std::move(snap)));
}

// ---- estimateSmartFee CONSERVATIVE >= ECONOMICAL when both succeed ----

BOOST_AUTO_TEST_CASE(conservative_at_least_economical) {
    using namespace policy::fee_estimator;
    CBlockPolicyEstimator est;
    for (unsigned int h = 1; h <= 50; ++h) {
        std::vector<uint256> confirmed;
        for (uint32_t i = 0; i < 5; ++i) {
            uint256 t = MakeTxHash(h * 100 + i);
            est.processTx(t, h, 50000, 250, true);
            confirmed.push_back(t);
        }
        est.processBlock(h, confirmed);
    }
    auto cons = est.estimateSmartFee(2, EstimateMode::CONSERVATIVE);
    auto econ = est.estimateSmartFee(2, EstimateMode::ECONOMICAL);
    if (cons.feerate > 0.0L && econ.feerate > 0.0L) {
        // CONSERVATIVE picks the highest feerate across horizons, ECONOMICAL
        // picks the lowest. So cons >= econ always.
        BOOST_CHECK_GE(static_cast<double>(cons.feerate),
                       static_cast<double>(econ.feerate));
    }
}

BOOST_AUTO_TEST_SUITE_END()
