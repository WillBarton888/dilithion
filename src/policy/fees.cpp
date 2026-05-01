// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <policy/fees.h>

#include <algorithm>
#include <cmath>
#include <stdexcept>

// Process-wide fee estimator handle. Defined in fees.cpp so the symbol
// exists even when no node binary is linked (e.g. test_dilithion). PR-EF-2
// wiring sets/clears this from dilithion-node.cpp / dilv-node.cpp main().
policy::fee_estimator::CBlockPolicyEstimator* g_fee_estimator = nullptr;

namespace policy {
namespace fee_estimator {

namespace {

// Compute a sentinel value used internally by the bucket map: the bucket
// boundaries are upper-bounds, so we look up via lower_bound on the map.
// Using `long double` keys is safe here because the bucket ladder has
// O(200) entries, and ladder construction is deterministic from the
// pinned constants.
long double NormalizeFeerate(CAmount fee, size_t vsize) {
    if (vsize == 0) return 0.0L;
    // Ions per 1000 bytes. Match BC's CFeeRate convention: integer-divide
    // semantics aren't needed here since we're only used as a bucket lookup
    // key, not in consensus.
    return static_cast<long double>(fee) * 1000.0L /
           static_cast<long double>(vsize);
}

// Initialize a TxConfirmStats with zero-filled vectors. confirm_periods is
// the per-horizon bucket count (12, 24, 42).
void InitTxConfirmStats(TxConfirmStats& stats,
                        size_t bucket_count,
                        unsigned int confirm_periods,
                        unsigned int scale,
                        long double decay) {
    stats.scale = scale;
    stats.decay = decay;
    stats.conf_avg.assign(confirm_periods,
                          std::vector<long double>(bucket_count, 0.0L));
    stats.fail_avg.assign(confirm_periods,
                          std::vector<long double>(bucket_count, 0.0L));
    stats.tx_ct_avg.assign(bucket_count, 0.0L);
    // Unconfirmed-ring depth: we track up to confirm_periods*scale blocks of
    // age. At confirm_periods=12, scale=1, this is 12 buckets of age.
    stats.unconf_txs.assign(confirm_periods * scale,
                            std::vector<int>(bucket_count, 0));
    stats.old_unconf_txs.assign(bucket_count, 0);
}

}  // anonymous namespace

CBlockPolicyEstimator::CBlockPolicyEstimator() {
    initBuckets();
    initStats();
}

CBlockPolicyEstimator::~CBlockPolicyEstimator() = default;

void CBlockPolicyEstimator::initBuckets() {
    m_buckets.clear();
    m_bucket_map.clear();
    long double bucket = MIN_BUCKET_FEERATE;
    while (bucket <= MAX_BUCKET_FEERATE) {
        m_buckets.push_back(bucket);
        m_bucket_map[bucket] = static_cast<unsigned int>(m_buckets.size() - 1);
        bucket *= FEE_SPACING;
    }
    // Top-of-ladder sentinel for "anything above MAX_BUCKET_FEERATE".
    m_buckets.push_back(INF_FEERATE);
    m_bucket_map[INF_FEERATE] =
        static_cast<unsigned int>(m_buckets.size() - 1);
}

void CBlockPolicyEstimator::initStats() {
    const size_t bucket_count = m_buckets.size();
    InitTxConfirmStats(m_short, bucket_count, SHORT_BLOCK_PERIODS,
                       SHORT_SCALE, SHORT_DECAY);
    InitTxConfirmStats(m_med,   bucket_count, MED_BLOCK_PERIODS,
                       MED_SCALE,   MED_DECAY);
    InitTxConfirmStats(m_long,  bucket_count, LONG_BLOCK_PERIODS,
                       LONG_SCALE,  LONG_DECAY);
}

unsigned int CBlockPolicyEstimator::findBucket(long double feerate) const {
    // lower_bound returns the first bucket whose upper-bound >= feerate.
    auto it = m_bucket_map.lower_bound(feerate);
    if (it == m_bucket_map.end()) {
        // feerate exceeds all bucket boundaries -- bucket into INF.
        return static_cast<unsigned int>(m_buckets.size() - 1);
    }
    return it->second;
}

void CBlockPolicyEstimator::recordTxAdmit(TxConfirmStats& stats,
                                          unsigned int bucket_index) {
    if (bucket_index >= stats.tx_ct_avg.size()) return;
    stats.tx_ct_avg[bucket_index] += 1.0L;
    // The newest age slot is row 0 of the ring. processBlock rotates the
    // ring forward so a tx admitted at block H sits in row 0 until H+1,
    // then row 1, and so on.
    if (!stats.unconf_txs.empty() &&
        bucket_index < stats.unconf_txs[0].size()) {
        stats.unconf_txs[0][bucket_index] += 1;
    }
}

void CBlockPolicyEstimator::recordBlockTx(TxConfirmStats& stats,
                                          unsigned int blocks_to_confirm,
                                          unsigned int bucket_index) {
    if (bucket_index >= stats.tx_ct_avg.size()) return;
    if (blocks_to_confirm == 0) blocks_to_confirm = 1;

    // For every confirmation target d >= blocks_to_confirm, this tx counts
    // as a SUCCESS for that target (it confirmed within d blocks).
    const unsigned int max_track = static_cast<unsigned int>(stats.conf_avg.size());
    const unsigned int from = std::min(blocks_to_confirm, max_track);
    for (unsigned int d = from; d <= max_track; ++d) {
        const unsigned int row = d - 1;
        if (row < stats.conf_avg.size() &&
            bucket_index < stats.conf_avg[row].size()) {
            stats.conf_avg[row][bucket_index] += 1.0L;
        }
    }
    // Also remove from the unconfirmed ring -- the tx confirmed.
    // We don't know which ring slot it's in without extra bookkeeping, so
    // we walk and decrement the first non-zero slot at this bucket. This
    // matches BC's behavior in `removeTx` with `inBlock=true`.
    for (auto& row : stats.unconf_txs) {
        if (bucket_index < row.size() && row[bucket_index] > 0) {
            row[bucket_index] -= 1;
            return;
        }
    }
    // Could be in the aged-out bin.
    if (bucket_index < stats.old_unconf_txs.size() &&
        stats.old_unconf_txs[bucket_index] > 0) {
        stats.old_unconf_txs[bucket_index] -= 1;
    }
}

void CBlockPolicyEstimator::decayStats(TxConfirmStats& stats) {
    for (auto& row : stats.conf_avg) {
        for (auto& v : row) v *= stats.decay;
    }
    for (auto& row : stats.fail_avg) {
        for (auto& v : row) v *= stats.decay;
    }
    for (auto& v : stats.tx_ct_avg) v *= stats.decay;
}

void CBlockPolicyEstimator::agingUnconfirmed(TxConfirmStats& stats) {
    if (stats.unconf_txs.empty()) return;
    // Rotate ring forward: row N-1 ages out into old_unconf_txs (counted
    // as failures), rows 1..N-2 shift down, row 0 starts fresh.
    const size_t depth = stats.unconf_txs.size();
    if (depth == 0) return;
    const size_t bucket_count = stats.unconf_txs[0].size();

    // The aged-out row becomes part of fail_avg (timed out without
    // confirming) and is added to old_unconf_txs.
    for (unsigned int b = 0; b < bucket_count; ++b) {
        const int aged_out = stats.unconf_txs[depth - 1][b];
        if (aged_out > 0) {
            stats.old_unconf_txs[b] += aged_out;
            // For every confirmation target d, txs that didn't confirm in
            // d blocks count as failures at that target. The aged-out
            // slot represents txs >= depth blocks old, so they failed at
            // every target up to stats.conf_avg.size().
            for (size_t d = 0; d < stats.fail_avg.size(); ++d) {
                if (b < stats.fail_avg[d].size()) {
                    stats.fail_avg[d][b] += static_cast<long double>(aged_out);
                }
            }
        }
    }
    // Shift rows: row[i] = row[i-1] for i >= 1; row[0] becomes zeroed.
    for (size_t i = depth - 1; i > 0; --i) {
        stats.unconf_txs[i] = stats.unconf_txs[i - 1];
    }
    std::fill(stats.unconf_txs[0].begin(), stats.unconf_txs[0].end(), 0);
}

void CBlockPolicyEstimator::processTx(const uint256& txhash,
                                      unsigned int height,
                                      CAmount fee,
                                      size_t vsize,
                                      bool valid_fee_estimate) {
    if (!valid_fee_estimate) return;
    if (vsize == 0) return;
    if (fee < 0) return;  // CAmount overflow / sentinel guard

    const long double feerate = NormalizeFeerate(fee, vsize);
    if (feerate <= 0.0L) return;

    std::lock_guard<std::mutex> lk(m_mutex);

    // Don't accept retro observations for blocks we already aged past --
    // matches BC's anti-replay behavior on restore-from-disk.
    if (m_best_seen_height > 0 && height < m_best_seen_height) return;

    if (m_tracked.count(txhash)) return;  // already tracked -- ignore

    const unsigned int bucket_index = findBucket(feerate);

    TrackedTx t;
    t.height       = height;
    t.bucket_index = bucket_index;
    t.horizon_mask = 0x07;  // start tracked across all three horizons

    m_tracked[txhash] = t;

    recordTxAdmit(m_short, bucket_index);
    recordTxAdmit(m_med,   bucket_index);
    recordTxAdmit(m_long,  bucket_index);
}

bool CBlockPolicyEstimator::processBlockTx(unsigned int block_height,
                                           const uint256& txhash) {
    std::lock_guard<std::mutex> lk(m_mutex);
    return processBlockTxLocked(block_height, txhash);
}

// PR-EF-1-FIX Finding F2: extracted from processBlockTx so processBlock
// can call it WITHOUT releasing/reacquiring the lock between phases.
// Caller MUST hold m_mutex.
bool CBlockPolicyEstimator::processBlockTxLocked(unsigned int block_height,
                                                 const uint256& txhash) {
    auto it = m_tracked.find(txhash);
    if (it == m_tracked.end()) return false;

    const unsigned int admit_height = it->second.height;
    const unsigned int bucket_index = it->second.bucket_index;
    const unsigned int blocks_to_confirm =
        block_height >= admit_height ? (block_height - admit_height) : 0;

    if (it->second.horizon_mask & 0x01) {
        recordBlockTx(m_short, blocks_to_confirm, bucket_index);
    }
    if (it->second.horizon_mask & 0x02) {
        recordBlockTx(m_med, blocks_to_confirm, bucket_index);
    }
    if (it->second.horizon_mask & 0x04) {
        recordBlockTx(m_long, blocks_to_confirm, bucket_index);
    }

    m_tracked.erase(it);
    return true;
}

void CBlockPolicyEstimator::processBlock(
        unsigned int block_height,
        const std::vector<uint256>& confirmed_txhashes) {
    // PR-EF-1-FIX Finding F2: hold the lock for the ENTIRE call. Pre-fix
    // the lock was released between (a) the height update, (b) the
    // per-tx confirm loop, and (c) the decay+age phase. A concurrent
    // snapshot()/DumpFeeEstimates between phases would persist
    // internally inconsistent state (height advanced but unconf_txs
    // ring not yet aged). The header docstring claimed "single mutex"
    // and "coarse locking is adequate" -- both were lies pre-fix.
    // Now true: one acquire, one release, full atomicity.
    std::lock_guard<std::mutex> lk(m_mutex);

    if (m_historical_first == 0) m_historical_first = block_height;
    if (block_height > m_best_seen_height) m_best_seen_height = block_height;
    m_historical_best = block_height;

    for (const auto& h : confirmed_txhashes) {
        processBlockTxLocked(block_height, h);
    }

    decayStats(m_short);
    decayStats(m_med);
    decayStats(m_long);
    agingUnconfirmed(m_short);
    agingUnconfirmed(m_med);
    agingUnconfirmed(m_long);
}

void CBlockPolicyEstimator::removeTx(const uint256& txhash, bool in_block) {
    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_tracked.find(txhash);
    if (it == m_tracked.end()) return;

    const unsigned int bucket_index = it->second.bucket_index;
    if (!in_block) {
        // Decrement unconfirmed-ring counts for all horizons -- BC's
        // removeTx(inBlock=false) treats the tx as "evicted, not confirmed":
        // it goes neither in conf_avg nor fail_avg.
        auto strip = [&](TxConfirmStats& stats) {
            for (auto& row : stats.unconf_txs) {
                if (bucket_index < row.size() && row[bucket_index] > 0) {
                    row[bucket_index] -= 1;
                    return;
                }
            }
            if (bucket_index < stats.old_unconf_txs.size() &&
                stats.old_unconf_txs[bucket_index] > 0) {
                stats.old_unconf_txs[bucket_index] -= 1;
            }
        };
        if (it->second.horizon_mask & 0x01) strip(m_short);
        if (it->second.horizon_mask & 0x02) strip(m_med);
        if (it->second.horizon_mask & 0x04) strip(m_long);
    }
    m_tracked.erase(it);
}

long double CBlockPolicyEstimator::estimateMedianFee(
        const TxConfirmStats& stats,
        unsigned int target_blocks,
        double success_threshold) const {
    if (target_blocks == 0) return -1.0L;
    if (stats.conf_avg.empty()) return -1.0L;
    if (target_blocks > stats.conf_avg.size())
        target_blocks = static_cast<unsigned int>(stats.conf_avg.size());

    const unsigned int row = target_blocks - 1;

    // Walk buckets from highest feerate down. Find the lowest feerate
    // bucket whose confirm-success rate within target_blocks meets the
    // threshold. BC's algorithm has more sophistication (confidence
    // intervals, multi-bucket smoothing); for PR-EF-1 we ship a faithful
    // BUT simpler "first bucket meeting threshold" estimator. PR-EF-2 can
    // upgrade to BC's full algorithm once mempool wiring lands.
    if (row >= stats.conf_avg.size()) return -1.0L;
    const auto& confs  = stats.conf_avg[row];
    const auto& tx_cts = stats.tx_ct_avg;

    // Aggregate from highest bucket down. We're looking for the lowest-
    // feerate bucket where the cumulative confirm rate >= threshold.
    long double total_cts   = 0.0L;
    long double total_confs = 0.0L;
    long double last_good_feerate = -1.0L;

    for (size_t b = m_buckets.size(); b-- > 0;) {
        if (b >= confs.size() || b >= tx_cts.size()) continue;
        total_cts   += tx_cts[b];
        total_confs += confs[b];
        // Need at least a small base of observations before declaring an
        // estimate -- otherwise a bucket with 0.5 confirms / 0.5 admits
        // would always beat the threshold trivially.
        constexpr long double MIN_BUCKET_OBSERVATIONS = 0.5L;
        if (total_cts < MIN_BUCKET_OBSERVATIONS) continue;
        const long double rate = total_confs / total_cts;
        if (rate >= static_cast<long double>(success_threshold)) {
            // This bucket (and all lower ones we already aggregated) meet
            // the threshold. The "lowest feerate that still satisfies" is
            // the bucket we're currently at; remember it.
            last_good_feerate = m_buckets[b];
        } else {
            // Aggregating lower-feerate buckets only DECREASES the success
            // rate. We can stop here.
            break;
        }
    }

    return last_good_feerate;
}

EstimationResult CBlockPolicyEstimator::estimateRawFee(
        unsigned int target_blocks,
        double success_threshold,
        EstimateHorizon horizon) const {
    EstimationResult out;
    out.target_blocks = target_blocks;

    std::lock_guard<std::mutex> lk(m_mutex);

    // PR-EF-1-FIX Finding F1: off-by-one. Number of observed blocks is
    // (best - first + 1), not (best - first). With heights 1..25 observed
    // (count = 25), pre-fix `25 - 1 = 24 < 25` → still accumulating. The
    // gate would only release after 26 blocks, contradicting the contract
    // C3 claim "Estimator returns null until enough data accumulated
    // (~25 blocks)" and the docstring "Below this many blocks of
    // accumulation, the estimator must report 'insufficient data'."
    // Use getBlocksObserved() which already includes the +1 correctly.
    if (m_historical_best == 0 ||
        getBlocksObservedLocked() < ACCUMULATION_BLOCKS_MIN) {
        out.error = "insufficient data: estimator still in accumulation window "
                    "(observed " + std::to_string(getBlocksObservedLocked()) +
                    " blocks, need >= " +
                    std::to_string(ACCUMULATION_BLOCKS_MIN) + ")";
        return out;
    }

    const TxConfirmStats* stats = nullptr;
    switch (horizon) {
        case EstimateHorizon::SHORT_HALFLIFE: stats = &m_short; break;
        case EstimateHorizon::MED_HALFLIFE:   stats = &m_med;   break;
        case EstimateHorizon::LONG_HALFLIFE:  stats = &m_long;  break;
    }
    if (stats == nullptr) {
        out.error = "invalid horizon";
        return out;
    }

    out.feerate = estimateMedianFee(*stats, target_blocks, success_threshold);
    if (out.feerate < 0.0L) {
        out.error = "no bucket met success_threshold for target";
    }
    return out;
}

EstimationResult CBlockPolicyEstimator::estimateSmartFee(
        unsigned int target_blocks,
        EstimateMode mode) const {
    const double threshold = (mode == EstimateMode::CONSERVATIVE)
                                ? SUCCESS_PCT_CONSERVATIVE
                                : SUCCESS_PCT_ECONOMICAL;

    // Try short first, then medium, then long, picking the highest
    // estimate (CONSERVATIVE) or first-good (ECONOMICAL). This mirrors
    // BC's progressive horizon fallback.
    auto r_short = estimateRawFee(target_blocks, threshold,
                                  EstimateHorizon::SHORT_HALFLIFE);
    auto r_med   = estimateRawFee(target_blocks, threshold,
                                  EstimateHorizon::MED_HALFLIFE);
    auto r_long  = estimateRawFee(target_blocks, threshold,
                                  EstimateHorizon::LONG_HALFLIFE);

    EstimationResult best;
    best.target_blocks = target_blocks;
    best.feerate = -1.0L;

    auto consider = [&](const EstimationResult& r) {
        if (r.feerate <= 0.0L) return;
        if (mode == EstimateMode::CONSERVATIVE) {
            if (r.feerate > best.feerate) best.feerate = r.feerate;
        } else {
            if (best.feerate < 0.0L || r.feerate < best.feerate) {
                best.feerate = r.feerate;
            }
        }
    };
    consider(r_short);
    consider(r_med);
    consider(r_long);

    if (best.feerate < 0.0L) {
        // Coalesce the three error messages so the RPC layer can surface
        // the most informative one.
        if (!r_short.error.empty()) best.error = r_short.error;
        else if (!r_med.error.empty()) best.error = r_med.error;
        else if (!r_long.error.empty()) best.error = r_long.error;
        else best.error = "no estimate available";
    }
    return best;
}

unsigned int CBlockPolicyEstimator::getBestSeenHeight() const {
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_best_seen_height;
}

unsigned int CBlockPolicyEstimator::getBlocksObserved() const {
    std::lock_guard<std::mutex> lk(m_mutex);
    return getBlocksObservedLocked();
}

// Caller must hold m_mutex.
unsigned int CBlockPolicyEstimator::getBlocksObservedLocked() const {
    if (m_historical_best == 0) return 0;
    return m_historical_best - m_historical_first + 1;
}

std::vector<long double> CBlockPolicyEstimator::getBuckets() const {
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_buckets;
}

size_t CBlockPolicyEstimator::getTrackedTxCount() const {
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_tracked.size();
}

CBlockPolicyEstimator::Snapshot CBlockPolicyEstimator::snapshot() const {
    std::lock_guard<std::mutex> lk(m_mutex);
    Snapshot s;
    s.best_seen_height = m_best_seen_height;
    s.historical_first = m_historical_first;
    s.historical_best  = m_historical_best;
    s.buckets          = m_buckets;
    s.short_stats      = m_short;
    s.med_stats        = m_med;
    s.long_stats       = m_long;
    s.tracked_txs.reserve(m_tracked.size());
    for (const auto& [k, v] : m_tracked) {
        Snapshot::Tracked t{v.height, v.bucket_index, v.horizon_mask};
        s.tracked_txs.emplace_back(k, t);
    }
    return s;
}

bool CBlockPolicyEstimator::restore(Snapshot s) {
    std::lock_guard<std::mutex> lk(m_mutex);

    // Sanity-check the bucket ladder matches our compiled-in constants.
    // If it doesn't, a future code change has changed the bucket schema
    // and we must cold-start.
    if (s.buckets.size() != m_buckets.size()) return false;
    for (size_t i = 0; i < m_buckets.size(); ++i) {
        // The bucket ladder is constructed deterministically from compiled-in
        // constants. We allow a 1e-3 RELATIVE tolerance to absorb the loss-y
        // round-trip from on-disk Q-encoded bucket boundaries (BUCKET_SCALE
        // gives ~6 decimal digits of precision per bucket value); this is
        // far below the inter-bucket spacing of 5%, so a corrupted or
        // schema-mismatched ladder is still detected.
        const long double a = m_buckets[i];
        const long double b = s.buckets[i];
        const long double diff_ld = (a > b) ? (a - b) : (b - a);
        const long double abs_a   = (a < 0.0L) ? -a : a;
        const long double tol     = abs_a * 1e-3L + 1e-6L;
        if (diff_ld > tol) return false;
    }

    // Sanity-check stats shape.
    auto stats_shape_ok = [](const TxConfirmStats& s,
                             unsigned int periods, size_t bucket_count) {
        if (s.conf_avg.size() != periods)  return false;
        if (s.fail_avg.size() != periods)  return false;
        if (s.tx_ct_avg.size() != bucket_count) return false;
        for (const auto& row : s.conf_avg)
            if (row.size() != bucket_count) return false;
        for (const auto& row : s.fail_avg)
            if (row.size() != bucket_count) return false;
        return true;
    };
    if (!stats_shape_ok(s.short_stats, SHORT_BLOCK_PERIODS, m_buckets.size()))
        return false;
    if (!stats_shape_ok(s.med_stats,   MED_BLOCK_PERIODS,   m_buckets.size()))
        return false;
    if (!stats_shape_ok(s.long_stats,  LONG_BLOCK_PERIODS,  m_buckets.size()))
        return false;

    m_best_seen_height = s.best_seen_height;
    m_historical_first = s.historical_first;
    m_historical_best  = s.historical_best;
    m_short            = std::move(s.short_stats);
    m_med              = std::move(s.med_stats);
    m_long             = std::move(s.long_stats);

    // Restore decay/scale -- the constants in the file might disagree with
    // our compiled-in values (across upgrades); we trust the in-memory
    // constants and overwrite the snapshot's.
    m_short.decay = SHORT_DECAY; m_short.scale = SHORT_SCALE;
    m_med.decay   = MED_DECAY;   m_med.scale   = MED_SCALE;
    m_long.decay  = LONG_DECAY;  m_long.scale  = LONG_SCALE;

    m_tracked.clear();
    for (const auto& [k, t] : s.tracked_txs) {
        TrackedTx tt{t.height, t.bucket_index, t.horizon_mask};
        m_tracked[k] = tt;
    }
    return true;
}

}  // namespace fee_estimator
}  // namespace policy
