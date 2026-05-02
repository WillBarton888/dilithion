// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_POLICY_FEES_H
#define DILITHION_POLICY_FEES_H

// Adaptive fee estimator -- port of Bitcoin Core v28.0
// `src/policy/fees.{h,cpp}` (CBlockPolicyEstimator). PR-EF-1: estimator core
// + persistence module ONLY. Mempool/chainstate hooks land in PR-EF-2; RPC
// handlers land in PR-EF-3.
//
// Algorithm overview (verbatim port from Bitcoin Core):
//   - On every successful mempool admit, the estimator records the entry
//     height + feerate of the tx (processTx).
//   - On every block connect, for each tx that confirmed in this block, we
//     record the number of blocks elapsed since admit (processBlockTx) into
//     a per-bucket-per-confirmation-target histogram.
//   - Three independent stat collections track different time horizons:
//       short  -- 12 buckets of confirmation-period weight, decay 0.962
//       medium -- 24 buckets, decay 0.9952
//       long   -- 42 buckets, decay 0.99931
//   - Each collection has its own decay parameter so a sudden spike in fees
//     dominates the short-horizon estimate first; slow-moving averages
//     dominate the long-horizon estimate.
//   - estimateRawFee(target, threshold, horizon) returns the lowest feerate
//     bucket whose historical confirmation rate within `target` blocks
//     exceeds `threshold` (0.85 by default; 0.95 for CONSERVATIVE mode).
//   - estimateSmartFee combines all three horizons + falls back to longer
//     horizons when the requested horizon lacks data.
//
// CAmount adaptation:
//   Bitcoin Core uses CFeeRate(sat/kvB). Dilithion uses CAmount (ions, where
//   1 DIL = 1e8 ions). We model feerate as CAmount-per-1000-bytes (a `long
//   double` internally for buckets, since we multiply / divide constantly).
//   The bucket constants (MIN/MAX_BUCKET_FEERATE, FEE_SPACING) are pinned to
//   Bitcoin Core's values; this is intentional. Dilithion's smallest-unit
//   semantics match Bitcoin's at the ion/satoshi level (both 1e-8 of base
//   coin), so the fee-discovery dynamic range is the same and porting the
//   constants verbatim is the correct call.
//
// Concurrency:
//   All public methods acquire m_mutex on entry and hold it for the entire
//   call body. processBlock in particular holds the lock continuously
//   across the height-update + per-tx-confirm + decay+age phases (see
//   processBlockTxLocked); a concurrent snapshot()/DumpFeeEstimates
//   between phases would otherwise persist internally inconsistent state.
//   The estimator's working set is small (~1 MB even at maximum bucket
//   count) so coarse locking is adequate; we follow Bitcoin Core's
//   pattern of a single estimator-wide lock rather than per-collection
//   locks. Default seq_cst ordering on the atomics.
//   (PR-EF-1-FIX Finding F2 corrected the previous claim that "coarse
//   locking suffices" without surfacing the lock-release-reacquire
//   between phases.)

#include <amount.h>
#include <uint256.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

class CTransaction;

namespace policy {
namespace fee_estimator {

// ---------------------------------------------------------------------------
// Bucket constants -- pinned to Bitcoin Core v28.0 src/policy/fees.cpp.
// Do not adjust without bumping FEE_ESTIMATES_FILE_VERSION below.
// ---------------------------------------------------------------------------

// Minimum bucket feerate (ions per 1000 bytes). BC: MIN_BUCKET_FEERATE = 1000.
constexpr long double MIN_BUCKET_FEERATE = 1000.0L;

// Maximum bucket feerate (ions per 1000 bytes). BC: MAX_BUCKET_FEERATE = 1e7.
constexpr long double MAX_BUCKET_FEERATE = 1e7L;

// Bucket spacing factor: each bucket is FEE_SPACING * previous bucket.
// BC: FEE_SPACING = 1.05 (5% increments).
constexpr long double FEE_SPACING = 1.05L;

// "Infinite" feerate sentinel for the top-of-ladder bucket. BC: INF_FEERATE.
// Set to MAX_MONEY (21M DIL in ions) so any conceivable real feerate falls
// below it.
constexpr long double INF_FEERATE = static_cast<long double>(MAX_MONEY);

// Confirmation-target horizons (blocks). BC: src/policy/fees.h.
//   short  -- 1..2 hour estimates (typical wallet send)
//   medium -- 2..24 hour estimates (default RPC target)
//   long   -- multi-day estimates (cold-storage sweeps)
constexpr unsigned int SHORT_BLOCK_PERIODS = 12;
constexpr unsigned int MED_BLOCK_PERIODS   = 24;
constexpr unsigned int LONG_BLOCK_PERIODS  = 42;

// Decay parameter per horizon. Each block, every bucket's confirmation
// counter is multiplied by the decay; older confirmations weigh less.
//   - short:  0.962    -- recent ~25-block window dominates
//   - medium: 0.9952   -- recent ~200-block window dominates
//   - long:   0.99931  -- recent ~1500-block window dominates
constexpr long double SHORT_DECAY = 0.962L;
constexpr long double MED_DECAY   = 0.9952L;
constexpr long double LONG_DECAY  = 0.99931L;

// "Half-life" for the rolling block windows. BC: SHORT_SCALE = 1, MED_SCALE = 2,
// LONG_SCALE = 24. Decimates how many entries are kept per bucket.
constexpr unsigned int SHORT_SCALE = 1;
constexpr unsigned int MED_SCALE   = 2;
constexpr unsigned int LONG_SCALE  = 24;

// Confidence success threshold per estimate mode (matches BC v28.0).
//   ECONOMICAL: 0.60  (faster confirms but more variance)
//   CONSERVATIVE: 0.85 default RPC threshold; aim for 85% confirm success
constexpr double SUCCESS_PCT_ECONOMICAL   = 0.60;
constexpr double SUCCESS_PCT_CONSERVATIVE = 0.85;

// Number of blocks observed before any estimate is returned. Below this
// many blocks of accumulation, the estimator must report
// "insufficient data" (BC behavior; matches the C3 acceptance criterion).
constexpr unsigned int ACCUMULATION_BLOCKS_MIN = 25;

// File-format version for fee_estimates.dat. Bump on any wire-format
// change; LoadFeeEstimates returns cold-start on mismatch.
//
// (PR-EF-1-FIX Finding F8: dead constant MAX_CONFIRM_TRACK removed.
// Per-horizon confirmation tracking is bounded by the SHORT/MED/LONG
// _BLOCK_PERIODS constants and the per-horizon scale; no need for a
// global cap that nothing referenced.)
constexpr uint8_t FEE_ESTIMATES_FILE_VERSION = 0x01;

// Estimate mode -- matches Bitcoin Core's FeeEstimateMode enum (only
// CONSERVATIVE / ECONOMICAL are implemented; UNSET maps to default).
enum class EstimateMode : uint8_t {
    UNSET        = 0,
    ECONOMICAL   = 1,
    CONSERVATIVE = 2,
};

// Estimate horizon -- which of the three internal stat collections to consult.
enum class EstimateHorizon : uint8_t {
    SHORT_HALFLIFE = 0,  // 12-block window
    MED_HALFLIFE   = 1,  // 24-block window
    LONG_HALFLIFE  = 2,  // 42-block window
};

// Per-bucket per-confirmation-target counters used internally.
//
// Bitcoin Core's TxConfirmStats keeps three parallel arrays:
//   - confAvg[target][bucket]  -- decayed count of txs in this bucket that
//                                  confirmed within `target` blocks
//   - failAvg[target][bucket]  -- decayed count that did NOT confirm in
//                                  `target` blocks (aged out)
//   - txCtAvg[bucket]          -- decayed count of txs entering this bucket
//
// All three decay every block. We mirror the same shape; bucket index is
// the upper-bound bucket ladder index (see ConstructBuckets).
struct TxConfirmStats {
    // confAvg[d][b] = fraction of bucket-b txs that confirmed within d+1 blocks
    std::vector<std::vector<long double>> conf_avg;
    // failAvg[d][b] = fraction that did NOT confirm in d+1 blocks
    std::vector<std::vector<long double>> fail_avg;
    // txCtAvg[b] = decayed count of txs that entered bucket b
    std::vector<long double> tx_ct_avg;
    // unconfTxs[blocks_in_pool][bucket] -- ring buffer of unconfirmed txs
    // indexed by their age-in-pool. When a tx's age exceeds the buffer's
    // depth, it counts as a failure.
    std::vector<std::vector<int>> unconf_txs;
    // oldUnconfTxs[bucket] -- aged-out unconfirmed counts
    std::vector<int> old_unconf_txs;
    // Decay parameter for this stats collection.
    long double decay = 0.0L;
    // Scale (window) for this stats collection.
    unsigned int scale = 1;
};

// Public-facing estimate result. `feerate` is in ions per 1000 bytes; if
// `feerate` is negative, the estimator did not have enough data. Errors
// is non-empty when the caller should surface a textual diagnostic.
struct EstimationResult {
    // Bucket-aligned feerate -- ions per 1000 bytes. -1 = no estimate.
    long double feerate = -1.0L;
    // The number of blocks the estimate is valid for.
    unsigned int target_blocks = 0;
    // Per-target diagnostic; populated by estimateRawFee.
    std::string error;
};

// ---------------------------------------------------------------------------
// CBlockPolicyEstimator
// ---------------------------------------------------------------------------

class CBlockPolicyEstimator {
public:
    CBlockPolicyEstimator();
    ~CBlockPolicyEstimator();

    CBlockPolicyEstimator(const CBlockPolicyEstimator&)            = delete;
    CBlockPolicyEstimator& operator=(const CBlockPolicyEstimator&) = delete;

    // -- Observation surface -----------------------------------------------
    //
    // processTx -- record an admitted-to-mempool tx. Called by PR-EF-2 from
    // CTxMemPool::AddTx. validFeeEstimate==false means "this tx came in via
    // a special path (block, bypass) and should NOT influence the estimator"
    // -- mirrors BC's `validFeeEstimate` flag.
    void processTx(const uint256& txhash,
                   unsigned int height,
                   CAmount fee,
                   size_t vsize,
                   bool valid_fee_estimate);

    // processBlockTx -- record a tx confirming in a block. age_in_pool is the
    // # of blocks since processTx was called for this txhash.
    // Returns true if the tx was tracked by the estimator (else it's a tx
    // we didn't see admitted, e.g. came in via a private relay).
    bool processBlockTx(unsigned int block_height, const uint256& txhash);

    // processBlock -- aging tick. Called once per block-connect from
    // PR-EF-2. Walks each stats collection and decays counters; ages out
    // unconfirmed-tx ring buffer slots.
    void processBlock(unsigned int block_height,
                      const std::vector<uint256>& confirmed_txhashes);

    // removeTx -- called when a tx is removed from the mempool BEFORE it
    // confirmed (eviction, replacement, expiration). Drops the tx from
    // the unconfirmed ring buffers without updating fail counters --
    // mirroring BC behavior.
    void removeTx(const uint256& txhash, bool in_block);

    // -- Estimate surface --------------------------------------------------
    //
    // estimateRawFee -- raw histogram lookup. Returns the lowest feerate
    // bucket whose historical confirm rate within `target` exceeds
    // `success_threshold` (e.g. 0.85). If no bucket satisfies, feerate=-1.
    EstimationResult estimateRawFee(unsigned int target_blocks,
                                    double success_threshold,
                                    EstimateHorizon horizon) const;

    // estimateSmartFee -- combines the three horizons. PR-EF-3's
    // `estimatesmartfee` RPC calls this. mode selects success threshold.
    EstimationResult estimateSmartFee(unsigned int target_blocks,
                                      EstimateMode mode) const;

    // -- Diagnostic -----------------------------------------------------
    //
    // Get the highest block height ever observed.
    unsigned int getBestSeenHeight() const;

    // Get the count of blocks observed since startup. Below
    // ACCUMULATION_BLOCKS_MIN, no estimate is returned.
    unsigned int getBlocksObserved() const;

    // Bucket ladder accessor (for tests + persistence).
    std::vector<long double> getBuckets() const;

    // Tracked-tx count. Used by tests and the savefeeestimates RPC.
    size_t getTrackedTxCount() const;

    // -- Persistence helpers --------------------------------------------
    //
    // Below: serialization-friendly snapshots of internal state. The
    // fee_persist module uses these (rather than friend-access) to dump
    // and restore the estimator. All snapshots are taken under the
    // estimator's internal mutex; the returned values are by-value copies.

    struct Snapshot {
        unsigned int                              best_seen_height = 0;
        unsigned int                              historical_first = 0;
        unsigned int                              historical_best  = 0;
        std::vector<long double>                  buckets;
        TxConfirmStats                            short_stats;
        TxConfirmStats                            med_stats;
        TxConfirmStats                            long_stats;
        // Tracked txs: txhash -> (height_admitted, bucket_index, horizon_mask).
        // horizon_mask: bit0=short, bit1=medium, bit2=long.
        struct Tracked {
            unsigned int height;
            unsigned int bucket_index;
            uint8_t      horizon_mask;
        };
        std::vector<std::pair<uint256, Tracked>>  tracked_txs;
    };

    Snapshot snapshot() const;

    // Restore from a snapshot. Returns false on internal-shape mismatch
    // (caller should treat as cold-start).
    bool restore(Snapshot s);

private:
    // Caller must hold m_mutex. Body of processBlockTx, extracted so
    // processBlock can call it without releasing/reacquiring the lock.
    // PR-EF-1-FIX Finding F2.
    bool processBlockTxLocked(unsigned int block_height, const uint256& txhash);

    // Caller must hold m_mutex. Body of getBlocksObserved, extracted so
    // estimateRawFee's accumulation gate can use it without nested
    // locking. Returns 0 when no blocks have been observed; otherwise
    // (m_historical_best - m_historical_first + 1) -- the +1 closes
    // PR-EF-1-FIX Finding F1's off-by-one.
    unsigned int getBlocksObservedLocked() const;

    mutable std::mutex m_mutex;

    // Bucket ladder: bucket[i] is the upper bound (ions/kB) of feerate
    // bucket i. bucket[0] = MIN_BUCKET_FEERATE; bucket[N-1] = INF_FEERATE.
    std::vector<long double> m_buckets;

    // bucketMap: feerate -> bucket-index. Exact-match-or-lower-bound
    // lookup; saves doing a binary search on every observation.
    std::map<long double, unsigned int> m_bucket_map;

    // Three stat collections (one per horizon).
    TxConfirmStats m_short;
    TxConfirmStats m_med;
    TxConfirmStats m_long;

    // Currently tracked unconfirmed txs. Maps txhash to (height_admitted,
    // bucket_index, horizon_mask). The horizon mask says which of the
    // three stat collections this tx is currently being tracked by.
    struct TrackedTx {
        unsigned int height;
        unsigned int bucket_index;
        uint8_t      horizon_mask;  // bit0=short, bit1=medium, bit2=long
    };
    std::map<uint256, TrackedTx> m_tracked;

    // The highest block height we've observed (anti-replay during
    // restore-from-disk: don't replay ages that have already passed).
    unsigned int m_best_seen_height = 0;
    unsigned int m_historical_first = 0;  // first block we observed
    unsigned int m_historical_best  = 0;  // last block we observed

    // Construct the bucket ladder from MIN_BUCKET_FEERATE to MAX_BUCKET_FEERATE
    // by FEE_SPACING; append INF_FEERATE.
    void initBuckets();

    // Lazy-init the three stats collections based on current bucket ladder.
    void initStats();

    // Helpers used by both observe and decay paths.
    unsigned int findBucket(long double feerate) const;
    void recordBlockTx(TxConfirmStats& stats,
                       unsigned int blocks_to_confirm,
                       unsigned int bucket_index);
    void recordTxAdmit(TxConfirmStats& stats, unsigned int bucket_index);
    void decayStats(TxConfirmStats& stats);
    void agingUnconfirmed(TxConfirmStats& stats);

    // Estimate within a single horizon. Returns -1 if the bucket histogram
    // has insufficient data.
    long double estimateMedianFee(const TxConfirmStats& stats,
                                  unsigned int target_blocks,
                                  double success_threshold) const;
};

// Smart pointer for shared use; mirrors BC's `std::unique_ptr<CBlockPolicyEstimator>`.
using EstimatorPtr = std::shared_ptr<CBlockPolicyEstimator>;

}  // namespace fee_estimator
}  // namespace policy

// Process-wide fee estimator handle. Mirrors `g_tx_index` ownership pattern.
// Set by node startup (PR-EF-2) when -feeestimates=1 (default), cleared on
// shutdown. Mempool admit hook (CTxMemPool::AddTxUnlocked) and chainstate
// connect callback both load() this pointer; if null, the estimator is
// disabled (operator passed -feeestimates=0). Null-safe to read at any time.
//
// Owned externally (typically by main()'s NodeContext). Not thread-safe to
// reassign during operation; intended set-once-at-startup semantics. Reads
// are plain pointer loads -- shutdown ordering guarantees no concurrent
// reader after the owner has nulled this pointer.
extern policy::fee_estimator::CBlockPolicyEstimator* g_fee_estimator;

#endif  // DILITHION_POLICY_FEES_H
