// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_KERNEL_COINSTATS_H
#define DILITHION_KERNEL_COINSTATS_H

// PR-BA-2: UTXO-set statistics primitives.
//
// Bitcoin Core port: `src/kernel/coinstats.{h,cpp}` (v28.0).
//
// Bitcoin Core offers two algorithms for hashing the UTXO set:
//   - `hash_serialized` (deterministic order-dependent SHA-256 of all coins
//     in their canonical traversal order)
//   - `muhash` (commutative incremental hash; order-invariant)
//
// Dilithion ports `hash_serialized` only (KISS), with **SHA-3 substituted
// for SHA-256** per the project-wide post-quantum hash convention. The hash
// is computed by the BLOCK-DELTA method: starting from the parent block's
// hash, we incrementally fold in the per-coin records added or removed by
// the block. The fold is implemented by feeding (parent_hash || delta_record)
// into SHA3-256 and taking the result as the new running hash. This is the
// same pattern as BC's "hash_serialized_3 with block-delta" but specialised
// to a single algorithm.
//
// The order in which coins are folded matters for the final hash value, but
// is fully deterministic given the block's transactions and undo data:
//   - Spent inputs (from `CBlockUndo::vSpent`) are folded first, in the
//     writer's emit order (vin order across vtx, coinbase skipped).
//   - New outputs (from `CBlock` after deserialization) are folded second,
//     in (txid_lex_order, vout_index_ascending) order. This deterministic
//     order is the SAME canonicalisation BC uses for `hash_serialized` so
//     two implementations independently computing the hash agree.
//
// The Dilithion divergence (SHA-3 vs SHA-256) is module-local and fully
// documented; consumers MUST NOT compare hashes across BC and Dilithion.
//
// --- Concurrency --------------------------------------------------------
//
// `CoinStats` is a plain value type. The helper functions below mutate the
// passed-in struct in place and are thread-compatible (re-entrant on
// independent objects). The caller serialises access if the same object
// is shared across threads.

#include <primitives/transaction.h>
#include <node/undo_data.h>
#include <uint256.h>

#include <cstdint>

/**
 * Aggregate UTXO-set statistics at a particular block height.
 *
 * Mirrors BC's `CCoinsStats` shape with the SHA-3 substitution. Tracked per
 * height by `CCoinStatsIndex`.
 */
struct CoinStats {
    /** Hash of the UTXO set after this block was applied. SHA-3 256-bit. */
    uint256 hashSerialized;

    /** Number of coins in the UTXO set after this block was applied. */
    uint64_t coinsCount = 0;

    /** Sum of all output values still in the UTXO set after this block. */
    uint64_t totalAmount = 0;

    /**
     * Per-block delta: number of output additions and prevout-removals
     * processed by this block. Bookkeeping for round-trip / parity tests.
     */
    uint64_t blockAdditions = 0;
    uint64_t blockRemovals  = 0;

    /** Block-local total of new output amounts (coinbase + tx outs). */
    uint64_t blockTotalOut  = 0;
    /** Block-local total of spent prevout amounts. */
    uint64_t blockTotalIn   = 0;

    /**
     * Block subsidy + fees claimed by the coinbase output (block.vtx[0]).
     * Computed during ApplyBlock as the coinbase output total.
     */
    uint64_t blockSubsidyFees = 0;
};

/**
 * Fold one delta record into the running UTXO-set hash.
 *
 * The record is either a spent prevout (REMOVAL) or a new output (ADDITION).
 * Spend tags (uint8_t 0=ADD, 1=REMOVE) are included in the hash payload so
 * an addition record cannot be confused with a removal record bearing the
 * same outpoint+output.
 *
 * @param running_hash  The accumulator. Mutated in place.
 * @param outpoint      The outpoint (txid + vout index) for this coin.
 * @param out           The CTxOut payload (value + scriptPubKey).
 * @param height        Height where the coin was created (for ADD: this
 *                      block; for REMOVE: the height recorded in the undo
 *                      record, i.e. where the spent UTXO was originally
 *                      created).
 * @param fCoinBase     true if this coin was a coinbase output.
 * @param fAddition     true if this is an addition (false = removal).
 */
void CoinStatsFoldRecord(uint256& running_hash,
                         const COutPoint& outpoint,
                         const CTxOut& out,
                         uint32_t height,
                         bool fCoinBase,
                         bool fAddition);

/**
 * Apply a block's adds/removes to a CoinStats running snapshot.
 *
 * Folds removals first (in writer order from the undo data), then additions
 * (in canonical txid-lex order; outputs within a tx in ascending vout
 * order). Updates coinsCount, totalAmount, hashSerialized.
 *
 * @param stats        Mutated in place. On entry, holds the parent-block
 *                     stats. On return, holds the after-this-block stats.
 * @param block        The block being applied.
 * @param undo         The block's CBlockUndo (spent inputs).
 * @param txs          Deserialised transactions of the block (in vtx order).
 *                     Caller is responsible for deserialising via
 *                     CBlockValidator::DeserializeBlockTransactions.
 * @param block_height The height at which this block is being applied.
 *
 * @return true on success; false if the block's coinbase has zero outputs
 *         (malformed) or any other inconsistency is detected. Failure leaves
 *         `stats` in an undefined state (caller should discard and retry).
 */
bool CoinStatsApplyBlock(CoinStats& stats,
                         const CBlock& block,
                         const CBlockUndo& undo,
                         const std::vector<CTransactionRef>& txs,
                         uint32_t block_height);

#endif // DILITHION_KERNEL_COINSTATS_H
