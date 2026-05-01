// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_UNDO_DATA_H
#define DILITHION_NODE_UNDO_DATA_H

#include <primitives/transaction.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

/**
 * Block undo data -- Dilithion-native types.
 *
 * --- Bitcoin Core port note ----------------------------------------------
 *
 * Bitcoin Core organises undo data per-tx as `CBlockUndo { vtxundo: vector<
 * CTxUndo> }` where `CTxUndo` holds `vprevout: vector<Coin>`. The grouping
 * preserves which `Coin` was spent by which transaction in the block.
 *
 * Dilithion's existing on-disk format (written by `CUTXOSet::ApplyBlock` and
 * read by `CUTXOSet::UndoBlock`) does NOT preserve per-tx grouping. The
 * writer iterates txs in order and serialises every spent input into one
 * flat list:
 *
 *     count : uint32_t        (number of spent inputs across the whole block)
 *     for each spent input:
 *         hash         : 32 bytes        (prevout txid)
 *         n            : uint32_t        (prevout index)
 *         nValue       : uint64_t        (spent value, in ions)
 *         script_len   : uint32_t        (scriptPubKey length)
 *         scriptPubKey : script_len bytes
 *         nHeight      : uint32_t        (height when the spent UTXO was created)
 *         fCoinBase    : uint8_t         (1 if the spent UTXO was a coinbase output)
 *     sha3_checksum : 32 bytes           (SHA3-256 of all preceding bytes)
 *
 * This means a `CBlockUndo` returned from disk is a flat list, not a list of
 * lists. The order matches the writer's iteration order (txs in vtx order,
 * inputs in vin order, coinbase skipped). For the consumers this read
 * accessor was added for (per-block fee aggregation, UTXO-set statistics
 * indexing), the flat layout is sufficient -- aggregate metrics do not care
 * which tx a spent input belonged to.
 *
 * If a future port (e.g. a full BC-style fee-distribution-by-tx breakdown)
 * needs per-tx grouping, the writer in `ApplyBlock` will need an additional
 * boundary marker; this is out of scope for the read accessor.
 *
 * --- Concurrency ---------------------------------------------------------
 *
 * `CBlockUndo` is a plain value type. Reads from disk are serialised by the
 * `CUTXOSet` mutex; the returned object is owned by the caller.
 * -------------------------------------------------------------------------
 */

/**
 * One spent input restored from a block's undo data.
 *
 * Mirrors the inner record written in `CUTXOSet::ApplyBlock`. Equivalent in
 * spirit to BC's `Coin` (the previous-output payload that the input spent),
 * with the addition of the outpoint identifier so a reader can reconstruct
 * which UTXO was consumed without consulting the block's tx body.
 */
struct CSpentInput {
    COutPoint outpoint;                  // prevout that was spent
    CTxOut    out;                       // spent UTXO payload (value + scriptPubKey)
    uint32_t  nHeight;                   // height where the spent UTXO was created
    bool      fCoinBase;                 // true if the spent UTXO was a coinbase output

    CSpentInput() : nHeight(0), fCoinBase(false) {}
    CSpentInput(const COutPoint& op, const CTxOut& o, uint32_t h, bool cb)
        : outpoint(op), out(o), nHeight(h), fCoinBase(cb) {}
};

/**
 * All spent inputs for one block, flat list.
 *
 * See the file-level docblock for the layout rationale and the deviation
 * from Bitcoin Core's per-tx-grouped CBlockUndo.
 */
struct CBlockUndo {
    std::vector<CSpentInput> vSpent;     // all spent inputs in writer order

    bool empty() const { return vSpent.empty(); }
    size_t size() const { return vSpent.size(); }

    void Clear() { vSpent.clear(); }
};

#endif // DILITHION_NODE_UNDO_DATA_H
