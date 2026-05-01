// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <kernel/coinstats.h>

#include <crypto/sha3.h>

#include <algorithm>
#include <cstring>

namespace {

// Serialise one delta record into a flat byte buffer in a fixed canonical
// layout. The record format (caller-private; not persisted on disk; only
// consumed inside SHA3-256):
//
//   uint8_t   tag             (0=ADD, 1=REMOVE)
//   uint8_t   fCoinBase       (0 or 1)
//   uint32_t  height          little-endian
//   uint32_t  vout_n          little-endian
//   uint8_t[32] outpoint_hash raw
//   uint64_t  nValue          little-endian
//   uint32_t  spk_len         little-endian
//   uint8_t[]  scriptPubKey   raw bytes
//
// The choice of fields and order matches the on-disk undo writer's emit
// (see CUTXOSet::ApplyBlock and node/undo_data.h) so cross-implementation
// agreement is straightforward to verify by reading both sources side by
// side.
std::vector<uint8_t> SerializeRecord(const COutPoint& op,
                                     const CTxOut& out,
                                     uint32_t height,
                                     bool fCoinBase,
                                     bool fAddition) {
    const uint32_t spk_len = static_cast<uint32_t>(out.scriptPubKey.size());
    std::vector<uint8_t> buf;
    buf.reserve(1 + 1 + 4 + 4 + 32 + 8 + 4 + spk_len);

    buf.push_back(fAddition ? 0u : 1u);
    buf.push_back(fCoinBase  ? 1u : 0u);

    auto append_u32 = [&buf](uint32_t v) {
        for (int i = 0; i < 4; ++i) {
            buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
        }
    };
    auto append_u64 = [&buf](uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
        }
    };

    append_u32(height);
    append_u32(op.n);
    buf.insert(buf.end(), op.hash.data, op.hash.data + 32);
    append_u64(out.nValue);
    append_u32(spk_len);
    if (spk_len > 0) {
        buf.insert(buf.end(),
                   out.scriptPubKey.begin(),
                   out.scriptPubKey.end());
    }
    return buf;
}

} // namespace

void CoinStatsFoldRecord(uint256& running_hash,
                         const COutPoint& outpoint,
                         const CTxOut& out,
                         uint32_t height,
                         bool fCoinBase,
                         bool fAddition) {
    // Build payload = previous_hash (32 bytes) || record_bytes.
    const std::vector<uint8_t> record =
        SerializeRecord(outpoint, out, height, fCoinBase, fAddition);

    std::vector<uint8_t> payload;
    payload.reserve(32 + record.size());
    payload.insert(payload.end(), running_hash.data, running_hash.data + 32);
    payload.insert(payload.end(), record.begin(), record.end());

    uint8_t out_hash[32];
    SHA3_256(payload.data(), payload.size(), out_hash);
    std::memcpy(running_hash.data, out_hash, 32);
}

bool CoinStatsApplyBlock(CoinStats& stats,
                         const CBlock& block,
                         const CBlockUndo& undo,
                         const std::vector<CTransactionRef>& txs,
                         uint32_t block_height) {
    if (txs.empty()) {
        // A block must have at least the coinbase tx.
        return false;
    }

    // Reset per-block tallies; preserve cumulative running counters.
    stats.blockAdditions   = 0;
    stats.blockRemovals    = 0;
    stats.blockTotalOut    = 0;
    stats.blockTotalIn     = 0;
    stats.blockSubsidyFees = 0;

    // ---- Removals -----------------------------------------------------
    //
    // Fold the spent inputs in writer order (vin order across vtx, coinbase
    // skipped). The writer's order is the order of CBlockUndo::vSpent --
    // see node/undo_data.h.
    for (const CSpentInput& sp : undo.vSpent) {
        CoinStatsFoldRecord(stats.hashSerialized,
                            sp.outpoint,
                            sp.out,
                            sp.nHeight,
                            sp.fCoinBase,
                            /*fAddition=*/false);
        stats.blockRemovals += 1;
        stats.blockTotalIn  += sp.out.nValue;
        if (stats.coinsCount > 0) {
            stats.coinsCount -= 1;
        }
        if (stats.totalAmount >= sp.out.nValue) {
            stats.totalAmount -= sp.out.nValue;
        } else {
            // Inconsistency: a removal would underflow totalAmount.
            return false;
        }
    }

    // ---- Additions ----------------------------------------------------
    //
    // Fold the new outputs in canonical (txid_lex, vout_index_asc) order.
    // We collect (txid, idx_in_txs) pairs first, sort by txid, then iterate
    // outputs within each tx in order.
    struct TxOrderKey {
        uint256 txid;
        size_t  vtx_index;
    };
    std::vector<TxOrderKey> order;
    order.reserve(txs.size());
    for (size_t i = 0; i < txs.size(); ++i) {
        order.push_back({txs[i]->GetHash(), i});
    }
    std::sort(order.begin(), order.end(),
              [](const TxOrderKey& a, const TxOrderKey& b) {
                  return a.txid < b.txid;
              });

    // Per-tx-fee bookkeeping for blockSubsidyFees: BC reports the coinbase
    // output total as "subsidy + fees claimed". We precompute this by
    // summing the coinbase's vout.nValue. The coinbase is at txs[0] in the
    // canonical block layout.
    {
        const CTransactionRef& coinbase = txs[0];
        for (const CTxOut& o : coinbase->vout) {
            stats.blockSubsidyFees += o.nValue;
        }
    }

    for (const TxOrderKey& key : order) {
        const CTransactionRef& tx = txs[key.vtx_index];
        const bool isCoinBase = (key.vtx_index == 0);
        for (size_t out_idx = 0; out_idx < tx->vout.size(); ++out_idx) {
            const CTxOut& o = tx->vout[out_idx];
            COutPoint op(key.txid, static_cast<uint32_t>(out_idx));

            CoinStatsFoldRecord(stats.hashSerialized,
                                op,
                                o,
                                block_height,
                                isCoinBase,
                                /*fAddition=*/true);
            stats.blockAdditions += 1;
            stats.blockTotalOut  += o.nValue;
            stats.coinsCount     += 1;
            stats.totalAmount    += o.nValue;
        }
    }

    (void)block;   // currently unused; reserved for future header-derived
                   // fields (e.g. cumulative work / chain_total_in).
    return true;
}
