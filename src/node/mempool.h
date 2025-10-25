// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_MEMPOOL_H
#define DILITHION_NODE_MEMPOOL_H

#include <primitives/transaction.h>
#include <consensus/fees.h>
#include <amount.h>
#include <uint256.h>
#include <map>
#include <set>
#include <vector>
#include <memory>
#include <mutex>

class CTxMemPoolEntry {
private:
    CTransactionRef tx;
    CAmount fee;
    size_t tx_size;
    double fee_rate;
    int64_t time;
    unsigned int height;
public:
    CTxMemPoolEntry(const CTransactionRef& _tx, CAmount _fee, int64_t _time, unsigned int _height);
    const CTransaction& GetTx() const { return *tx; }
    CTransactionRef GetSharedTx() const { return tx; }
    const uint256& GetTxHash() const { return tx->GetHash(); }
    CAmount GetFee() const { return fee; }
    size_t GetTxSize() const { return tx_size; }
    double GetFeeRate() const { return fee_rate; }
    int64_t GetTime() const { return time; }
    unsigned int GetHeight() const { return height; }
};

struct CompareTxMemPoolEntryByFeeRate {
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const;
};

class CTxMemPool {
private:
    mutable std::mutex cs;
    std::map<uint256, CTxMemPoolEntry> mapTx;
    std::set<CTxMemPoolEntry, CompareTxMemPoolEntryByFeeRate> setEntries;
    unsigned int nHeight;
    size_t max_mempool_size;
    size_t mempool_size;
public:
    CTxMemPool();
    bool AddTx(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, std::string* error = nullptr);
    bool RemoveTx(const uint256& txid);
    bool Exists(const uint256& txid) const;
    bool GetTx(const uint256& txid, CTxMemPoolEntry& entry) const;
    std::vector<CTransactionRef> GetOrderedTxs() const;
    std::vector<CTransactionRef> GetTopTxs(size_t n) const;
    void Clear();
    size_t Size() const;
    size_t GetMempoolSize() const;
    void GetStats(size_t& size, size_t& bytes, double& min_fee_rate, double& max_fee_rate) const;
    void SetHeight(unsigned int height);
    void RemoveConfirmedTxs(const std::vector<CTransactionRef>& block_txs);
};

#endif
