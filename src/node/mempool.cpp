// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/mempool.h>
#include <algorithm>

static const size_t DEFAULT_MAX_MEMPOOL_SIZE = 300 * 1024 * 1024;

CTxMemPoolEntry::CTxMemPoolEntry(const CTransactionRef& _tx, CAmount _fee, int64_t _time, unsigned int _height)
    : tx(_tx), fee(_fee), time(_time), height(_height) {
    tx_size = tx->GetSerializedSize();
    fee_rate = Consensus::CalculateFeeRate(fee, tx_size);
}

bool CompareTxMemPoolEntryByFeeRate::operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const {
    if (a.GetFeeRate() != b.GetFeeRate()) return a.GetFeeRate() > b.GetFeeRate();
    if (a.GetTime() != b.GetTime()) return a.GetTime() < b.GetTime();
    return a.GetTxHash() < b.GetTxHash();
}

CTxMemPool::CTxMemPool() : nHeight(0), max_mempool_size(DEFAULT_MAX_MEMPOOL_SIZE), mempool_size(0) {}

bool CTxMemPool::AddTx(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, std::string* error) {
    std::lock_guard<std::mutex> lock(cs);
    if (!tx) { if (error) *error = "Null tx"; return false; }
    const uint256 txid = tx->GetHash();
    if (mapTx.count(txid) > 0) { if (error) *error = "Already in mempool"; return false; }
    std::string fee_error;
    if (!Consensus::CheckFee(*tx, fee, true, &fee_error)) {
        if (error) *error = fee_error;
        return false;
    }
    size_t tx_size = tx->GetSerializedSize();
    if (mempool_size + tx_size > max_mempool_size) { if (error) *error = "Mempool full"; return false; }
    CTxMemPoolEntry entry(tx, fee, time, height);
    mapTx.emplace(txid, entry);
    setEntries.insert(entry);
    mempool_size += tx_size;
    return true;
}

bool CTxMemPool::RemoveTx(const uint256& txid) {
    std::lock_guard<std::mutex> lock(cs);
    auto it = mapTx.find(txid);
    if (it == mapTx.end()) return false;
    setEntries.erase(it->second);
    mempool_size -= it->second.GetTxSize();
    mapTx.erase(it);
    return true;
}

bool CTxMemPool::Exists(const uint256& txid) const {
    std::lock_guard<std::mutex> lock(cs);
    return mapTx.count(txid) > 0;
}

bool CTxMemPool::GetTx(const uint256& txid, CTxMemPoolEntry& entry) const {
    std::lock_guard<std::mutex> lock(cs);
    auto it = mapTx.find(txid);
    if (it == mapTx.end()) return false;
    entry = it->second;
    return true;
}

std::vector<CTransactionRef> CTxMemPool::GetOrderedTxs() const {
    std::lock_guard<std::mutex> lock(cs);
    std::vector<CTransactionRef> result;
    result.reserve(setEntries.size());
    for (const auto& entry : setEntries) result.push_back(entry.GetSharedTx());
    return result;
}

std::vector<CTransactionRef> CTxMemPool::GetTopTxs(size_t n) const {
    std::lock_guard<std::mutex> lock(cs);
    std::vector<CTransactionRef> result;
    result.reserve(std::min(n, setEntries.size()));
    size_t count = 0;
    for (const auto& entry : setEntries) {
        if (count >= n) break;
        result.push_back(entry.GetSharedTx());
        count++;
    }
    return result;
}

void CTxMemPool::Clear() {
    std::lock_guard<std::mutex> lock(cs);
    mapTx.clear();
    setEntries.clear();
    mempool_size = 0;
}

size_t CTxMemPool::Size() const {
    std::lock_guard<std::mutex> lock(cs);
    return mapTx.size();
}

size_t CTxMemPool::GetMempoolSize() const {
    std::lock_guard<std::mutex> lock(cs);
    return mempool_size;
}

void CTxMemPool::GetStats(size_t& size, size_t& bytes, double& min_fee_rate, double& max_fee_rate) const {
    std::lock_guard<std::mutex> lock(cs);
    size = mapTx.size();
    bytes = mempool_size;
    if (setEntries.empty()) {
        min_fee_rate = 0.0;
        max_fee_rate = 0.0;
        return;
    }
    max_fee_rate = setEntries.begin()->GetFeeRate();
    min_fee_rate = setEntries.rbegin()->GetFeeRate();
}

void CTxMemPool::SetHeight(unsigned int height) {
    std::lock_guard<std::mutex> lock(cs);
    nHeight = height;
}

void CTxMemPool::RemoveConfirmedTxs(const std::vector<CTransactionRef>& block_txs) {
    std::lock_guard<std::mutex> lock(cs);
    for (const auto& tx : block_txs) {
        const uint256 txid = tx->GetHash();
        auto it = mapTx.find(txid);
        if (it != mapTx.end()) {
            setEntries.erase(it->second);
            mempool_size -= it->second.GetTxSize();
            mapTx.erase(it);
        }
    }
}
