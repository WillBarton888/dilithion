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
#include <thread>
#include <atomic>
#include <condition_variable>
#include <optional>

class CTxMemPoolEntry {
private:
    CTransactionRef tx;
    uint256 tx_hash;  // Cached transaction hash
    CAmount fee;
    size_t tx_size;
    double fee_rate;
    int64_t time;
    unsigned int height;
public:
    CTxMemPoolEntry(const CTransactionRef& _tx, CAmount _fee, int64_t _time, unsigned int _height);
    const CTransaction& GetTx() const { return *tx; }
    CTransactionRef GetSharedTx() const { return tx; }
    const uint256& GetTxHash() const { return tx_hash; }
    CAmount GetFee() const { return fee; }
    size_t GetTxSize() const { return tx_size; }
    double GetFeeRate() const { return fee_rate; }
    int64_t GetTime() const { return time; }
    unsigned int GetHeight() const { return height; }
};

// MEMPOOL-017 FIX: Pointer-based comparator for memory optimization
// Allows setEntries to store pointers instead of copies, reducing memory usage by 50%
struct CompareTxMemPoolEntryByFeeRate {
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const;
    bool operator()(const CTxMemPoolEntry* a, const CTxMemPoolEntry* b) const;
};

// MEMPOOL-009 FIX: Forward declaration for exception safety guard
class MempoolInsertionGuard;

class CTxMemPool {
private:
    // MEMPOOL-009 FIX: Grant friend access to RAII guard for rollback operations
    friend class MempoolInsertionGuard;
    mutable std::mutex cs;
    std::map<uint256, CTxMemPoolEntry> mapTx;
    // MEMPOOL-017 FIX: Store pointers instead of copies to reduce memory usage by 50%
    // std::map provides pointer stability in C++11+, so pointers remain valid until element erased
    std::set<const CTxMemPoolEntry*, CompareTxMemPoolEntryByFeeRate> setEntries;
    std::set<COutPoint> mapSpentOutpoints;  // VULN-007 FIX: Track spent outpoints to detect double-spends

    // MEMPOOL-002 FIX: Descendant tracking to prevent orphaning child transactions during eviction
    // Maps transaction hash → set of transaction hashes that spend its outputs (children)
    // This ensures we never evict a transaction that has descendants in the mempool
    std::map<uint256, std::set<uint256>> mapDescendants;

    unsigned int nHeight;

    // MEMPOOL-001 FIX: Add transaction count limit to prevent DoS
    // Without count limit, attacker can fill mempool with 1.2M minimum-size transactions
    // causing excessive std::map/std::set overhead (160 bytes per transaction = 192MB overhead)
    // and severe O(n) performance degradation
    static const size_t DEFAULT_MAX_MEMPOOL_COUNT = 100000;  // 100k transactions limit

    size_t max_mempool_size;
    size_t mempool_size;
    size_t max_mempool_count;
    size_t mempool_count;

    // MEMPOOL-007 FIX: Transaction expiration with background cleanup
    // Transactions older than 14 days are automatically removed
    static const int64_t MEMPOOL_EXPIRY_SECONDS = 14 * 24 * 60 * 60;  // 14 days
    std::thread expiration_thread;
    std::atomic<bool> stop_expiration_thread;
    std::condition_variable expiration_cv;
    std::mutex expiration_mutex;

    // MEMPOOL-018 FIX: Metrics tracking for monitoring and debugging
    // Atomic counters to track mempool operations without lock contention
    std::atomic<uint64_t> metric_adds;
    std::atomic<uint64_t> metric_removes;
    std::atomic<uint64_t> metric_evictions;
    std::atomic<uint64_t> metric_expirations;
    std::atomic<uint64_t> metric_rbf_replacements;
    std::atomic<uint64_t> metric_add_failures;
    std::atomic<uint64_t> metric_rbf_failures;

    // MEMPOOL-002 FIX: Private helper methods for eviction policy
    bool EvictTransactions(size_t bytes_needed, std::string* error = nullptr);
    bool HasDescendants(const uint256& txid) const;
    void UpdateDescendantsAdd(const CTransactionRef& tx);
    void UpdateDescendantsRemove(const uint256& txid);

    // MEMPOOL-007 FIX: Expiration cleanup methods
    void ExpirationThreadFunc();
    void CleanupExpiredTransactions();

public:
    CTxMemPool();
    ~CTxMemPool();  // MEMPOOL-007 FIX: Destructor to stop expiration thread
    bool AddTx(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, std::string* error = nullptr);
    bool RemoveTx(const uint256& txid);
    bool ReplaceTransaction(const CTransactionRef& replacement_tx, CAmount replacement_fee, int64_t time, unsigned int height, std::string* error = nullptr);  // MEMPOOL-008 FIX: RBF support
    bool Exists(const uint256& txid) const;
    bool GetTx(const uint256& txid, CTxMemPoolEntry& entry) const;
    std::optional<CTxMemPoolEntry> GetTxIfExists(const uint256& txid) const;  // MEMPOOL-010 FIX: TOCTOU-safe API
    std::vector<CTransactionRef> GetOrderedTxs() const;
    std::vector<CTransactionRef> GetTopTxs(size_t n) const;
    void Clear();
    size_t Size() const;
    size_t GetMempoolSize() const;
    void GetStats(size_t& size, size_t& bytes, double& min_fee_rate, double& max_fee_rate) const;
    void SetHeight(unsigned int height);
    void RemoveConfirmedTxs(const std::vector<CTransactionRef>& block_txs);

    // MEMPOOL-018 FIX: Get metrics for monitoring
    struct MempoolMetrics {
        uint64_t total_adds;
        uint64_t total_removes;
        uint64_t total_evictions;
        uint64_t total_expirations;
        uint64_t total_rbf_replacements;
        uint64_t total_add_failures;
        uint64_t total_rbf_failures;
    };
    MempoolMetrics GetMetrics() const;
};

#endif
