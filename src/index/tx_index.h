// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_INDEX_TX_INDEX_H
#define DILITHION_INDEX_TX_INDEX_H

#include <primitives/block.h>
#include <leveldb/db.h>
#include <leveldb/write_batch.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

class CBlockchainDB;

class CTxIndex {
public:
    CTxIndex();
    ~CTxIndex();

    CTxIndex(const CTxIndex&) = delete;
    CTxIndex& operator=(const CTxIndex&) = delete;

    bool Init(const std::string& datadir, CBlockchainDB* chain_db);

    bool WriteBlock(const CBlock& block, int height, const uint256& block_hash);
    bool EraseBlock(const CBlock& block, int height, const uint256& block_hash);

    bool FindTx(const uint256& txid, uint256& block_hash, uint32_t& tx_pos) const;

    int  LastIndexedHeight() const;
    bool IsBuiltUpToHeight(int h) const;
    bool IsSynced() const;

    // PR-4 will fill in actual thread bodies.
    void StartBackgroundSync();
    void Interrupt();
    void Stop();

    void IncrementMismatches();
    uint64_t MismatchCount() const;

private:
    static constexpr uint8_t SCHEMA_VERSION = 0x01;
    static constexpr size_t TX_KEY_SIZE = 33;       // 't' + 32-byte raw txid
    static constexpr size_t TX_VALUE_SIZE = 40;     // ver(1) + hash(32) + pos(4) + reserved(3)
    static constexpr size_t META_VALUE_SIZE = 13;   // ver(1) + height(4) + truncated_hash(8)

    static const std::string META_KEY;              // "\x00meta" — 5 bytes literal

    std::unique_ptr<leveldb::DB> m_db;
    CBlockchainDB* m_chain_db = nullptr;

    mutable std::mutex m_mutex;

    std::atomic<bool>     m_synced{false};
    std::atomic<int>      m_last_height{-1};
    std::atomic<bool>     m_interrupt{false};
    std::atomic<uint64_t> m_mismatches_observed{0};

    // SEC-MD-1: gates the spawn-vs-stop race. Set under m_mutex inside
    // StartBackgroundSync before m_mutex is released for the chainstate
    // query. Cleared after m_sync_thread has been assigned. Stop() waits
    // for this to clear before checking m_sync_thread.joinable() so a
    // concurrent Stop never observes a half-spawned thread.
    std::atomic<bool>     m_starting{false};

    std::thread m_sync_thread;

    static std::string MakeTxKey(const uint256& txid);

    bool WriteMeta(leveldb::WriteBatch& batch, int height, const uint256& hash);

    // Single-WriteBatch wipe: collects Deletes for every 't'-prefix key plus
    // the meta key, issues one m_db->Write. Caller must NOT hold m_mutex.
    bool WipeIndex();

    // Reindex thread body. Spawned by StartBackgroundSync; reads g_chainstate
    // and m_chain_db without holding m_mutex (m_mutex is acquired only inside
    // WriteBlock). Honors m_interrupt between blocks.
    void SyncLoop(int snapshotted_tip_height);
};

extern std::unique_ptr<CTxIndex> g_tx_index;

#endif // DILITHION_INDEX_TX_INDEX_H
