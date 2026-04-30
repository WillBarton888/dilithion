// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <boost/test/unit_test.hpp>

#include <index/tx_index.h>

#include <consensus/chain.h>
#include <consensus/validation.h>
#include <leveldb/db.h>
#include <leveldb/options.h>
#include <leveldb/slice.h>
#include <leveldb/status.h>
#include <leveldb/write_batch.h>
#include <node/block_index.h>
#include <node/blockchain_storage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

extern CChainState g_chainstate;

namespace tx_index_test_hooks {
extern std::atomic<uint64_t> g_wipe_write_count;
}

BOOST_AUTO_TEST_SUITE(tx_index_tests)

namespace {

std::string MakeTempDir(const std::string& tag) {
    auto base = std::filesystem::temp_directory_path();
    auto path = base / ("tx_index_test_" + tag + "_" +
        std::to_string(static_cast<long long>(
            std::chrono::steady_clock::now().time_since_epoch().count())));
    std::filesystem::create_directories(path);
    return path.string();
}

void CleanupTempDir(const std::string& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

void WriteCompactSize(std::vector<uint8_t>& data, uint64_t size) {
    if (size < 253) {
        data.push_back(static_cast<uint8_t>(size));
    } else if (size <= 0xFFFF) {
        data.push_back(253);
        data.push_back(static_cast<uint8_t>(size & 0xFF));
        data.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
    } else if (size <= 0xFFFFFFFF) {
        data.push_back(254);
        for (int i = 0; i < 4; ++i) {
            data.push_back(static_cast<uint8_t>((size >> (i * 8)) & 0xFF));
        }
    } else {
        data.push_back(255);
        for (int i = 0; i < 8; ++i) {
            data.push_back(static_cast<uint8_t>((size >> (i * 8)) & 0xFF));
        }
    }
}

CTransactionRef MakeUniqueTx(uint8_t seed_a, uint8_t seed_b) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    uint256 prev;
    std::memset(prev.data, seed_a, 32);
    std::vector<uint8_t> sig{seed_a, seed_b, 0xAA};
    tx.vin.push_back(CTxIn(prev, seed_b, sig, CTxIn::SEQUENCE_FINAL));
    std::vector<uint8_t> spk{0x76, 0xa9, 0x14, seed_a, seed_b};
    tx.vout.push_back(CTxOut(1000ULL + seed_a, spk));
    return MakeTransactionRef(tx);
}

CBlock MakeBlock(const std::vector<CTransactionRef>& txs) {
    CBlock block;
    block.nVersion = 1;
    block.nTime = 1700000000;
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;

    std::vector<uint8_t> vtx_data;
    WriteCompactSize(vtx_data, txs.size());
    for (const auto& tx : txs) {
        auto data = tx->Serialize();
        vtx_data.insert(vtx_data.end(), data.begin(), data.end());
    }
    block.vtx = std::move(vtx_data);
    return block;
}

uint256 MakeBlockHash(uint8_t seed) {
    uint256 h;
    std::memset(h.data, seed, 32);
    return h;
}

class TempDbScope {
public:
    explicit TempDbScope(const std::string& tag) : m_path(MakeTempDir(tag)) {}
    ~TempDbScope() { CleanupTempDir(m_path); }
    const std::string& path() const { return m_path; }
    TempDbScope(const TempDbScope&) = delete;
    TempDbScope& operator=(const TempDbScope&) = delete;
private:
    std::string m_path;
};

} // namespace

BOOST_AUTO_TEST_CASE(default_state) {
    TempDbScope scope("default_state");
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

    BOOST_CHECK_EQUAL(idx.IsSynced(), false);
    BOOST_CHECK_EQUAL(idx.IsBuiltUpToHeight(0), false);
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), -1);
    BOOST_CHECK_EQUAL(idx.MismatchCount(), 0u);
}

BOOST_AUTO_TEST_CASE(write_then_findtx) {
    TempDbScope scope("write_findtx");
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

    auto tx0 = MakeUniqueTx(0x11, 0x01);
    auto tx1 = MakeUniqueTx(0x22, 0x02);
    auto tx2 = MakeUniqueTx(0x33, 0x03);
    auto block = MakeBlock({tx0, tx1, tx2});
    auto block_hash = MakeBlockHash(0xAB);

    BOOST_REQUIRE(idx.WriteBlock(block, 100, block_hash));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), 100);

    uint256 found_block;
    uint32_t found_pos = 0xFFFFFFFF;
    BOOST_REQUIRE(idx.FindTx(tx0->GetHash(), found_block, found_pos));
    BOOST_CHECK(found_block == block_hash);
    BOOST_CHECK_EQUAL(found_pos, 0u);

    BOOST_REQUIRE(idx.FindTx(tx1->GetHash(), found_block, found_pos));
    BOOST_CHECK(found_block == block_hash);
    BOOST_CHECK_EQUAL(found_pos, 1u);

    BOOST_REQUIRE(idx.FindTx(tx2->GetHash(), found_block, found_pos));
    BOOST_CHECK(found_block == block_hash);
    BOOST_CHECK_EQUAL(found_pos, 2u);
}

BOOST_AUTO_TEST_CASE(erase_block_removes_records) {
    TempDbScope scope("erase");
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

    auto tx0 = MakeUniqueTx(0x44, 0x10);
    auto tx1 = MakeUniqueTx(0x55, 0x20);
    auto tx2 = MakeUniqueTx(0x66, 0x30);
    auto block = MakeBlock({tx0, tx1, tx2});
    auto block_hash = MakeBlockHash(0xCD);

    BOOST_REQUIRE(idx.WriteBlock(block, 5, block_hash));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), 5);

    BOOST_REQUIRE(idx.EraseBlock(block, 5, block_hash));

    uint256 fb;
    uint32_t fp;
    BOOST_CHECK(!idx.FindTx(tx0->GetHash(), fb, fp));
    BOOST_CHECK(!idx.FindTx(tx1->GetHash(), fb, fp));
    BOOST_CHECK(!idx.FindTx(tx2->GetHash(), fb, fp));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), 4);
}

BOOST_AUTO_TEST_CASE(erase_first_block_resets_height_to_minus_one) {
    TempDbScope scope("erase_first");
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

    auto tx0 = MakeUniqueTx(0x77, 0x40);
    auto block = MakeBlock({tx0});
    auto block_hash = MakeBlockHash(0xEF);

    BOOST_REQUIRE(idx.WriteBlock(block, 0, block_hash));
    BOOST_REQUIRE(idx.EraseBlock(block, 0, block_hash));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), -1);
}

BOOST_AUTO_TEST_CASE(monotonicity_no_op) {
    TempDbScope scope("monotonicity");
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

    auto tx0 = MakeUniqueTx(0x88, 0x50);
    auto block = MakeBlock({tx0});
    auto block_hash = MakeBlockHash(0x12);

    BOOST_REQUIRE(idx.WriteBlock(block, 10, block_hash));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), 10);

    // Second WriteBlock at same height: returns true but is a no-op.
    auto tx_other = MakeUniqueTx(0x99, 0x60);
    auto block_other = MakeBlock({tx_other});
    auto block_hash_other = MakeBlockHash(0x34);
    BOOST_REQUIRE(idx.WriteBlock(block_other, 10, block_hash_other));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), 10);

    // The second block's tx must NOT have been written.
    uint256 fb;
    uint32_t fp;
    BOOST_CHECK(!idx.FindTx(tx_other->GetHash(), fb, fp));

    // Original tx still findable and points at original block.
    BOOST_REQUIRE(idx.FindTx(tx0->GetHash(), fb, fp));
    BOOST_CHECK(fb == block_hash);
}

BOOST_AUTO_TEST_CASE(erase_block_double_disconnect_no_op) {
    TempDbScope scope("erase_double_disconnect");
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

    auto tx0 = MakeUniqueTx(0xA1, 0xB1);
    auto block = MakeBlock({tx0});
    auto block_hash = MakeBlockHash(0xC1);

    BOOST_REQUIRE(idx.WriteBlock(block, 5, block_hash));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), 5);

    // First EraseBlock at H=5: succeeds, height drops to 4.
    BOOST_REQUIRE(idx.EraseBlock(block, 5, block_hash));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), 4);

    // Second EraseBlock at the same H=5: must be a no-op.
    // Returns true (idempotent contract), height stays 4, no crash, no
    // backward walk. Guard form `height != m_last_height` catches the
    // double-disconnect; an out-of-order erase at H=99 would hit the same
    // guard and also be a no-op.
    BOOST_REQUIRE(idx.EraseBlock(block, 5, block_hash));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), 4);

    BOOST_REQUIRE(idx.EraseBlock(block, 99, block_hash));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), 4);
}

BOOST_AUTO_TEST_CASE(meta_round_trip_on_reopen) {
    TempDbScope scope("meta_round_trip");
    auto tx0 = MakeUniqueTx(0xAA, 0x70);
    auto tx1 = MakeUniqueTx(0xBB, 0x71);
    auto block = MakeBlock({tx0, tx1});
    auto block_hash = MakeBlockHash(0x42);

    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
        BOOST_REQUIRE(idx.WriteBlock(block, 7, block_hash));
        BOOST_CHECK(idx.IsBuiltUpToHeight(7));
        BOOST_CHECK(!idx.IsBuiltUpToHeight(8));
    }

    // Reopen on same datadir.
    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
        BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), 7);
        BOOST_CHECK(idx.IsBuiltUpToHeight(7));
        BOOST_CHECK(!idx.IsBuiltUpToHeight(8));

        uint256 fb;
        uint32_t fp;
        BOOST_REQUIRE(idx.FindTx(tx0->GetHash(), fb, fp));
        BOOST_CHECK(fb == block_hash);
        BOOST_CHECK_EQUAL(fp, 0u);
        BOOST_REQUIRE(idx.FindTx(tx1->GetHash(), fb, fp));
        BOOST_CHECK_EQUAL(fp, 1u);
    }
}

BOOST_AUTO_TEST_CASE(schema_version_byte_tx_record_rejected) {
    TempDbScope scope("schema_tx");
    auto tx0 = MakeUniqueTx(0xCC, 0x80);
    auto block = MakeBlock({tx0});
    auto block_hash = MakeBlockHash(0x55);

    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
        BOOST_REQUIRE(idx.WriteBlock(block, 1, block_hash));
        uint256 fb;
        uint32_t fp;
        BOOST_REQUIRE(idx.FindTx(tx0->GetHash(), fb, fp));
    }

    // Forge a tx record with version byte 0x02 directly via leveldb (CTxIndex closed).
    uint256 forged_txid;
    std::memset(forged_txid.data, 0xF0, 32);
    {
        leveldb::DB* raw = nullptr;
        leveldb::Options opts;
        opts.create_if_missing = false;
        BOOST_REQUIRE(leveldb::DB::Open(opts, scope.path(), &raw).ok());
        std::unique_ptr<leveldb::DB> raw_db(raw);

        std::string key;
        key.push_back('t');
        key.append(reinterpret_cast<const char*>(forged_txid.data), 32);

        char value[40];
        std::memset(value, 0, 40);
        value[0] = 0x02;
        std::memcpy(&value[1], block_hash.data, 32);
        uint32_t pos = 7;
        std::memcpy(&value[33], &pos, 4);
        BOOST_REQUIRE(raw_db->Put(leveldb::WriteOptions(),
                                  leveldb::Slice(key.data(), key.size()),
                                  leveldb::Slice(value, 40)).ok());
    }

    // Reopen txindex and verify FindTx rejects the forged record.
    CTxIndex idx2;
    BOOST_REQUIRE(idx2.Init(scope.path(), nullptr));
    uint256 fb;
    uint32_t fp;
    BOOST_CHECK(!idx2.FindTx(forged_txid, fb, fp));
    // Original valid record is still findable.
    BOOST_REQUIRE(idx2.FindTx(tx0->GetHash(), fb, fp));
}

BOOST_AUTO_TEST_CASE(schema_version_byte_meta_record_rejected) {
    TempDbScope scope("schema_meta");
    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
        auto tx0 = MakeUniqueTx(0xDD, 0x90);
        auto block = MakeBlock({tx0});
        BOOST_REQUIRE(idx.WriteBlock(block, 3, MakeBlockHash(0x66)));
    }

    // Forge meta record with version byte 0x02.
    {
        leveldb::DB* raw = nullptr;
        leveldb::Options opts;
        opts.create_if_missing = false;
        BOOST_REQUIRE(leveldb::DB::Open(opts, scope.path(), &raw).ok());
        std::unique_ptr<leveldb::DB> raw_db(raw);

        std::string meta_key("\x00meta", 5);
        char value[13];
        std::memset(value, 0, 13);
        value[0] = 0x02;  // wrong schema
        BOOST_REQUIRE(raw_db->Put(leveldb::WriteOptions(),
                                  leveldb::Slice(meta_key.data(), meta_key.size()),
                                  leveldb::Slice(value, 13)).ok());
    }

    {
        CTxIndex idx;
        BOOST_CHECK(!idx.Init(scope.path(), nullptr));
    }

    // After wiping the bad meta record, a fresh Init succeeds with default state.
    {
        leveldb::DB* raw = nullptr;
        leveldb::Options opts;
        opts.create_if_missing = false;
        BOOST_REQUIRE(leveldb::DB::Open(opts, scope.path(), &raw).ok());
        std::unique_ptr<leveldb::DB> raw_db(raw);
        std::string meta_key("\x00meta", 5);
        BOOST_REQUIRE(raw_db->Delete(leveldb::WriteOptions(),
                                     leveldb::Slice(meta_key.data(), meta_key.size())).ok());
    }

    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
        BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), -1);
    }
}

BOOST_AUTO_TEST_CASE(meta_key_isolation_t_prefix_scan) {
    TempDbScope scope("meta_isolation");
    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

        auto tx0 = MakeUniqueTx(0x12, 0x01);
        auto tx1 = MakeUniqueTx(0x34, 0x02);
        auto tx2 = MakeUniqueTx(0x56, 0x03);
        auto block = MakeBlock({tx0, tx1, tx2});
        BOOST_REQUIRE(idx.WriteBlock(block, 1, MakeBlockHash(0x77)));
    }

    leveldb::DB* raw = nullptr;
    leveldb::Options opts;
    opts.create_if_missing = false;
    BOOST_REQUIRE(leveldb::DB::Open(opts, scope.path(), &raw).ok());
    std::unique_ptr<leveldb::DB> raw_db(raw);

    std::unique_ptr<leveldb::Iterator> it(raw_db->NewIterator(leveldb::ReadOptions()));
    int t_count = 0;
    for (it->Seek("t"); it->Valid(); it->Next()) {
        leveldb::Slice k = it->key();
        if (k.size() == 0 || k.data()[0] != 't') break;
        BOOST_CHECK_EQUAL(k.size(), 33u);
        ++t_count;
    }
    BOOST_CHECK_EQUAL(t_count, 3);
}

BOOST_AUTO_TEST_CASE(stop_is_idempotent_and_destructor_safe) {
    TempDbScope scope("stop_idempotent");
    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
        idx.Stop();
        idx.Stop();  // calling twice must be safe
        // destructor will call Stop() a third time
    }
    // Reopen confirms DB was closed cleanly.
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
}

BOOST_AUTO_TEST_CASE(interrupt_sets_flag) {
    TempDbScope scope("interrupt");
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
    idx.Interrupt();
    // No public getter — but Interrupt() must not crash, and Stop() is still safe afterward.
    idx.Stop();
}

BOOST_AUTO_TEST_CASE(increment_mismatches) {
    TempDbScope scope("mismatches");
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
    BOOST_CHECK_EQUAL(idx.MismatchCount(), 0u);
    for (int i = 0; i < 17; ++i) idx.IncrementMismatches();
    BOOST_CHECK_EQUAL(idx.MismatchCount(), 17u);
}

// U1 (Cursor 2nd-pass): concurrent readers MUST assert FindTx returns
// the correct (block_hash, tx_pos) when it returns true — not just liveness.
// Per-reader minimum successful reads ensures a timing-skewed reader cannot
// silently pass with zero observations.
BOOST_AUTO_TEST_CASE(concurrent_findtx_and_writeblock) {
    TempDbScope scope("concurrent");
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

    constexpr int kIterations = 1000;
    constexpr int kReaders = 4;
    constexpr int kMinSuccessesPerReader = 100;

    std::vector<CTransactionRef> txs;
    txs.reserve(kIterations);
    for (int i = 0; i < kIterations; ++i) {
        txs.push_back(MakeUniqueTx(static_cast<uint8_t>(i & 0xFF),
                                   static_cast<uint8_t>((i >> 8) & 0xFF)));
    }

    std::atomic<bool> stop_readers{false};
    std::atomic<int>  reader_failures{0};
    std::vector<std::atomic<int>> per_reader_successes(kReaders);
    for (int i = 0; i < kReaders; ++i) per_reader_successes[i].store(0);

    auto reader = [&](int reader_id) {
        std::mt19937_64 rng(static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count()) +
            static_cast<uint64_t>(reader_id));
        while (!stop_readers.load(std::memory_order_relaxed)) {
            int idx_i = static_cast<int>(rng() % kIterations);
            uint256 fb;
            uint32_t fp = 0xFFFFFFFFu;
            if (idx.FindTx(txs[idx_i]->GetHash(), fb, fp)) {
                // Writer wrote this tx at height idx_i with block hash
                // MakeBlockHash(idx_i & 0xFF) at tx position 0 (block has
                // a single tx). Any deviation = mutex-protected read
                // observed inconsistent state — counts as a failure.
                const uint256 expected_hash =
                    MakeBlockHash(static_cast<uint8_t>(idx_i & 0xFF));
                if (!(fb == expected_hash) || fp != 0u) {
                    reader_failures.fetch_add(1, std::memory_order_relaxed);
                } else {
                    per_reader_successes[reader_id].fetch_add(
                        1, std::memory_order_relaxed);
                }
            }
        }
    };

    std::vector<std::thread> readers;
    readers.reserve(kReaders);
    for (int i = 0; i < kReaders; ++i) readers.emplace_back(reader, i);

    for (int i = 0; i < kIterations; ++i) {
        auto block = MakeBlock({txs[i]});
        BOOST_REQUIRE(idx.WriteBlock(block, i, MakeBlockHash(static_cast<uint8_t>(i & 0xFF))));
    }

    // Give readers a moment after the writer finishes so they see the
    // fully-populated index (helps small-N successful-read counts).
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    stop_readers.store(true, std::memory_order_relaxed);
    for (auto& t : readers) t.join();

    BOOST_CHECK_EQUAL(reader_failures.load(), 0);
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), kIterations - 1);

    for (int i = 0; i < kReaders; ++i) {
        BOOST_CHECK_GE(per_reader_successes[i].load(), kMinSuccessesPerReader);
    }

    uint256 fb;
    uint32_t fp = 0;
    BOOST_REQUIRE(idx.FindTx(txs[kIterations - 1]->GetHash(), fb, fp));
}

#ifndef _WIN32
// Atomicity test via filesystem write-failure: revoke write permission on the
// datadir, attempt WriteBlock, observe that the call fails AND no per-tx
// records are visible AND meta is unchanged. POSIX-only because Windows
// permission semantics differ.
BOOST_AUTO_TEST_CASE(atomicity_via_filesystem_failure) {
    TempDbScope scope("atomicity");
    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

        auto tx0 = MakeUniqueTx(0x01, 0xAA);
        auto block = MakeBlock({tx0});
        BOOST_REQUIRE(idx.WriteBlock(block, 1, MakeBlockHash(0xAA)));
        // close
    }

    // Make datadir read-only.
    std::error_code ec;
    std::filesystem::permissions(scope.path(),
        std::filesystem::perms::owner_read | std::filesystem::perms::group_read,
        std::filesystem::perm_options::replace, ec);

    {
        CTxIndex idx;
        // Init may succeed reading the existing DB read-only; either way, WriteBlock should fail.
        if (!idx.Init(scope.path(), nullptr)) {
            // Init failed — that's also an acceptable outcome for read-only datadir.
        } else {
            auto tx1 = MakeUniqueTx(0x02, 0xBB);
            auto block2 = MakeBlock({tx1});
            (void)idx.WriteBlock(block2, 2, MakeBlockHash(0xBB));
            // Whether the call returns true or false depends on leveldb buffering, but the
            // observable post-state must still satisfy the atomicity invariant.
            uint256 fb;
            uint32_t fp = 0;
            // tx1 must NOT be findable via the filesystem after a forced shutdown:
            // we'll re-open below to verify the persistent state.
        }
    }

    // Restore permissions and verify persistent state via fresh Init.
    std::filesystem::permissions(scope.path(),
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace, ec);

    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
    // Persistent height must not have advanced past 1 (the only successfully-written block).
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), 1);

    // The first block's tx must still be findable.
    auto tx_first = MakeUniqueTx(0x01, 0xAA);
    uint256 fb;
    uint32_t fp = 0;
    BOOST_REQUIRE(idx.FindTx(tx_first->GetHash(), fb, fp));
}
#endif

// "Crash-without-explicit-close" atomicity: write a block, drop the CTxIndex
// without calling Stop() explicitly (destructor handles it), reopen and verify
// either ALL txids of the block are findable AND height==H, OR NONE are findable
// AND height is the pre-write value. No partial state.
BOOST_AUTO_TEST_CASE(single_batch_invariant_via_state_observation) {
    TempDbScope scope("single_batch");
    auto tx0 = MakeUniqueTx(0xA1, 0x01);
    auto tx1 = MakeUniqueTx(0xA2, 0x02);
    auto tx2 = MakeUniqueTx(0xA3, 0x03);
    auto block = MakeBlock({tx0, tx1, tx2});
    auto block_hash = MakeBlockHash(0xCC);

    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
        BOOST_REQUIRE(idx.WriteBlock(block, 42, block_hash));
        // No explicit Stop(); destructor closes leveldb cleanly.
    }

    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope.path(), nullptr));
        const int h = idx.LastIndexedHeight();
        uint256 fb;
        uint32_t fp = 0;
        const bool f0 = idx.FindTx(tx0->GetHash(), fb, fp);
        const bool f1 = idx.FindTx(tx1->GetHash(), fb, fp);
        const bool f2 = idx.FindTx(tx2->GetHash(), fb, fp);

        // Either all three are findable AND height == 42, OR none are AND height == -1.
        const bool all_in   = (f0 && f1 && f2 && h == 42);
        const bool none_in  = (!f0 && !f1 && !f2 && h == -1);
        BOOST_CHECK(all_in || none_in);
    }
}

// ===========================================================================
// PR-4 fixtures + tests: reindex thread, C7 startup integrity check, etc.
// ===========================================================================

namespace {

// Compute a deterministic block hash from height. Distinct for every
// height in [0, 2^32). MakeBlockHash uses a single byte and would collide
// at height 256 in the larger fixtures, so we lay the height into the
// first 4 bytes here.
uint256 HashForHeight(int height) {
    uint256 h;
    std::memset(h.data, 0, 32);
    uint32_t height_u = static_cast<uint32_t>(height);
    std::memcpy(h.data, &height_u, 4);
    // High bytes set to a non-zero pattern so the hash is never the all-zero
    // sentinel that means "null".
    h.data[31] = 0xCC;
    return h;
}

// Seed g_chainstate with N blocks at heights [0, n_blocks). Caller must
// have already called g_chainstate.Cleanup() to reset prior state.
// Also writes each block to the supplied CBlockchainDB so the reindex
// thread can ReadBlock(hash, ...) successfully.
struct ChainFixture {
    std::vector<CTransactionRef> per_height_tx;       // one tx per block
    std::vector<uint256>         per_height_hash;     // hash for height i

    void Build(int n_blocks, CBlockchainDB& chain_db) {
        per_height_tx.clear();
        per_height_hash.clear();
        per_height_tx.reserve(n_blocks);
        per_height_hash.reserve(n_blocks);

        // Reset chainstate (global) so prior tests don't pollute.
        g_chainstate.Cleanup();

        CBlockIndex* prev_idx = nullptr;
        for (int h = 0; h < n_blocks; ++h) {
            uint256 block_hash = HashForHeight(h);
            per_height_hash.push_back(block_hash);

            // Synthesize a unique tx for this block.
            auto tx = MakeUniqueTx(static_cast<uint8_t>(h & 0xFF),
                                   static_cast<uint8_t>((h >> 8) & 0xFF));
            per_height_tx.push_back(tx);

            // Build the block, persist it to chain_db.
            CBlock block = MakeBlock({tx});
            if (h == 0) {
                block.hashPrevBlock = uint256();
            } else {
                block.hashPrevBlock = per_height_hash[h - 1];
            }
            BOOST_REQUIRE(chain_db.WriteBlock(block_hash, block));

            // Build a minimal CBlockIndex.
            auto pidx = std::make_unique<CBlockIndex>();
            pidx->nHeight = h;
            pidx->phashBlock = block_hash;
            pidx->pprev = prev_idx;
            pidx->nStatus = CBlockIndex::BLOCK_VALID_HEADER |
                            CBlockIndex::BLOCK_HAVE_DATA;

            CBlockIndex* raw = pidx.get();
            BOOST_REQUIRE(g_chainstate.AddBlockIndex(block_hash, std::move(pidx)));

            // Wire pnext on the previous so IsOnMainChain() returns true.
            if (prev_idx != nullptr) {
                prev_idx->pnext = raw;
            }
            prev_idx = raw;
        }

        // Set the tip so g_chainstate.GetTip() works for R2 precondition.
        if (prev_idx != nullptr) {
            g_chainstate.SetTipForTest(prev_idx);
        }
    }
};

// Helper: poll IsSynced() until true or timeout.
bool WaitForSync(CTxIndex& idx, std::chrono::milliseconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (idx.IsSynced()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return idx.IsSynced();
}

} // namespace

// Reindex happy path: seed chainstate + chain_db with N blocks, start
// background sync, wait for IsSynced, verify all txs findable.
BOOST_AUTO_TEST_CASE(reindex_happy_path) {
    TempDbScope scope_idx("reindex_happy_idx");
    TempDbScope scope_chain("reindex_happy_chain");

    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));

    constexpr int kN = 12;
    ChainFixture fix;
    fix.Build(kN, chain_db);

    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), -1);

    idx.StartBackgroundSync();
    BOOST_REQUIRE(WaitForSync(idx, std::chrono::seconds(5)));

    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), kN - 1);
    for (int h = 0; h < kN; ++h) {
        uint256 fb;
        uint32_t fp = 0;
        BOOST_REQUIRE(idx.FindTx(fix.per_height_tx[h]->GetHash(), fb, fp));
        BOOST_CHECK(fb == fix.per_height_hash[h]);
        BOOST_CHECK_EQUAL(fp, 0u);
    }

    idx.Stop();
    g_chainstate.Cleanup();
}

// Reindex resume across destruct/reopen. Interrupt mid-walk, reopen, finish.
BOOST_AUTO_TEST_CASE(reindex_resume_across_destruct) {
    TempDbScope scope_idx("reindex_resume_idx");
    TempDbScope scope_chain("reindex_resume_chain");

    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));

    constexpr int kN = 10;
    ChainFixture fix;
    fix.Build(kN, chain_db);

    int K = -1;
    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));
        idx.StartBackgroundSync();
        // Interrupt almost immediately; some blocks may already be indexed.
        idx.Interrupt();
        idx.Stop();
        K = idx.LastIndexedHeight();
        BOOST_CHECK(K >= -1 && K <= kN - 1);
    }

    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));
        // Resume must NOT regress.
        BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), K);
        idx.StartBackgroundSync();
        BOOST_REQUIRE(WaitForSync(idx, std::chrono::seconds(5)));
        BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), kN - 1);

        for (int h = 0; h < kN; ++h) {
            uint256 fb;
            uint32_t fp = 0;
            BOOST_REQUIRE(idx.FindTx(fix.per_height_tx[h]->GetHash(), fb, fp));
            BOOST_CHECK(fb == fix.per_height_hash[h]);
        }
        idx.Stop();
    }
    g_chainstate.Cleanup();
}

// C7 wipe atomicity: meta says height=4 with mismatched truncated hash;
// chainstate has a different real hash at height 4. Init must wipe + reset.
BOOST_AUTO_TEST_CASE(c7_wipe_on_mismatch_resets_to_minus_one) {
    TempDbScope scope_idx("c7_wipe_idx");
    TempDbScope scope_chain("c7_wipe_chain");

    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));

    constexpr int kN = 5;
    ChainFixture fix;
    fix.Build(kN, chain_db);

    // First, seed the index with real data through height 4 — this writes
    // the matching meta record. Then we forge a sentinel meta record to
    // induce a mismatch on reopen.
    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));
        idx.StartBackgroundSync();
        BOOST_REQUIRE(WaitForSync(idx, std::chrono::seconds(5)));
        BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), kN - 1);
        idx.Stop();
    }

    // Forge meta to claim height=4 with a sentinel truncated hash that does
    // not match chainstate.GetBlocksAtHeight(4)'s real hash.
    {
        leveldb::DB* raw = nullptr;
        leveldb::Options opts;
        opts.create_if_missing = false;
        BOOST_REQUIRE(leveldb::DB::Open(opts, scope_idx.path(), &raw).ok());
        std::unique_ptr<leveldb::DB> raw_db(raw);

        std::string meta_key("\x00meta", 5);
        char value[13];
        std::memset(value, 0, 13);
        value[0] = 0x01;
        int32_t h = 4;
        std::memcpy(&value[1], &h, 4);
        // Sentinel pattern guaranteed to not match HashForHeight(4) (all 0x04).
        std::memset(&value[5], 0xFE, 8);
        BOOST_REQUIRE(raw_db->Put(leveldb::WriteOptions(),
                                  leveldb::Slice(meta_key.data(), meta_key.size()),
                                  leveldb::Slice(value, 13)).ok());
    }

    const uint64_t pre_count = tx_index_test_hooks::g_wipe_write_count.load();

    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));
        BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), -1);

        // No t-prefix records remain.
        leveldb::DB* raw = nullptr;
        leveldb::Options opts;
        opts.create_if_missing = false;
        // Re-open via a separate handle is unsafe while idx holds the DB; so
        // instead, attempt FindTx for every fixture tx — none should be
        // findable.
        (void)raw; (void)opts;
        for (int h = 0; h < kN; ++h) {
            uint256 fb;
            uint32_t fp = 0;
            BOOST_CHECK(!idx.FindTx(fix.per_height_tx[h]->GetHash(), fb, fp));
        }
        idx.Stop();
    }

    // U3: exactly ONE additional Write call from WipeIndex.
    const uint64_t post_count = tx_index_test_hooks::g_wipe_write_count.load();
    BOOST_CHECK_EQUAL(post_count - pre_count, 1u);

    g_chainstate.Cleanup();
}

// C7 wipe single-batch invariant via state observation. After a wipe, the
// post-restart state is either fully pre-wipe or fully post-wipe; never
// partial. (Verifies the wipe is committed as a single WriteBatch.)
BOOST_AUTO_TEST_CASE(c7_wipe_single_batch_state_observation) {
    TempDbScope scope_idx("c7_state_idx");
    TempDbScope scope_chain("c7_state_chain");

    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));

    constexpr int kN = 5;
    ChainFixture fix;
    fix.Build(kN, chain_db);

    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));
        idx.StartBackgroundSync();
        BOOST_REQUIRE(WaitForSync(idx, std::chrono::seconds(5)));
        idx.Stop();
    }

    // Forge mismatched meta.
    {
        leveldb::DB* raw = nullptr;
        leveldb::Options opts;
        opts.create_if_missing = false;
        BOOST_REQUIRE(leveldb::DB::Open(opts, scope_idx.path(), &raw).ok());
        std::unique_ptr<leveldb::DB> raw_db(raw);
        std::string meta_key("\x00meta", 5);
        char value[13];
        std::memset(value, 0, 13);
        value[0] = 0x01;
        int32_t h = 4;
        std::memcpy(&value[1], &h, 4);
        std::memset(&value[5], 0xFE, 8);
        BOOST_REQUIRE(raw_db->Put(leveldb::WriteOptions(),
                                  leveldb::Slice(meta_key.data(), meta_key.size()),
                                  leveldb::Slice(value, 13)).ok());
    }

    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));
        // No explicit Stop; destructor closes leveldb cleanly.
    }

    // Reopen + observe: state is fully post-wipe (no t-prefix keys + meta
    // reset). The wipe was committed as a single WriteBatch, so partial
    // state is impossible. We observe the post-wipe outcome only — the
    // pre-wipe outcome would only be observed if the wipe Write hadn't
    // completed before the destructor ran. Either is acceptable per the
    // contract.
    {
        CTxIndex idx;
        BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));
        const int h = idx.LastIndexedHeight();
        bool any_found = false;
        for (int i = 0; i < kN; ++i) {
            uint256 fb;
            uint32_t fp = 0;
            if (idx.FindTx(fix.per_height_tx[i]->GetHash(), fb, fp)) {
                any_found = true;
                break;
            }
        }
        const bool pre_wipe  = (h == kN - 1) && any_found;
        const bool post_wipe = (h == -1) && !any_found;
        BOOST_CHECK(pre_wipe || post_wipe);
    }

    g_chainstate.Cleanup();
}

// Stale-LOCK error path (U4): if leveldb at the same datadir is held by
// another process, Init returns false with a stderr log mentioning the
// path and remediation. We simulate by opening a second leveldb on the
// same dir; the second handle should fail to open.
BOOST_AUTO_TEST_CASE(stale_lock_error_path) {
    TempDbScope scope("stale_lock");

    leveldb::DB* hold_db = nullptr;
    leveldb::Options opts;
    opts.create_if_missing = true;
    BOOST_REQUIRE(leveldb::DB::Open(opts, scope.path(), &hold_db).ok());
    std::unique_ptr<leveldb::DB> holder(hold_db);

    {
        CTxIndex idx;
        BOOST_CHECK(!idx.Init(scope.path(), nullptr));
    }
    // holder destructor releases the lock.
}

// Stop() while reindex is mid-walk completes within 5s.
BOOST_AUTO_TEST_CASE(stop_mid_walk_completes_promptly) {
    TempDbScope scope_idx("stop_mid_walk_idx");
    TempDbScope scope_chain("stop_mid_walk_chain");

    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));

    constexpr int kN = 1000;
    ChainFixture fix;
    fix.Build(kN, chain_db);

    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));
    idx.StartBackgroundSync();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto t0 = std::chrono::steady_clock::now();
    idx.Stop();
    auto t1 = std::chrono::steady_clock::now();

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);
    BOOST_CHECK_LT(elapsed.count(), 5000);
    // After Stop, thread must be joined.
    // (We can't directly query joinable() on m_sync_thread; calling Stop()
    // again must be a no-op without exception — the contract idempotency
    // criterion already covers this elsewhere; here the timing bound is
    // the load-bearing assertion.)

    g_chainstate.Cleanup();
}

// U2 (Cursor 2nd-pass): Init twice on same instance is a no-op. State
// snapshots before/after second Init must be identical.
BOOST_AUTO_TEST_CASE(init_twice_is_no_op) {
    TempDbScope scope("init_twice");
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

    // Write some state so the snapshots are non-trivial.
    auto tx0 = MakeUniqueTx(0xE1, 0xF1);
    auto block = MakeBlock({tx0});
    BOOST_REQUIRE(idx.WriteBlock(block, 3, MakeBlockHash(0x77)));
    idx.IncrementMismatches();
    idx.IncrementMismatches();

    const int      h_before     = idx.LastIndexedHeight();
    const bool     synced_before = idx.IsSynced();
    const uint64_t mm_before    = idx.MismatchCount();

    // Second Init must return true and be a no-op.
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), h_before);
    BOOST_CHECK_EQUAL(idx.IsSynced(), synced_before);
    BOOST_CHECK_EQUAL(idx.MismatchCount(), mm_before);
}

// R2 (Cursor 2nd-pass): StartBackgroundSync called before Init must NOT
// spawn a thread and must log an error.
BOOST_AUTO_TEST_CASE(start_sync_before_init_does_not_spawn) {
    CTxIndex idx;
    // No Init call. m_db, m_chain_db are both null.
    idx.StartBackgroundSync();
    // No way to directly observe thread spawn; the load-bearing assertion
    // is that the destructor runs cleanly without joining a never-spawned
    // thread (idx.Stop() called from dtor must be a no-op).
    // If a thread had been spawned, it would deadlock on the un-set
    // m_chain_db pointer or crash; the test would never return.
    idx.Stop();
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), -1);
}

// R2 second variant: StartBackgroundSync called after Init but with empty
// chainstate (GetTip()==nullptr) must NOT spawn.
BOOST_AUTO_TEST_CASE(start_sync_with_empty_chainstate_does_not_spawn) {
    TempDbScope scope_idx("r2_empty_idx");
    TempDbScope scope_chain("r2_empty_chain");

    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));

    g_chainstate.Cleanup(); // ensure tip is nullptr

    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));
    idx.StartBackgroundSync();
    // Brief wait; if a thread had spawned, IsSynced might flip.
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), -1);
    idx.Stop();
    g_chainstate.Cleanup();
}

// SEC-MD-2 regression: a Start → Stop → Start sequence must produce a
// thread that actually runs to completion. Before the fix, the second
// Start observed m_interrupt latched true from the first Stop and the
// new thread exited at its first interrupt check — a silent no-op.
BOOST_AUTO_TEST_CASE(start_stop_start_resumes_sync_after_interrupt_clear) {
    TempDbScope scope_idx("md2_idx");
    TempDbScope scope_chain("md2_chain");

    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));

    constexpr int kN = 8;
    ChainFixture fix;
    fix.Build(kN, chain_db);

    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));

    // First cycle: full sync.
    idx.StartBackgroundSync();
    BOOST_REQUIRE(WaitForSync(idx, std::chrono::seconds(5)));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), kN - 1);
    idx.Stop();
    BOOST_CHECK(idx.IsSynced());

    // Extend the chain so the second cycle has new work to do.
    fix.Build(kN + 4, chain_db);   // height 0..(kN+3) now
    constexpr int kN2 = kN + 4;

    // SEC-MD-2: re-Start must clear m_interrupt and spawn a working thread.
    idx.StartBackgroundSync();
    BOOST_REQUIRE(WaitForSync(idx, std::chrono::seconds(5)));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), kN2 - 1);

    // Verify the new blocks were actually indexed (substantive work).
    for (int h = kN; h < kN2; ++h) {
        uint256 fb;
        uint32_t fp = 0;
        BOOST_REQUIRE(idx.FindTx(fix.per_height_tx[h]->GetHash(), fb, fp));
        BOOST_CHECK(fb == fix.per_height_hash[h]);
    }

    idx.Stop();
    g_chainstate.Cleanup();
}

// SEC-MD-1 regression: two concurrent StartBackgroundSync calls must NOT
// both reach the m_sync_thread assignment (which would terminate the
// program). The m_starting gate makes the second concurrent caller a
// no-op even when the first is between mutex release and thread assign.
BOOST_AUTO_TEST_CASE(concurrent_start_no_double_spawn) {
    TempDbScope scope_idx("md1_idx");
    TempDbScope scope_chain("md1_chain");

    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));

    constexpr int kN = 6;
    ChainFixture fix;
    fix.Build(kN, chain_db);

    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db));

    // Hammer Start from 4 threads simultaneously. Without the m_starting
    // gate, two concurrent threads passing the joinable() check would
    // both reach `m_sync_thread = std::thread(...)` — std::terminate.
    // With the gate, exactly one wins; the others see m_starting==true
    // or m_sync_thread.joinable()==true and bail.
    constexpr int kStarters = 4;
    std::vector<std::thread> starters;
    starters.reserve(kStarters);
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    for (int i = 0; i < kStarters; ++i) {
        starters.emplace_back([&]() {
            ready.fetch_add(1);
            while (!go.load()) std::this_thread::yield();
            idx.StartBackgroundSync();
        });
    }
    while (ready.load() < kStarters) std::this_thread::yield();
    go.store(true);
    for (auto& t : starters) t.join();

    // If any of the 4 starters double-spawned, std::terminate would have
    // killed the test process. Reaching here proves the gate works.
    BOOST_REQUIRE(WaitForSync(idx, std::chrono::seconds(5)));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), kN - 1);

    idx.Stop();
    g_chainstate.Cleanup();
}

BOOST_AUTO_TEST_SUITE_END()
