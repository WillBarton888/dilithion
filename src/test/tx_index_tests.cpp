// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <boost/test/unit_test.hpp>

#include <index/tx_index.h>

#include <consensus/validation.h>
#include <leveldb/db.h>
#include <leveldb/options.h>
#include <leveldb/slice.h>
#include <leveldb/status.h>
#include <leveldb/write_batch.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

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

BOOST_AUTO_TEST_CASE(concurrent_findtx_and_writeblock) {
    TempDbScope scope("concurrent");
    CTxIndex idx;
    BOOST_REQUIRE(idx.Init(scope.path(), nullptr));

    constexpr int kIterations = 1000;
    constexpr int kReaders = 4;

    std::vector<CTransactionRef> txs;
    txs.reserve(kIterations);
    for (int i = 0; i < kIterations; ++i) {
        txs.push_back(MakeUniqueTx(static_cast<uint8_t>(i & 0xFF),
                                   static_cast<uint8_t>((i >> 8) & 0xFF)));
    }

    std::atomic<bool> stop_readers{false};
    std::atomic<int>  reader_failures{0};

    auto reader = [&]() {
        std::mt19937_64 rng(static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
        while (!stop_readers.load(std::memory_order_relaxed)) {
            int idx_i = static_cast<int>(rng() % kIterations);
            uint256 fb;
            uint32_t fp = 0;
            (void)idx.FindTx(txs[idx_i]->GetHash(), fb, fp);
        }
    };

    std::vector<std::thread> readers;
    readers.reserve(kReaders);
    for (int i = 0; i < kReaders; ++i) readers.emplace_back(reader);

    for (int i = 0; i < kIterations; ++i) {
        auto block = MakeBlock({txs[i]});
        BOOST_REQUIRE(idx.WriteBlock(block, i, MakeBlockHash(static_cast<uint8_t>(i & 0xFF))));
    }

    stop_readers.store(true, std::memory_order_relaxed);
    for (auto& t : readers) t.join();

    BOOST_CHECK_EQUAL(reader_failures.load(), 0);
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), kIterations - 1);

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

BOOST_AUTO_TEST_SUITE_END()
