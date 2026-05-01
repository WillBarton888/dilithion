// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Undo-data read accessor tests -- PR-BA-1.
 *
 * Exercises CUTXOSet::ReadUndoBlock on:
 *   - round-trip from ApplyBlock (the on-disk writer) through ReadUndoBlock
 *     (the new reader), confirming every spent input survives byte-identical
 *   - missing-block lookup (returns false, leaves output cleared)
 *   - empty-undo block (a coinbase-only block produces an undo record with
 *     spentCount=0 and a SHA3 footer; reader returns true with empty vSpent)
 *   - large-block round-trip with many spent inputs
 *   - corruption detection (flipped checksum byte, truncated record,
 *     bogus spentCount) -- defensive surface for the analytics consumers
 *     that will call this from tight RPC loops.
 *
 * Tests build their own UTXO set on a temp directory; no shared chainstate.
 */

#include <boost/test/unit_test.hpp>

#include <node/utxo_set.h>
#include <node/undo_data.h>

#include <consensus/validation.h>
#include <crypto/sha3.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <leveldb/db.h>
#include <leveldb/options.h>

#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>
#include <vector>

BOOST_AUTO_TEST_SUITE(undo_data_tests)

namespace {

// ---------------------------------------------------------------------------
// Temp-dir helpers (mirrors the convention used in tx_index_tests +
// mempool_persist_tests).
// ---------------------------------------------------------------------------

std::filesystem::path MakeTempDir(const std::string& tag) {
    auto base = std::filesystem::temp_directory_path();
    auto path = base / ("undo_data_test_" + tag + "_" +
        std::to_string(static_cast<long long>(
            std::chrono::steady_clock::now().time_since_epoch().count())));
    std::filesystem::create_directories(path);
    return path;
}

void CleanupTempDir(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

class TempUtxoScope {
public:
    explicit TempUtxoScope(const std::string& tag)
        : m_path(MakeTempDir(tag)) {
        BOOST_REQUIRE(m_utxo.Open(m_path.string(), true));
    }
    ~TempUtxoScope() {
        m_utxo.Close();
        CleanupTempDir(m_path);
    }
    CUTXOSet& utxo() { return m_utxo; }
    const std::filesystem::path& path() const { return m_path; }
    TempUtxoScope(const TempUtxoScope&) = delete;
    TempUtxoScope& operator=(const TempUtxoScope&) = delete;
private:
    std::filesystem::path m_path;
    CUTXOSet              m_utxo;
};

// ---------------------------------------------------------------------------
// Block / tx fabrication helpers.
// ---------------------------------------------------------------------------

uint256 MakeHash(uint8_t seed) {
    uint256 h;
    std::memset(h.data, seed, 32);
    return h;
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

CTransactionRef MakeCoinbase(uint32_t height_marker,
                             uint64_t reward,
                             uint8_t  spk_seed) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    std::vector<uint8_t> sig;
    sig.push_back(0x04);
    sig.push_back(static_cast<uint8_t>(height_marker & 0xFF));
    sig.push_back(static_cast<uint8_t>((height_marker >> 8) & 0xFF));
    sig.push_back(static_cast<uint8_t>((height_marker >> 16) & 0xFF));
    sig.push_back(static_cast<uint8_t>((height_marker >> 24) & 0xFF));
    tx.vin.push_back(CTxIn(COutPoint(), sig));
    std::vector<uint8_t> spk(25, spk_seed);
    spk[0] = 0x76; spk[1] = 0xa9; spk[2] = 0x14;
    spk[23] = 0x88; spk[24] = 0xac;
    tx.vout.push_back(CTxOut(reward, spk));
    return MakeTransactionRef(tx);
}

CTransactionRef MakeSpender(const std::vector<COutPoint>& inputs,
                            const std::vector<uint64_t>& output_values,
                            uint8_t spk_seed) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    for (const auto& op : inputs) {
        std::vector<uint8_t> sig(64, 0xAA);
        tx.vin.push_back(CTxIn(op, sig, CTxIn::SEQUENCE_FINAL));
    }
    for (uint64_t v : output_values) {
        std::vector<uint8_t> spk(25, spk_seed);
        spk[0] = 0x76; spk[1] = 0xa9; spk[2] = 0x14;
        spk[23] = 0x88; spk[24] = 0xac;
        tx.vout.push_back(CTxOut(v, spk));
    }
    return MakeTransactionRef(tx);
}

CBlock MakeBlock(const std::vector<CTransactionRef>& txs, uint32_t time_off) {
    CBlock block;
    block.nVersion = 1;
    block.nTime = 1700000000u + time_off;
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;

    std::vector<uint8_t> vtx_data;
    WriteCompactSize(vtx_data, txs.size());
    for (const auto& tx : txs) {
        auto data = tx->Serialize();
        vtx_data.insert(vtx_data.end(), data.begin(), data.end());
    }
    block.vtx = std::move(vtx_data);

    CBlockValidator validator;
    block.hashMerkleRoot = validator.BuildMerkleRoot(txs);
    return block;
}

// Seed the UTXO set with a coinbase output so a follow-up block has
// something to spend. Returns the outpoint of the seeded UTXO and the
// payload (value + script) for round-trip comparison.
struct Seeded {
    COutPoint outpoint;
    CTxOut    out;
    uint32_t  height;
    bool      fCoinBase;
};

Seeded SeedUtxo(CUTXOSet& utxo,
                uint8_t   seed,
                uint64_t  value,
                uint32_t  height,
                bool      coinbase) {
    Seeded s;
    s.outpoint = COutPoint(MakeHash(seed), 0);
    std::vector<uint8_t> spk(25, seed);
    spk[0] = 0x76; spk[1] = 0xa9; spk[2] = 0x14;
    spk[23] = 0x88; spk[24] = 0xac;
    s.out = CTxOut(value, spk);
    s.height = height;
    s.fCoinBase = coinbase;
    BOOST_REQUIRE(utxo.AddUTXO(s.outpoint, s.out, height, coinbase));
    BOOST_REQUIRE(utxo.Flush());
    return s;
}

} // namespace

// ===========================================================================
// Test 1: round-trip on a typical block (1 coinbase + 1 spender of 2 inputs).
// ===========================================================================

BOOST_AUTO_TEST_CASE(read_undo_round_trip) {
    TempUtxoScope scope("round_trip");

    // Seed two existing UTXOs that the new block will spend.
    auto seed_a = SeedUtxo(scope.utxo(), 0xA1, 50'000'000ULL, 10, false);
    auto seed_b = SeedUtxo(scope.utxo(), 0xB2, 75'000'000ULL, 11, true);

    // Build a block: coinbase + spender consuming both seeded UTXOs.
    auto coinbase = MakeCoinbase(/*height=*/100, /*reward=*/12'500'000ULL, 0xC0);
    auto spender  = MakeSpender({seed_a.outpoint, seed_b.outpoint},
                                {30'000'000ULL, 90'000'000ULL},
                                0xD0);
    auto block    = MakeBlock({coinbase, spender}, /*time_off=*/0);
    auto block_hash = MakeHash(0x42);

    BOOST_REQUIRE(scope.utxo().ApplyBlock(block, /*height=*/100, block_hash));
    BOOST_REQUIRE(scope.utxo().HasUndoData(block_hash));

    CBlockUndo undo;
    BOOST_REQUIRE(scope.utxo().ReadUndoBlock(block_hash, undo));

    // Two spent inputs, in the order the writer iterates (vin order of
    // the spender; coinbase is skipped).
    BOOST_REQUIRE_EQUAL(undo.size(), 2u);

    BOOST_CHECK(undo.vSpent[0].outpoint == seed_a.outpoint);
    BOOST_CHECK_EQUAL(undo.vSpent[0].out.nValue, seed_a.out.nValue);
    BOOST_CHECK(undo.vSpent[0].out.scriptPubKey == seed_a.out.scriptPubKey);
    BOOST_CHECK_EQUAL(undo.vSpent[0].nHeight, seed_a.height);
    BOOST_CHECK_EQUAL(undo.vSpent[0].fCoinBase, seed_a.fCoinBase);

    BOOST_CHECK(undo.vSpent[1].outpoint == seed_b.outpoint);
    BOOST_CHECK_EQUAL(undo.vSpent[1].out.nValue, seed_b.out.nValue);
    BOOST_CHECK(undo.vSpent[1].out.scriptPubKey == seed_b.out.scriptPubKey);
    BOOST_CHECK_EQUAL(undo.vSpent[1].nHeight, seed_b.height);
    BOOST_CHECK_EQUAL(undo.vSpent[1].fCoinBase, seed_b.fCoinBase);
}

// ===========================================================================
// Test 2: missing-block lookup returns false and clears the output.
// ===========================================================================

BOOST_AUTO_TEST_CASE(read_undo_missing_block) {
    TempUtxoScope scope("missing");

    // Pre-populate the output with junk so we can prove ReadUndoBlock
    // clears it on failure.
    CBlockUndo undo;
    undo.vSpent.emplace_back(
        COutPoint(MakeHash(0xEE), 7),
        CTxOut(999ULL, std::vector<uint8_t>{0x01, 0x02}),
        42u, false);
    BOOST_REQUIRE_EQUAL(undo.size(), 1u);

    auto absent = MakeHash(0xFF);
    BOOST_CHECK(!scope.utxo().HasUndoData(absent));

    bool ok = scope.utxo().ReadUndoBlock(absent, undo);
    BOOST_CHECK(!ok);
    BOOST_CHECK(undo.empty());  // cleared on failure
}

// ===========================================================================
// Test 3: empty-undo block (coinbase-only -> spentCount=0).
// ===========================================================================

BOOST_AUTO_TEST_CASE(read_undo_empty_block) {
    TempUtxoScope scope("empty");

    auto coinbase = MakeCoinbase(/*height=*/0, /*reward=*/50'000'000ULL, 0xC1);
    auto block    = MakeBlock({coinbase}, /*time_off=*/0);
    auto block_hash = MakeHash(0x01);

    BOOST_REQUIRE(scope.utxo().ApplyBlock(block, /*height=*/0, block_hash));
    BOOST_REQUIRE(scope.utxo().HasUndoData(block_hash));

    CBlockUndo undo;
    BOOST_REQUIRE(scope.utxo().ReadUndoBlock(block_hash, undo));
    BOOST_CHECK(undo.empty());
    BOOST_CHECK_EQUAL(undo.size(), 0u);
}

// ===========================================================================
// Test 4: large-block round-trip (1 coinbase + 1 spender consuming 256
// seeded UTXOs).
// ===========================================================================

BOOST_AUTO_TEST_CASE(read_undo_large_block) {
    TempUtxoScope scope("large");

    constexpr size_t kInputs = 256;

    // Seed kInputs UTXOs with varying value, height, coinbase flag, and
    // script length so the round-trip exercises every record field.
    std::vector<Seeded> seeded;
    seeded.reserve(kInputs);
    std::mt19937 rng(0xC0FFEE);
    for (size_t i = 0; i < kInputs; ++i) {
        Seeded s;
        s.outpoint = COutPoint(MakeHash(static_cast<uint8_t>(i & 0xFF)),
                               static_cast<uint32_t>(i));
        // Vary script size 1..200 to exercise multi-byte boundary cases.
        const size_t script_size = 1 + (i % 200);
        std::vector<uint8_t> spk(script_size,
                                 static_cast<uint8_t>(rng() & 0xFF));
        s.out = CTxOut(1'000ULL + i, spk);
        s.height = static_cast<uint32_t>(i + 1);
        s.fCoinBase = (i % 7 == 0);
        BOOST_REQUIRE(scope.utxo().AddUTXO(s.outpoint, s.out, s.height, s.fCoinBase));
        seeded.push_back(s);
    }
    BOOST_REQUIRE(scope.utxo().Flush());

    // Build the spender that consumes every seeded UTXO.
    std::vector<COutPoint> inputs;
    inputs.reserve(kInputs);
    for (const auto& s : seeded) inputs.push_back(s.outpoint);

    auto coinbase = MakeCoinbase(/*height=*/500, /*reward=*/12'500'000ULL, 0xC2);
    auto spender  = MakeSpender(inputs, {1'000'000ULL}, 0xD2);
    auto block    = MakeBlock({coinbase, spender}, /*time_off=*/1);
    auto block_hash = MakeHash(0xAB);

    BOOST_REQUIRE(scope.utxo().ApplyBlock(block, /*height=*/500, block_hash));

    CBlockUndo undo;
    BOOST_REQUIRE(scope.utxo().ReadUndoBlock(block_hash, undo));
    BOOST_REQUIRE_EQUAL(undo.size(), kInputs);

    // Verify every record byte-for-byte against the seeded values.
    for (size_t i = 0; i < kInputs; ++i) {
        BOOST_CHECK(undo.vSpent[i].outpoint == seeded[i].outpoint);
        BOOST_CHECK_EQUAL(undo.vSpent[i].out.nValue, seeded[i].out.nValue);
        BOOST_CHECK(undo.vSpent[i].out.scriptPubKey == seeded[i].out.scriptPubKey);
        BOOST_CHECK_EQUAL(undo.vSpent[i].nHeight, seeded[i].height);
        BOOST_CHECK_EQUAL(undo.vSpent[i].fCoinBase, seeded[i].fCoinBase);
    }
}

// ===========================================================================
// Test 5: closed db -> ReadUndoBlock returns false (no crash).
// ===========================================================================

BOOST_AUTO_TEST_CASE(read_undo_closed_db) {
    CUTXOSet utxo;
    BOOST_CHECK(!utxo.IsOpen());

    CBlockUndo undo;
    bool ok = utxo.ReadUndoBlock(MakeHash(0x77), undo);
    BOOST_CHECK(!ok);
    BOOST_CHECK(undo.empty());
}

// ===========================================================================
// Test 6: corrupted footer -> ReadUndoBlock returns false. We round-trip
// through ApplyBlock to write a real entry, then reach into the LevelDB
// directly to flip the last byte (the SHA3 footer).
// ===========================================================================

BOOST_AUTO_TEST_CASE(read_undo_corrupted_checksum) {
    auto path = MakeTempDir("corruption");

    auto block_hash = MakeHash(0x55);
    auto seed       = MakeHash(0xA9);

    {
        CUTXOSet utxo;
        BOOST_REQUIRE(utxo.Open(path.string(), true));

        // Seed + spend so we have a non-trivial undo entry.
        Seeded s;
        s.outpoint = COutPoint(seed, 0);
        std::vector<uint8_t> spk(25, 0xA9);
        spk[0] = 0x76; spk[1] = 0xa9; spk[2] = 0x14;
        spk[23] = 0x88; spk[24] = 0xac;
        s.out = CTxOut(50'000'000ULL, spk);
        BOOST_REQUIRE(utxo.AddUTXO(s.outpoint, s.out, 5, false));
        BOOST_REQUIRE(utxo.Flush());

        auto coinbase = MakeCoinbase(/*height=*/200, /*reward=*/12'500'000ULL, 0xC3);
        auto spender  = MakeSpender({s.outpoint}, {40'000'000ULL}, 0xD3);
        auto block    = MakeBlock({coinbase, spender}, /*time_off=*/2);

        BOOST_REQUIRE(utxo.ApplyBlock(block, /*height=*/200, block_hash));

        // Sanity: clean read works.
        CBlockUndo undo;
        BOOST_REQUIRE(utxo.ReadUndoBlock(block_hash, undo));
        BOOST_REQUIRE_EQUAL(undo.size(), 1u);

        utxo.Close();
    }

    // Reach into the underlying LevelDB and flip the last byte of the
    // undo entry (the SHA3 checksum). Then reopen via CUTXOSet and confirm
    // ReadUndoBlock rejects the entry.
    {
        leveldb::DB* raw_db = nullptr;
        leveldb::Options opts;
        opts.create_if_missing = false;
        BOOST_REQUIRE(leveldb::DB::Open(opts, path.string(), &raw_db).ok());
        std::unique_ptr<leveldb::DB> db_owner(raw_db);

        std::string key = "undo_";
        key.append(reinterpret_cast<const char*>(block_hash.data), 32);

        std::string val;
        BOOST_REQUIRE(db_owner->Get(leveldb::ReadOptions(), key, &val).ok());
        BOOST_REQUIRE(val.size() >= 36u);
        // Flip the last byte.
        val[val.size() - 1] ^= 0xFF;
        BOOST_REQUIRE(db_owner->Put(leveldb::WriteOptions(), key, val).ok());
        db_owner.reset();
    }

    {
        CUTXOSet utxo;
        BOOST_REQUIRE(utxo.Open(path.string(), false));

        CBlockUndo undo;
        bool ok = utxo.ReadUndoBlock(block_hash, undo);
        BOOST_CHECK(!ok);
        BOOST_CHECK(undo.empty());

        utxo.Close();
    }

    CleanupTempDir(path);
}

// ===========================================================================
// Test 7: truncated entry -> ReadUndoBlock returns false. Same setup as the
// checksum test, but we lop off the last 16 bytes (which puts the read
// below the 36-byte minimum required).
// ===========================================================================

BOOST_AUTO_TEST_CASE(read_undo_truncated) {
    auto path = MakeTempDir("truncated");

    auto block_hash = MakeHash(0x66);

    {
        CUTXOSet utxo;
        BOOST_REQUIRE(utxo.Open(path.string(), true));

        auto coinbase = MakeCoinbase(/*height=*/0, /*reward=*/50'000'000ULL, 0xC4);
        auto block    = MakeBlock({coinbase}, /*time_off=*/3);

        BOOST_REQUIRE(utxo.ApplyBlock(block, /*height=*/0, block_hash));
        utxo.Close();
    }

    {
        leveldb::DB* raw_db = nullptr;
        leveldb::Options opts;
        opts.create_if_missing = false;
        BOOST_REQUIRE(leveldb::DB::Open(opts, path.string(), &raw_db).ok());
        std::unique_ptr<leveldb::DB> db_owner(raw_db);

        std::string key = "undo_";
        key.append(reinterpret_cast<const char*>(block_hash.data), 32);

        std::string val;
        BOOST_REQUIRE(db_owner->Get(leveldb::ReadOptions(), key, &val).ok());
        // Truncate so the value is below the minimum (4 + 32 = 36 bytes).
        // An empty-undo entry is exactly 36 bytes; lopping any non-zero
        // amount off pushes us under.
        val.resize(val.size() / 2);
        BOOST_REQUIRE(db_owner->Put(leveldb::WriteOptions(), key, val).ok());
        db_owner.reset();
    }

    {
        CUTXOSet utxo;
        BOOST_REQUIRE(utxo.Open(path.string(), false));

        CBlockUndo undo;
        bool ok = utxo.ReadUndoBlock(block_hash, undo);
        BOOST_CHECK(!ok);
        BOOST_CHECK(undo.empty());

        utxo.Close();
    }

    CleanupTempDir(path);
}

// ===========================================================================
// Test 8: bogus spentCount that overflows the payload bound. We craft a raw
// LevelDB entry with a huge declared count and a fresh SHA3 footer so the
// checksum passes; the per-record bound check must reject it before any
// allocation.
// ===========================================================================

BOOST_AUTO_TEST_CASE(read_undo_bogus_spent_count) {
    auto path = MakeTempDir("bogus_count");
    auto block_hash = MakeHash(0x99);

    {
        CUTXOSet utxo;
        BOOST_REQUIRE(utxo.Open(path.string(), true));
        utxo.Close();
    }

    {
        leveldb::DB* raw_db = nullptr;
        leveldb::Options opts;
        opts.create_if_missing = false;
        BOOST_REQUIRE(leveldb::DB::Open(opts, path.string(), &raw_db).ok());
        std::unique_ptr<leveldb::DB> db_owner(raw_db);

        // Body: spentCount = 0xFFFFFFFF, then no records.
        std::vector<uint8_t> body(4, 0xFF);

        // Append a valid SHA3-256 footer over body.
        uint8_t checksum[32];
        SHA3_256(body.data(), body.size(), checksum);
        body.insert(body.end(), checksum, checksum + 32);

        std::string key = "undo_";
        key.append(reinterpret_cast<const char*>(block_hash.data), 32);
        std::string val(reinterpret_cast<const char*>(body.data()), body.size());
        BOOST_REQUIRE(db_owner->Put(leveldb::WriteOptions(), key, val).ok());
        db_owner.reset();
    }

    {
        CUTXOSet utxo;
        BOOST_REQUIRE(utxo.Open(path.string(), false));

        CBlockUndo undo;
        bool ok = utxo.ReadUndoBlock(block_hash, undo);
        BOOST_CHECK(!ok);
        BOOST_CHECK(undo.empty());

        utxo.Close();
    }

    CleanupTempDir(path);
}

BOOST_AUTO_TEST_SUITE_END()
