// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <boost/test/unit_test.hpp>

#include <node/mempool_persist.h>

#include <node/mempool.h>
#include <rpc/server.h>
#include <crypto/sha3.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <random>
#include <string>
#include <system_error>
#include <vector>

BOOST_AUTO_TEST_SUITE(mempool_persist_tests)

namespace {

// Make a unique synthetic transaction. Two seed bytes give 65k unique txs --
// enough headroom for the large-mempool test.
CTransactionRef MakePersistTestTx(uint8_t seed_a, uint8_t seed_b) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    uint256 prev;
    std::memset(prev.data, seed_a, 32);
    prev.data[31] = seed_b;     // make prevout unique across all 65k seeds
    std::vector<uint8_t> sig{seed_a, seed_b, 0xAA, 0xBB};
    tx.vin.push_back(CTxIn(prev, seed_b, sig, CTxIn::SEQUENCE_FINAL));
    std::vector<uint8_t> spk{0x76, 0xa9, 0x14, seed_a, seed_b};
    tx.vout.push_back(CTxOut(1000ULL + (seed_a * 256 + seed_b), spk));
    return MakeTransactionRef(tx);
}

std::filesystem::path MakeTempDir(const std::string& tag) {
    auto base = std::filesystem::temp_directory_path();
    auto path = base / ("mempool_persist_test_" + tag + "_" +
        std::to_string(static_cast<long long>(
            std::chrono::steady_clock::now().time_since_epoch().count())));
    std::filesystem::create_directories(path);
    return path;
}

void CleanupTempDir(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

class TempDir {
public:
    explicit TempDir(const std::string& tag) : m_path(MakeTempDir(tag)) {}
    ~TempDir() { CleanupTempDir(m_path); }
    const std::filesystem::path& path() const { return m_path; }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
private:
    std::filesystem::path m_path;
};

// Helper: populate `mempool` with N synthetic txs at the given height with a
// provided fee. Returns the count actually admitted.
size_t PopulateMempool(CTxMemPool& mempool, size_t n,
                       unsigned int height = 1,
                       CAmount fee = 100) {
    const int64_t now = std::time(nullptr);
    size_t added = 0;
    for (size_t i = 0; i < n; ++i) {
        const uint8_t a = static_cast<uint8_t>((i >> 8) & 0xFF);
        const uint8_t b = static_cast<uint8_t>(i & 0xFF);
        auto tx = MakePersistTestTx(a, b);
        std::string err;
        if (mempool.AddTx(tx, fee, /*time=*/now, /*height=*/height,
                          &err, /*bypass_fee_check=*/true)) {
            ++added;
        }
    }
    return added;
}

// Build a mempool.dat file by hand for malformed-input tests. Caller supplies
// the in-the-clear payload (everything between the version+key header and the
// footer); we add the version, key, scramble, and footer.
void WriteForgedMempoolFile(const std::filesystem::path& datadir,
                            const std::vector<uint8_t>& clear_body) {
    std::vector<uint8_t> bytes;
    bytes.reserve(1 + mempool_persist::XOR_KEY_SIZE + clear_body.size() +
                  mempool_persist::FOOTER_SIZE);

    bytes.push_back(mempool_persist::SCHEMA_VERSION);

    // Generate a deterministic-ish key for tests (so failures are reproducible).
    std::vector<uint8_t> key(mempool_persist::XOR_KEY_SIZE);
    for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i ^ 0xA5);
    bytes.insert(bytes.end(), key.begin(), key.end());

    // Compute footer over the UNSCRAMBLED [version + key + clear_body].
    std::vector<uint8_t> for_hash = bytes;
    for_hash.insert(for_hash.end(), clear_body.begin(), clear_body.end());
    uint8_t hash_full[32];
    SHA3_256(for_hash.data(), for_hash.size(), hash_full);

    // Append clear body, then XOR-scramble the body.
    const size_t body_start = bytes.size();
    bytes.insert(bytes.end(), clear_body.begin(), clear_body.end());
    for (size_t i = 0; i < clear_body.size(); ++i) {
        bytes[body_start + i] ^= key[i % key.size()];
    }

    // Append the footer (truncated SHA3-256), also scrambled.
    const size_t footer_offset = bytes.size() - body_start;
    for (size_t i = 0; i < mempool_persist::FOOTER_SIZE; ++i) {
        bytes.push_back(hash_full[i] ^ key[(footer_offset + i) % key.size()]);
    }

    const auto fp = datadir / mempool_persist::FILENAME;
    std::ofstream f(fp.string(), std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

}  // anonymous namespace

// ---- C1: round-trip basic + identity (B3) -------------------------------

BOOST_AUTO_TEST_CASE(roundtrip_basic) {
    TempDir scope("roundtrip_basic");

    CTxMemPool mp_dump;
    BOOST_REQUIRE_EQUAL(PopulateMempool(mp_dump, 5, /*height=*/1, /*fee=*/250), 5u);
    BOOST_REQUIRE_EQUAL(mp_dump.Size(), 5u);

    // B3: capture the dumped {txid -> (fee, time)} map for identity check.
    std::map<uint256, std::pair<int64_t, int64_t>> dumped;
    for (const auto& e : mp_dump.GetAllEntries()) {
        dumped[e.GetTxHash()] = {e.GetTime(), static_cast<int64_t>(e.GetFee())};
    }

    auto dump = mempool_persist::DumpMempool(mp_dump, scope.path());
    BOOST_REQUIRE(dump.success);
    BOOST_REQUIRE_EQUAL(dump.txs_written, 5u);

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(!load.cold_start);
    BOOST_CHECK_EQUAL(load.txs_read, 5u);
    BOOST_CHECK_EQUAL(load.txs_admitted, 5u);
    BOOST_CHECK_EQUAL(mp_load.Size(), 5u);

    // B3: identity assertion -- every dumped tx must be loaded with the same
    // (fee, time). A bug that wrote fee=0 or swapped the time/fee fields
    // would surface here.
    for (const auto& e : mp_load.GetAllEntries()) {
        auto it = dumped.find(e.GetTxHash());
        BOOST_REQUIRE_MESSAGE(it != dumped.end(),
            "loaded tx not found in dumped set: " << e.GetTxHash().GetHex());
        BOOST_CHECK_EQUAL(e.GetTime(), it->second.first);
        BOOST_CHECK_EQUAL(static_cast<int64_t>(e.GetFee()), it->second.second);
    }
    BOOST_CHECK_EQUAL(mp_load.Size(), dumped.size());
}

// ---- C2: round-trip empty -----------------------------------------------

BOOST_AUTO_TEST_CASE(roundtrip_empty) {
    TempDir scope("roundtrip_empty");

    CTxMemPool mp_dump;
    BOOST_REQUIRE_EQUAL(mp_dump.Size(), 0u);

    auto dump = mempool_persist::DumpMempool(mp_dump, scope.path());
    BOOST_REQUIRE(dump.success);
    BOOST_CHECK_EQUAL(dump.txs_written, 0u);

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(!load.cold_start);
    BOOST_CHECK_EQUAL(load.txs_read, 0u);
    BOOST_CHECK_EQUAL(load.txs_admitted, 0u);
    BOOST_CHECK_EQUAL(mp_load.Size(), 0u);
}

// ---- C3: round-trip large + identity (B3) -------------------------------

BOOST_AUTO_TEST_CASE(roundtrip_large) {
    TempDir scope("roundtrip_large");
    constexpr size_t kCount = 1000;

    CTxMemPool mp_dump;
    BOOST_REQUIRE_EQUAL(PopulateMempool(mp_dump, kCount), kCount);

    std::map<uint256, std::pair<int64_t, int64_t>> dumped;
    for (const auto& e : mp_dump.GetAllEntries()) {
        dumped[e.GetTxHash()] = {e.GetTime(), static_cast<int64_t>(e.GetFee())};
    }

    auto dump = mempool_persist::DumpMempool(mp_dump, scope.path());
    BOOST_REQUIRE(dump.success);
    BOOST_CHECK_EQUAL(dump.txs_written, kCount);

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK_EQUAL(load.txs_read, kCount);
    BOOST_CHECK_EQUAL(load.txs_admitted, kCount);
    BOOST_CHECK_EQUAL(mp_load.Size(), kCount);

    // B3: identity check across all 1000 entries.
    size_t identity_matches = 0;
    for (const auto& e : mp_load.GetAllEntries()) {
        auto it = dumped.find(e.GetTxHash());
        if (it == dumped.end()) continue;
        if (e.GetTime() != it->second.first) continue;
        if (static_cast<int64_t>(e.GetFee()) != it->second.second) continue;
        ++identity_matches;
    }
    BOOST_CHECK_EQUAL(identity_matches, kCount);
}

// ---- C4: missing file -> cold start --------------------------------------

BOOST_AUTO_TEST_CASE(missing_file_cold_start) {
    TempDir scope("missing_file");
    BOOST_REQUIRE(!std::filesystem::exists(scope.path() / mempool_persist::FILENAME));

    CTxMemPool mp;
    auto load = mempool_persist::LoadMempool(mp, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK_EQUAL(load.txs_read, 0u);
    BOOST_CHECK_EQUAL(mp.Size(), 0u);
}

// ---- C5: truncated file -> cold start ------------------------------------

BOOST_AUTO_TEST_CASE(corrupt_truncated_cold_start) {
    TempDir scope("corrupt_truncated");

    CTxMemPool mp_dump;
    BOOST_REQUIRE_EQUAL(PopulateMempool(mp_dump, 3), 3u);
    BOOST_REQUIRE(mempool_persist::DumpMempool(mp_dump, scope.path()).success);

    const auto fp = scope.path() / mempool_persist::FILENAME;
    {
        std::error_code ec;
        std::filesystem::resize_file(fp, mempool_persist::MIN_FILE_SIZE - 1, ec);
        BOOST_REQUIRE(!ec);
    }

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK_EQUAL(mp_load.Size(), 0u);
}

// ---- C6: bad version byte -> cold start ----------------------------------

BOOST_AUTO_TEST_CASE(corrupt_bad_version_cold_start) {
    TempDir scope("corrupt_bad_version");

    CTxMemPool mp_dump;
    BOOST_REQUIRE_EQUAL(PopulateMempool(mp_dump, 2), 2u);
    BOOST_REQUIRE(mempool_persist::DumpMempool(mp_dump, scope.path()).success);

    const auto fp = scope.path() / mempool_persist::FILENAME;
    {
        std::fstream f(fp.string(), std::ios::binary | std::ios::in | std::ios::out);
        BOOST_REQUIRE(f.is_open());
        f.seekp(0);
        const uint8_t bad = 0xFF;
        f.write(reinterpret_cast<const char*>(&bad), 1);
    }

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK_EQUAL(mp_load.Size(), 0u);
}

// ---- C7: corrupted footer -> cold start ----------------------------------

BOOST_AUTO_TEST_CASE(corrupt_footer_cold_start) {
    TempDir scope("corrupt_footer");

    CTxMemPool mp_dump;
    BOOST_REQUIRE_EQUAL(PopulateMempool(mp_dump, 2), 2u);
    BOOST_REQUIRE(mempool_persist::DumpMempool(mp_dump, scope.path()).success);

    const auto fp = scope.path() / mempool_persist::FILENAME;
    const auto file_size = std::filesystem::file_size(fp);
    {
        std::fstream f(fp.string(), std::ios::binary | std::ios::in | std::ios::out);
        BOOST_REQUIRE(f.is_open());
        f.seekp(file_size - 1);
        const uint8_t flipped = 0xCC;
        f.write(reinterpret_cast<const char*>(&flipped), 1);
    }

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK_EQUAL(mp_load.Size(), 0u);
}

// ---- C8: forced EARLY dump failure -> previous file intact ---------------

BOOST_AUTO_TEST_CASE(atomicity_forced_early_failure) {
    TempDir scope("atomicity_early");

    CTxMemPool mp_first;
    BOOST_REQUIRE_EQUAL(PopulateMempool(mp_first, 3), 3u);
    BOOST_REQUIRE(mempool_persist::DumpMempool(mp_first, scope.path()).success);
    const auto fp = scope.path() / mempool_persist::FILENAME;
    BOOST_REQUIRE(std::filesystem::exists(fp));
    const auto first_size = std::filesystem::file_size(fp);

    CTxMemPool mp_second;
    BOOST_REQUIRE_EQUAL(PopulateMempool(mp_second, 5), 5u);
    mempool_persist::test_hooks::g_force_dump_failure.store(true);
    auto dump = mempool_persist::DumpMempool(mp_second, scope.path());
    mempool_persist::test_hooks::g_force_dump_failure.store(false);
    BOOST_CHECK(!dump.success);
    BOOST_CHECK(!dump.error_message.empty());

    BOOST_REQUIRE(std::filesystem::exists(fp));
    BOOST_CHECK_EQUAL(std::filesystem::file_size(fp), first_size);
    BOOST_CHECK(!std::filesystem::exists(scope.path() / mempool_persist::FILENAME_TMP));

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK_EQUAL(load.txs_admitted, 3u);
}

// ---- B2: forced LATE dump failure -> .new cleaned up, prior file intact --

BOOST_AUTO_TEST_CASE(atomicity_forced_late_failure) {
    TempDir scope("atomicity_late");

    // Step 1: write a valid mempool.dat.
    CTxMemPool mp_first;
    BOOST_REQUIRE_EQUAL(PopulateMempool(mp_first, 3), 3u);
    BOOST_REQUIRE(mempool_persist::DumpMempool(mp_first, scope.path()).success);
    const auto fp = scope.path() / mempool_persist::FILENAME;
    const auto fp_tmp = scope.path() / mempool_persist::FILENAME_TMP;
    const auto first_size = std::filesystem::file_size(fp);

    // Step 2: try to overwrite, fail AFTER .new is fully written and fflush'd.
    // This exercises the actual cleanup path (.new file exists at injection
    // point) -- the early-failure test cannot cover it.
    CTxMemPool mp_second;
    BOOST_REQUIRE_EQUAL(PopulateMempool(mp_second, 7), 7u);
    mempool_persist::test_hooks::g_force_late_dump_failure.store(true);
    auto dump = mempool_persist::DumpMempool(mp_second, scope.path());
    mempool_persist::test_hooks::g_force_late_dump_failure.store(false);
    BOOST_CHECK(!dump.success);
    BOOST_CHECK(dump.error_message.find("late") != std::string::npos);

    // Step 3: .new file must have been cleaned up.
    BOOST_CHECK(!std::filesystem::exists(fp_tmp));

    // Step 4: prior mempool.dat untouched.
    BOOST_REQUIRE(std::filesystem::exists(fp));
    BOOST_CHECK_EQUAL(std::filesystem::file_size(fp), first_size);

    // Step 5: load yields the FIRST mempool's 3 txs, not the failed-second's 7.
    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK_EQUAL(load.txs_admitted, 3u);
}

// ---- C9: schema lock-in (validates structural shape, not exact bytes) ---

BOOST_AUTO_TEST_CASE(schema_lock_in_structure) {
    TempDir scope("schema_lock");

    CTxMemPool mp;
    auto tx = MakePersistTestTx(0xAA, 0x55);
    std::string err;
    constexpr int64_t kFixedTime = 1700000000;
    BOOST_REQUIRE(mp.AddTx(tx, /*fee=*/777, kFixedTime, /*height=*/1,
                           &err, /*bypass_fee_check=*/true));

    auto dump = mempool_persist::DumpMempool(mp, scope.path());
    BOOST_REQUIRE(dump.success);

    const auto fp = scope.path() / mempool_persist::FILENAME;
    std::ifstream f(fp.string(), std::ios::binary);
    BOOST_REQUIRE(f.is_open());
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());

    // Structural shape:
    //   +0           u8 version
    //   +1           u8[32] xor_key
    //   +33..end-8   scrambled body (variable length)
    //   +end-8..end  scrambled footer
    BOOST_REQUIRE_GT(bytes.size(),
                     1u + mempool_persist::XOR_KEY_SIZE +
                     mempool_persist::FOOTER_SIZE);
    BOOST_CHECK_EQUAL(bytes[0], mempool_persist::SCHEMA_VERSION);

    // The XOR key is in-the-clear at +1; we don't pin its value (random
    // per dump), only its presence and size.
    // Body + footer must round-trip via LoadMempool, which is the real
    // schema verifier; this test guards against accidental file-shape
    // changes (e.g., a future PR adding a field without bumping version).
    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK_EQUAL(load.txs_admitted, 1u);
    BOOST_CHECK_EQUAL(mp_load.Size(), 1u);

    // Verify the loaded tx has the exact pinned (fee, time).
    auto loaded_entries = mp_load.GetAllEntries();
    BOOST_REQUIRE_EQUAL(loaded_entries.size(), 1u);
    BOOST_CHECK_EQUAL(loaded_entries[0].GetTime(), kFixedTime);
    BOOST_CHECK_EQUAL(static_cast<int64_t>(loaded_entries[0].GetFee()), 777);
}

// ---- B1: oversize file -> cold start (DoS protection) -------------------

BOOST_AUTO_TEST_CASE(b1_oversize_file_cold_start) {
    TempDir scope("oversize");
    const auto fp = scope.path() / mempool_persist::FILENAME;

    // Create a file that exceeds MAX_FILE_SIZE without actually writing
    // 512 MB of zeros: use truncate-to-size which is sparse on most FSes.
    std::ofstream f(fp.string(), std::ios::binary | std::ios::trunc);
    f.put(0x01);
    f.close();
    std::error_code ec;
    std::filesystem::resize_file(fp, mempool_persist::MAX_FILE_SIZE + 1, ec);
    BOOST_REQUIRE(!ec);

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);            // not catastrophic
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK(load.cold_start_reason.find("MAX_FILE_SIZE") != std::string::npos);
    BOOST_CHECK_EQUAL(mp_load.Size(), 0u);
}

// ---- C4-a: tx_count > MAX_TX_COUNT -> cold start ------------------------

BOOST_AUTO_TEST_CASE(c4a_overcap_tx_count_cold_start) {
    TempDir scope("c4a_overcap_tx_count");

    // Forge a body with tx_count = MAX_TX_COUNT + 1, no actual tx records.
    std::vector<uint8_t> clear_body;
    const uint64_t bad_count = mempool_persist::MAX_TX_COUNT + 1;
    for (int i = 0; i < 8; ++i) {
        clear_body.push_back(static_cast<uint8_t>((bad_count >> (i * 8)) & 0xFF));
    }
    WriteForgedMempoolFile(scope.path(), clear_body);

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK(load.cold_start_reason.find("tx_count") != std::string::npos);
    BOOST_CHECK_EQUAL(mp_load.Size(), 0u);
}

// ---- C4-b: tx_size mid-stream too large -> cold start -------------------

BOOST_AUTO_TEST_CASE(c4b_overcap_tx_size_cold_start) {
    TempDir scope("c4b_overcap_tx_size");

    // Forge: tx_count=1, then tx_size = MAX_TX_SIZE+1.
    std::vector<uint8_t> clear_body;
    const uint64_t count = 1;
    for (int i = 0; i < 8; ++i)
        clear_body.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
    const uint32_t bad_tx_size = mempool_persist::MAX_TX_SIZE + 1;
    for (int i = 0; i < 4; ++i)
        clear_body.push_back(static_cast<uint8_t>((bad_tx_size >> (i * 8)) & 0xFF));

    WriteForgedMempoolFile(scope.path(), clear_body);

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK(load.cold_start_reason.find("malformed tx_size") != std::string::npos);
}

// ---- C4-c: tx_size = 0 -> cold start ------------------------------------

BOOST_AUTO_TEST_CASE(c4c_zero_tx_size_cold_start) {
    TempDir scope("c4c_zero_tx_size");

    std::vector<uint8_t> clear_body;
    const uint64_t count = 1;
    for (int i = 0; i < 8; ++i)
        clear_body.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
    // tx_size = 0
    clear_body.insert(clear_body.end(), {0x00, 0x00, 0x00, 0x00});

    WriteForgedMempoolFile(scope.path(), clear_body);

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK(load.cold_start_reason.find("malformed tx_size") != std::string::npos);
}

// ---- C4-d: read-past-end mid-tx -> cold start ---------------------------

BOOST_AUTO_TEST_CASE(c4d_read_past_end_cold_start) {
    TempDir scope("c4d_read_past_end");

    // tx_count=1, tx_size=100, but only 5 bytes of tx body present.
    std::vector<uint8_t> clear_body;
    const uint64_t count = 1;
    for (int i = 0; i < 8; ++i)
        clear_body.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
    const uint32_t tx_size = 100;
    for (int i = 0; i < 4; ++i)
        clear_body.push_back(static_cast<uint8_t>((tx_size >> (i * 8)) & 0xFF));
    // Only 5 bytes of tx (claimed 100); CDataStream::read should throw.
    clear_body.insert(clear_body.end(), {0x01, 0x02, 0x03, 0x04, 0x05});

    WriteForgedMempoolFile(scope.path(), clear_body);

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK(load.cold_start_reason.find("stream error") != std::string::npos);
}

// ---- C4-e: tx body fails Deserialize but stream stays valid -------------

BOOST_AUTO_TEST_CASE(c4e_garbage_tx_body_dropped_invalid) {
    TempDir scope("c4e_garbage_tx_body");

    // tx_count=1, tx_size=10, 10 bytes of garbage that won't deserialize as
    // a valid CTransaction, then valid entry_time + fee_paid trailing.
    std::vector<uint8_t> clear_body;
    const uint64_t count = 1;
    for (int i = 0; i < 8; ++i)
        clear_body.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
    const uint32_t tx_size = 10;
    for (int i = 0; i < 4; ++i)
        clear_body.push_back(static_cast<uint8_t>((tx_size >> (i * 8)) & 0xFF));
    // 10 bytes of garbage tx data.
    for (int i = 0; i < 10; ++i)
        clear_body.push_back(static_cast<uint8_t>(0xDE + i));
    // entry_time (i64) and fee (i64) -- these must STILL be readable.
    const int64_t t = 1700000000;
    const int64_t fee = 999;
    for (int i = 0; i < 8; ++i)
        clear_body.push_back(static_cast<uint8_t>((t >> (i * 8)) & 0xFF));
    for (int i = 0; i < 8; ++i)
        clear_body.push_back(static_cast<uint8_t>((fee >> (i * 8)) & 0xFF));

    WriteForgedMempoolFile(scope.path(), clear_body);

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(!load.cold_start);          // file structure is valid
    BOOST_CHECK_EQUAL(load.txs_read, 0u);   // tx didn't deserialize
    BOOST_CHECK_EQUAL(load.txs_admitted, 0u);
    BOOST_CHECK_EQUAL(load.txs_dropped_invalid, 1u);
    BOOST_CHECK_EQUAL(mp_load.Size(), 0u);
}

// ---- C6: bypass_fee_check regression -- restored tx with fee=0 loads ---

BOOST_AUTO_TEST_CASE(c6_bypass_fee_check_regression) {
    // This test admits a tx with fee=0, dumps, and verifies it loads back.
    // Bitcoin Core's Consensus::CheckFee (called when bypass_fee_check=false)
    // typically rejects fee=0. If a future refactor of LoadMempool drops
    // bypass_fee_check=true, this test surfaces the regression immediately.
    TempDir scope("c6_bypass_fee");

    CTxMemPool mp_dump;
    auto tx = MakePersistTestTx(0x42, 0x42);
    std::string err;
    BOOST_REQUIRE(mp_dump.AddTx(tx, /*fee=*/0, std::time(nullptr), 1,
                                &err, /*bypass_fee_check=*/true));
    BOOST_REQUIRE(mempool_persist::DumpMempool(mp_dump, scope.path()).success);

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(!load.cold_start);
    BOOST_CHECK_EQUAL(load.txs_admitted, 1u);
    BOOST_CHECK_EQUAL(mp_load.Size(), 1u);
}

// ---- PR-MP-3: savemempool RPC handler smoke test -----------------------

// Verifies the RPC handler triggers DumpMempool correctly. We don't stand
// up an HTTP server -- we exercise the handler directly via a minimal
// CRPCServer instance, mirroring the getindexinfo schema-lock-in pattern.
BOOST_AUTO_TEST_CASE(savemempool_rpc_handler) {
    TempDir scope("savemempool_rpc");

    CTxMemPool mp;
    BOOST_REQUIRE_EQUAL(PopulateMempool(mp, 3), 3u);

    // Stand up a CRPCServer just for the handler call. We don't call Start();
    // the handler does not depend on the network being up.
    CRPCServer server(/*port=*/18999);
    server.RegisterMempool(&mp);
    server.SetDataDir(scope.path().string());

    // Call the handler directly. It returns JSON {"filename": "<absolute-path>"}
    // matching Bitcoin Core v28.0's savemempool response schema.
    const std::string response = server.RPC_SaveMempool("");

    // Response shape lock: must contain "filename" key and the file's
    // absolute path. We don't pin the exact bytes of the path because
    // absolute paths are platform-specific (Windows backslashes get
    // JSON-escaped to "\\\\").
    BOOST_CHECK(response.find("\"filename\"") != std::string::npos);
    BOOST_CHECK(response.find(mempool_persist::FILENAME) != std::string::npos);

    // File must actually exist on disk and round-trip correctly.
    const auto fp = scope.path() / mempool_persist::FILENAME;
    BOOST_REQUIRE(std::filesystem::exists(fp));

    CTxMemPool mp_load;
    auto load = mempool_persist::LoadMempool(mp_load, scope.path(), 1);
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(!load.cold_start);
    BOOST_CHECK_EQUAL(load.txs_admitted, 3u);
}

// Negative path: missing mempool registration must throw with a clear error.
BOOST_AUTO_TEST_CASE(savemempool_rpc_no_mempool) {
    TempDir scope("savemempool_no_mempool");

    CRPCServer server(/*port=*/18998);
    // Deliberately do NOT call RegisterMempool(); m_mempool stays null.
    server.SetDataDir(scope.path().string());

    BOOST_CHECK_THROW(server.RPC_SaveMempool(""), std::runtime_error);
}

// Negative path: empty datadir must throw with a clear error.
BOOST_AUTO_TEST_CASE(savemempool_rpc_no_datadir) {
    CTxMemPool mp;

    CRPCServer server(/*port=*/18997);
    server.RegisterMempool(&mp);
    // Deliberately do NOT call SetDataDir(); m_dataDir stays empty.

    BOOST_CHECK_THROW(server.RPC_SaveMempool(""), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
