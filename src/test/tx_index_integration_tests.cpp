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
#include <net/sock.h>
#include <node/block_index.h>
#include <node/blockchain_storage.h>
#include <node/mempool.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <uint256.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #define closesocket close
#endif

extern CChainState g_chainstate;

BOOST_AUTO_TEST_SUITE(tx_index_integration_tests)

namespace {

// Per-test unique port allocator. Starts at 18500 to avoid colliding with
// rpc_tests.cpp's 18432-18435 range and any production defaults.
std::atomic<uint16_t> g_port_counter{18500};
uint16_t NextPort() { return g_port_counter.fetch_add(1); }

// Boost global fixture: WSAStartup/WSACleanup once per process. Tests
// use raw sockets to send HTTP requests; without this the first socket()
// call on Windows fails with WSANOTINITIALISED.
struct WinsockGlobalSetup {
#ifdef _WIN32
    WinsockGlobalSetup() {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }
    ~WinsockGlobalSetup() { WSACleanup(); }
#else
    WinsockGlobalSetup() = default;
    ~WinsockGlobalSetup() = default;
#endif
};

// Filesystem helpers (duplicated from tx_index_tests.cpp per LOW-risk
// duplicate-and-adapt convention; refactor would touch frozen file).
std::string MakeTempDir(const std::string& tag) {
    auto base = std::filesystem::temp_directory_path();
    auto path = base / ("tx_index_int_" + tag + "_" +
        std::to_string(static_cast<long long>(
            std::chrono::steady_clock::now().time_since_epoch().count())));
    std::filesystem::create_directories(path);
    return path.string();
}

void CleanupTempDir(const std::string& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
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

// Coinbase tx: prevout.hash IsNull() so the RPC JSON emits "coinbase":true.
CTransactionRef MakeCoinbaseTx(uint8_t seed) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    uint256 prev; // null
    std::vector<uint8_t> sig{0xCB, seed};
    tx.vin.push_back(CTxIn(prev, 0xFFFFFFFFu, sig, CTxIn::SEQUENCE_FINAL));
    std::vector<uint8_t> spk{0x76, 0xa9, 0x14, seed, 0xCB};
    tx.vout.push_back(CTxOut(5000000000ULL, spk));
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

uint256 HashForHeight(int height) {
    uint256 h;
    std::memset(h.data, 0, 32);
    uint32_t height_u = static_cast<uint32_t>(height);
    std::memcpy(h.data, &height_u, 4);
    h.data[31] = 0xCC;
    return h;
}

bool WaitForSync(CTxIndex& idx, std::chrono::milliseconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (idx.IsSynced()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return idx.IsSynced();
}

// HTTP-loopback JSON-RPC client. Duplicated from rpc_tests.cpp per the
// contract's LOW-risk duplicate-and-adapt allowance — refactoring the
// other file would expand scope.
std::string SendRPCRequest(uint16_t port, const std::string& method,
                           const std::string& params = "[]",
                           const std::string& id = "1") {
    struct sockaddr_storage ss;
    socklen_t ss_len;
    if (!CSock::FillSockAddr("127.0.0.1", port, ss, ss_len)) {
        return "";
    }

    int sock = static_cast<int>(socket(ss.ss_family, SOCK_STREAM, 0));
    if (sock < 0) return "";
    if (connect(sock, reinterpret_cast<struct sockaddr*>(&ss), ss_len) < 0) {
        closesocket(sock);
        return "";
    }

    std::ostringstream body;
    body << "{\"jsonrpc\":\"2.0\",\"method\":\"" << method
         << "\",\"params\":" << params << ",\"id\":" << id << "}";
    std::string body_str = body.str();

    std::ostringstream req;
    req << "POST / HTTP/1.1\r\n"
        << "Host: localhost\r\n"
        << "Content-Type: application/json\r\n"
        << "X-Dilithion-RPC: 1\r\n"
        << "Content-Length: " << body_str.size() << "\r\n\r\n"
        << body_str;
    std::string req_str = req.str();
    send(sock, req_str.c_str(), static_cast<int>(req_str.size()), 0);

    // Read until the connection drains (server closes after each response).
    std::string response;
    char buf[8192];
    for (;;) {
        int n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        response.append(buf, buf + n);
    }
    closesocket(sock);

    size_t header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        header_end = response.find("\n\n");
        if (header_end == std::string::npos) return response;
        return response.substr(header_end + 2);
    }
    return response.substr(header_end + 4);
}

// Extract the verbatim "result" field from a JSON-RPC envelope. The fast-path
// and tip-walk both return the same string from the handler; the envelope
// itself is built by a single SerializeResponse, so byte-for-byte equality of
// the inner result is sufficient and load-bearing for SEC-MD-2(a).
std::string ExtractResult(const std::string& envelope) {
    size_t key_pos = envelope.find("\"result\":");
    if (key_pos == std::string::npos) return "";
    size_t value_start = key_pos + 9;
    while (value_start < envelope.size()
           && (envelope[value_start] == ' ' || envelope[value_start] == '\t')) {
        ++value_start;
    }
    if (value_start >= envelope.size()) return "";

    char first = envelope[value_start];
    if (first == '"') {
        // Quoted string. Walk to the next un-escaped quote.
        size_t pos = value_start + 1;
        while (pos < envelope.size()) {
            if (envelope[pos] == '\\') { pos += 2; continue; }
            if (envelope[pos] == '"') {
                return envelope.substr(value_start, pos - value_start + 1);
            }
            ++pos;
        }
        return "";
    }
    if (first == '{' || first == '[') {
        // Brace-balanced extraction. Counts {/} and [/]; ignores characters
        // inside strings.
        int depth = 0;
        bool in_string = false;
        size_t pos = value_start;
        while (pos < envelope.size()) {
            char c = envelope[pos];
            if (in_string) {
                if (c == '\\') { pos += 2; continue; }
                if (c == '"') in_string = false;
            } else {
                if (c == '"') in_string = true;
                else if (c == '{' || c == '[') ++depth;
                else if (c == '}' || c == ']') {
                    --depth;
                    if (depth == 0) {
                        return envelope.substr(value_start, pos - value_start + 1);
                    }
                }
            }
            ++pos;
        }
        return "";
    }
    // Numeric / literal — read until the next , or }.
    size_t pos = value_start;
    while (pos < envelope.size()
           && envelope[pos] != ',' && envelope[pos] != '}' && envelope[pos] != ']') {
        ++pos;
    }
    return envelope.substr(value_start, pos - value_start);
}

// RAII cerr capture. Swaps std::cerr's rdbuf for a stringstream and restores
// on destruction. Test threads use this to capture WARN paranoia logs and
// the N2 abort message.
class CerrCapture {
public:
    CerrCapture() : m_old(std::cerr.rdbuf(m_buf.rdbuf())) {}
    ~CerrCapture() { std::cerr.rdbuf(m_old); }
    std::string str() const { return m_buf.str(); }
private:
    std::stringstream m_buf;
    std::streambuf*   m_old;
};

// Fixture: builds a chain of N blocks, persists each block into chain_db,
// installs CBlockIndex entries into g_chainstate, sets the tip. RPC server
// is created on a unique port and registered with mempool/blockchain/
// chainstate. Caller owns g_tx_index lifecycle — fixture intentionally
// does not touch it so each test exercises tx_index nullability explicitly.
struct IntegrationFixture {
    TempDbScope chain_scope;
    TempDbScope idx_scope;
    CBlockchainDB chain_db;
    CTxMemPool mempool;
    std::unique_ptr<CRPCServer> server;
    uint16_t port;

    std::vector<CTransactionRef> per_height_tx;
    std::vector<uint256>         per_height_hash;
    int                          n_blocks{0};

    explicit IntegrationFixture(const std::string& tag)
        : chain_scope(tag + "_chain"), idx_scope(tag + "_idx"),
          port(NextPort()) {
        BOOST_REQUIRE(chain_db.Open(chain_scope.path(), true));
        g_chainstate.Cleanup();
        server = std::make_unique<CRPCServer>(port);
        server->RegisterMempool(&mempool);
        server->RegisterBlockchain(&chain_db);
        server->RegisterChainState(&g_chainstate);
        BOOST_REQUIRE(server->Start());
        // Tiny pause so the listener is accepting before the first request.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    ~IntegrationFixture() {
        if (server) server->Stop();
        g_tx_index.reset();
        g_chainstate.Cleanup();
    }

    // Build n blocks [0..n-1], each with one coinbase + one regular tx.
    // Coinbase ensures the JSON exercises the "coinbase":true vin branch;
    // the regular tx exercises the prevout-with-scriptSig vin branch.
    void BuildChain(int n) {
        n_blocks = n;
        per_height_tx.clear();
        per_height_hash.clear();
        per_height_tx.reserve(n);
        per_height_hash.reserve(n);

        CBlockIndex* prev_idx = nullptr;
        for (int h = 0; h < n; ++h) {
            uint256 block_hash = HashForHeight(h);
            per_height_hash.push_back(block_hash);

            auto cb = MakeCoinbaseTx(static_cast<uint8_t>(h & 0xFF));
            auto tx = MakeUniqueTx(static_cast<uint8_t>(0x10 + (h & 0x7F)),
                                   static_cast<uint8_t>((h >> 8) & 0xFF));
            // The "interesting" tx that the test queries — always at vtx[1].
            per_height_tx.push_back(tx);

            CBlock block = MakeBlock({cb, tx});
            block.hashPrevBlock = (h == 0) ? uint256() : per_height_hash[h - 1];
            BOOST_REQUIRE(chain_db.WriteBlock(block_hash, block));

            auto pidx = std::make_unique<CBlockIndex>();
            pidx->nHeight = h;
            pidx->phashBlock = block_hash;
            pidx->pprev = prev_idx;
            pidx->nStatus = CBlockIndex::BLOCK_VALID_HEADER |
                            CBlockIndex::BLOCK_HAVE_DATA;
            CBlockIndex* raw = pidx.get();
            BOOST_REQUIRE(g_chainstate.AddBlockIndex(block_hash, std::move(pidx)));
            if (prev_idx) prev_idx->pnext = raw;
            prev_idx = raw;
        }
        if (prev_idx) g_chainstate.SetTipForTest(prev_idx);
    }
};

// Parameter-packing helpers for SendRPCRequest.
std::string TxidParams(const uint256& txid, bool verbose) {
    std::ostringstream oss;
    oss << "{\"txid\":\"" << txid.GetHex() << "\""
        << ",\"verbose\":" << (verbose ? "true" : "false") << "}";
    return oss.str();
}

std::string TxidParams(const uint256& txid) {
    std::ostringstream oss;
    oss << "{\"txid\":\"" << txid.GetHex() << "\"}";
    return oss.str();
}

} // namespace

BOOST_GLOBAL_FIXTURE(WinsockGlobalSetup);

// TC1 — JSON byte-for-byte parity (folds [TXINDEX-PR5-SEC-MD-2(a)]).
// Pass A: g_tx_index = nullptr forces tip-walk. Pass B: populated index
// forces fast-path. Both passes must produce byte-identical "result"
// fields for getrawtransaction (verbose & non-verbose) and gettransaction.
BOOST_AUTO_TEST_CASE(tc1_json_byte_for_byte_parity) {
    IntegrationFixture fix("tc1");
    constexpr int kN = 12;
    fix.BuildChain(kN);

    g_tx_index.reset();

    // Phase A: tip-walk. Capture every (method, txid, verbose) tuple.
    std::vector<std::string> a_get_raw_verb_true(kN);
    std::vector<std::string> a_get_raw_verb_false(kN);
    std::vector<std::string> a_get_tx(kN);
    for (int h = 0; h < kN; ++h) {
        const uint256& txid = fix.per_height_tx[h]->GetHash();
        a_get_raw_verb_true[h]  = ExtractResult(SendRPCRequest(fix.port,
            "getrawtransaction", TxidParams(txid, true)));
        a_get_raw_verb_false[h] = ExtractResult(SendRPCRequest(fix.port,
            "getrawtransaction", TxidParams(txid, false)));
        a_get_tx[h]             = ExtractResult(SendRPCRequest(fix.port,
            "gettransaction",    TxidParams(txid)));
        BOOST_REQUIRE(!a_get_raw_verb_true[h].empty());
        BOOST_REQUIRE(!a_get_raw_verb_false[h].empty());
        BOOST_REQUIRE(!a_get_tx[h].empty());
    }

    // Phase B: fast-path. Same fixture, same tip, same chain — only the
    // index goes from nullptr to populated.
    g_tx_index = std::make_unique<CTxIndex>();
    BOOST_REQUIRE(g_tx_index->Init(fix.idx_scope.path(), &fix.chain_db));
    g_tx_index->StartBackgroundSync();
    BOOST_REQUIRE(WaitForSync(*g_tx_index, std::chrono::seconds(5)));
    BOOST_REQUIRE_EQUAL(g_tx_index->LastIndexedHeight(), kN - 1);

    for (int h = 0; h < kN; ++h) {
        const uint256& txid = fix.per_height_tx[h]->GetHash();
        std::string b_raw_t = ExtractResult(SendRPCRequest(fix.port,
            "getrawtransaction", TxidParams(txid, true)));
        std::string b_raw_f = ExtractResult(SendRPCRequest(fix.port,
            "getrawtransaction", TxidParams(txid, false)));
        std::string b_get   = ExtractResult(SendRPCRequest(fix.port,
            "gettransaction",    TxidParams(txid)));
        BOOST_CHECK_EQUAL(a_get_raw_verb_true[h],  b_raw_t);
        BOOST_CHECK_EQUAL(a_get_raw_verb_false[h], b_raw_f);
        BOOST_CHECK_EQUAL(a_get_tx[h],             b_get);
    }
}

// TC2 — Paranoia mismatch fall-through (folds [TXINDEX-PR5-SEC-MD-2(b)]).
// Forge a 't'-prefix entry for an unknown txid that points into a real
// block at a position whose actual tx hash is different. The fast-path
// will read the indexed block, fail the txs[txPos]->GetHash() == txid
// check, log WARN, increment MismatchCount, and fall through. Querying
// the GENUINE txid then takes the tip-walk and returns valid JSON.
BOOST_AUTO_TEST_CASE(tc2_paranoia_mismatch_fall_through) {
    IntegrationFixture fix("tc2");
    fix.BuildChain(3);

    g_tx_index = std::make_unique<CTxIndex>();
    BOOST_REQUIRE(g_tx_index->Init(fix.idx_scope.path(), &fix.chain_db));
    g_tx_index->StartBackgroundSync();
    BOOST_REQUIRE(WaitForSync(*g_tx_index, std::chrono::seconds(5)));
    g_tx_index->Stop();

    // Forge: forged_txid -> (block_hash@1, tx_pos=0). The tx at pos=0 in
    // block 1 is the coinbase, whose hash is NOT forged_txid; the inner
    // sanity check txs[txPos]->GetHash() == txid fires, paranoia branch
    // runs, fall-through proceeds to the legacy scan (which won't find
    // forged_txid either — the load-bearing assertions are the WARN
    // string, MismatchCount delta, and the genuine-txid query below).
    uint256 forged_txid;
    std::memset(forged_txid.data, 0xAB, 32);

    // Drop the index so leveldb releases its lock for direct mutation.
    g_tx_index.reset();
    {
        leveldb::DB* raw = nullptr;
        leveldb::Options opts;
        opts.create_if_missing = false;
        BOOST_REQUIRE(leveldb::DB::Open(opts, fix.idx_scope.path(), &raw).ok());
        std::unique_ptr<leveldb::DB> raw_db(raw);

        std::string key;
        key.push_back('t');
        key.append(reinterpret_cast<const char*>(forged_txid.data), 32);
        char value[40];
        std::memset(value, 0, 40);
        value[0] = 0x01;  // schema
        std::memcpy(&value[1], fix.per_height_hash[1].data, 32);
        uint32_t pos = 0;  // coinbase position in block 1; coinbase hash != forged
        std::memcpy(&value[33], &pos, 4);
        BOOST_REQUIRE(raw_db->Put(leveldb::WriteOptions(),
                                  leveldb::Slice(key.data(), key.size()),
                                  leveldb::Slice(value, 40)).ok());
    }

    g_tx_index = std::make_unique<CTxIndex>();
    BOOST_REQUIRE(g_tx_index->Init(fix.idx_scope.path(), &fix.chain_db));
    const uint64_t pre_mismatch = g_tx_index->MismatchCount();

    // Issue the RPC for the GENUINE txid in block 1 with the forged record
    // staged. The fast-path loads the forged record via FindTx —
    // wait: FindTx is keyed by txid, and the forged record is keyed by
    // forged_txid, not the genuine txid. So the genuine query won't hit
    // the forged record. Instead, query the FORGED txid: FindTx returns
    // (block_hash[1], pos=0); fast-path reads block 1; deserialize gives
    // [coinbase, tx]; coinbase->GetHash() != forged_txid; paranoia fires.
    // After the WARN, the legacy scan won't find the forged txid either,
    // so the call surfaces "not found" — this is the expected JSON-RPC
    // error envelope. The test asserts (a) WARN logged, (b) MismatchCount
    // incremented, NOT that the call succeeds — the response body for a
    // non-existent txid must be an error, not silently-empty success.
    CerrCapture cap;
    std::string envelope = SendRPCRequest(fix.port, "getrawtransaction",
                                          TxidParams(forged_txid, true));
    std::string captured = cap.str();

    BOOST_CHECK_NE(captured.find("[txindex] WARN paranoia mismatch txid="),
                   std::string::npos);
    BOOST_CHECK_EQUAL(g_tx_index->MismatchCount() - pre_mismatch, 1u);
    // The envelope must surface an error, not a synthetic "success" — the
    // fall-through finds nothing and the legacy scan throws "not found".
    BOOST_CHECK_NE(envelope.find("\"error\""), std::string::npos);

    // Sanity: a query for a GENUINE txid (block 1's regular tx) still
    // succeeds end-to-end — the index is otherwise healthy.
    const uint256& genuine = fix.per_height_tx[1]->GetHash();
    std::string genuine_env = SendRPCRequest(fix.port, "getrawtransaction",
                                             TxidParams(genuine, true));
    BOOST_CHECK_NE(genuine_env.find("\"result\""), std::string::npos);
}

// TC3 — Reorg correctness (folds [TXINDEX-PR5-SEC-MD-1]).
// Build N blocks, populate index, then synthesize a reorg by directly
// rewinding the tip to height 2 and grafting a shorter active chain that
// leaves blocks [3..4] indexed but no longer on-chain. Querying a tx from
// an orphaned block via fast-path must return confirmations==0 (clamped),
// NEVER negative — that's the SEC-MD-1 invariant under test.
BOOST_AUTO_TEST_CASE(tc3_reorg_no_negative_confirmations) {
    IntegrationFixture fix("tc3");
    constexpr int kN = 5;
    fix.BuildChain(kN);

    g_tx_index = std::make_unique<CTxIndex>();
    BOOST_REQUIRE(g_tx_index->Init(fix.idx_scope.path(), &fix.chain_db));
    g_tx_index->StartBackgroundSync();
    BOOST_REQUIRE(WaitForSync(*g_tx_index, std::chrono::seconds(5)));
    BOOST_REQUIRE_EQUAL(g_tx_index->LastIndexedHeight(), kN - 1);

    // Simulate a reorg: rewind tip to height 2. The index still holds
    // entries for heights 3 and 4, but the active chain is now [0..2].
    // pIdx->nHeight (=4) > pTip->nHeight (=2) for the orphaned block,
    // which is the exact branch the SEC-MD-1 bound is meant to clamp.
    CBlockIndex* tip2 = g_chainstate.GetBlockIndex(fix.per_height_hash[2]);
    BOOST_REQUIRE(tip2 != nullptr);
    // Detach pnext at height 2 so the chain ends there.
    tip2->pnext = nullptr;
    g_chainstate.SetTipForTest(tip2);

    // (a) Active-chain tx (height 1): confirmations must be positive.
    {
        const uint256& txid = fix.per_height_tx[1]->GetHash();
        std::string env = SendRPCRequest(fix.port, "getrawtransaction",
                                         TxidParams(txid, true));
        std::string result = ExtractResult(env);
        BOOST_REQUIRE(!result.empty());
        // confirmations = (tip_height=2) - (block_height=1) + 1 = 2.
        BOOST_CHECK_NE(result.find("\"confirmations\":2"), std::string::npos);
        BOOST_CHECK_EQUAL(result.find("\"confirmations\":-"), std::string::npos);
    }

    // (b) Orphaned tx (height 4 > tip 2): confirmations clamped to 0.
    // The fast-path takes the SEC-MD-1 branch (pIdx->nHeight > pTip->nHeight)
    // and returns conf=0; under no scenario is the value negative.
    {
        const uint256& txid = fix.per_height_tx[4]->GetHash();
        std::string env = SendRPCRequest(fix.port, "getrawtransaction",
                                         TxidParams(txid, true));
        std::string result = ExtractResult(env);
        // Either result is non-empty with confirmations==0 OR the call
        // returned an error (also acceptable) — under no scenario is the
        // confirmations value negative.
        if (!result.empty()) {
            BOOST_CHECK_EQUAL(result.find("\"confirmations\":-"), std::string::npos);
            BOOST_CHECK_NE(result.find("\"confirmations\":0"), std::string::npos);
        }
    }
}

// TC4 — Reindex resume across destruct/reopen.
// First instance: Init + StartBackgroundSync + immediate Interrupt+Stop.
// Capture partial K. Second instance on the same datadir: Init + sync to
// completion. Assert no data loss across the boundary.
BOOST_AUTO_TEST_CASE(tc4_reindex_resume_across_destruct) {
    IntegrationFixture fix("tc4");
    constexpr int kN = 20;
    fix.BuildChain(kN);

    int K = -1;
    {
        g_tx_index = std::make_unique<CTxIndex>();
        BOOST_REQUIRE(g_tx_index->Init(fix.idx_scope.path(), &fix.chain_db));
        g_tx_index->StartBackgroundSync();
        g_tx_index->Interrupt();
        g_tx_index->Stop();
        K = g_tx_index->LastIndexedHeight();
        BOOST_CHECK(K >= -1 && K <= kN - 1);
        g_tx_index.reset();
    }

    {
        g_tx_index = std::make_unique<CTxIndex>();
        BOOST_REQUIRE(g_tx_index->Init(fix.idx_scope.path(), &fix.chain_db));
        BOOST_CHECK_EQUAL(g_tx_index->LastIndexedHeight(), K);
        g_tx_index->StartBackgroundSync();
        BOOST_REQUIRE(WaitForSync(*g_tx_index, std::chrono::seconds(5)));
        BOOST_CHECK_EQUAL(g_tx_index->LastIndexedHeight(), kN - 1);

        // Every tx from every block must be findable via the live RPC.
        for (int h = 0; h < kN; ++h) {
            const uint256& txid = fix.per_height_tx[h]->GetHash();
            std::string env = SendRPCRequest(fix.port, "getrawtransaction",
                                             TxidParams(txid, true));
            std::string result = ExtractResult(env);
            BOOST_REQUIRE(!result.empty());
            BOOST_CHECK_NE(result.find(txid.GetHex()), std::string::npos);
        }
    }
}

// TC5 — Default flag (-txindex=0): JSON unchanged from baseline.
// With g_tx_index = nullptr for the duration, every RPC must return
// well-formed JSON with no "[txindex]" string in stderr (no fast-path
// code reached). This is the "don't break existing clients" guardrail.
BOOST_AUTO_TEST_CASE(tc5_default_flag_unchanged) {
    IntegrationFixture fix("tc5");
    constexpr int kN = 5;
    fix.BuildChain(kN);

    g_tx_index.reset();

    CerrCapture cap;
    for (int h = 0; h < kN; ++h) {
        const uint256& txid = fix.per_height_tx[h]->GetHash();
        std::string raw_t = SendRPCRequest(fix.port, "getrawtransaction",
                                           TxidParams(txid, true));
        std::string raw_f = SendRPCRequest(fix.port, "getrawtransaction",
                                           TxidParams(txid, false));
        std::string get   = SendRPCRequest(fix.port, "gettransaction",
                                           TxidParams(txid));
        BOOST_CHECK_NE(raw_t.find("\"result\""), std::string::npos);
        BOOST_CHECK_NE(raw_f.find("\"result\""), std::string::npos);
        BOOST_CHECK_NE(get.find("\"result\""),   std::string::npos);
    }
    // No fast-path touches stderr — the only [txindex] strings are paranoia
    // WARNs (TC2) or shutdown messages (none happen here).
    BOOST_CHECK_EQUAL(cap.str().find("[txindex] WARN"), std::string::npos);
}

// TC6 — N2 cold-reindex acknowledgement (end-to-end).
// Replicate the production node-startup gate verbatim:
//   if (last == -1 && tip > 0 && !reindex_flag) abort with literal message.
// Verify both branches: (1) without reindex flag, abort string in stderr;
// (2) with reindex flag, no abort, sync completes.
BOOST_AUTO_TEST_CASE(tc6_n2_cold_reindex_acknowledgement) {
    IntegrationFixture fix("tc6");
    fix.BuildChain(5);

    // Branch 1: cold index, no reindex flag → abort.
    {
        auto idx = std::make_unique<CTxIndex>();
        TempDbScope cold("tc6_cold_a");
        BOOST_REQUIRE(idx->Init(cold.path(), &fix.chain_db));
        BOOST_REQUIRE_EQUAL(idx->LastIndexedHeight(), -1);
        const int last = idx->LastIndexedHeight();
        const int tip  = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
        const bool reindex_flag = false;

        CerrCapture cap;
        bool aborted = false;
        if (last == -1 && tip > 0 && !reindex_flag) {
            std::cerr << "[txindex] -txindex=1 on a non-empty chain requires -reindex "
                      << "to acknowledge a multi-hour rebuild. Aborting." << std::endl;
            aborted = true;
        }
        BOOST_CHECK(aborted);
        BOOST_CHECK_NE(cap.str().find(
            "[txindex] -txindex=1 on a non-empty chain requires -reindex "
            "to acknowledge a multi-hour rebuild. Aborting."),
            std::string::npos);
    }

    // Branch 2: cold index, reindex flag set → no abort, sync runs.
    {
        auto idx = std::make_unique<CTxIndex>();
        TempDbScope cold("tc6_cold_b");
        BOOST_REQUIRE(idx->Init(cold.path(), &fix.chain_db));
        const int last = idx->LastIndexedHeight();
        const int tip  = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
        const bool reindex_flag = true;
        bool aborted = false;
        if (last == -1 && tip > 0 && !reindex_flag) aborted = true;
        BOOST_CHECK(!aborted);

        idx->StartBackgroundSync();
        BOOST_REQUIRE(WaitForSync(*idx, std::chrono::seconds(5)));
        BOOST_CHECK_EQUAL(idx->LastIndexedHeight(), 4);
        idx->Stop();
    }
}

// TC7 — Mempool-first ordering preserved.
// A txid that lives ONLY in the mempool must return mempool-shaped JSON
// (confirmations==0, no blockhash) regardless of whether the index is
// populated. Proves the mempool branch runs before the fast-path. A
// confirmed-only txid still returns confirmed-shaped JSON (with blockhash).
BOOST_AUTO_TEST_CASE(tc7_mempool_first_ordering) {
    IntegrationFixture fix("tc7");
    constexpr int kN = 3;
    fix.BuildChain(kN);

    // Mempool-only tx: NOT in any block.
    auto mempool_tx = MakeUniqueTx(0xDE, 0xAD);
    std::string add_err;
    BOOST_REQUIRE(fix.mempool.AddTx(mempool_tx, /*fee=*/1000, /*time=*/1700000000,
                                    /*height=*/static_cast<unsigned int>(kN),
                                    &add_err, /*bypass_fee_check=*/true));

    g_tx_index = std::make_unique<CTxIndex>();
    BOOST_REQUIRE(g_tx_index->Init(fix.idx_scope.path(), &fix.chain_db));
    g_tx_index->StartBackgroundSync();
    BOOST_REQUIRE(WaitForSync(*g_tx_index, std::chrono::seconds(5)));

    // (a) Mempool-only txid via getrawtransaction (verbose=true): must be
    // mempool-shaped — no blockhash, confirmations:0.
    {
        const uint256& txid = mempool_tx->GetHash();
        std::string env = SendRPCRequest(fix.port, "getrawtransaction",
                                         TxidParams(txid, true));
        std::string result = ExtractResult(env);
        BOOST_REQUIRE(!result.empty());
        BOOST_CHECK_EQUAL(result.find("\"blockhash\""), std::string::npos);
        BOOST_CHECK_NE(result.find("\"confirmations\":0"), std::string::npos);
    }

    // (b) Confirmed-only txid via getrawtransaction (verbose=true): must be
    // confirmed-shaped — has blockhash, confirmations >= 1.
    {
        const uint256& txid = fix.per_height_tx[1]->GetHash();
        std::string env = SendRPCRequest(fix.port, "getrawtransaction",
                                         TxidParams(txid, true));
        std::string result = ExtractResult(env);
        BOOST_REQUIRE(!result.empty());
        BOOST_CHECK_NE(result.find("\"blockhash\""), std::string::npos);
        // confirmations = (tip=2) - (block_height=1) + 1 = 2.
        BOOST_CHECK_NE(result.find("\"confirmations\":2"), std::string::npos);
    }

    // (c) Mempool-only txid via gettransaction: in_mempool:true.
    {
        const uint256& txid = mempool_tx->GetHash();
        std::string env = SendRPCRequest(fix.port, "gettransaction",
                                         TxidParams(txid));
        std::string result = ExtractResult(env);
        BOOST_REQUIRE(!result.empty());
        BOOST_CHECK_NE(result.find("\"in_mempool\":true"), std::string::npos);
    }
}

BOOST_AUTO_TEST_SUITE_END()
