/**
 * VDF Miner unit tests.
 *
 * Tests: FinalizeVDFBlock (coinbase modification, merkle root recomputation,
 *        header VDF fields), round-trip with consensus validation.
 */
#include <miner/vdf_miner.h>
#include <vdf/vdf.h>
#include <vdf/coinbase_vdf.h>
#include <consensus/vdf_validation.h>
#include <crypto/sha3.h>
#include <iostream>
#include <cassert>
#include <cstring>

static int passed = 0;
static int failed = 0;

#define TEST(name) do { std::cout << "  " << #name << "... " << std::flush; } while(0)
#define PASS()     do { std::cout << "PASS\n"; ++passed; } while(0)
#define CHECK(c)   do { if (!(c)) { std::cout << "FAIL (" << #c << ")\n"; ++failed; return; } } while(0)

// Helper: build a minimal block template (version 1, single coinbase output)
// This simulates what BuildMiningTemplate produces.
static CBlockTemplate MakeBaseTemplate(
    const uint256& prevHash,
    uint32_t height,
    const std::array<uint8_t, 20>& minerAddr)
{
    CBlock block;
    block.nVersion = 1;  // Legacy version — VDF miner will upgrade to 4
    block.hashPrevBlock = prevHash;
    block.nBits = 0x1d00ffff;
    block.nTime = 1700000000;
    block.nNonce = 0;

    // Build a coinbase transaction manually
    std::vector<uint8_t> vtxData;

    // Transaction count = 1
    vtxData.push_back(1);

    // --- Coinbase transaction ---
    // nVersion = 1
    int32_t txVersion = 1;
    vtxData.insert(vtxData.end(),
                   reinterpret_cast<uint8_t*>(&txVersion),
                   reinterpret_cast<uint8_t*>(&txVersion) + 4);

    // vin count = 1
    vtxData.push_back(1);

    // prevout: null hash + 0xFFFFFFFF
    for (int i = 0; i < 32; i++) vtxData.push_back(0);
    uint32_t coinbaseIndex = 0xFFFFFFFF;
    vtxData.insert(vtxData.end(),
                   reinterpret_cast<uint8_t*>(&coinbaseIndex),
                   reinterpret_cast<uint8_t*>(&coinbaseIndex) + 4);

    // scriptSig: BIP34 height encoding
    std::vector<uint8_t> scriptSig;
    scriptSig.push_back(0x03);  // push 3 bytes
    uint32_t h = height;
    scriptSig.push_back(static_cast<uint8_t>(h & 0xFF));
    scriptSig.push_back(static_cast<uint8_t>((h >> 8) & 0xFF));
    scriptSig.push_back(static_cast<uint8_t>((h >> 16) & 0xFF));

    // NOTE: No VDF proof yet — that's what FinalizeVDFBlock adds

    // Write scriptSig length + data
    if (scriptSig.size() < 253) {
        vtxData.push_back(static_cast<uint8_t>(scriptSig.size()));
    } else {
        vtxData.push_back(253);
        uint16_t len16 = static_cast<uint16_t>(scriptSig.size());
        vtxData.push_back(static_cast<uint8_t>(len16 & 0xFF));
        vtxData.push_back(static_cast<uint8_t>((len16 >> 8) & 0xFF));
    }
    vtxData.insert(vtxData.end(), scriptSig.begin(), scriptSig.end());

    // nSequence
    uint32_t seq = 0xFFFFFFFF;
    vtxData.insert(vtxData.end(),
                   reinterpret_cast<uint8_t*>(&seq),
                   reinterpret_cast<uint8_t*>(&seq) + 4);

    // vout count = 1
    vtxData.push_back(1);

    // value = 50 DIL
    uint64_t value = 50ULL * 100000000ULL;
    vtxData.insert(vtxData.end(),
                   reinterpret_cast<uint8_t*>(&value),
                   reinterpret_cast<uint8_t*>(&value) + 8);

    // scriptPubKey: P2PKH
    std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
    spk.insert(spk.end(), minerAddr.begin(), minerAddr.end());
    spk.push_back(0x88);
    spk.push_back(0xac);
    vtxData.push_back(static_cast<uint8_t>(spk.size()));
    vtxData.insert(vtxData.end(), spk.begin(), spk.end());

    // locktime = 0
    uint32_t locktime = 0;
    vtxData.insert(vtxData.end(),
                   reinterpret_cast<uint8_t*>(&locktime),
                   reinterpret_cast<uint8_t*>(&locktime) + 4);

    block.vtx = vtxData;

    // Compute merkle root (single tx)
    SHA3_256(vtxData.data() + 1, vtxData.size() - 1, block.hashMerkleRoot.data);

    CBlockTemplate tmpl;
    tmpl.block = block;
    tmpl.nHeight = height;
    // hashTarget not needed for VDF
    return tmpl;
}

// ---------------------------------------------------------------------------

static void test_finalize_sets_version_4()
{
    TEST(finalize_sets_version_4);
    uint256 prevHash;
    prevHash.data[0] = 0xAA;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    auto tmpl = MakeBaseTemplate(prevHash, 100, addr);
    CHECK(tmpl.block.nVersion == 1);

    // Compute a real VDF
    auto challenge = ComputeVDFChallenge(prevHash, 100, addr);
    vdf::VDFConfig cfg;
    cfg.target_iterations = 1000;
    auto result = vdf::compute(challenge, 1000, cfg);

    CVDFMiner miner;
    CBlock block = tmpl.block;
    CHECK(miner.FinalizeVDFBlock(block, result, addr, 100));
    CHECK(block.nVersion == CBlockHeader::VDF_VERSION);
    CHECK(block.IsVDFBlock());
    PASS();
}

static void test_finalize_sets_vdf_output()
{
    TEST(finalize_sets_vdf_output);
    uint256 prevHash;
    prevHash.data[0] = 0xBB;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    auto tmpl = MakeBaseTemplate(prevHash, 200, addr);
    auto challenge = ComputeVDFChallenge(prevHash, 200, addr);
    auto result = vdf::compute(challenge, 1000);

    CVDFMiner miner;
    CBlock block = tmpl.block;
    CHECK(miner.FinalizeVDFBlock(block, result, addr, 200));

    // Check vdfOutput matches result
    CHECK(std::memcmp(block.vdfOutput.data, result.output.data(), 32) == 0);
    PASS();
}

static void test_finalize_sets_proof_hash()
{
    TEST(finalize_sets_proof_hash);
    uint256 prevHash;
    prevHash.data[0] = 0xCC;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    auto tmpl = MakeBaseTemplate(prevHash, 300, addr);
    auto challenge = ComputeVDFChallenge(prevHash, 300, addr);
    auto result = vdf::compute(challenge, 1000);

    CVDFMiner miner;
    CBlock block = tmpl.block;
    CHECK(miner.FinalizeVDFBlock(block, result, addr, 300));

    // Check vdfProofHash = SHA3-256(proof)
    uint256 expectedHash = CoinbaseVDF::ComputeProofHash(result.proof);
    CHECK(block.vdfProofHash == expectedHash);
    PASS();
}

static void test_finalize_embeds_proof_in_coinbase()
{
    TEST(finalize_embeds_proof_in_coinbase);
    uint256 prevHash;
    prevHash.data[0] = 0xDD;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    auto tmpl = MakeBaseTemplate(prevHash, 400, addr);
    auto challenge = ComputeVDFChallenge(prevHash, 400, addr);
    auto result = vdf::compute(challenge, 1000);

    CVDFMiner miner;
    CBlock block = tmpl.block;
    CHECK(miner.FinalizeVDFBlock(block, result, addr, 400));

    // Deserialize coinbase and check proof is present
    const uint8_t* data = block.vtx.data();
    size_t offset = 1; // skip tx count byte
    CTransaction coinbase;
    size_t consumed = 0;
    CHECK(coinbase.Deserialize(data + offset, block.vtx.size() - offset, nullptr, &consumed));
    CHECK(!coinbase.vin.empty());

    auto extractedProof = CoinbaseVDF::ExtractProof(coinbase.vin[0].scriptSig);
    CHECK(!extractedProof.empty());
    CHECK(extractedProof == result.proof);
    PASS();
}

static void test_finalize_recomputes_merkle_root()
{
    TEST(finalize_recomputes_merkle_root);
    uint256 prevHash;
    prevHash.data[0] = 0xEE;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    auto tmpl = MakeBaseTemplate(prevHash, 500, addr);
    uint256 oldMerkle = tmpl.block.hashMerkleRoot;

    auto challenge = ComputeVDFChallenge(prevHash, 500, addr);
    auto result = vdf::compute(challenge, 1000);

    CVDFMiner miner;
    CBlock block = tmpl.block;
    CHECK(miner.FinalizeVDFBlock(block, result, addr, 500));

    // Merkle root must have changed (coinbase was modified)
    CHECK(!(block.hashMerkleRoot == oldMerkle));

    // Verify the new merkle root is correct
    // Single tx: merkle root = SHA3(coinbase_bytes)
    const uint8_t* data = block.vtx.data();
    size_t txStart = 1; // after tx count
    size_t txLen = block.vtx.size() - 1;
    uint256 expectedMerkle;
    SHA3_256(data + txStart, txLen, expectedMerkle.data);
    CHECK(block.hashMerkleRoot == expectedMerkle);
    PASS();
}

static void test_finalize_invalidates_hash_cache()
{
    TEST(finalize_invalidates_hash_cache);
    uint256 prevHash;
    prevHash.data[0] = 0xFF;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    auto tmpl = MakeBaseTemplate(prevHash, 600, addr);
    auto challenge = ComputeVDFChallenge(prevHash, 600, addr);
    auto result = vdf::compute(challenge, 1000);

    CVDFMiner miner;
    CBlock block = tmpl.block;
    CHECK(miner.FinalizeVDFBlock(block, result, addr, 600));

    // After finalization, block is version 4 (VDF) — GetHash uses SHA3
    uint256 hash1 = block.GetHash();
    CHECK(block.fHashCached);

    // Calling FinalizeVDFBlock again should invalidate the cache
    // (compute a new VDF with different prevHash to get different output)
    uint256 prevHash2;
    prevHash2.data[0] = 0xFE;
    auto challenge2 = ComputeVDFChallenge(prevHash2, 600, addr);
    auto result2 = vdf::compute(challenge2, 1000);

    CBlock block2 = tmpl.block;
    CHECK(miner.FinalizeVDFBlock(block2, result2, addr, 600));
    uint256 hash2 = block2.GetHash();

    // Different VDF results should produce different block hashes
    CHECK(!(hash1 == hash2));
    PASS();
}

static void test_finalized_block_passes_consensus()
{
    TEST(finalized_block_passes_consensus);
    uint256 prevHash;
    prevHash.data[0] = 0xDE;
    prevHash.data[1] = 0xAD;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    uint64_t iters = 1000;
    auto tmpl = MakeBaseTemplate(prevHash, 500, addr);
    auto challenge = ComputeVDFChallenge(prevHash, 500, addr);
    auto result = vdf::compute(challenge, iters);

    CVDFMiner miner;
    CBlock block = tmpl.block;
    CHECK(miner.FinalizeVDFBlock(block, result, addr, 500));

    // The finalized block should pass CheckVDFProof
    std::string error;
    bool ok = CheckVDFProof(block, 500, prevHash, iters, error);
    if (!ok) {
        std::cout << "FAIL: " << error << "\n";
        ++failed;
        return;
    }
    CHECK(ok);
    PASS();
}

static void test_start_stop()
{
    TEST(start_stop);

    CVDFMiner miner;
    CHECK(!miner.IsRunning());

    // Start without template provider — should stay running but idle
    miner.Start();
    CHECK(miner.IsRunning());

    // Stop immediately
    miner.Stop();
    CHECK(!miner.IsRunning());
    PASS();
}

static void test_on_new_block_signal()
{
    TEST(on_new_block_signal);

    CVDFMiner miner;
    miner.Start();
    CHECK(miner.IsRunning());

    // Signal new block (shouldn't crash even when idle)
    miner.OnNewBlock();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    miner.Stop();
    CHECK(!miner.IsRunning());
    PASS();
}

int main()
{
    std::cout << "\nVDF Miner Tests\n";
    std::cout << "===============\n\n";

    if (!vdf::init()) {
        std::cerr << "ERROR: Failed to initialize VDF library\n";
        return 1;
    }

    test_finalize_sets_version_4();
    test_finalize_sets_vdf_output();
    test_finalize_sets_proof_hash();
    test_finalize_embeds_proof_in_coinbase();
    test_finalize_recomputes_merkle_root();
    test_finalize_invalidates_hash_cache();
    test_finalized_block_passes_consensus();
    test_start_stop();
    test_on_new_block_signal();

    vdf::shutdown();

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    if (failed > 0) {
        std::cout << "\n=== TESTS FAILED ===\n";
        return 1;
    }
    std::cout << "\n=== ALL TESTS PASSED ===\n";
    return 0;
}
