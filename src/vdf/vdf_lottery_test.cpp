/**
 * VDF Distribution unit tests.
 *
 * Tests the "lowest VDF output wins" mechanism:
 *   - ShouldReplaceVDFTip with lower/higher/equal outputs
 *   - Grace period enforcement
 *   - Pre-activation height behavior
 *   - Non-VDF block handling
 *   - Accept time anchoring (no reset on replacement)
 */
#include <consensus/chain.h>
#include <consensus/pow.h>
#include <core/chainparams.h>
#include <primitives/block.h>
#include <node/block_index.h>
#include <crypto/sha3.h>

#include <iostream>
#include <cstring>
#include <chrono>
#include <memory>

static int passed = 0;
static int failed = 0;

#define TEST(name) do { std::cout << "  " << #name << "... " << std::flush; } while(0)
#define PASS()     do { std::cout << "PASS\n"; ++passed; } while(0)
#define CHECK(c)   do { if (!(c)) { std::cout << "FAIL (" << #c << ")\n"; ++failed; return; } } while(0)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static uint32_t g_hashCounter = 100;

// Compute a deterministic hash for a test block
static uint256 ComputeTestHash(uint32_t counter)
{
    uint8_t preimage[4];
    std::memcpy(preimage, &counter, 4);
    uint256 result;
    SHA3_256(preimage, 4, result.data);
    return result;
}

// Create a uint256 with a specific MSB value (big-endian, byte[31])
// Lower MSB = lower in HashLessThan comparison
static uint256 MakeOutput(uint8_t msbValue)
{
    uint256 result;
    std::memset(result.data, 0, 32);
    result.data[31] = msbValue;
    return result;
}

// Simple test block index — heap-allocated with a stable hash.
// These bypass AddBlockIndex (no mapBlockIndex invariants to satisfy).
struct TestBlock {
    CBlockIndex index;
    uint256 hash;

    TestBlock() {
        hash = ComputeTestHash(g_hashCounter++);
        index.phashBlock = hash;
    }
};

// Create a VDF block at given height with parent and vdfOutput
static TestBlock MakeVDFBlock(int height, CBlockIndex* pprev, const uint256& vdfOutput)
{
    TestBlock tb;
    tb.index.nHeight = height;
    tb.index.pprev = pprev;
    tb.index.nVersion = CBlockHeader::VDF_VERSION;
    tb.index.header.nVersion = CBlockHeader::VDF_VERSION;
    tb.index.header.vdfOutput = vdfOutput;
    if (pprev) {
        tb.index.header.hashPrevBlock = pprev->GetBlockHash();
    }
    return tb;
}

// Create a RandomX block (version 1) at given height with parent
static TestBlock MakeRandomXBlock(int height, CBlockIndex* pprev)
{
    TestBlock tb;
    tb.index.nHeight = height;
    tb.index.pprev = pprev;
    tb.index.nVersion = 1;
    tb.index.header.nVersion = 1;
    if (pprev) {
        tb.index.header.hashPrevBlock = pprev->GetBlockHash();
    }
    return tb;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void test_lower_output_replaces()
{
    TEST(lower_output_replaces);

    Dilithion::ChainParams params = Dilithion::ChainParams::Testnet();
    params.vdfLotteryActivationHeight = 5;
    params.vdfLotteryGracePeriod = 60;
    Dilithion::g_chainParams = &params;

    CChainState cs;

    // Parent block at height 9
    TestBlock parent = MakeVDFBlock(9, nullptr, uint256());

    // Tip has HIGH VDF output (height 10)
    uint256 highOutput = MakeOutput(0xFF);
    TestBlock tip = MakeVDFBlock(10, &parent.index, highOutput);
    cs.SetTipForTest(&tip.index);

    // Competing block has LOW VDF output (same parent, same height 10)
    uint256 lowOutput = MakeOutput(0x01);
    TestBlock competitor = MakeVDFBlock(10, &parent.index, lowOutput);

    cs.m_vdfTipAcceptTime = std::chrono::steady_clock::now();
    cs.m_vdfTipAcceptHeight = 10;

    CHECK(cs.ShouldReplaceVDFTip(&competitor.index) == true);

    Dilithion::g_chainParams = nullptr;
    PASS();
}

static void test_higher_output_does_not_replace()
{
    TEST(higher_output_does_not_replace);

    Dilithion::ChainParams params = Dilithion::ChainParams::Testnet();
    params.vdfLotteryActivationHeight = 5;
    params.vdfLotteryGracePeriod = 60;
    Dilithion::g_chainParams = &params;

    CChainState cs;

    TestBlock parent = MakeVDFBlock(9, nullptr, uint256());

    uint256 lowOutput = MakeOutput(0x01);
    TestBlock tip = MakeVDFBlock(10, &parent.index, lowOutput);
    cs.SetTipForTest(&tip.index);

    uint256 highOutput = MakeOutput(0xFF);
    TestBlock competitor = MakeVDFBlock(10, &parent.index, highOutput);

    cs.m_vdfTipAcceptTime = std::chrono::steady_clock::now();
    cs.m_vdfTipAcceptHeight = 10;

    CHECK(cs.ShouldReplaceVDFTip(&competitor.index) == false);

    Dilithion::g_chainParams = nullptr;
    PASS();
}

static void test_equal_output_does_not_replace()
{
    TEST(equal_output_does_not_replace);

    Dilithion::ChainParams params = Dilithion::ChainParams::Testnet();
    params.vdfLotteryActivationHeight = 5;
    params.vdfLotteryGracePeriod = 60;
    Dilithion::g_chainParams = &params;

    CChainState cs;

    TestBlock parent = MakeVDFBlock(9, nullptr, uint256());

    uint256 sameOutput = MakeOutput(0x42);
    TestBlock tip = MakeVDFBlock(10, &parent.index, sameOutput);
    cs.SetTipForTest(&tip.index);

    TestBlock competitor = MakeVDFBlock(10, &parent.index, sameOutput);

    cs.m_vdfTipAcceptTime = std::chrono::steady_clock::now();
    cs.m_vdfTipAcceptHeight = 10;

    CHECK(cs.ShouldReplaceVDFTip(&competitor.index) == false);

    Dilithion::g_chainParams = nullptr;
    PASS();
}

static void test_grace_period_expired()
{
    TEST(grace_period_expired);

    Dilithion::ChainParams params = Dilithion::ChainParams::Testnet();
    params.vdfLotteryActivationHeight = 5;
    params.vdfLotteryGracePeriod = 1;  // 1 second
    Dilithion::g_chainParams = &params;

    CChainState cs;

    TestBlock parent = MakeVDFBlock(9, nullptr, uint256());

    uint256 highOutput = MakeOutput(0xFF);
    TestBlock tip = MakeVDFBlock(10, &parent.index, highOutput);
    cs.SetTipForTest(&tip.index);

    uint256 lowOutput = MakeOutput(0x01);
    TestBlock competitor = MakeVDFBlock(10, &parent.index, lowOutput);

    // Set accept time 2 seconds in the past (exceeds 1s grace)
    cs.m_vdfTipAcceptTime = std::chrono::steady_clock::now() - std::chrono::seconds(2);
    cs.m_vdfTipAcceptHeight = 10;

    CHECK(cs.ShouldReplaceVDFTip(&competitor.index) == false);

    Dilithion::g_chainParams = nullptr;
    PASS();
}

static void test_pre_activation_skips_lottery()
{
    TEST(pre_activation_skips_lottery);

    Dilithion::ChainParams params = Dilithion::ChainParams::Testnet();
    params.vdfLotteryActivationHeight = 90000;  // Far in the future
    params.vdfLotteryGracePeriod = 60;
    Dilithion::g_chainParams = &params;

    CChainState cs;

    TestBlock parent = MakeVDFBlock(9, nullptr, uint256());

    uint256 highOutput = MakeOutput(0xFF);
    TestBlock tip = MakeVDFBlock(10, &parent.index, highOutput);
    cs.SetTipForTest(&tip.index);

    uint256 lowOutput = MakeOutput(0x01);
    TestBlock competitor = MakeVDFBlock(10, &parent.index, lowOutput);

    cs.m_vdfTipAcceptTime = std::chrono::steady_clock::now();
    cs.m_vdfTipAcceptHeight = 10;

    // Height 10 < activation 90000
    CHECK(cs.ShouldReplaceVDFTip(&competitor.index) == false);

    Dilithion::g_chainParams = nullptr;
    PASS();
}

static void test_non_vdf_tip_skips_lottery()
{
    TEST(non_vdf_tip_skips_lottery);

    Dilithion::ChainParams params = Dilithion::ChainParams::Testnet();
    params.vdfLotteryActivationHeight = 5;
    params.vdfLotteryGracePeriod = 60;
    Dilithion::g_chainParams = &params;

    CChainState cs;

    TestBlock parent = MakeVDFBlock(9, nullptr, uint256());

    // Tip is RandomX (version 1)
    TestBlock tip = MakeRandomXBlock(10, &parent.index);
    cs.SetTipForTest(&tip.index);

    uint256 lowOutput = MakeOutput(0x01);
    TestBlock competitor = MakeVDFBlock(10, &parent.index, lowOutput);

    cs.m_vdfTipAcceptTime = std::chrono::steady_clock::now();
    cs.m_vdfTipAcceptHeight = 10;

    CHECK(cs.ShouldReplaceVDFTip(&competitor.index) == false);

    Dilithion::g_chainParams = nullptr;
    PASS();
}

static void test_different_height_skips_lottery()
{
    TEST(different_height_skips_lottery);

    Dilithion::ChainParams params = Dilithion::ChainParams::Testnet();
    params.vdfLotteryActivationHeight = 5;
    params.vdfLotteryGracePeriod = 60;
    Dilithion::g_chainParams = &params;

    CChainState cs;

    TestBlock parent = MakeVDFBlock(9, nullptr, uint256());

    uint256 highOutput = MakeOutput(0xFF);
    TestBlock tip = MakeVDFBlock(10, &parent.index, highOutput);
    cs.SetTipForTest(&tip.index);

    // Competitor at height 11 (different from tip's 10)
    uint256 lowOutput = MakeOutput(0x01);
    TestBlock competitor = MakeVDFBlock(11, &tip.index, lowOutput);

    cs.m_vdfTipAcceptTime = std::chrono::steady_clock::now();
    cs.m_vdfTipAcceptHeight = 10;

    CHECK(cs.ShouldReplaceVDFTip(&competitor.index) == false);

    Dilithion::g_chainParams = nullptr;
    PASS();
}

static void test_different_parent_skips_lottery()
{
    TEST(different_parent_skips_lottery);

    Dilithion::ChainParams params = Dilithion::ChainParams::Testnet();
    params.vdfLotteryActivationHeight = 5;
    params.vdfLotteryGracePeriod = 60;
    Dilithion::g_chainParams = &params;

    CChainState cs;

    // Two different parents at height 9
    TestBlock parent1 = MakeVDFBlock(9, nullptr, uint256());
    TestBlock parent2 = MakeVDFBlock(9, nullptr, uint256());

    uint256 highOutput = MakeOutput(0xFF);
    TestBlock tip = MakeVDFBlock(10, &parent1.index, highOutput);
    cs.SetTipForTest(&tip.index);

    // Competitor has different parent
    uint256 lowOutput = MakeOutput(0x01);
    TestBlock competitor = MakeVDFBlock(10, &parent2.index, lowOutput);

    cs.m_vdfTipAcceptTime = std::chrono::steady_clock::now();
    cs.m_vdfTipAcceptHeight = 10;

    CHECK(cs.ShouldReplaceVDFTip(&competitor.index) == false);

    Dilithion::g_chainParams = nullptr;
    PASS();
}

static void test_null_output_skips()
{
    TEST(null_output_skips);

    Dilithion::ChainParams params = Dilithion::ChainParams::Testnet();
    params.vdfLotteryActivationHeight = 5;
    params.vdfLotteryGracePeriod = 60;
    Dilithion::g_chainParams = &params;

    CChainState cs;

    TestBlock parent = MakeVDFBlock(9, nullptr, uint256());

    // Tip has null VDF output
    TestBlock tip = MakeVDFBlock(10, &parent.index, uint256());
    cs.SetTipForTest(&tip.index);

    uint256 lowOutput = MakeOutput(0x01);
    TestBlock competitor = MakeVDFBlock(10, &parent.index, lowOutput);

    cs.m_vdfTipAcceptTime = std::chrono::steady_clock::now();
    cs.m_vdfTipAcceptHeight = 10;

    CHECK(cs.ShouldReplaceVDFTip(&competitor.index) == false);

    Dilithion::g_chainParams = nullptr;
    PASS();
}

static void test_hash_less_than_big_endian()
{
    TEST(hash_less_than_big_endian);

    // Verify HashLessThan does big-endian (MSB-first) comparison
    uint256 a, b;
    std::memset(a.data, 0, 32);
    std::memset(b.data, 0, 32);

    // In big-endian, byte[31] is the most significant
    a.data[31] = 0x01;
    b.data[31] = 0xFF;

    CHECK(HashLessThan(a, b) == true);
    CHECK(HashLessThan(b, a) == false);
    CHECK(HashLessThan(a, a) == false);

    PASS();
}

static void test_accept_time_not_set()
{
    TEST(accept_time_not_set);

    Dilithion::ChainParams params = Dilithion::ChainParams::Testnet();
    params.vdfLotteryActivationHeight = 100;
    params.vdfLotteryGracePeriod = 60;
    Dilithion::g_chainParams = &params;

    CChainState cs;

    TestBlock parent = MakeVDFBlock(199, nullptr, uint256());

    uint256 highOutput = MakeOutput(0xFF);
    TestBlock tip = MakeVDFBlock(200, &parent.index, highOutput);
    cs.SetTipForTest(&tip.index);

    uint256 lowOutput = MakeOutput(0x01);
    TestBlock competitor = MakeVDFBlock(200, &parent.index, lowOutput);

    // Do NOT set accept time (m_vdfTipAcceptHeight defaults to -1)
    // ShouldReplaceVDFTip checks m_vdfTipAcceptHeight == pindexTip->nHeight

    CHECK(cs.ShouldReplaceVDFTip(&competitor.index) == false);

    Dilithion::g_chainParams = nullptr;
    PASS();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main()
{
    std::cout << "VDF Distribution Tests" << std::endl;
    std::cout << "=================" << std::endl;
    std::cout << std::endl;

    test_lower_output_replaces();
    test_higher_output_does_not_replace();
    test_equal_output_does_not_replace();
    test_grace_period_expired();
    test_pre_activation_skips_lottery();
    test_non_vdf_tip_skips_lottery();
    test_different_height_skips_lottery();
    test_different_parent_skips_lottery();
    test_null_output_skips();
    test_hash_less_than_big_endian();
    test_accept_time_not_set();

    std::cout << std::endl;
    std::cout << passed << " passed, " << failed << " failed" << std::endl;

    if (failed > 0) {
        std::cout << "\n*** TESTS FAILED ***\n";
        return 1;
    }

    std::cout << "\n=== ALL TESTS PASSED ===" << std::endl;
    return 0;
}
