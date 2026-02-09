/**
 * CoinbaseVDF proof embedding/extraction tests.
 */
#include "coinbase_vdf.h"
#include <iostream>
#include <cassert>

static int passed = 0;
static int failed = 0;

#define TEST(name) do { std::cout << "  " << #name << "... "; } while(0)
#define PASS()     do { std::cout << "PASS\n"; ++passed; } while(0)
#define CHECK(c)   do { if (!(c)) { std::cout << "FAIL (" << #c << ")\n"; ++failed; return; } } while(0)

static void test_embed_extract_roundtrip()
{
    TEST(embed_extract_roundtrip);

    CTxIn coinbaseIn;
    // Simulate height bytes already in scriptSig
    coinbaseIn.scriptSig = {0x03, 0x01, 0x00, 0x00};  // height 1

    // Fake proof data
    std::vector<uint8_t> proof(100);
    for (int i = 0; i < 100; i++) proof[i] = static_cast<uint8_t>(i);

    CoinbaseVDF::EmbedProof(coinbaseIn, proof);

    // scriptSig should be: 4 (height) + 4 (tag) + 2 (len) + 100 (proof) = 110
    CHECK(coinbaseIn.scriptSig.size() == 110);

    // Extract
    auto extracted = CoinbaseVDF::ExtractProof(coinbaseIn.scriptSig);
    CHECK(extracted.size() == 100);
    CHECK(extracted == proof);

    PASS();
}

static void test_extract_from_empty()
{
    TEST(extract_from_empty);
    std::vector<uint8_t> empty;
    auto result = CoinbaseVDF::ExtractProof(empty);
    CHECK(result.empty());
    PASS();
}

static void test_extract_no_tag()
{
    TEST(extract_no_tag);
    std::vector<uint8_t> data = {0x03, 0x01, 0x00, 0x00, 0xFF, 0xFF};
    auto result = CoinbaseVDF::ExtractProof(data);
    CHECK(result.empty());
    PASS();
}

static void test_proof_hash_commitment()
{
    TEST(proof_hash_commitment);

    CTxIn coinbaseIn;
    coinbaseIn.scriptSig = {0x03, 0x01, 0x00, 0x00};

    std::vector<uint8_t> proof = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};
    CoinbaseVDF::EmbedProof(coinbaseIn, proof);

    uint256 proofHash = CoinbaseVDF::ComputeProofHash(proof);
    CHECK(!proofHash.IsNull());

    // Validate commitment
    CHECK(CoinbaseVDF::ValidateProofCommitment(coinbaseIn.scriptSig, proofHash));

    // Tamper with expected hash - should fail
    uint256 badHash = proofHash;
    badHash.data[0] ^= 0xFF;
    CHECK(!CoinbaseVDF::ValidateProofCommitment(coinbaseIn.scriptSig, badHash));

    PASS();
}

static void test_truncated_proof()
{
    TEST(truncated_proof);

    // Craft a scriptSig with tag but truncated proof
    std::vector<uint8_t> data = {
        0x03, 0x01, 0x00, 0x00,           // height
        0x56, 0x44, 0x46, 0x01,           // VDF tag
        0x64, 0x00,                        // length = 100
        0xAA, 0xBB                         // only 2 bytes of proof (should be 100)
    };
    auto result = CoinbaseVDF::ExtractProof(data);
    CHECK(result.empty());  // Should fail - not enough data
    PASS();
}

static void test_zero_length_proof()
{
    TEST(zero_length_proof);

    std::vector<uint8_t> data = {
        0x56, 0x44, 0x46, 0x01,           // VDF tag
        0x00, 0x00                          // length = 0
    };
    auto result = CoinbaseVDF::ExtractProof(data);
    CHECK(result.empty());  // Zero-length is invalid
    PASS();
}

static void test_oversized_proof()
{
    TEST(oversized_proof);

    std::vector<uint8_t> data = {
        0x56, 0x44, 0x46, 0x01,           // VDF tag
        0x01, 0x04                          // length = 1025 (> MAX_PROOF_SIZE=512)
    };
    // Pad enough bytes
    data.resize(6 + 1025, 0xCC);
    auto result = CoinbaseVDF::ExtractProof(data);
    CHECK(result.empty());  // Too large
    PASS();
}

int main()
{
    std::cout << "\nCoinbaseVDF Proof Tests\n";
    std::cout << "=======================\n\n";

    test_embed_extract_roundtrip();
    test_extract_from_empty();
    test_extract_no_tag();
    test_proof_hash_commitment();
    test_truncated_proof();
    test_zero_length_proof();
    test_oversized_proof();

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    if (failed > 0) {
        std::cout << "\n=== TESTS FAILED ===\n";
        return 1;
    }
    std::cout << "\n=== ALL TESTS PASSED ===\n";
    return 0;
}
