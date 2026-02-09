/**
 * Block header VDF extension tests.
 *
 * Tests: IsVDFBlock(), GetHeaderSize(), SerializeHeader() round-trip,
 *        GetHash() dispatching (SHA3 for VDF, RandomX for legacy),
 *        GetFastHash() version-awareness, VDF field persistence.
 */
#include <primitives/block.h>
#include <crypto/sha3.h>
#include <iostream>
#include <cassert>
#include <cstring>

static int passed = 0;
static int failed = 0;

#define TEST(name) \
    do { std::cout << "  " << #name << "... "; } while(0)

#define PASS() \
    do { std::cout << "PASS\n"; ++passed; } while(0)

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cout << "FAIL (" << #cond << ")\n"; \
            ++failed; \
            return; \
        } \
    } while(0)

static void test_legacy_header_not_vdf()
{
    TEST(legacy_header_not_vdf);
    CBlockHeader h;
    h.nVersion = 1;
    CHECK(!h.IsVDFBlock());
    CHECK(h.GetHeaderSize() == 80);
    PASS();
}

static void test_vdf_header_version4()
{
    TEST(vdf_header_version4);
    CBlockHeader h;
    h.nVersion = 4;
    CHECK(h.IsVDFBlock());
    CHECK(h.GetHeaderSize() == 144);
    PASS();
}

static void test_vdf_header_version5()
{
    TEST(vdf_header_version5);
    CBlockHeader h;
    h.nVersion = 5;
    CHECK(h.IsVDFBlock());
    PASS();
}

static void test_serialize_legacy_80_bytes()
{
    TEST(serialize_legacy_80_bytes);
    CBlockHeader h;
    h.nVersion = 1;
    h.nTime = 1700000000;
    h.nBits = 0x1d00ffff;
    h.nNonce = 42;
    h.hashPrevBlock.data[0] = 0xAB;
    h.hashMerkleRoot.data[31] = 0xCD;

    auto buf = h.SerializeHeader();
    CHECK(buf.size() == 80);

    // Check version bytes (little-endian)
    int32_t ver;
    std::memcpy(&ver, buf.data(), 4);
    CHECK(ver == 1);

    // Check nonce at offset 76
    uint32_t nonce;
    std::memcpy(&nonce, buf.data() + 76, 4);
    CHECK(nonce == 42);

    PASS();
}

static void test_serialize_vdf_144_bytes()
{
    TEST(serialize_vdf_144_bytes);
    CBlockHeader h;
    h.nVersion = 4;
    h.nTime = 1700000000;
    h.nBits = 0x1d00ffff;
    h.nNonce = 0;
    h.hashPrevBlock.data[0] = 0xAB;
    h.hashMerkleRoot.data[31] = 0xCD;

    // Set VDF fields
    for (int i = 0; i < 32; i++) {
        h.vdfOutput.data[i] = static_cast<uint8_t>(i);
        h.vdfProofHash.data[i] = static_cast<uint8_t>(0xFF - i);
    }

    auto buf = h.SerializeHeader();
    CHECK(buf.size() == 144);

    // VDF output starts at offset 80
    CHECK(buf[80] == 0x00);    // vdfOutput.data[0]
    CHECK(buf[81] == 0x01);    // vdfOutput.data[1]
    CHECK(buf[111] == 0x1F);   // vdfOutput.data[31]

    // VDF proof hash starts at offset 112
    CHECK(buf[112] == 0xFF);   // vdfProofHash.data[0]
    CHECK(buf[113] == 0xFE);   // vdfProofHash.data[1]
    CHECK(buf[143] == 0xE0);   // vdfProofHash.data[31]

    PASS();
}

static void test_vdf_get_hash_uses_sha3()
{
    TEST(vdf_get_hash_uses_sha3);
    CBlockHeader h;
    h.nVersion = 4;
    h.nTime = 1700000000;
    h.nBits = 0x1d00ffff;
    h.nNonce = 0;
    h.hashPrevBlock.data[0] = 0xAB;
    h.vdfOutput.data[0] = 0x42;
    h.vdfProofHash.data[0] = 0x99;

    // Compute GetHash() - should use SHA3-256
    uint256 hash = h.GetHash();

    // Manually compute SHA3-256 of the serialized header
    auto buf = h.SerializeHeader();
    uint256 expected;
    SHA3_256(buf.data(), buf.size(), expected.data);

    CHECK(hash == expected);
    PASS();
}

static void test_vdf_get_hash_cached()
{
    TEST(vdf_get_hash_cached);
    CBlockHeader h;
    h.nVersion = 4;
    h.nBits = 0x1d00ffff;
    h.vdfOutput.data[0] = 0x42;

    uint256 hash1 = h.GetHash();
    uint256 hash2 = h.GetHash();
    CHECK(hash1 == hash2);

    // Invalidate cache and recompute
    h.InvalidateCache();
    uint256 hash3 = h.GetHash();
    CHECK(hash1 == hash3);

    PASS();
}

static void test_vdf_fast_hash_includes_vdf_fields()
{
    TEST(vdf_fast_hash_includes_vdf_fields);

    // Two headers identical except for vdfOutput
    CBlockHeader h1, h2;
    h1.nVersion = h2.nVersion = 4;
    h1.nBits = h2.nBits = 0x1d00ffff;
    h1.nTime = h2.nTime = 1700000000;
    h1.vdfOutput.data[0] = 0x01;
    h2.vdfOutput.data[0] = 0x02;

    // Fast hashes should differ
    uint256 fh1 = h1.GetFastHash();
    uint256 fh2 = h2.GetFastHash();
    CHECK(fh1 != fh2);

    PASS();
}

static void test_legacy_fast_hash_ignores_vdf_fields()
{
    TEST(legacy_fast_hash_ignores_vdf_fields);

    // Legacy header: vdfOutput is not serialized even if set
    CBlockHeader h1, h2;
    h1.nVersion = h2.nVersion = 1;
    h1.nBits = h2.nBits = 0x1d00ffff;
    h1.nTime = h2.nTime = 1700000000;
    h1.vdfOutput.data[0] = 0x01;
    h2.vdfOutput.data[0] = 0x02;

    // Fast hashes should be the same (VDF fields not included for v1)
    uint256 fh1 = h1.GetFastHash();
    uint256 fh2 = h2.GetFastHash();
    CHECK(fh1 == fh2);

    PASS();
}

static void test_set_null_clears_vdf_fields()
{
    TEST(set_null_clears_vdf_fields);
    CBlockHeader h;
    h.nVersion = 4;
    h.vdfOutput.data[0] = 0xFF;
    h.vdfProofHash.data[15] = 0xAB;

    h.SetNull();

    CHECK(h.vdfOutput.IsNull());
    CHECK(h.vdfProofHash.IsNull());
    CHECK(!h.IsVDFBlock());

    PASS();
}

static void test_cblock_inherits_vdf_fields()
{
    TEST(cblock_inherits_vdf_fields);

    CBlockHeader hdr;
    hdr.nVersion = 4;
    hdr.nBits = 0x1d00ffff;
    hdr.vdfOutput.data[0] = 0x42;
    hdr.vdfProofHash.data[0] = 0x99;

    CBlock block(hdr);
    CHECK(block.IsVDFBlock());
    CHECK(block.vdfOutput.data[0] == 0x42);
    CHECK(block.vdfProofHash.data[0] == 0x99);

    PASS();
}

int main()
{
    std::cout << "\nBlock Header VDF Extension Tests\n";
    std::cout << "================================\n\n";

    test_legacy_header_not_vdf();
    test_vdf_header_version4();
    test_vdf_header_version5();
    test_serialize_legacy_80_bytes();
    test_serialize_vdf_144_bytes();
    test_vdf_get_hash_uses_sha3();
    test_vdf_get_hash_cached();
    test_vdf_fast_hash_includes_vdf_fields();
    test_legacy_fast_hash_ignores_vdf_fields();
    test_set_null_clears_vdf_fields();
    test_cblock_inherits_vdf_fields();

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";

    if (failed > 0) {
        std::cout << "\n=== TESTS FAILED ===\n";
        return 1;
    }

    std::cout << "\n=== ALL TESTS PASSED ===\n";
    return 0;
}
