// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * BIP39 Mnemonic Tests
 *
 * Comprehensive tests for Dilithion's HD wallet mnemonic phrase implementation:
 * - Mnemonic generation (128, 160, 192, 224, 256 bit entropy)
 * - Mnemonic validation (checksum verification)
 * - Seed derivation (PBKDF2-SHA3-512)
 * - Entropy conversion (to/from mnemonic)
 *
 * Adapted from BIP39 test vectors with SHA-3 instead of SHA-2
 * for quantum resistance.
 */

#include <boost/test/unit_test.hpp>

#include <wallet/mnemonic.h>
#include <crypto/sha3.h>
#include <cstring>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

// Helper: Convert hex string to bytes
static std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper: Convert bytes to hex string
static std::string BytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

// Helper: Convert vector to hex string
static std::string BytesToHex(const std::vector<uint8_t>& data) {
    return BytesToHex(data.data(), data.size());
}

BOOST_AUTO_TEST_SUITE(mnemonic_tests)

/**
 * Test Suite 1: Entropy and Word Count Validation
 */
BOOST_AUTO_TEST_SUITE(entropy_validation_tests)

BOOST_AUTO_TEST_CASE(valid_entropy_bits) {
    // Valid entropy sizes
    BOOST_CHECK_EQUAL(CMnemonic::GetWordCount(128), 12);
    BOOST_CHECK_EQUAL(CMnemonic::GetWordCount(160), 15);
    BOOST_CHECK_EQUAL(CMnemonic::GetWordCount(192), 18);
    BOOST_CHECK_EQUAL(CMnemonic::GetWordCount(224), 21);
    BOOST_CHECK_EQUAL(CMnemonic::GetWordCount(256), 24);
}

BOOST_AUTO_TEST_CASE(invalid_entropy_bits) {
    // Invalid entropy sizes should return 0
    BOOST_CHECK_EQUAL(CMnemonic::GetWordCount(64), 0);
    BOOST_CHECK_EQUAL(CMnemonic::GetWordCount(96), 0);
    BOOST_CHECK_EQUAL(CMnemonic::GetWordCount(129), 0);
    BOOST_CHECK_EQUAL(CMnemonic::GetWordCount(512), 0);
}

BOOST_AUTO_TEST_CASE(valid_word_counts) {
    // Valid word counts
    BOOST_CHECK_EQUAL(CMnemonic::GetEntropyBits(12), 128);
    BOOST_CHECK_EQUAL(CMnemonic::GetEntropyBits(15), 160);
    BOOST_CHECK_EQUAL(CMnemonic::GetEntropyBits(18), 192);
    BOOST_CHECK_EQUAL(CMnemonic::GetEntropyBits(21), 224);
    BOOST_CHECK_EQUAL(CMnemonic::GetEntropyBits(24), 256);
}

BOOST_AUTO_TEST_CASE(invalid_word_counts) {
    // Invalid word counts should return 0
    BOOST_CHECK_EQUAL(CMnemonic::GetEntropyBits(6), 0);
    BOOST_CHECK_EQUAL(CMnemonic::GetEntropyBits(11), 0);
    BOOST_CHECK_EQUAL(CMnemonic::GetEntropyBits(13), 0);
    BOOST_CHECK_EQUAL(CMnemonic::GetEntropyBits(25), 0);
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 2: Mnemonic Generation from Entropy
 */
BOOST_AUTO_TEST_SUITE(mnemonic_generation_tests)

BOOST_AUTO_TEST_CASE(generate_from_entropy_12_words) {
    // Test 12-word mnemonic generation (128-bit entropy)
    uint8_t entropy[16];
    std::memset(entropy, 0x00, 16);  // All zeros for predictable test

    std::string mnemonic;
    BOOST_REQUIRE(CMnemonic::FromEntropy(entropy, 16, mnemonic));

    // Should produce exactly 12 words
    std::vector<std::string> words;
    std::istringstream iss(mnemonic);
    std::string word;
    while (iss >> word) {
        words.push_back(word);
    }
    BOOST_CHECK_EQUAL(words.size(), 12);

    // Validate the generated mnemonic
    BOOST_CHECK(CMnemonic::Validate(mnemonic));
}

BOOST_AUTO_TEST_CASE(generate_from_entropy_24_words) {
    // Test 24-word mnemonic generation (256-bit entropy)
    uint8_t entropy[32];
    std::memset(entropy, 0xFF, 32);  // All ones for predictable test

    std::string mnemonic;
    BOOST_REQUIRE(CMnemonic::FromEntropy(entropy, 32, mnemonic));

    // Should produce exactly 24 words
    std::vector<std::string> words;
    std::istringstream iss(mnemonic);
    std::string word;
    while (iss >> word) {
        words.push_back(word);
    }
    BOOST_CHECK_EQUAL(words.size(), 24);

    // Validate the generated mnemonic
    BOOST_CHECK(CMnemonic::Validate(mnemonic));
}

BOOST_AUTO_TEST_CASE(generate_random_12_words) {
    std::string mnemonic1, mnemonic2;

    // Generate two 12-word mnemonics
    BOOST_REQUIRE(CMnemonic::Generate(128, mnemonic1));
    BOOST_REQUIRE(CMnemonic::Generate(128, mnemonic2));

    // Both should be valid
    BOOST_CHECK(CMnemonic::Validate(mnemonic1));
    BOOST_CHECK(CMnemonic::Validate(mnemonic2));

    // Should be different (with overwhelming probability)
    BOOST_CHECK(mnemonic1 != mnemonic2);
}

BOOST_AUTO_TEST_CASE(generate_random_24_words) {
    std::string mnemonic1, mnemonic2;

    // Generate two 24-word mnemonics
    BOOST_REQUIRE(CMnemonic::Generate(256, mnemonic1));
    BOOST_REQUIRE(CMnemonic::Generate(256, mnemonic2));

    // Both should be valid
    BOOST_CHECK(CMnemonic::Validate(mnemonic1));
    BOOST_CHECK(CMnemonic::Validate(mnemonic2));

    // Should be different (with overwhelming probability)
    BOOST_CHECK(mnemonic1 != mnemonic2);
}

BOOST_AUTO_TEST_CASE(reject_invalid_entropy_length) {
    std::string mnemonic;

    // 15 bytes is invalid (not 16, 20, 24, 28, or 32)
    uint8_t entropy[15];
    std::memset(entropy, 0x00, 15);

    BOOST_CHECK(!CMnemonic::FromEntropy(entropy, 15, mnemonic));
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 3: Mnemonic Validation
 */
BOOST_AUTO_TEST_SUITE(mnemonic_validation_tests)

BOOST_AUTO_TEST_CASE(validate_known_good_mnemonic) {
    // Known valid 12-word mnemonic (Dilithion uses SHA3-256 for checksums, so "absorb" not "about")
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";
    BOOST_CHECK(CMnemonic::Validate(mnemonic));
}

BOOST_AUTO_TEST_CASE(reject_invalid_word_count) {
    // 11 words (invalid count)
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    BOOST_CHECK(!CMnemonic::Validate(mnemonic));
}

BOOST_AUTO_TEST_CASE(reject_invalid_word) {
    // Contains "notaword" which is not in BIP39 wordlist
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
    BOOST_CHECK(!CMnemonic::Validate(mnemonic));
}

BOOST_AUTO_TEST_CASE(reject_bad_checksum) {
    // Valid words but wrong checksum (last word changed)
    // "abandon abandon..." should end with "about" for correct checksum
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ability";
    BOOST_CHECK(!CMnemonic::Validate(mnemonic));
}

BOOST_AUTO_TEST_CASE(case_insensitive_validation) {
    // Mixed case should work (Dilithion SHA3-256 checksum: "absorb" not "about")
    std::string mnemonic_lower = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";
    std::string mnemonic_upper = "ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABSORB";
    std::string mnemonic_mixed = "Abandon Abandon abandon ABANDON abandon Abandon abandon abandon ABANDON abandon abandon absorb";

    BOOST_CHECK(CMnemonic::Validate(mnemonic_lower));
    BOOST_CHECK(CMnemonic::Validate(mnemonic_upper));
    BOOST_CHECK(CMnemonic::Validate(mnemonic_mixed));
}

BOOST_AUTO_TEST_CASE(validate_all_entropy_sizes) {
    // Generate and validate mnemonics for all valid entropy sizes
    for (size_t bits : {128, 160, 192, 224, 256}) {
        std::string mnemonic;
        BOOST_REQUIRE(CMnemonic::Generate(bits, mnemonic));
        BOOST_CHECK(CMnemonic::Validate(mnemonic));
    }
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 4: Entropy Conversion (Roundtrip)
 */
BOOST_AUTO_TEST_SUITE(entropy_conversion_tests)

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_to_entropy_128bit) {
    // Original entropy
    uint8_t original_entropy[16];
    for (int i = 0; i < 16; i++) {
        original_entropy[i] = static_cast<uint8_t>(i * 17);  // Predictable pattern
    }

    // Convert to mnemonic
    std::string mnemonic;
    BOOST_REQUIRE(CMnemonic::FromEntropy(original_entropy, 16, mnemonic));

    // Convert back to entropy
    std::vector<uint8_t> recovered_entropy;
    BOOST_REQUIRE(CMnemonic::ToEntropy(mnemonic, recovered_entropy));

    // Should match original
    BOOST_REQUIRE_EQUAL(recovered_entropy.size(), 16);
    BOOST_CHECK(std::memcmp(original_entropy, recovered_entropy.data(), 16) == 0);
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_to_entropy_256bit) {
    // Original entropy
    uint8_t original_entropy[32];
    for (int i = 0; i < 32; i++) {
        original_entropy[i] = static_cast<uint8_t>(i * 7 + 3);  // Predictable pattern
    }

    // Convert to mnemonic
    std::string mnemonic;
    BOOST_REQUIRE(CMnemonic::FromEntropy(original_entropy, 32, mnemonic));

    // Convert back to entropy
    std::vector<uint8_t> recovered_entropy;
    BOOST_REQUIRE(CMnemonic::ToEntropy(mnemonic, recovered_entropy));

    // Should match original
    BOOST_REQUIRE_EQUAL(recovered_entropy.size(), 32);
    BOOST_CHECK(std::memcmp(original_entropy, recovered_entropy.data(), 32) == 0);
}

BOOST_AUTO_TEST_CASE(reject_invalid_mnemonic_in_to_entropy) {
    std::vector<uint8_t> entropy;

    // Invalid mnemonic (bad checksum)
    std::string bad_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ability";
    BOOST_CHECK(!CMnemonic::ToEntropy(bad_mnemonic, entropy));
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 5: Seed Derivation (PBKDF2-SHA3-512)
 */
BOOST_AUTO_TEST_SUITE(seed_derivation_tests)

BOOST_AUTO_TEST_CASE(derive_seed_without_passphrase) {
    // Dilithion SHA3-256 checksum: "absorb" not "about"
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";
    uint8_t seed[64];

    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "", seed));

    // Seed should be non-zero
    bool all_zero = true;
    for (int i = 0; i < 64; i++) {
        if (seed[i] != 0) {
            all_zero = false;
            break;
        }
    }
    BOOST_CHECK(!all_zero);
}

BOOST_AUTO_TEST_CASE(derive_seed_with_passphrase) {
    // Dilithion SHA3-256 checksum: "absorb" not "about"
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";
    uint8_t seed_no_pass[64];
    uint8_t seed_with_pass[64];

    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "", seed_no_pass));
    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "TREZOR", seed_with_pass));

    // Seeds should be different
    BOOST_CHECK(std::memcmp(seed_no_pass, seed_with_pass, 64) != 0);
}

BOOST_AUTO_TEST_CASE(seed_derivation_is_deterministic) {
    // Dilithion SHA3-256 checksum: "absorb" not "about"
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";
    uint8_t seed1[64];
    uint8_t seed2[64];

    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "test", seed1));
    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "test", seed2));

    // Same mnemonic and passphrase should produce same seed
    BOOST_CHECK(std::memcmp(seed1, seed2, 64) == 0);
}

BOOST_AUTO_TEST_CASE(different_mnemonics_different_seeds) {
    std::string mnemonic1;
    std::string mnemonic2;
    uint8_t seed1[64];
    uint8_t seed2[64];

    BOOST_REQUIRE(CMnemonic::Generate(256, mnemonic1));
    BOOST_REQUIRE(CMnemonic::Generate(256, mnemonic2));

    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic1, "", seed1));
    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic2, "", seed2));

    // Different mnemonics should produce different seeds
    BOOST_CHECK(std::memcmp(seed1, seed2, 64) != 0);
}

BOOST_AUTO_TEST_CASE(reject_invalid_mnemonic_in_seed_derivation) {
    uint8_t seed[64];

    // Invalid mnemonic (bad checksum)
    std::string bad_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ability";
    BOOST_CHECK(!CMnemonic::ToSeed(bad_mnemonic, "", seed));
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 6: Specific Test Vectors
 *
 * Note: These test vectors are adapted for SHA-3 instead of SHA-2.
 * The mnemonics will differ from standard BIP39 test vectors because
 * we use SHA3-256 for checksums instead of SHA-256.
 */
BOOST_AUTO_TEST_SUITE(test_vectors)

BOOST_AUTO_TEST_CASE(test_vector_all_zeros_entropy) {
    // 16 bytes of zero entropy
    uint8_t entropy[16];
    std::memset(entropy, 0x00, 16);

    std::string mnemonic;
    BOOST_REQUIRE(CMnemonic::FromEntropy(entropy, 16, mnemonic));

    // Validate the mnemonic
    BOOST_CHECK(CMnemonic::Validate(mnemonic));

    // Roundtrip test
    std::vector<uint8_t> recovered_entropy;
    BOOST_REQUIRE(CMnemonic::ToEntropy(mnemonic, recovered_entropy));
    BOOST_CHECK(std::memcmp(entropy, recovered_entropy.data(), 16) == 0);

    // Derive seed
    uint8_t seed[64];
    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "", seed));
}

BOOST_AUTO_TEST_CASE(test_vector_all_ones_entropy) {
    // 32 bytes of 0xFF entropy
    uint8_t entropy[32];
    std::memset(entropy, 0xFF, 32);

    std::string mnemonic;
    BOOST_REQUIRE(CMnemonic::FromEntropy(entropy, 32, mnemonic));

    // Validate the mnemonic
    BOOST_CHECK(CMnemonic::Validate(mnemonic));

    // Roundtrip test
    std::vector<uint8_t> recovered_entropy;
    BOOST_REQUIRE(CMnemonic::ToEntropy(mnemonic, recovered_entropy));
    BOOST_CHECK(std::memcmp(entropy, recovered_entropy.data(), 32) == 0);

    // Derive seed
    uint8_t seed[64];
    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "Dilithion", seed));
}

BOOST_AUTO_TEST_CASE(test_vector_sequential_entropy) {
    // 24 bytes of sequential values (0x00, 0x01, 0x02, ...)
    uint8_t entropy[24];
    for (int i = 0; i < 24; i++) {
        entropy[i] = static_cast<uint8_t>(i);
    }

    std::string mnemonic;
    BOOST_REQUIRE(CMnemonic::FromEntropy(entropy, 24, mnemonic));

    // Validate the mnemonic
    BOOST_CHECK(CMnemonic::Validate(mnemonic));

    // Roundtrip test
    std::vector<uint8_t> recovered_entropy;
    BOOST_REQUIRE(CMnemonic::ToEntropy(mnemonic, recovered_entropy));
    BOOST_CHECK(std::memcmp(entropy, recovered_entropy.data(), 24) == 0);
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 7: Edge Cases and Error Handling
 */
BOOST_AUTO_TEST_SUITE(edge_cases)

BOOST_AUTO_TEST_CASE(empty_mnemonic) {
    BOOST_CHECK(!CMnemonic::Validate(""));
}

BOOST_AUTO_TEST_CASE(whitespace_handling) {
    // Multiple spaces between words (Dilithion SHA3-256 checksum: "absorb")
    std::string mnemonic_multi_space = "abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  absorb";
    BOOST_CHECK(CMnemonic::Validate(mnemonic_multi_space));

    // Leading/trailing spaces
    std::string mnemonic_spaces = "  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb  ";
    BOOST_CHECK(CMnemonic::Validate(mnemonic_spaces));
}

BOOST_AUTO_TEST_CASE(unicode_passphrase) {
    // Dilithion SHA3-256 checksum: "absorb" not "about"
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";
    uint8_t seed_ascii[64];
    uint8_t seed_unicode[64];

    // ASCII passphrase
    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "test", seed_ascii));

    // UTF-8 passphrase (Japanese characters)
    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "テスト", seed_unicode));

    // Should be different
    BOOST_CHECK(std::memcmp(seed_ascii, seed_unicode, 64) != 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE_END()
