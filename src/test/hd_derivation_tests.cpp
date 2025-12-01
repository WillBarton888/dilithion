// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * HD Derivation Tests
 *
 * Comprehensive tests for Dilithion's Hierarchical Deterministic wallet:
 * - Extended key management
 * - BIP44 path parsing and validation
 * - Master key derivation from BIP39 seed
 * - Child key derivation (hardened only for security)
 * - Path derivation through multiple levels
 * - Dilithium keypair generation from extended keys
 * - Determinism and reproducibility
 */

#include <boost/test/unit_test.hpp>

#include <wallet/hd_derivation.h>
#include <wallet/mnemonic.h>
#include <cstring>
#include <vector>

BOOST_AUTO_TEST_SUITE(hd_derivation_tests)

/**
 * Test Suite 1: CHDExtendedKey Basic Operations
 */
BOOST_AUTO_TEST_SUITE(extended_key_tests)

BOOST_AUTO_TEST_CASE(extended_key_initialization) {
    CHDExtendedKey key;

    // Should be initialized to zeros
    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(key.seed[i], 0);
        BOOST_CHECK_EQUAL(key.chaincode[i], 0);
    }
    BOOST_CHECK_EQUAL(key.depth, 0);
    BOOST_CHECK_EQUAL(key.fingerprint, 0);
    BOOST_CHECK_EQUAL(key.child_index, 0);
}

BOOST_AUTO_TEST_CASE(extended_key_wipe) {
    CHDExtendedKey key;

    // Set some values
    std::memset(key.seed, 0xFF, 32);
    std::memset(key.chaincode, 0xAA, 32);
    key.depth = 5;
    key.fingerprint = 0x12345678;
    key.child_index = 100;

    // Wipe
    key.Wipe();

    // Should all be zero
    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(key.seed[i], 0);
        BOOST_CHECK_EQUAL(key.chaincode[i], 0);
    }
    BOOST_CHECK_EQUAL(key.depth, 0);
    BOOST_CHECK_EQUAL(key.fingerprint, 0);
    BOOST_CHECK_EQUAL(key.child_index, 0);
}

BOOST_AUTO_TEST_CASE(extended_key_is_master) {
    CHDExtendedKey key;

    // Depth 0 is master
    key.depth = 0;
    BOOST_CHECK(key.IsMaster());

    // Depth > 0 is not master
    key.depth = 1;
    BOOST_CHECK(!key.IsMaster());

    key.depth = 5;
    BOOST_CHECK(!key.IsMaster());
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 2: CHDKeyPath Parsing
 */
BOOST_AUTO_TEST_SUITE(key_path_tests)

BOOST_AUTO_TEST_CASE(parse_simple_path) {
    CHDKeyPath path;

    BOOST_REQUIRE(path.Parse("m/44'/573'/0'/0'/0'"));
    BOOST_REQUIRE_EQUAL(path.indices.size(), 5);
    BOOST_CHECK_EQUAL(path.indices[0], 44 | HD_HARDENED_BIT);
    BOOST_CHECK_EQUAL(path.indices[1], 573 | HD_HARDENED_BIT);
    BOOST_CHECK_EQUAL(path.indices[2], 0 | HD_HARDENED_BIT);
    BOOST_CHECK_EQUAL(path.indices[3], 0 | HD_HARDENED_BIT);
    BOOST_CHECK_EQUAL(path.indices[4], 0 | HD_HARDENED_BIT);
}

BOOST_AUTO_TEST_CASE(parse_receive_address_path) {
    CHDKeyPath path;

    // First receive address of account 0
    BOOST_REQUIRE(path.Parse("m/44'/573'/0'/0'/0'"));
    BOOST_CHECK(path.IsValid());

    // 10th receive address of account 2
    BOOST_REQUIRE(path.Parse("m/44'/573'/2'/0'/9'"));
    BOOST_CHECK(path.IsValid());
}

BOOST_AUTO_TEST_CASE(parse_change_address_path) {
    CHDKeyPath path;

    // First change address of account 0
    BOOST_REQUIRE(path.Parse("m/44'/573'/0'/1'/0'"));
    BOOST_CHECK(path.IsValid());

    // 5th change address of account 1
    BOOST_REQUIRE(path.Parse("m/44'/573'/1'/1'/4'"));
    BOOST_CHECK(path.IsValid());
}

BOOST_AUTO_TEST_CASE(path_to_string) {
    CHDKeyPath path("m/44'/573'/0'/0'/0'");
    BOOST_CHECK_EQUAL(path.ToString(), "m/44'/573'/0'/0'/0'");

    CHDKeyPath path2("m/44'/573'/2'/1'/10'");
    BOOST_CHECK_EQUAL(path2.ToString(), "m/44'/573'/2'/1'/10'");
}

BOOST_AUTO_TEST_CASE(reject_invalid_paths) {
    CHDKeyPath path;

    // Empty path
    BOOST_CHECK(!path.Parse(""));

    // Wrong prefix
    BOOST_CHECK(!path.Parse("n/44'/573'/0'/0'/0'"));

    // Too few levels (parses OK syntactically, fails validation)
    BOOST_CHECK(path.Parse("m/44'/573'/0'"));
    BOOST_CHECK(!path.IsValid());

    // Too many levels (parses OK syntactically, fails validation)
    BOOST_CHECK(path.Parse("m/44'/573'/0'/0'/0'/0'"));
    BOOST_CHECK(!path.IsValid());

    // Wrong purpose
    BOOST_CHECK(path.Parse("m/49'/573'/0'/0'/0'"));
    BOOST_CHECK(!path.IsValid());

    // Wrong coin type
    BOOST_CHECK(path.Parse("m/44'/0'/0'/0'/0'"));
    BOOST_CHECK(!path.IsValid());

    // Non-hardened derivation (not supported for Dilithium)
    BOOST_CHECK(path.Parse("m/44'/573'/0/0/0"));
    BOOST_CHECK(!path.IsValid());
}

BOOST_AUTO_TEST_CASE(standard_paths) {
    // Test ReceiveAddress helper
    CHDKeyPath receive = CHDKeyPath::ReceiveAddress(0, 0);
    BOOST_CHECK(receive.IsValid());
    BOOST_CHECK_EQUAL(receive.ToString(), "m/44'/573'/0'/0'/0'");

    CHDKeyPath receive5 = CHDKeyPath::ReceiveAddress(2, 5);
    BOOST_CHECK(receive5.IsValid());
    BOOST_CHECK_EQUAL(receive5.ToString(), "m/44'/573'/2'/0'/5'");

    // Test ChangeAddress helper
    CHDKeyPath change = CHDKeyPath::ChangeAddress(0, 0);
    BOOST_CHECK(change.IsValid());
    BOOST_CHECK_EQUAL(change.ToString(), "m/44'/573'/0'/1'/0'");

    CHDKeyPath change3 = CHDKeyPath::ChangeAddress(1, 3);
    BOOST_CHECK(change3.IsValid());
    BOOST_CHECK_EQUAL(change3.ToString(), "m/44'/573'/1'/1'/3'");
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 3: Master Key Derivation
 */
BOOST_AUTO_TEST_SUITE(master_derivation_tests)

BOOST_AUTO_TEST_CASE(derive_master_from_seed) {
    // Create test seed (would come from BIP39 mnemonic)
    uint8_t seed[64];
    std::memset(seed, 0x00, 64);

    CHDExtendedKey master;
    DeriveMaster(seed, master);

    // Master key should be generated
    BOOST_CHECK(master.IsMaster());
    BOOST_CHECK_EQUAL(master.depth, 0);
    BOOST_CHECK_EQUAL(master.fingerprint, 0);
    BOOST_CHECK_EQUAL(master.child_index, 0);

    // Seed and chaincode should be non-zero
    bool seed_nonzero = false;
    bool chaincode_nonzero = false;
    for (int i = 0; i < 32; i++) {
        if (master.seed[i] != 0) seed_nonzero = true;
        if (master.chaincode[i] != 0) chaincode_nonzero = true;
    }
    BOOST_CHECK(seed_nonzero);
    BOOST_CHECK(chaincode_nonzero);
}

BOOST_AUTO_TEST_CASE(master_derivation_deterministic) {
    uint8_t seed[64];
    for (int i = 0; i < 64; i++) {
        seed[i] = static_cast<uint8_t>(i * 3);
    }

    CHDExtendedKey master1, master2;
    DeriveMaster(seed, master1);
    DeriveMaster(seed, master2);

    // Same seed should produce same master key
    BOOST_CHECK(std::memcmp(master1.seed, master2.seed, 32) == 0);
    BOOST_CHECK(std::memcmp(master1.chaincode, master2.chaincode, 32) == 0);
}

BOOST_AUTO_TEST_CASE(different_seeds_different_masters) {
    uint8_t seed1[64], seed2[64];
    std::memset(seed1, 0x00, 64);
    std::memset(seed2, 0xFF, 64);

    CHDExtendedKey master1, master2;
    DeriveMaster(seed1, master1);
    DeriveMaster(seed2, master2);

    // Different seeds should produce different master keys
    BOOST_CHECK(std::memcmp(master1.seed, master2.seed, 32) != 0);
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 4: Child Key Derivation
 */
BOOST_AUTO_TEST_SUITE(child_derivation_tests)

BOOST_AUTO_TEST_CASE(derive_hardened_child) {
    // Create test master key
    uint8_t seed[64];
    std::memset(seed, 0xAB, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    // Derive hardened child
    CHDExtendedKey child;
    uint32_t hardened_index = 0 | HD_HARDENED_BIT;
    BOOST_REQUIRE(DeriveChild(master, hardened_index, child));

    // Child should have incremented depth
    BOOST_CHECK_EQUAL(child.depth, master.depth + 1);
    BOOST_CHECK_EQUAL(child.child_index, hardened_index);

    // Child should have different seed/chaincode
    BOOST_CHECK(std::memcmp(child.seed, master.seed, 32) != 0);
    BOOST_CHECK(std::memcmp(child.chaincode, master.chaincode, 32) != 0);
}

BOOST_AUTO_TEST_CASE(reject_non_hardened_derivation) {
    uint8_t seed[64];
    std::memset(seed, 0x00, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    // Non-hardened derivation should fail (security requirement for Dilithium)
    CHDExtendedKey child;
    BOOST_CHECK(!DeriveChild(master, 0, child));
    BOOST_CHECK(!DeriveChild(master, 100, child));
}

BOOST_AUTO_TEST_CASE(child_derivation_deterministic) {
    uint8_t seed[64];
    std::memset(seed, 0xCD, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    uint32_t index = 5 | HD_HARDENED_BIT;
    CHDExtendedKey child1, child2;
    BOOST_REQUIRE(DeriveChild(master, index, child1));
    BOOST_REQUIRE(DeriveChild(master, index, child2));

    // Same parent + index should produce same child
    BOOST_CHECK(std::memcmp(child1.seed, child2.seed, 32) == 0);
    BOOST_CHECK(std::memcmp(child1.chaincode, child2.chaincode, 32) == 0);
}

BOOST_AUTO_TEST_CASE(different_indices_different_children) {
    uint8_t seed[64];
    std::memset(seed, 0x42, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    CHDExtendedKey child1, child2;
    BOOST_REQUIRE(DeriveChild(master, 0 | HD_HARDENED_BIT, child1));
    BOOST_REQUIRE(DeriveChild(master, 1 | HD_HARDENED_BIT, child2));

    // Different indices should produce different children
    BOOST_CHECK(std::memcmp(child1.seed, child2.seed, 32) != 0);
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 5: Path Derivation
 */
BOOST_AUTO_TEST_SUITE(path_derivation_tests)

BOOST_AUTO_TEST_CASE(derive_receive_address) {
    uint8_t seed[64];
    std::memset(seed, 0x12, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    // Derive first receive address: m/44'/573'/0'/0'/0'
    CHDExtendedKey derived;
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/0'/0'", derived));

    BOOST_CHECK_EQUAL(derived.depth, 5);
    BOOST_CHECK(!derived.IsMaster());
}

BOOST_AUTO_TEST_CASE(derive_change_address) {
    uint8_t seed[64];
    std::memset(seed, 0x34, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    // Derive first change address: m/44'/573'/0'/1'/0'
    CHDExtendedKey derived;
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/1'/0'", derived));

    BOOST_CHECK_EQUAL(derived.depth, 5);
}

BOOST_AUTO_TEST_CASE(path_derivation_deterministic) {
    uint8_t seed[64];
    std::memset(seed, 0x56, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    CHDExtendedKey derived1, derived2;
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/0'/5'", derived1));
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/0'/5'", derived2));

    // Same path should produce same result
    BOOST_CHECK(std::memcmp(derived1.seed, derived2.seed, 32) == 0);
    BOOST_CHECK(std::memcmp(derived1.chaincode, derived2.chaincode, 32) == 0);
}

BOOST_AUTO_TEST_CASE(different_paths_different_keys) {
    uint8_t seed[64];
    std::memset(seed, 0x78, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    CHDExtendedKey key1, key2;
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/0'/0'", key1));
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/0'/1'", key2));

    // Different paths should produce different keys
    BOOST_CHECK(std::memcmp(key1.seed, key2.seed, 32) != 0);
}

BOOST_AUTO_TEST_CASE(reject_invalid_path_derivation) {
    uint8_t seed[64];
    std::memset(seed, 0x9A, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    CHDExtendedKey derived;

    // Invalid paths should fail
    BOOST_CHECK(!DerivePath(master, "m/44'/0'/0'/0'/0'", derived));  // Wrong coin type
    BOOST_CHECK(!DerivePath(master, "m/49'/573'/0'/0'/0'", derived)); // Wrong purpose
    BOOST_CHECK(!DerivePath(master, "m/44'/573'/0/0/0", derived));   // Non-hardened
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 6: Dilithium Keypair Generation
 */
BOOST_AUTO_TEST_SUITE(keypair_generation_tests)

BOOST_AUTO_TEST_CASE(generate_dilithium_keypair) {
    uint8_t seed[64];
    std::memset(seed, 0xBC, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    CHDExtendedKey derived;
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/0'/0'", derived));

    // Generate Dilithium keypair
    uint8_t pk[1952];  // Dilithium3 public key size
    uint8_t sk[4032];  // Dilithium3 secret key size (NOT 4000!)
    BOOST_REQUIRE(GenerateDilithiumKey(derived, pk, sk));

    // Keys should be non-zero
    bool pk_nonzero = false, sk_nonzero = false;
    for (int i = 0; i < 1952; i++) {
        if (pk[i] != 0) pk_nonzero = true;
    }
    for (int i = 0; i < 4032; i++) {
        if (sk[i] != 0) sk_nonzero = true;
    }
    BOOST_CHECK(pk_nonzero);
    BOOST_CHECK(sk_nonzero);
}

BOOST_AUTO_TEST_CASE(keypair_generation_deterministic) {
    uint8_t seed[64];
    std::memset(seed, 0xDE, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    CHDExtendedKey derived;
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/0'/0'", derived));

    // Generate twice
    uint8_t pk1[1952], sk1[4032];
    uint8_t pk2[1952], sk2[4032];
    BOOST_REQUIRE(GenerateDilithiumKey(derived, pk1, sk1));
    BOOST_REQUIRE(GenerateDilithiumKey(derived, pk2, sk2));

    // Should produce identical keys
    BOOST_CHECK(std::memcmp(pk1, pk2, 1952) == 0);
    BOOST_CHECK(std::memcmp(sk1, sk2, 4000) == 0);
}

BOOST_AUTO_TEST_CASE(different_paths_different_keypairs) {
    uint8_t seed[64];
    std::memset(seed, 0xEF, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    CHDExtendedKey key1, key2;
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/0'/0'", key1));
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/0'/1'", key2));

    uint8_t pk1[1952], sk1[4032];
    uint8_t pk2[1952], sk2[4032];
    BOOST_REQUIRE(GenerateDilithiumKey(key1, pk1, sk1));
    BOOST_REQUIRE(GenerateDilithiumKey(key2, pk2, sk2));

    // Different paths should produce different keypairs
    BOOST_CHECK(std::memcmp(pk1, pk2, 1952) != 0);
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 7: Fingerprint Computation
 */
BOOST_AUTO_TEST_SUITE(fingerprint_tests)

BOOST_AUTO_TEST_CASE(compute_fingerprint) {
    uint8_t seed[64];
    std::memset(seed, 0xF0, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    uint32_t fp = master.GetFingerprint();

    // Fingerprint should be non-zero
    BOOST_CHECK(fp != 0);
}

BOOST_AUTO_TEST_CASE(fingerprint_deterministic) {
    uint8_t seed[64];
    std::memset(seed, 0xF1, 64);
    CHDExtendedKey master;
    DeriveMaster(seed, master);

    uint32_t fp1 = master.GetFingerprint();
    uint32_t fp2 = master.GetFingerprint();

    // Same key should produce same fingerprint
    BOOST_CHECK_EQUAL(fp1, fp2);
}

BOOST_AUTO_TEST_CASE(different_keys_different_fingerprints) {
    uint8_t seed1[64], seed2[64];
    std::memset(seed1, 0xF2, 64);
    std::memset(seed2, 0xF3, 64);

    CHDExtendedKey master1, master2;
    DeriveMaster(seed1, master1);
    DeriveMaster(seed2, master2);

    uint32_t fp1 = master1.GetFingerprint();
    uint32_t fp2 = master2.GetFingerprint();

    // Different keys should (very likely) have different fingerprints
    BOOST_CHECK(fp1 != fp2);
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Test Suite 8: End-to-End Integration
 */
BOOST_AUTO_TEST_SUITE(integration_tests)

BOOST_AUTO_TEST_CASE(full_hd_wallet_flow) {
    // 1. Generate mnemonic
    std::string mnemonic;
    BOOST_REQUIRE(CMnemonic::Generate(256, mnemonic));

    // 2. Derive seed from mnemonic
    uint8_t bip39_seed[64];
    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "", bip39_seed));

    // 3. Derive master HD key
    CHDExtendedKey master;
    DeriveMaster(bip39_seed, master);
    BOOST_CHECK(master.IsMaster());

    // 4. Derive first receive address
    CHDExtendedKey receive_key;
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/0'/0'", receive_key));

    // 5. Generate Dilithium keypair
    uint8_t pk[1952], sk[4032];
    BOOST_REQUIRE(GenerateDilithiumKey(receive_key, pk, sk));

    // 6. Derive first change address
    CHDExtendedKey change_key;
    BOOST_REQUIRE(DerivePath(master, "m/44'/573'/0'/1'/0'", change_key));

    // 7. Generate change keypair
    uint8_t change_pk[1952], change_sk[4032];
    BOOST_REQUIRE(GenerateDilithiumKey(change_key, change_pk, change_sk));

    // Receive and change keys should be different
    BOOST_CHECK(std::memcmp(pk, change_pk, 1952) != 0);

    // Cleanup
    std::memset(sk, 0, 4032);
    std::memset(change_sk, 0, 4032);
    master.Wipe();
}

BOOST_AUTO_TEST_CASE(wallet_recovery) {
    // Generate original mnemonic
    std::string mnemonic;
    BOOST_REQUIRE(CMnemonic::Generate(256, mnemonic));

    // Derive keys the first time
    uint8_t seed1[64];
    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "", seed1));

    CHDExtendedKey master1;
    DeriveMaster(seed1, master1);

    CHDExtendedKey key1;
    BOOST_REQUIRE(DerivePath(master1, "m/44'/573'/0'/0'/0'", key1));

    uint8_t pk1[1952], sk1[4032];
    BOOST_REQUIRE(GenerateDilithiumKey(key1, pk1, sk1));

    // "Recover" wallet from same mnemonic
    uint8_t seed2[64];
    BOOST_REQUIRE(CMnemonic::ToSeed(mnemonic, "", seed2));

    CHDExtendedKey master2;
    DeriveMaster(seed2, master2);

    CHDExtendedKey key2;
    BOOST_REQUIRE(DerivePath(master2, "m/44'/573'/0'/0'/0'", key2));

    uint8_t pk2[1952], sk2[4032];
    BOOST_REQUIRE(GenerateDilithiumKey(key2, pk2, sk2));

    // Should produce identical keys
    BOOST_CHECK(std::memcmp(pk1, pk2, 1952) == 0);
    BOOST_CHECK(std::memcmp(sk1, sk2, 4000) == 0);

    // Cleanup
    std::memset(sk1, 0, 4032);
    std::memset(sk2, 0, 4032);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE_END()
