// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license.

#include <boost/test/unit_test.hpp>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <support/cleanse.h>

/**
 * Bitcoin Core-compatible key management tests using Dilithium.
 * Tests CKey and CPubKey classes with post-quantum signatures.
 */

BOOST_AUTO_TEST_SUITE(key_tests)

BOOST_AUTO_TEST_CASE(key_basic_generation)
{
    CKey key;
    BOOST_CHECK(!key.IsValid());

    key.MakeNewKey(false);
    BOOST_CHECK(key.IsValid());
}

BOOST_AUTO_TEST_CASE(key_pubkey_derivation)
{
    CKey key;
    key.MakeNewKey(false);
    BOOST_CHECK(key.IsValid());

    CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), DILITHIUM_PUBLICKEYBYTES);
}

BOOST_AUTO_TEST_CASE(key_sign_verify_basic)
{
    // Generate key
    CKey key;
    key.MakeNewKey(false);
    CPubKey pubkey = key.GetPubKey();

    // Create test hash
    uint256 hash;
    GetRandBytes(hash.data, 32);

    // Sign
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));
    BOOST_CHECK_EQUAL(sig.size(), DILITHIUM_BYTES);

    // Verify
    BOOST_CHECK(pubkey.Verify(hash, sig));
}

BOOST_AUTO_TEST_CASE(key_invalid_signature_detection)
{
    CKey key;
    key.MakeNewKey(false);
    CPubKey pubkey = key.GetPubKey();

    uint256 hash;
    GetRandBytes(hash.data, 32);

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));

    // Corrupt signature
    sig[0] ^= 0x01;

    // Verify should fail
    BOOST_CHECK(!pubkey.Verify(hash, sig));
}

BOOST_AUTO_TEST_CASE(key_wrong_hash_detection)
{
    CKey key;
    key.MakeNewKey(false);
    CPubKey pubkey = key.GetPubKey();

    uint256 hash1, hash2;
    GetRandBytes(hash1.data, 32);
    GetRandBytes(hash2.data, 32);

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash1, sig));

    // Verify with wrong hash should fail
    BOOST_CHECK(!pubkey.Verify(hash2, sig));
}

BOOST_AUTO_TEST_CASE(key_paranoid_mode)
{
    CKey key;
    key.MakeNewKey(true); // Paranoid mode
    BOOST_CHECK(key.IsValid());
    BOOST_CHECK(key.IsParanoid());

    CPubKey pubkey = key.GetPubKey();

    uint256 hash;
    GetRandBytes(hash.data, 32);

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));

    // Paranoid verification
    BOOST_CHECK(pubkey.VerifyParanoid(hash, sig));
}

BOOST_AUTO_TEST_CASE(key_serialization)
{
    CKey key1;
    key1.MakeNewKey(false);

    // Serialize
    std::vector<unsigned char> serialized(DILITHIUM_SECRETKEYBYTES);
    memcpy(serialized.data(), key1.data(), DILITHIUM_SECRETKEYBYTES);

    // Deserialize
    CKey key2;
    BOOST_CHECK(key2.Set(serialized.data(), serialized.data() + serialized.size(), false));
    BOOST_CHECK(key2.IsValid());

    // Both keys should produce same public key
    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();
    BOOST_CHECK(pubkey1 == pubkey2);
}

BOOST_AUTO_TEST_CASE(pubkey_equality)
{
    CKey key1, key2;
    key1.MakeNewKey(false);
    key2.MakeNewKey(false);

    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();
    CPubKey pubkey1_copy = key1.GetPubKey();

    BOOST_CHECK(pubkey1 == pubkey1_copy);
    BOOST_CHECK(pubkey1 != pubkey2);
}

BOOST_AUTO_TEST_CASE(key_multiple_signatures)
{
    CKey key;
    key.MakeNewKey(false);
    CPubKey pubkey = key.GetPubKey();

    // Sign 10 different messages
    for (int i = 0; i < 10; i++) {
        uint256 hash;
        GetRandBytes(hash.data, 32);

        std::vector<unsigned char> sig;
        BOOST_CHECK(key.Sign(hash, sig));
        BOOST_CHECK(pubkey.Verify(hash, sig));
    }
}

BOOST_AUTO_TEST_CASE(key_verify_pubkey)
{
    CKey key;
    key.MakeNewKey(false);
    CPubKey pubkey = key.GetPubKey();

    // VerifyPubKey should confirm match
    BOOST_CHECK(key.VerifyPubKey(pubkey));

    // Different key should not match
    CKey key2;
    key2.MakeNewKey(false);
    CPubKey pubkey2 = key2.GetPubKey();

    BOOST_CHECK(!key.VerifyPubKey(pubkey2));
}

BOOST_AUTO_TEST_SUITE_END()
