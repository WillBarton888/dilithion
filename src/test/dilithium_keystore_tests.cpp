// Copyright (c) 2025 The Dilithion Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dilithium/dilithiumkey.h>
#include <dilithium/dilithiumkeystore.h>
#include <dilithium/dilithiumpubkey.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(dilithium_keystore_tests)

BOOST_AUTO_TEST_CASE(keystore_add_and_get_key)
{
    // Create a fresh keystore
    DilithiumKeyStore keystore;

    // Generate a test key
    DilithiumKey key;
    BOOST_CHECK(key.MakeNewKey());
    BOOST_CHECK(key.IsValid());

    // Add key to keystore
    std::string keyid;
    BOOST_CHECK(keystore.AddKey(key, "test-key-1", keyid));
    BOOST_CHECK(!keyid.empty());
    BOOST_CHECK_EQUAL(keyid.length(), 16); // Key ID is 16 hex characters

    // Retrieve the key
    DilithiumKey retrieved_key;
    BOOST_CHECK(keystore.GetKey(keyid, retrieved_key));
    BOOST_CHECK(retrieved_key.IsValid());

    // Verify it's the same key by comparing public keys
    BOOST_CHECK(key.GetPubKey() == retrieved_key.GetPubKey());
}

BOOST_AUTO_TEST_CASE(keystore_duplicate_key_rejected)
{
    DilithiumKeyStore keystore;

    // Generate a key
    DilithiumKey key;
    BOOST_CHECK(key.MakeNewKey());

    // Add it once
    std::string keyid1;
    BOOST_CHECK(keystore.AddKey(key, "first", keyid1));

    // Try to add the same key again - should fail
    std::string keyid2;
    BOOST_CHECK(!keystore.AddKey(key, "second", keyid2));
}

BOOST_AUTO_TEST_CASE(keystore_list_keys)
{
    DilithiumKeyStore keystore;

    // Initially empty
    std::vector<DilithiumKeyInfo> keys = keystore.ListKeys();
    BOOST_CHECK_EQUAL(keys.size(), 0);

    // Add first key
    DilithiumKey key1;
    BOOST_CHECK(key1.MakeNewKey());
    std::string keyid1;
    BOOST_CHECK(keystore.AddKey(key1, "key-1", keyid1));

    // Add second key
    DilithiumKey key2;
    BOOST_CHECK(key2.MakeNewKey());
    std::string keyid2;
    BOOST_CHECK(keystore.AddKey(key2, "key-2", keyid2));

    // List should have 2 keys
    keys = keystore.ListKeys();
    BOOST_CHECK_EQUAL(keys.size(), 2);

    // Verify key info
    bool found_key1 = false;
    bool found_key2 = false;
    for (const auto& info : keys) {
        if (info.keyid == keyid1) {
            found_key1 = true;
            BOOST_CHECK_EQUAL(info.label, "key-1");
            BOOST_CHECK(info.pubkey == key1.GetPubKey());
            BOOST_CHECK(info.pubkey.IsValid());
            BOOST_CHECK_EQUAL(info.usage_count, 0);
        }
        if (info.keyid == keyid2) {
            found_key2 = true;
            BOOST_CHECK_EQUAL(info.label, "key-2");
            BOOST_CHECK(info.pubkey == key2.GetPubKey());
            BOOST_CHECK(info.pubkey.IsValid());
            BOOST_CHECK_EQUAL(info.usage_count, 0);
        }
    }
    BOOST_CHECK(found_key1);
    BOOST_CHECK(found_key2);
}

BOOST_AUTO_TEST_CASE(keystore_metadata_tracking)
{
    DilithiumKeyStore keystore;

    // Add a key
    DilithiumKey key;
    BOOST_CHECK(key.MakeNewKey());
    std::string keyid;
    BOOST_CHECK(keystore.AddKey(key, "test-meta", keyid));

    // Get metadata
    DilithiumKeyMetadata meta;
    BOOST_CHECK(keystore.GetMetadata(keyid, meta));
    BOOST_CHECK_EQUAL(meta.keyid, keyid);
    BOOST_CHECK_EQUAL(meta.label, "test-meta");
    BOOST_CHECK_GT(meta.created_time, 0);
    BOOST_CHECK_EQUAL(meta.last_used_time, 0);
    BOOST_CHECK_EQUAL(meta.usage_count, 0);

    // Update usage
    keystore.UpdateUsage(keyid);

    // Check updated metadata
    BOOST_CHECK(keystore.GetMetadata(keyid, meta));
    BOOST_CHECK_EQUAL(meta.usage_count, 1);
    BOOST_CHECK_GT(meta.last_used_time, 0);

    // Update again
    keystore.UpdateUsage(keyid);
    BOOST_CHECK(keystore.GetMetadata(keyid, meta));
    BOOST_CHECK_EQUAL(meta.usage_count, 2);
}

BOOST_AUTO_TEST_CASE(keystore_get_by_pubkey)
{
    DilithiumKeyStore keystore;

    // Add a key
    DilithiumKey key;
    BOOST_CHECK(key.MakeNewKey());
    DilithiumPubKey pubkey = key.GetPubKey();
    std::string keyid;
    BOOST_CHECK(keystore.AddKey(key, "test-pubkey", keyid));

    // Retrieve by public key
    DilithiumKey retrieved_key;
    BOOST_CHECK(keystore.GetKeyByPubKey(pubkey, retrieved_key));
    BOOST_CHECK(retrieved_key.GetPubKey() == pubkey);
}

BOOST_AUTO_TEST_CASE(keystore_remove_key)
{
    DilithiumKeyStore keystore;

    // Add a key
    DilithiumKey key;
    BOOST_CHECK(key.MakeNewKey());
    std::string keyid;
    BOOST_CHECK(keystore.AddKey(key, "to-remove", keyid));

    // Verify it exists
    BOOST_CHECK(keystore.HaveKey(keyid));

    // Remove it
    BOOST_CHECK(keystore.RemoveKey(keyid));

    // Verify it's gone
    BOOST_CHECK(!keystore.HaveKey(keyid));
    DilithiumKey retrieved_key;
    BOOST_CHECK(!keystore.GetKey(keyid, retrieved_key));
}

BOOST_AUTO_TEST_CASE(keystore_clear)
{
    DilithiumKeyStore keystore;

    // Add multiple keys
    for (int i = 0; i < 3; i++) {
        DilithiumKey key;
        BOOST_CHECK(key.MakeNewKey());
        std::string keyid;
        BOOST_CHECK(keystore.AddKey(key, "key-" + std::to_string(i), keyid));
    }

    // Verify they exist
    std::vector<DilithiumKeyInfo> keys = keystore.ListKeys();
    BOOST_CHECK_EQUAL(keys.size(), 3);

    // Clear keystore
    keystore.Clear();

    // Verify empty
    keys = keystore.ListKeys();
    BOOST_CHECK_EQUAL(keys.size(), 0);
}

BOOST_AUTO_TEST_CASE(keystore_pubkey_hex_conversion)
{
    // This test verifies that public keys can be properly converted to hex
    // This was the root cause of the pubkey display bug
    DilithiumKeyStore keystore;

    // Generate a key
    DilithiumKey key;
    BOOST_CHECK(key.MakeNewKey());
    DilithiumPubKey pubkey = key.GetPubKey();

    // Add to keystore
    std::string keyid;
    BOOST_CHECK(keystore.AddKey(key, "hex-test", keyid));

    // List keys and check pubkey is not empty
    std::vector<DilithiumKeyInfo> keys = keystore.ListKeys();
    BOOST_CHECK_EQUAL(keys.size(), 1);

    const DilithiumKeyInfo& info = keys[0];
    BOOST_CHECK(info.pubkey.IsValid());
    BOOST_CHECK_EQUAL(info.pubkey.size(), DILITHIUM_PUBLICKEYBYTES);

    // Convert to hex - this is what RPC does
    std::string pubkey_hex = HexStr(info.pubkey.GetVch());
    BOOST_CHECK(!pubkey_hex.empty());
    BOOST_CHECK_EQUAL(pubkey_hex.length(), DILITHIUM_PUBLICKEYBYTES * 2); // 2 hex chars per byte
}

BOOST_AUTO_TEST_CASE(keystore_invalid_key_rejected)
{
    DilithiumKeyStore keystore;

    // Create an invalid key (not initialized)
    DilithiumKey invalid_key;
    BOOST_CHECK(!invalid_key.IsValid());

    // Try to add it - should fail
    std::string keyid;
    BOOST_CHECK(!keystore.AddKey(invalid_key, "invalid", keyid));
}

BOOST_AUTO_TEST_SUITE_END()
