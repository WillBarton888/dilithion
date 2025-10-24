// Copyright (c) 2025 The Dilithion Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dilithium/dilithiumkey.h>
#include <dilithium/dilithiumkeystore.h>
#include <dilithium/dilithiumpubkey.h>
#include <crypto/dilithium/dilithium.h>
#include <rpc/client.h>
#include <rpc/server.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

// External keystore used by RPC commands
extern DilithiumKeyStore g_dilithium_keystore;

BOOST_FIXTURE_TEST_SUITE(rpc_dilithium_tests, TestingSetup)

// Helper function to call RPC
static UniValue CallRPC(TestingSetup* setup, const std::string& strMethod, const UniValue& params = UniValue(UniValue::VARR))
{
    JSONRPCRequest request;
    request.context = &setup->m_node;
    request.strMethod = strMethod;
    request.params = params;

    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();

    UniValue result = tableRPC.execute(request);
    return result;
}

BOOST_AUTO_TEST_CASE(rpc_generatedilithiumkeypair)
{
    // Test basic key generation
    UniValue result = CallRPC(this, "generatedilithiumkeypair");

    // Verify result structure
    BOOST_CHECK(result.isObject());
    BOOST_CHECK(result.exists("privkey"));
    BOOST_CHECK(result.exists("pubkey"));
    BOOST_CHECK(result.exists("privkey_size"));
    BOOST_CHECK(result.exists("pubkey_size"));

    // Verify key sizes
    BOOST_CHECK_EQUAL(result["privkey_size"].getInt<int>(), DILITHIUM_SECRETKEYBYTES);
    BOOST_CHECK_EQUAL(result["pubkey_size"].getInt<int>(), DILITHIUM_PUBLICKEYBYTES);

    // Verify hex encoding (each byte = 2 hex chars)
    std::string privkey_hex = result["privkey"].get_str();
    std::string pubkey_hex = result["pubkey"].get_str();
    BOOST_CHECK_EQUAL(privkey_hex.length(), DILITHIUM_SECRETKEYBYTES * 2);
    BOOST_CHECK_EQUAL(pubkey_hex.length(), DILITHIUM_PUBLICKEYBYTES * 2);

    // Verify keys are valid hex
    BOOST_CHECK(IsHex(privkey_hex));
    BOOST_CHECK(IsHex(pubkey_hex));
}

BOOST_AUTO_TEST_CASE(rpc_signmessagedilithium)
{
    // Generate a keypair first
    UniValue keys = CallRPC(this, "generatedilithiumkeypair");
    std::string privkey = keys["privkey"].get_str();

    // Sign a message
    UniValue params(UniValue::VARR);
    params.push_back(privkey);
    params.push_back("Test message for Dilithium");

    UniValue result = CallRPC(this, "signmessagedilithium", params);

    // Verify result structure
    BOOST_CHECK(result.isObject());
    BOOST_CHECK(result.exists("signature"));
    BOOST_CHECK(result.exists("signature_size"));
    BOOST_CHECK(result.exists("message_hash"));

    // Verify signature size (2420 bytes + 1 hash type byte)
    BOOST_CHECK_EQUAL(result["signature_size"].getInt<int>(), DILITHIUM_BITCOIN_BYTES);

    // Verify signature is valid hex
    std::string signature_hex = result["signature"].get_str();
    BOOST_CHECK(IsHex(signature_hex));
    BOOST_CHECK_EQUAL(signature_hex.length(), DILITHIUM_BITCOIN_BYTES * 2);

    // Verify message_hash is valid
    std::string message_hash = result["message_hash"].get_str();
    BOOST_CHECK_EQUAL(message_hash.length(), 64); // 32 bytes = 64 hex chars
    BOOST_CHECK(IsHex(message_hash));
}

BOOST_AUTO_TEST_CASE(rpc_signmessagedilithium_invalid_key)
{
    // Test with invalid private key size - should throw an error
    UniValue params(UniValue::VARR);
    params.push_back("deadbeef"); // Too short
    params.push_back("Test message");

    // Verify that calling with invalid key throws an exception
    bool caught_exception = false;
    try {
        CallRPC(this, "signmessagedilithium", params);
    } catch (...) {
        caught_exception = true;
    }
    BOOST_CHECK(caught_exception);
}

BOOST_AUTO_TEST_CASE(rpc_verifymessagedilithium)
{
    // Generate keys and sign a message
    UniValue keys = CallRPC(this, "generatedilithiumkeypair");
    std::string privkey = keys["privkey"].get_str();
    std::string pubkey = keys["pubkey"].get_str();

    UniValue sign_params(UniValue::VARR);
    sign_params.push_back(privkey);
    sign_params.push_back("Test verification message");
    UniValue sig_result = CallRPC(this, "signmessagedilithium", sign_params);

    std::string signature = sig_result["signature"].get_str();

    // Verify the signature
    UniValue verify_params(UniValue::VARR);
    verify_params.push_back(pubkey);
    verify_params.push_back(signature);
    verify_params.push_back("Test verification message");

    UniValue result = CallRPC(this, "verifymessagedilithium", verify_params);

    // Check result structure
    BOOST_CHECK(result.isObject());
    BOOST_CHECK(result.exists("valid"));
    BOOST_CHECK(result.exists("message_hash"));
    BOOST_CHECK(result.exists("signature_size"));
    BOOST_CHECK(result.exists("pubkey_size"));

    // Signature should be valid
    BOOST_CHECK_EQUAL(result["valid"].get_bool(), true);

    // Sizes should match
    BOOST_CHECK_EQUAL(result["signature_size"].getInt<int>(), DILITHIUM_BITCOIN_BYTES);
    BOOST_CHECK_EQUAL(result["pubkey_size"].getInt<int>(), DILITHIUM_PUBLICKEYBYTES);
}

BOOST_AUTO_TEST_CASE(rpc_verifymessagedilithium_invalid_signature)
{
    // Generate keys
    UniValue keys = CallRPC(this, "generatedilithiumkeypair");
    std::string pubkey = keys["pubkey"].get_str();

    // Create an invalid signature (all zeros)
    std::string bad_sig(DILITHIUM_BITCOIN_BYTES * 2, '0');

    UniValue params(UniValue::VARR);
    params.push_back(pubkey);
    params.push_back(bad_sig);
    params.push_back("Test message");

    UniValue result = CallRPC(this, "verifymessagedilithium", params);

    // Signature should be invalid
    BOOST_CHECK_EQUAL(result["valid"].get_bool(), false);
}

BOOST_AUTO_TEST_CASE(rpc_verifymessagedilithium_wrong_message)
{
    // Generate keys and sign a message
    UniValue keys = CallRPC(this, "generatedilithiumkeypair");
    std::string privkey = keys["privkey"].get_str();
    std::string pubkey = keys["pubkey"].get_str();

    UniValue sign_params(UniValue::VARR);
    sign_params.push_back(privkey);
    sign_params.push_back("Original message");
    UniValue sig_result = CallRPC(this, "signmessagedilithium", sign_params);

    std::string signature = sig_result["signature"].get_str();

    // Try to verify with different message
    UniValue verify_params(UniValue::VARR);
    verify_params.push_back(pubkey);
    verify_params.push_back(signature);
    verify_params.push_back("Different message");

    UniValue result = CallRPC(this, "verifymessagedilithium", verify_params);

    // Signature should be invalid for different message
    BOOST_CHECK_EQUAL(result["valid"].get_bool(), false);
}

BOOST_AUTO_TEST_CASE(rpc_dilithium_e2e_workflow)
{
    // Test complete end-to-end workflow

    // Step 1: Generate keypair
    UniValue keys = CallRPC(this, "generatedilithiumkeypair");
    BOOST_CHECK(keys.isObject());
    std::string privkey = keys["privkey"].get_str();
    std::string pubkey = keys["pubkey"].get_str();

    // Step 2: Sign multiple messages
    std::vector<std::string> messages = {
        "Hello, Dilithium!",
        "Post-quantum cryptography",
        "NIST FIPS 204 standardized",
        "Bitcoin meets quantum resistance"
    };

    std::vector<std::string> signatures;

    for (const auto& msg : messages) {
        UniValue sign_params(UniValue::VARR);
        sign_params.push_back(privkey);
        sign_params.push_back(msg);

        UniValue sig_result = CallRPC(this, "signmessagedilithium", sign_params);
        BOOST_CHECK(sig_result.exists("signature"));

        signatures.push_back(sig_result["signature"].get_str());
    }

    // Step 3: Verify all signatures
    for (size_t i = 0; i < messages.size(); ++i) {
        UniValue verify_params(UniValue::VARR);
        verify_params.push_back(pubkey);
        verify_params.push_back(signatures[i]);
        verify_params.push_back(messages[i]);

        UniValue result = CallRPC(this, "verifymessagedilithium", verify_params);
        BOOST_CHECK_EQUAL(result["valid"].get_bool(), true);
    }

    // Step 4: Verify signatures are unique (different messages = different signatures)
    BOOST_CHECK(signatures[0] != signatures[1]);
    BOOST_CHECK(signatures[1] != signatures[2]);
    BOOST_CHECK(signatures[2] != signatures[3]);
}

BOOST_AUTO_TEST_CASE(rpc_dilithium_multiple_keypairs)
{
    // Test that different keypairs produce different keys
    UniValue keys1 = CallRPC(this, "generatedilithiumkeypair");
    UniValue keys2 = CallRPC(this, "generatedilithiumkeypair");

    std::string privkey1 = keys1["privkey"].get_str();
    std::string privkey2 = keys2["privkey"].get_str();
    std::string pubkey1 = keys1["pubkey"].get_str();
    std::string pubkey2 = keys2["pubkey"].get_str();

    // Keys should be different
    BOOST_CHECK(privkey1 != privkey2);
    BOOST_CHECK(pubkey1 != pubkey2);

    // Sign same message with both keys
    UniValue sign1_params(UniValue::VARR);
    sign1_params.push_back(privkey1);
    sign1_params.push_back("Same message");
    UniValue sig1 = CallRPC(this, "signmessagedilithium", sign1_params);

    UniValue sign2_params(UniValue::VARR);
    sign2_params.push_back(privkey2);
    sign2_params.push_back("Same message");
    UniValue sig2 = CallRPC(this, "signmessagedilithium", sign2_params);

    // Signatures should be different
    BOOST_CHECK(sig1["signature"].get_str() != sig2["signature"].get_str());

    // Each signature should only verify with its own public key
    UniValue verify1_params(UniValue::VARR);
    verify1_params.push_back(pubkey1);
    verify1_params.push_back(sig1["signature"].get_str());
    verify1_params.push_back("Same message");
    BOOST_CHECK_EQUAL(CallRPC(this, "verifymessagedilithium", verify1_params)["valid"].get_bool(), true);

    UniValue verify2_params(UniValue::VARR);
    verify2_params.push_back(pubkey2);
    verify2_params.push_back(sig1["signature"].get_str());
    verify2_params.push_back("Same message");
    BOOST_CHECK_EQUAL(CallRPC(this, "verifymessagedilithium", verify2_params)["valid"].get_bool(), false);
}

BOOST_AUTO_TEST_CASE(rpc_importdilithiumkey)
{
    // Clear keystore to ensure clean test state
    g_dilithium_keystore.Clear();

    // Generate a keypair to import
    UniValue keys = CallRPC(this, "generatedilithiumkeypair");
    std::string privkey = keys["privkey"].get_str();
    std::string pubkey = keys["pubkey"].get_str();

    // Import the key with a label
    UniValue import_params(UniValue::VARR);
    import_params.push_back(privkey);
    import_params.push_back(pubkey);
    import_params.push_back("test-import-key");

    UniValue result = CallRPC(this, "importdilithiumkey", import_params);

    // Verify result structure
    BOOST_CHECK(result.isObject());
    BOOST_CHECK(result.exists("keyid"));
    BOOST_CHECK(result.exists("pubkey"));
    BOOST_CHECK(result.exists("label"));
    BOOST_CHECK(result.exists("imported"));

    // Verify values
    BOOST_CHECK_EQUAL(result["pubkey"].get_str(), pubkey);
    BOOST_CHECK_EQUAL(result["label"].get_str(), "test-import-key");
    BOOST_CHECK_EQUAL(result["imported"].get_bool(), true);

    // Verify keyid is a valid hex string
    std::string keyid = result["keyid"].get_str();
    BOOST_CHECK(IsHex(keyid));
    BOOST_CHECK(keyid.length() > 0);

    // Try to import the same key again - should fail
    bool caught_exception = false;
    try {
        CallRPC(this, "importdilithiumkey", import_params);
    } catch (...) {
        caught_exception = true;
    }
    BOOST_CHECK(caught_exception);
}

BOOST_AUTO_TEST_CASE(rpc_listdilithiumkeys)
{
    // Clear keystore to ensure clean test state
    g_dilithium_keystore.Clear();

    // Import multiple keys
    std::vector<std::string> keyids;
    std::vector<std::string> labels = {"key1", "key2", "key3"};

    for (const auto& label : labels) {
        UniValue keys = CallRPC(this, "generatedilithiumkeypair");
        std::string privkey = keys["privkey"].get_str();
        std::string pubkey = keys["pubkey"].get_str();

        UniValue import_params(UniValue::VARR);
        import_params.push_back(privkey);
        import_params.push_back(pubkey);
        import_params.push_back(label);

        UniValue import_result = CallRPC(this, "importdilithiumkey", import_params);
        keyids.push_back(import_result["keyid"].get_str());
    }

    // List all keys
    UniValue result = CallRPC(this, "listdilithiumkeys");

    // Verify result is an array
    BOOST_CHECK(result.isArray());
    BOOST_CHECK(result.size() >= 3); // At least our 3 keys

    // Find our imported keys in the list
    int found_count = 0;
    for (size_t i = 0; i < result.size(); ++i) {
        const UniValue& key_obj = result[i];
        BOOST_CHECK(key_obj.isObject());

        std::string keyid = key_obj["keyid"].get_str();
        if (std::find(keyids.begin(), keyids.end(), keyid) != keyids.end()) {
            found_count++;

            // Verify structure of each key entry
            BOOST_CHECK(key_obj.exists("pubkey"));
            BOOST_CHECK(key_obj.exists("label"));
            BOOST_CHECK(key_obj.exists("created"));
            BOOST_CHECK(key_obj.exists("last_used"));
            BOOST_CHECK(key_obj.exists("usage_count"));

            // Verify types
            BOOST_CHECK(IsHex(key_obj["pubkey"].get_str()));
            BOOST_CHECK(key_obj["created"].isNum());
            BOOST_CHECK(key_obj["last_used"].isNum());
            BOOST_CHECK(key_obj["usage_count"].isNum());
        }
    }

    // Ensure we found all our keys
    BOOST_CHECK_EQUAL(found_count, 3);
}

BOOST_AUTO_TEST_CASE(rpc_getdilithiumkeyinfo)
{
    // Clear keystore to ensure clean test state
    g_dilithium_keystore.Clear();

    // Import a key
    UniValue keys = CallRPC(this, "generatedilithiumkeypair");
    std::string privkey = keys["privkey"].get_str();
    std::string pubkey = keys["pubkey"].get_str();

    UniValue import_params(UniValue::VARR);
    import_params.push_back(privkey);
    import_params.push_back(pubkey);
    import_params.push_back("info-test-key");

    UniValue import_result = CallRPC(this, "importdilithiumkey", import_params);
    std::string keyid = import_result["keyid"].get_str();

    // Get key info
    UniValue info_params(UniValue::VARR);
    info_params.push_back(keyid);

    UniValue info = CallRPC(this, "getdilithiumkeyinfo", info_params);

    // Verify result structure
    BOOST_CHECK(info.isObject());
    BOOST_CHECK(info.exists("keyid"));
    BOOST_CHECK(info.exists("pubkey"));
    BOOST_CHECK(info.exists("label"));
    BOOST_CHECK(info.exists("created"));
    BOOST_CHECK(info.exists("last_used"));
    BOOST_CHECK(info.exists("usage_count"));

    // Verify values
    BOOST_CHECK_EQUAL(info["keyid"].get_str(), keyid);
    BOOST_CHECK_EQUAL(info["pubkey"].get_str(), pubkey);
    BOOST_CHECK_EQUAL(info["label"].get_str(), "info-test-key");
    BOOST_CHECK_EQUAL(info["usage_count"].getInt<int>(), 0);

    // Verify timestamps are reasonable
    // created should be > 0 (set when key is imported)
    // last_used can be 0 for newly imported keys that haven't been used yet
    int64_t created = info["created"].getInt<int64_t>();
    int64_t last_used = info["last_used"].getInt<int64_t>();
    BOOST_CHECK(created > 0);
    BOOST_CHECK(last_used >= 0);
    BOOST_CHECK(last_used == 0 || created <= last_used); // Either unused (0) or used after creation

    // Try to get info for non-existent key - should fail
    UniValue bad_params(UniValue::VARR);
    bad_params.push_back("nonexistent-key-id");

    bool caught_exception = false;
    try {
        CallRPC(this, "getdilithiumkeyinfo", bad_params);
    } catch (...) {
        caught_exception = true;
    }
    BOOST_CHECK(caught_exception);
}

BOOST_AUTO_TEST_SUITE_END()
