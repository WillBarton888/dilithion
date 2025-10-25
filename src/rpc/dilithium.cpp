// Copyright (c) 2025 The Dilithion Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dilithium/dilithiumkey.h>
#include <dilithium/dilithiumkeystore.h>
#include <dilithium/dilithiumpubkey.h>
#include <key_io.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <core_io.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/interpreter.h>

#include <string>

static RPCHelpMan generatedilithiumkeypair()
{
    return RPCHelpMan{"generatedilithiumkeypair",
        "\nGenerate a new Dilithium key pair for post-quantum signatures.\n"
        "\nDilithium is a NIST-standardized post-quantum signature scheme.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "privkey", "The private key in hex"},
                {RPCResult::Type::STR_HEX, "pubkey", "The public key in hex"},
                {RPCResult::Type::NUM, "privkey_size", "Size of private key in bytes"},
                {RPCResult::Type::NUM, "pubkey_size", "Size of public key in bytes"},
            }
        },
        RPCExamples{
            HelpExampleCli("generatedilithiumkeypair", "") +
            HelpExampleRpc("generatedilithiumkeypair", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            DilithiumKey key;
            if (!key.MakeNewKey()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate Dilithium key pair");
            }

            DilithiumPubKey pubkey = key.GetPubKey();

            UniValue result(UniValue::VOBJ);
            result.pushKV("privkey", HexStr(key.GetPrivKey()));
            result.pushKV("pubkey", HexStr(pubkey.GetVch()));
            result.pushKV("privkey_size", (int)key.GetPrivKey().size());
            result.pushKV("pubkey_size", (int)pubkey.size());

            return result;
        },
    };
}

static RPCHelpMan signmessagedilithium()
{
    return RPCHelpMan{"signmessagedilithium",
        "\nSign a message with a Dilithium private key.\n"
        "\nThe signature is 2421 bytes total.\n",
        {
            {"privkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The Dilithium private key in hex."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to sign."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "signature", "The signature in hex"},
                {RPCResult::Type::NUM, "signature_size", "Size of signature in bytes"},
                {RPCResult::Type::STR_HEX, "message_hash", "SHA256 hash of the message"},
            }
        },
        RPCExamples{
            HelpExampleCli("signmessagedilithium", "\"<privkey_hex>\" \"Hello!\"") +
            HelpExampleRpc("signmessagedilithium", "\"<privkey_hex>\", \"Hello!\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string strPrivkey = request.params[0].get_str();
            std::string strMessage = request.params[1].get_str();

            // Decode hex private key
            std::vector<unsigned char> privkeyData = ParseHex(strPrivkey);
            if (privkeyData.size() != DILITHIUM_SECRETKEYBYTES) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid private key size: expected %d bytes, got %d bytes",
                              DILITHIUM_SECRETKEYBYTES, privkeyData.size()));
            }

            // Create key from private key data
            DilithiumKey key;
            if (!key.SetPrivKey(privkeyData)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dilithium private key");
            }

            // Hash the message
            uint256 messageHash = Hash(strMessage);

            // Sign the hash
            std::vector<unsigned char> signature;
            if (!key.Sign(messageHash, signature)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Signing failed");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("signature", HexStr(signature));
            result.pushKV("signature_size", (int)signature.size());
            result.pushKV("message_hash", messageHash.ToString());

            return result;
        },
    };
}

static RPCHelpMan verifymessagedilithium()
{
    return RPCHelpMan{"verifymessagedilithium",
        "\nVerify a Dilithium signature on a message.\n",
        {
            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The Dilithium public key in hex."},
            {"signature", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The signature in hex."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message that was signed."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "valid", "Whether the signature is valid"},
                {RPCResult::Type::STR_HEX, "message_hash", "SHA256 hash of the message"},
                {RPCResult::Type::NUM, "signature_size", "Size of signature in bytes"},
                {RPCResult::Type::NUM, "pubkey_size", "Size of public key in bytes"},
            }
        },
        RPCExamples{
            HelpExampleCli("verifymessagedilithium", "\"<pubkey_hex>\" \"<sig_hex>\" \"Hello!\"") +
            HelpExampleRpc("verifymessagedilithium", "\"<pubkey_hex>\", \"<sig_hex>\", \"Hello!\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string strPubkey = request.params[0].get_str();
            std::string strSignature = request.params[1].get_str();
            std::string strMessage = request.params[2].get_str();

            // Decode hex public key
            std::vector<unsigned char> pubkeyData = ParseHex(strPubkey);
            if (pubkeyData.size() != DILITHIUM_PUBLICKEYBYTES) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid public key size: expected %d bytes, got %d bytes",
                              DILITHIUM_PUBLICKEYBYTES, pubkeyData.size()));
            }

            // Create public key
            DilithiumPubKey pubkey(pubkeyData);
            if (!pubkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dilithium public key");
            }

            // Decode signature
            std::vector<unsigned char> signature = ParseHex(strSignature);

            // Hash the message
            uint256 messageHash = Hash(strMessage);

            // Verify signature
            bool valid = pubkey.Verify(messageHash, signature);

            UniValue result(UniValue::VOBJ);
            result.pushKV("valid", valid);
            result.pushKV("message_hash", messageHash.ToString());
            result.pushKV("signature_size", (int)signature.size());
            result.pushKV("pubkey_size", (int)pubkeyData.size());

            return result;
        },
    };
}

static RPCHelpMan importdilithiumkey()
{
    return RPCHelpMan{"importdilithiumkey",
        "\nImport a Dilithium key pair into the keystore.\n"
        "\nThe key will be stored with an optional label for easy identification.\n",
        {
            {"privkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The Dilithium private key in hex."},
            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The Dilithium public key in hex."},
            {"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional label for the key."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "keyid", "The generated key identifier"},
                {RPCResult::Type::STR_HEX, "pubkey", "The public key in hex"},
                {RPCResult::Type::STR, "label", "The key label"},
                {RPCResult::Type::BOOL, "imported", "Always true on success"},
            }
        },
        RPCExamples{
            HelpExampleCli("importdilithiumkey", "\"<privkey_hex>\" \"<pubkey_hex>\" \"my-key\"") +
            HelpExampleRpc("importdilithiumkey", "\"<privkey_hex>\", \"<pubkey_hex>\", \"my-key\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string strPrivkey = request.params[0].get_str();
            std::string strPubkey = request.params[1].get_str();
            std::string label = request.params.size() > 2 ? request.params[2].get_str() : "";

            // Decode and validate private key
            std::vector<unsigned char> privkeyData = ParseHex(strPrivkey);
            if (privkeyData.size() != DILITHIUM_SECRETKEYBYTES) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid private key size: expected %d bytes, got %d bytes",
                              DILITHIUM_SECRETKEYBYTES, privkeyData.size()));
            }

            // Decode and validate public key
            std::vector<unsigned char> pubkeyData = ParseHex(strPubkey);
            if (pubkeyData.size() != DILITHIUM_PUBLICKEYBYTES) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid public key size: expected %d bytes, got %d bytes",
                              DILITHIUM_PUBLICKEYBYTES, pubkeyData.size()));
            }

            // Create key object and validate
            DilithiumKey key;
            if (!key.SetPrivKey(privkeyData)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dilithium private key");
            }

            // Set the public key explicitly (Dilithium secret key doesn't contain pubkey)
            key.SetPubKey(DilithiumPubKey(pubkeyData));

            // Add to keystore
            std::string keyid;
            if (!g_dilithium_keystore.AddKey(key, label, keyid)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Key already exists in keystore");
            }

            // Build result
            UniValue result(UniValue::VOBJ);
            result.pushKV("keyid", keyid);
            result.pushKV("pubkey", HexStr(key.GetPubKey().GetVch()));
            result.pushKV("label", label);
            result.pushKV("imported", true);

            return result;
        },
    };
}

static RPCHelpMan listdilithiumkeys()
{
    return RPCHelpMan{"listdilithiumkeys",
        "\nList all Dilithium keys stored in the keystore.\n"
        "\nReturns key identifiers, public keys, labels, and usage statistics.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "keyid", "Key identifier"},
                    {RPCResult::Type::STR_HEX, "pubkey", "Public key in hex"},
                    {RPCResult::Type::STR, "label", "Key label"},
                    {RPCResult::Type::NUM, "created", "Creation timestamp (Unix epoch)"},
                    {RPCResult::Type::NUM, "last_used", "Last used timestamp (Unix epoch)"},
                    {RPCResult::Type::NUM, "usage_count", "Number of times key has been used"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("listdilithiumkeys", "") +
            HelpExampleRpc("listdilithiumkeys", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::vector<DilithiumKeyInfo> keys = g_dilithium_keystore.ListKeys();

            UniValue result(UniValue::VARR);
            for (const auto& info : keys) {
                UniValue key_obj(UniValue::VOBJ);
                key_obj.pushKV("keyid", info.keyid);
                key_obj.pushKV("pubkey", HexStr(info.pubkey.GetVch()));
                key_obj.pushKV("label", info.label);
                key_obj.pushKV("created", info.created_time);
                key_obj.pushKV("last_used", info.last_used_time);
                key_obj.pushKV("usage_count", (int)info.usage_count);
                result.push_back(key_obj);
            }

            return result;
        },
    };
}

static RPCHelpMan getdilithiumkeyinfo()
{
    return RPCHelpMan{"getdilithiumkeyinfo",
        "\nGet detailed information about a specific Dilithium key.\n",
        {
            {"keyid", RPCArg::Type::STR, RPCArg::Optional::NO, "The key identifier."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "keyid", "Key identifier"},
                {RPCResult::Type::STR_HEX, "pubkey", "Public key in hex"},
                {RPCResult::Type::STR, "label", "Key label"},
                {RPCResult::Type::NUM, "created", "Creation timestamp (Unix epoch)"},
                {RPCResult::Type::NUM, "last_used", "Last used timestamp (Unix epoch)"},
                {RPCResult::Type::NUM, "usage_count", "Number of times key has been used"},
            }
        },
        RPCExamples{
            HelpExampleCli("getdilithiumkeyinfo", "\"abc123...\"") +
            HelpExampleRpc("getdilithiumkeyinfo", "\"abc123...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string keyid = request.params[0].get_str();

            // Retrieve key from keystore
            DilithiumKey key;
            if (!g_dilithium_keystore.GetKey(keyid, key)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Key not found in keystore");
            }

            // Retrieve metadata
            DilithiumKeyMetadata meta;
            if (!g_dilithium_keystore.GetMetadata(keyid, meta)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Metadata retrieval failed");
            }

            // Build result
            UniValue result(UniValue::VOBJ);
            result.pushKV("keyid", meta.keyid);
            result.pushKV("pubkey", HexStr(key.GetPubKey().GetVch()));
            result.pushKV("label", meta.label);
            result.pushKV("created", meta.created_time);
            result.pushKV("last_used", meta.last_used_time);
            result.pushKV("usage_count", (int)meta.usage_count);

            return result;
        },
    };
}

static RPCHelpMan builddilithiumtransaction()
{
    return RPCHelpMan{"builddilithiumtransaction",
        "\nBuild an unsigned transaction from inputs and outputs.\n"
        "\nSupports both Dilithium addresses and standard Bitcoin addresses.\n",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of transaction inputs",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                        },
                    },
                },
            },
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of transaction outputs",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination address (Dilithium or Bitcoin)"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in BTC"},
                        },
                    },
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The transaction hex string"},
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
            }
        },
        RPCExamples{
            HelpExampleCli("builddilithiumtransaction",
                "'[{\"txid\":\"abc...\",\"vout\":0}]' '[{\"address\":\"bcrt1q...\",\"amount\":1.0}]'") +
            HelpExampleRpc("builddilithiumtransaction",
                "[{\"txid\":\"abc...\",\"vout\":0}], [{\"address\":\"bcrt1q...\",\"amount\":1.0}]")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            RPCTypeCheck(request.params, {UniValue::VARR, UniValue::VARR});

            const UniValue& inputs_uv = request.params[0];
            const UniValue& outputs_uv = request.params[1];

            // Build CMutableTransaction
            CMutableTransaction tx;
            tx.nVersion = 2;
            tx.nLockTime = 0;

            // Process inputs
            for (unsigned int idx = 0; idx < inputs_uv.size(); idx++) {
                const UniValue& input = inputs_uv[idx];

                uint256 txid = ParseHashV(input["txid"], "txid");
                int nOutput = input["vout"].getInt<int>();

                if (nOutput < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid vout value");
                }

                CTxIn in(COutPoint(txid, nOutput));
                tx.vin.push_back(in);
            }

            // Process outputs
            for (unsigned int idx = 0; idx < outputs_uv.size(); idx++) {
                const UniValue& output = outputs_uv[idx];

                std::string address_str = output["address"].get_str();
                CAmount amount = AmountFromValue(output["amount"]);

                if (amount <= 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");
                }

                // Decode address to get scriptPubKey
                CTxDestination dest = DecodeDestination(address_str);
                if (!IsValidDestination(dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                        strprintf("Invalid address: %s", address_str));
                }

                CScript scriptPubKey = GetScriptForDestination(dest);
                CTxOut out(amount, scriptPubKey);
                tx.vout.push_back(out);
            }

            // Serialize transaction
            std::string hex = EncodeHexTx(CTransaction(tx));

            // Calculate txid
            uint256 txid = tx.GetHash();

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", hex);
            result.pushKV("txid", txid.GetHex());

            return result;
        },
    };
}

static RPCHelpMan signdilithiumtransactioninput()
{
    return RPCHelpMan{"signdilithiumtransactioninput",
        "\nSign a specific transaction input with a Dilithium key from the keystore.\n"
        "\nThe key must be previously imported into the keystore.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
            {"input_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "The input index to sign (0-based)"},
            {"keyid", RPCArg::Type::STR, RPCArg::Optional::NO, "The key identifier from the keystore"},
            {"prevout_scriptpubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The scriptPubKey of the previous output being spent"},
            {"prevout_value", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The value of the previous output being spent"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The signed transaction hex string"},
                {RPCResult::Type::BOOL, "complete", "Whether all inputs are signed (always false for partial signing)"},
                {RPCResult::Type::STR_HEX, "signature", "The generated Dilithium signature"},
            }
        },
        RPCExamples{
            HelpExampleCli("signdilithiumtransactioninput",
                "\"0200000001...\" 0 \"abc123...\" \"76a914...88ac\" 1.0") +
            HelpExampleRpc("signdilithiumtransactioninput",
                "\"0200000001...\", 0, \"abc123...\", \"76a914...88ac\", 1.0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            RPCTypeCheck(request.params, {
                UniValue::VSTR,
                UniValue::VNUM,
                UniValue::VSTR,
                UniValue::VSTR_HEX,
                UniValue::VNUM
            });

            // Decode transaction
            CMutableTransaction tx;
            if (!DecodeHexTx(tx, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }

            // Get input index
            int input_index = request.params[1].getInt<int>();
            if (input_index < 0 || input_index >= (int)tx.vin.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid input index: %d (tx has %d inputs)",
                        input_index, tx.vin.size()));
            }

            // Get key from keystore
            std::string keyid = request.params[2].get_str();
            DilithiumKey key;
            if (!g_dilithium_keystore.GetKey(keyid, key)) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Key not found in keystore: %s", keyid));
            }

            // Decode prevout scriptPubKey
            std::vector<unsigned char> scriptPubKeyData = ParseHex(request.params[3].get_str());
            CScript prevout_scriptPubKey(scriptPubKeyData.begin(), scriptPubKeyData.end());

            // Get prevout value
            CAmount prevout_value = AmountFromValue(request.params[4]);

            // Compute signature hash
            uint256 sighash = SignatureHash(
                prevout_scriptPubKey,
                tx,
                input_index,
                SIGHASH_ALL,
                prevout_value,
                SigVersion::WITNESS_V0
            );

            // Sign with Dilithium key
            std::vector<unsigned char> signature;
            if (!key.Sign(sighash, signature)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Dilithium signing failed");
            }

            // Add SIGHASH_ALL flag to signature
            signature.push_back(static_cast<unsigned char>(SIGHASH_ALL));

            // Build witness stack
            CScriptWitness witness;
            witness.stack.push_back(signature);
            witness.stack.push_back(ToByteVector(key.GetPubKey().GetVch()));

            // Set witness for this input
            tx.vin[input_index].scriptWitness = witness;

            // Serialize signed transaction
            std::string hex = EncodeHexTx(CTransaction(tx));

            // Check if all inputs are signed (simplified check)
            bool complete = true;
            for (const auto& input : tx.vin) {
                if (input.scriptWitness.IsNull()) {
                    complete = false;
                    break;
                }
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", hex);
            result.pushKV("complete", complete);
            result.pushKV("signature", HexStr(signature));

            return result;
        },
    };
}

void RegisterDilithiumRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"dilithium", &generatedilithiumkeypair},
        {"dilithium", &signmessagedilithium},
        {"dilithium", &verifymessagedilithium},
        {"dilithium", &importdilithiumkey},
        {"dilithium", &listdilithiumkeys},
        {"dilithium", &getdilithiumkeyinfo},
        {"dilithium", &builddilithiumtransaction},
        {"dilithium", &signdilithiumtransactioninput},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
