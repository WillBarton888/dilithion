// Copyright (c) 2025 The Dilithion Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dilithium/dilithiumkeystore.h>
#include <hash.h>
#include <util/strencodings.h>
#include <util/time.h>

// Global keystore instance
DilithiumKeyStore g_dilithium_keystore;

std::string DilithiumKeyStore::GenerateKeyID(const DilithiumPubKey& pubkey)
{
    // Generate deterministic ID: first 16 hex chars of SHA256(pubkey)
    const std::vector<unsigned char>& pubkey_bytes = pubkey.GetVch();
    uint256 hash = Hash(pubkey_bytes);
    return HexStr(hash).substr(0, 16);
}

bool DilithiumKeyStore::AddKey(const DilithiumKey& key, const std::string& label, std::string& keyid)
{
    if (!key.IsValid()) {
        return false;
    }

    // Get public key and generate ID
    DilithiumPubKey pubkey = key.GetPubKey();
    keyid = GenerateKeyID(pubkey);

    // Check if key already exists
    if (keys.find(keyid) != keys.end()) {
        return false; // Key already exists
    }

    // Store the key
    keys[keyid] = key;

    // Create and store metadata
    DilithiumKeyMetadata meta;
    meta.keyid = keyid;
    meta.label = label;
    meta.created_time = GetTime();
    meta.last_used_time = 0;
    meta.usage_count = 0;
    metadata[keyid] = meta;

    // Store pubkey-to-keyid mapping for reverse lookup
    pubkey_to_keyid[HexStr(pubkey)] = keyid;

    return true;
}

bool DilithiumKeyStore::GetKey(const std::string& keyid, DilithiumKey& key) const
{
    auto it = keys.find(keyid);
    if (it == keys.end()) {
        return false;
    }

    key = it->second;
    return true;
}

bool DilithiumKeyStore::GetKeyByPubKey(const DilithiumPubKey& pubkey, DilithiumKey& key) const
{
    std::string pubkey_hex = HexStr(pubkey);
    auto it = pubkey_to_keyid.find(pubkey_hex);
    if (it == pubkey_to_keyid.end()) {
        return false;
    }

    return GetKey(it->second, key);
}

bool DilithiumKeyStore::GetMetadata(const std::string& keyid, DilithiumKeyMetadata& meta) const
{
    auto it = metadata.find(keyid);
    if (it == metadata.end()) {
        return false;
    }

    meta = it->second;
    return true;
}

void DilithiumKeyStore::UpdateUsage(const std::string& keyid)
{
    auto it = metadata.find(keyid);
    if (it != metadata.end()) {
        it->second.last_used_time = GetTime();
        it->second.usage_count++;
    }
}

std::vector<DilithiumKeyInfo> DilithiumKeyStore::ListKeys() const
{
    std::vector<DilithiumKeyInfo> result;

    for (const auto& pair : keys) {
        const std::string& kid = pair.first;
        const DilithiumKey& k = pair.second;

        DilithiumKeyInfo info;
        info.keyid = kid;
        info.pubkey = k.GetPubKey();

        // Get metadata if available
        auto meta_it = metadata.find(kid);
        if (meta_it != metadata.end()) {
            const DilithiumKeyMetadata& meta = meta_it->second;
            info.label = meta.label;
            info.created_time = meta.created_time;
            info.last_used_time = meta.last_used_time;
            info.usage_count = meta.usage_count;
        } else {
            info.label = "";
            info.created_time = 0;
            info.last_used_time = 0;
            info.usage_count = 0;
        }

        result.push_back(info);
    }

    return result;
}

bool DilithiumKeyStore::HaveKey(const std::string& keyid) const
{
    return keys.find(keyid) != keys.end();
}

bool DilithiumKeyStore::RemoveKey(const std::string& keyid)
{
    auto key_it = keys.find(keyid);
    if (key_it == keys.end()) {
        return false;
    }

    // Get pubkey before erasing key
    DilithiumPubKey pubkey = key_it->second.GetPubKey();
    std::string pubkey_hex = HexStr(pubkey);

    // Remove key
    keys.erase(key_it);

    // Remove metadata
    metadata.erase(keyid);

    // Remove pubkey mapping
    pubkey_to_keyid.erase(pubkey_hex);

    return true;
}

void DilithiumKeyStore::Clear()
{
    keys.clear();
    metadata.clear();
    pubkey_to_keyid.clear();
}
