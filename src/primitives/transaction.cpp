// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <primitives/transaction.h>
#include <crypto/sha3.h>
#include <cstring>
#include <stdexcept>

/** Helper function to serialize a uint32_t in little-endian format */
static void SerializeUint32(std::vector<uint8_t>& data, uint32_t value) {
    data.push_back(static_cast<uint8_t>(value));
    data.push_back(static_cast<uint8_t>(value >> 8));
    data.push_back(static_cast<uint8_t>(value >> 16));
    data.push_back(static_cast<uint8_t>(value >> 24));
}

/** Helper function to serialize a uint64_t in little-endian format */
static void SerializeUint64(std::vector<uint8_t>& data, uint64_t value) {
    data.push_back(static_cast<uint8_t>(value));
    data.push_back(static_cast<uint8_t>(value >> 8));
    data.push_back(static_cast<uint8_t>(value >> 16));
    data.push_back(static_cast<uint8_t>(value >> 24));
    data.push_back(static_cast<uint8_t>(value >> 32));
    data.push_back(static_cast<uint8_t>(value >> 40));
    data.push_back(static_cast<uint8_t>(value >> 48));
    data.push_back(static_cast<uint8_t>(value >> 56));
}

/** Helper function to serialize a compact size (Bitcoin-style varint) */
static void SerializeCompactSize(std::vector<uint8_t>& data, uint64_t size) {
    if (size < 253) {
        data.push_back(static_cast<uint8_t>(size));
    } else if (size <= 0xFFFF) {
        data.push_back(253);
        data.push_back(static_cast<uint8_t>(size));
        data.push_back(static_cast<uint8_t>(size >> 8));
    } else if (size <= 0xFFFFFFFF) {
        data.push_back(254);
        SerializeUint32(data, static_cast<uint32_t>(size));
    } else {
        data.push_back(255);
        SerializeUint64(data, size);
    }
}

std::vector<uint8_t> CTransaction::Serialize() const {
    std::vector<uint8_t> data;
    data.reserve(GetSerializedSize());

    // Serialize version (4 bytes, little-endian)
    SerializeUint32(data, static_cast<uint32_t>(nVersion));

    // Serialize number of inputs
    SerializeCompactSize(data, vin.size());

    // Serialize each input
    for (const CTxIn& txin : vin) {
        // Serialize prevout hash (32 bytes)
        data.insert(data.end(), txin.prevout.hash.begin(), txin.prevout.hash.end());
        
        // Serialize prevout index (4 bytes, little-endian)
        SerializeUint32(data, txin.prevout.n);
        
        // Serialize scriptSig length and data
        SerializeCompactSize(data, txin.scriptSig.size());
        data.insert(data.end(), txin.scriptSig.begin(), txin.scriptSig.end());
        
        // Serialize sequence (4 bytes, little-endian)
        SerializeUint32(data, txin.nSequence);
    }

    // Serialize number of outputs
    SerializeCompactSize(data, vout.size());

    // Serialize each output
    for (const CTxOut& txout : vout) {
        // Serialize value (8 bytes, little-endian)
        SerializeUint64(data, txout.nValue);
        
        // Serialize scriptPubKey length and data
        SerializeCompactSize(data, txout.scriptPubKey.size());
        data.insert(data.end(), txout.scriptPubKey.begin(), txout.scriptPubKey.end());
    }

    // Serialize locktime (4 bytes, little-endian)
    SerializeUint32(data, nLockTime);

    return data;
}

uint256 CTransaction::GetHash() const {
    if (!hash_valid) {
        // Serialize transaction
        std::vector<uint8_t> data = Serialize();
        
        // Hash with SHA3-256 (quantum-resistant)
        SHA3_256(data.data(), data.size(), hash_cached.data);
        hash_valid = true;
    }
    return hash_cached;
}

size_t CTransaction::GetSerializedSize() const {
    size_t size = 0;
    
    // Version (4 bytes)
    size += 4;
    
    // Input count varint (1-9 bytes)
    uint64_t vin_size = vin.size();
    if (vin_size < 253) size += 1;
    else if (vin_size <= 0xFFFF) size += 3;
    else if (vin_size <= 0xFFFFFFFF) size += 5;
    else size += 9;
    
    // Each input
    for (const CTxIn& txin : vin) {
        size += 32;  // prevout hash
        size += 4;   // prevout index
        
        // scriptSig size varint
        uint64_t script_size = txin.scriptSig.size();
        if (script_size < 253) size += 1;
        else if (script_size <= 0xFFFF) size += 3;
        else if (script_size <= 0xFFFFFFFF) size += 5;
        else size += 9;
        
        size += txin.scriptSig.size();  // scriptSig data
        size += 4;  // sequence
    }
    
    // Output count varint (1-9 bytes)
    uint64_t vout_size = vout.size();
    if (vout_size < 253) size += 1;
    else if (vout_size <= 0xFFFF) size += 3;
    else if (vout_size <= 0xFFFFFFFF) size += 5;
    else size += 9;
    
    // Each output
    for (const CTxOut& txout : vout) {
        size += 8;  // value
        
        // scriptPubKey size varint
        uint64_t script_size = txout.scriptPubKey.size();
        if (script_size < 253) size += 1;
        else if (script_size <= 0xFFFF) size += 3;
        else if (script_size <= 0xFFFFFFFF) size += 5;
        else size += 9;
        
        size += txout.scriptPubKey.size();  // scriptPubKey data
    }
    
    // Locktime (4 bytes)
    size += 4;
    
    return size;
}

bool CTransaction::CheckBasicStructure() const {
    // Transaction must have at least one input and one output
    // Exception: coinbase transactions can have special inputs
    if (vin.empty()) {
        return false;
    }
    
    if (vout.empty()) {
        return false;
    }
    
    // Check that outputs don't overflow
    uint64_t totalOut = 0;
    for (const CTxOut& txout : vout) {
        if (txout.nValue > 21000000ULL * 100000000ULL) {  // Max supply * satoshis
            return false;
        }
        
        // Check for overflow
        if (totalOut + txout.nValue < totalOut) {
            return false;
        }
        totalOut += txout.nValue;
    }
    
    // Check for oversized transaction (max 1MB for now)
    if (GetSerializedSize() > 1000000) {
        return false;
    }
    
    // Coinbase transactions have special rules
    if (IsCoinBase()) {
        // Coinbase scriptSig must be between 2 and 100 bytes
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100) {
            return false;
        }
    } else {
        // Non-coinbase transactions must not have null prevouts
        for (const CTxIn& txin : vin) {
            if (txin.prevout.IsNull()) {
                return false;
            }
        }
    }
    
    return true;
}

uint64_t CTransaction::GetValueOut() const {
    uint64_t total = 0;
    for (const CTxOut& txout : vout) {
        // Check for overflow
        if (total + txout.nValue < total) {
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
        }
        total += txout.nValue;
    }
    return total;
}
