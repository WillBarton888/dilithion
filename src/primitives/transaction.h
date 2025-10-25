// Copyright (c) 2025 The Dilithion Core developers
#ifndef DILITHION_PRIMITIVES_TRANSACTION_H
#define DILITHION_PRIMITIVES_TRANSACTION_H

#include <primitives/block.h>
#include <cstdint>
#include <vector>
#include <memory>

class CTransaction {
public:
    int32_t nVersion;
    std::vector<uint8_t> vin;
    std::vector<uint8_t> vout;
    uint32_t nLockTime;
    mutable uint256 hash_cached;
    mutable bool hash_valid;

    CTransaction() : nVersion(0), nLockTime(0), hash_valid(false) {}

    uint256 GetHash() const {
        if (!hash_valid) {
            // Serialize transaction for hashing
            std::vector<uint8_t> data;
            data.reserve(GetSerializedSize());

            // Serialize: version (4) + vin + vout + locktime (4)
            const uint8_t* versionBytes = reinterpret_cast<const uint8_t*>(&nVersion);
            data.insert(data.end(), versionBytes, versionBytes + 4);
            data.insert(data.end(), vin.begin(), vin.end());
            data.insert(data.end(), vout.begin(), vout.end());
            const uint8_t* lockTimeBytes = reinterpret_cast<const uint8_t*>(&nLockTime);
            data.insert(data.end(), lockTimeBytes, lockTimeBytes + 4);

            // SHA-3-256 hash (quantum-resistant)
            extern void SHA3_256(const uint8_t* data, size_t len, uint8_t hash[32]);
            SHA3_256(data.data(), data.size(), hash_cached.data);
            hash_valid = true;
        }
        return hash_cached;
    }

    size_t GetSerializedSize() const {
        return 8 + vin.size() + vout.size();
    }
};

typedef std::shared_ptr<const CTransaction> CTransactionRef;

inline CTransactionRef MakeTransactionRef() {
    return std::make_shared<const CTransaction>();
}

#endif
