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
            hash_cached.data[0] = (uint8_t)nVersion;
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
