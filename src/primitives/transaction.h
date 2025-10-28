// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_PRIMITIVES_TRANSACTION_H
#define DILITHION_PRIMITIVES_TRANSACTION_H

#include <primitives/block.h>
#include <cstdint>
#include <vector>
#include <memory>

/**
 * An outpoint - a combination of a transaction hash and an index n into its vout
 */
class COutPoint {
public:
    uint256 hash;
    uint32_t n;

    COutPoint() : n(0xffffffff) {}
    COutPoint(const uint256& hashIn, uint32_t nIn) : hash(hashIn), n(nIn) {}

    bool IsNull() const { return hash.IsNull() && n == 0xffffffff; }

    void SetNull() {
        hash = uint256();
        n = 0xffffffff;
    }

    bool operator==(const COutPoint& other) const {
        return (hash == other.hash && n == other.n);
    }

    bool operator<(const COutPoint& other) const {
        if (hash == other.hash) {
            return n < other.n;
        }
        return hash < other.hash;
    }
};

/**
 * An input of a transaction. It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn {
public:
    COutPoint prevout;
    std::vector<uint8_t> scriptSig;  // Signature script (placeholder for Dilithium signature)
    uint32_t nSequence;

    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    CTxIn() : nSequence(SEQUENCE_FINAL) {}

    CTxIn(COutPoint prevoutIn, std::vector<uint8_t> scriptSigIn = std::vector<uint8_t>(), uint32_t nSequenceIn = SEQUENCE_FINAL)
        : prevout(prevoutIn), scriptSig(scriptSigIn), nSequence(nSequenceIn) {}

    CTxIn(uint256 hashPrevTx, uint32_t nOut, std::vector<uint8_t> scriptSigIn = std::vector<uint8_t>(), uint32_t nSequenceIn = SEQUENCE_FINAL)
        : prevout(hashPrevTx, nOut), scriptSig(scriptSigIn), nSequence(nSequenceIn) {}

    bool operator==(const CTxIn& other) const {
        return (prevout == other.prevout &&
                scriptSig == other.scriptSig &&
                nSequence == other.nSequence);
    }
};

/**
 * An output of a transaction. It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut {
public:
    uint64_t nValue;
    std::vector<uint8_t> scriptPubKey;  // Locking script (P2PKH for now)

    CTxOut() : nValue(0) {}

    CTxOut(uint64_t nValueIn, std::vector<uint8_t> scriptPubKeyIn)
        : nValue(nValueIn), scriptPubKey(scriptPubKeyIn) {}

    bool IsNull() const { return nValue == 0 && scriptPubKey.empty(); }

    void SetNull() {
        nValue = 0;
        scriptPubKey.clear();
    }

    bool operator==(const CTxOut& other) const {
        return (nValue == other.nValue &&
                scriptPubKey == other.scriptPubKey);
    }
};

/**
 * The basic transaction that is broadcast on the network and contained in
 * blocks. A transaction can contain multiple inputs and outputs.
 */
class CTransaction {
public:
    // Transaction version
    int32_t nVersion;

    // Transaction inputs
    std::vector<CTxIn> vin;

    // Transaction outputs
    std::vector<CTxOut> vout;

    // Lock time (0 = not locked)
    uint32_t nLockTime;

    // Cached hash
    mutable uint256 hash_cached;
    mutable bool hash_valid;

    /** Construct a CTransaction with default values. */
    CTransaction() : nVersion(1), nLockTime(0), hash_valid(false) {}

    /** Construct a CTransaction with specified values. */
    CTransaction(int32_t nVersionIn, std::vector<CTxIn> vinIn, std::vector<CTxOut> voutIn, uint32_t nLockTimeIn)
        : nVersion(nVersionIn), vin(vinIn), vout(voutIn), nLockTime(nLockTimeIn), hash_valid(false) {}

    /** Copy constructor */
    CTransaction(const CTransaction& tx)
        : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), hash_valid(false) {}

    /** Assignment operator */
    CTransaction& operator=(const CTransaction& tx) {
        nVersion = tx.nVersion;
        vin = tx.vin;
        vout = tx.vout;
        nLockTime = tx.nLockTime;
        hash_valid = false;
        return *this;
    }

    /** Compute the hash of this transaction. */
    uint256 GetHash() const;

    /** Get the serialized size of this transaction. */
    size_t GetSerializedSize() const;

    /** Check if transaction is null (no inputs or outputs). */
    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    /** Set transaction to null state. */
    void SetNull() {
        nVersion = 1;
        vin.clear();
        vout.clear();
        nLockTime = 0;
        hash_valid = false;
    }

    /** Basic validation - check structure is valid. */
    bool CheckBasicStructure() const;

    /** Get total output value. */
    uint64_t GetValueOut() const;

    /** Check if this is a coinbase transaction (first tx in block, creates new coins). */
    bool IsCoinBase() const {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    /** Serialize transaction data for hashing or transmission. */
    std::vector<uint8_t> Serialize() const;

    /** Deserialize transaction data from byte stream (CS-002). */
    bool Deserialize(const uint8_t* data, size_t len, std::string* error = nullptr);
};

/** A reference to a transaction (shared pointer for efficiency). */
typedef std::shared_ptr<const CTransaction> CTransactionRef;

/** Create a transaction reference. */
inline CTransactionRef MakeTransactionRef() {
    return std::make_shared<const CTransaction>();
}

/** Create a transaction reference from existing transaction. */
template <typename Tx>
inline CTransactionRef MakeTransactionRef(Tx&& txIn) {
    return std::make_shared<const CTransaction>(std::forward<Tx>(txIn));
}

#endif // DILITHION_PRIMITIVES_TRANSACTION_H
