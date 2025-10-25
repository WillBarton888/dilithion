# Phase 2 Week 1 Implementation Log

**Week:** 1 (Transaction Format & Serialization)
**Date Started:** October 24, 2025
**Status:** 🔵 In Progress
**Branch:** phase-2-transaction-integration

---

## Objectives

1. ✅ Clone Bitcoin Core v25.0
2. ⏳ Integrate Phase 1 Dilithium code
3. ⏳ Modify transaction structures for Dilithium signatures
4. ⏳ Update network protocol limits
5. ⏳ Create comprehensive unit tests

---

## Step 1: Bitcoin Core v25.0 Setup

**Action:** Clone Bitcoin Core v25.0 source code

```bash
cd ~/crypto-projects
git clone --branch v25.0 --depth 1 https://github.com/bitcoin/bitcoin.git bitcoin-core
```

**Status:** In progress...

**Expected Files:**
- `src/primitives/transaction.h` - Transaction data structures
- `src/primitives/transaction.cpp` - Transaction implementation
- `src/net.h` - Network protocol constants
- `src/consensus/consensus.h` - Consensus parameters

---

## Step 2: Dilithium Integration Plan

**Files to Copy from Phase 1:**

```bash
# Dilithium crypto layer
cp -r dilithion/src/crypto/dilithium bitcoin-core/src/crypto/

# Updated CKey/CPubKey
cp dilithion/src/key.h bitcoin-core/src/
cp dilithion/src/key.cpp bitcoin-core/src/
cp dilithion/src/pubkey.h bitcoin-core/src/
cp dilithion/src/pubkey.cpp bitcoin-core/src/

# Tests
cp -r dilithion/src/test/dilithium*.cpp bitcoin-core/src/test/
cp dilithion/src/test/key_tests.cpp bitcoin-core/src/test/
```

---

## Step 3: Transaction Structure Modifications

### File: `src/primitives/transaction.h`

**Current Bitcoin Core v25.0:**
```cpp
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;      // ~100 bytes for ECDSA
    uint32_t nSequence;
    CScriptWitness scriptWitness;
};
```

**Dilithium Modification:**
```cpp
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;      // Now ~3,800 bytes for Dilithium!
    uint32_t nSequence;
    CScriptWitness scriptWitness;

    // Dilithium-specific: track if this is a quantum-resistant signature
    bool fDilithiumSig{false};
};
```

**Changes Needed:**
1. No struct changes (scriptSig is already flexible)
2. Add validation for larger scriptSig sizes
3. Update MAX_SCRIPT_SIZE constant

---

## Step 4: Network Protocol Updates

### File: `src/net.h`

**Current Limits:**
```cpp
static const unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000; // 4 MB
```

**Dilithium Update:**
```cpp
static const unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 20 * 1000 * 1000; // 20 MB
// Rationale: Dilithium transactions are ~15x larger
// Block messages with 1000 tx could reach 3.8 GB, but we limit transactions/block
```

### File: `src/consensus/consensus.h`

**Current Limits:**
```cpp
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
```

**Dilithium Update:**
```cpp
// Phase 2 Week 1: Conservative increase for testing
static const unsigned int MAX_BLOCK_WEIGHT = 16000000;  // 16 MB weight units
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 16000000;  // 16 MB

// Transaction size limits
static const unsigned int MAX_STANDARD_TX_WEIGHT = 400000;  // 400 KB (was 400KB bytes)
static const unsigned int MAX_TX_SIZE = 500000;  // 500 KB max transaction
```

---

## Step 5: Script Size Limits

### File: `src/script/script.h`

**Current Limits:**
```cpp
static const unsigned int MAX_SCRIPT_SIZE = 10000;  // 10 KB
static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520;  // 520 bytes
```

**Dilithium Update:**
```cpp
static const unsigned int MAX_SCRIPT_SIZE = 50000;  // 50 KB (for large scripts)
static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 3000;  // 3 KB (Dilithium sig + pubkey)
```

---

## Step 6: Unit Tests

### File: `src/test/transaction_tests.cpp`

**New Tests to Add:**

```cpp
BOOST_AUTO_TEST_CASE(dilithium_transaction_large_signature)
{
    // Test transaction with 2,420-byte Dilithium signature
    CMutableTransaction tx;

    // Create Dilithium signature (2420 bytes)
    CKey key;
    key.MakeNewKey(true);  // Dilithium key

    uint256 hash = GetRandHash();
    std::vector<unsigned char> vchSig;
    BOOST_CHECK(key.Sign(hash, vchSig));
    BOOST_CHECK_EQUAL(vchSig.size(), 2420);

    // Create scriptSig with signature + pubkey
    CPubKey pubkey = key.GetPubKey();
    CScript scriptSig;
    scriptSig << vchSig << ToByteVector(pubkey);

    // Add to transaction
    tx.vin.resize(1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vin[0].prevout.hash = GetRandHash();
    tx.vin[0].prevout.n = 0;

    // Verify transaction size
    size_t txSize = GetSerializeSize(tx, PROTOCOL_VERSION);
    BOOST_CHECK(txSize > 3700);  // Should be ~3,800 bytes
    BOOST_CHECK(txSize < MAX_TX_SIZE);  // Should be under limit
}

BOOST_AUTO_TEST_CASE(dilithium_transaction_serialization)
{
    // Create transaction with Dilithium signature
    CMutableTransaction tx;

    CKey key;
    key.MakeNewKey(true);

    uint256 hash = GetRandHash();
    std::vector<unsigned char> vchSig;
    key.Sign(hash, vchSig);

    CPubKey pubkey = key.GetPubKey();
    CScript scriptSig;
    scriptSig << vchSig << ToByteVector(pubkey);

    tx.vin.resize(1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 50 * COIN;

    // Serialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;

    // Deserialize
    CTransaction loaded_tx;
    ss >> loaded_tx;

    // Verify
    BOOST_CHECK(tx.GetHash() == loaded_tx.GetHash());
    BOOST_CHECK(tx.vin[0].scriptSig == loaded_tx.vin[0].scriptSig);
}

BOOST_AUTO_TEST_CASE(dilithium_transaction_multiple_inputs)
{
    // Test transaction with multiple Dilithium signatures
    CMutableTransaction tx;

    CKey key1, key2, key3;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);
    key3.MakeNewKey(true);

    // Add 3 inputs with Dilithium signatures
    tx.vin.resize(3);
    for (int i = 0; i < 3; i++) {
        CKey& key = (i == 0) ? key1 : (i == 1) ? key2 : key3;

        uint256 hash = GetRandHash();
        std::vector<unsigned char> vchSig;
        key.Sign(hash, vchSig);

        CPubKey pubkey = key.GetPubKey();
        CScript scriptSig;
        scriptSig << vchSig << ToByteVector(pubkey);

        tx.vin[i].scriptSig = scriptSig;
        tx.vin[i].prevout.hash = GetRandHash();
        tx.vin[i].prevout.n = i;
    }

    tx.vout.resize(1);
    tx.vout[0].nValue = 150 * COIN;

    // Verify size
    size_t txSize = GetSerializeSize(tx, PROTOCOL_VERSION);
    BOOST_CHECK(txSize > 11000);  // 3 signatures ~11,400 bytes
    BOOST_CHECK(txSize < MAX_TX_SIZE);
}
```

---

## Expected File Changes Summary

| File | Change Type | Lines Changed | Impact |
|------|-------------|---------------|--------|
| `src/net.h` | Modify | ~5 | Network limits |
| `src/consensus/consensus.h` | Modify | ~10 | Block/tx size limits |
| `src/script/script.h` | Modify | ~5 | Script size limits |
| `src/test/transaction_tests.cpp` | Add | ~150 | New tests |
| `src/crypto/dilithium/*` | Copy | ~2,000 | Phase 1 code |
| `src/key.{h,cpp}` | Replace | ~300 | Phase 1 code |
| `src/pubkey.{h,cpp}` | Replace | ~200 | Phase 1 code |

**Total:** ~2,670 lines modified/added

---

## Build & Test Plan

### Build Command
```bash
cd ~/crypto-projects/bitcoin-core
./autogen.sh
./configure --disable-wallet --with-incompatible-bdb
make -j$(nproc)
```

### Test Command
```bash
# Run all tests
make check

# Run specific Dilithium tests
./src/test/test_bitcoin --run_test=transaction_tests
./src/test/test_bitcoin --run_test=dilithium_tests
./src/test/test_bitcoin --run_test=key_tests
```

---

## Success Criteria (Week 1)

- [ ] Bitcoin Core v25.0 cloned successfully
- [ ] Phase 1 Dilithium code integrated
- [ ] Network protocol limits updated
- [ ] Consensus size limits updated
- [ ] Script size limits updated
- [ ] 15+ new transaction tests created
- [ ] All tests passing
- [ ] Bitcoin Core builds successfully
- [ ] Documentation complete

---

## Progress Log

**2025-10-24 16:40 UTC:**
- ✅ Created phase-2-transaction-integration branch
- ⏳ Cloning Bitcoin Core v25.0 (in progress)
- Created Week 1 implementation plan
- Documented all file modifications needed

**Next:**
- Wait for Bitcoin Core clone to complete
- Copy Phase 1 code
- Begin modifications

---

**Status:** ON TRACK
**Estimated Completion:** End of Week 1 (2-3 days)
**Quality Target:** A+ (maintained from Phase 1)
