# Transaction Validation System - Integration Guide

**Phase:** 5.1.3 Complete
**Date:** 2025-10-27

---

## Overview

This guide demonstrates how to integrate the transaction validation system into various components of the Dilithion cryptocurrency.

---

## API Reference

### CTransactionValidator Class

The main validator class provides comprehensive transaction validation.

```cpp
#include <consensus/tx_validation.h>

CTransactionValidator validator;
```

### Key Methods

#### 1. CheckTransactionBasic
Validates transaction structure without UTXO access.

```cpp
bool CheckTransactionBasic(const CTransaction& tx, std::string& error) const;
```

**Use Cases:**
- Initial transaction acceptance
- Quick structural validation
- Pre-UTXO checks

**Example:**
```cpp
CTransactionValidator validator;
std::string error;

if (!validator.CheckTransactionBasic(tx, error)) {
    LogPrintf("Invalid transaction structure: %s\n", error);
    return false;
}
```

#### 2. CheckTransactionInputs
Validates inputs against UTXO set.

```cpp
bool CheckTransactionInputs(const CTransaction& tx, CUTXOSet& utxoSet,
                            uint32_t currentHeight, CAmount& txFee,
                            std::string& error) const;
```

**Use Cases:**
- UTXO verification
- Fee calculation
- Coinbase maturity checks

**Example:**
```cpp
CAmount fee = 0;
uint32_t height = blockchain.GetHeight();

if (!validator.CheckTransactionInputs(tx, utxoSet, height, fee, error)) {
    LogPrintf("Input validation failed: %s\n", error);
    return false;
}

LogPrintf("Transaction fee: %lld ions\n", fee);
```

#### 3. CheckTransaction
Complete validation pipeline.

```cpp
bool CheckTransaction(const CTransaction& tx, CUTXOSet& utxoSet,
                     uint32_t currentHeight, CAmount& txFee,
                     std::string& error) const;
```

**Use Cases:**
- Mempool acceptance
- Block validation
- RPC transaction submission

**Example:**
```cpp
CAmount fee = 0;
std::string error;
uint32_t height = blockchain.GetHeight();

if (!validator.CheckTransaction(tx, utxoSet, height, fee, error)) {
    LogPrintf("Transaction validation failed: %s\n", error);
    return false;
}

// Transaction is valid, add to mempool or block
LogPrintf("Transaction valid. Fee: %lld ions\n", fee);
```

---

## Integration Examples

### 1. Mempool Integration

```cpp
// In src/node/mempool.cpp

#include <consensus/tx_validation.h>

bool CMemPool::AcceptToMemoryPool(const CTransaction& tx, std::string& reason) {
    CTransactionValidator validator;
    std::string error;
    CAmount fee = 0;

    // Get current blockchain height
    uint32_t currentHeight = chainState.GetHeight();

    // Step 1: Check if transaction already exists
    if (exists(tx.GetHash())) {
        reason = "Transaction already in mempool";
        return false;
    }

    // Step 2: Basic structural validation (quick check)
    if (!validator.CheckTransactionBasic(tx, error)) {
        reason = "Invalid transaction structure: " + error;
        return false;
    }

    // Step 3: Complete validation with UTXO set
    if (!validator.CheckTransaction(tx, utxoSet, currentHeight, fee, error)) {
        reason = "Validation failed: " + error;
        return false;
    }

    // Step 4: Check if transaction is standard
    if (!validator.IsStandardTransaction(tx)) {
        reason = "Non-standard transaction";
        return false;
    }

    // Step 5: Check minimum fee
    CAmount minFee = validator.GetMinimumFee(tx);
    if (fee < minFee) {
        reason = "Insufficient fee";
        return false;
    }

    // Step 6: Check for conflicts with mempool
    if (HasConflicts(tx)) {
        reason = "Transaction conflicts with mempool";
        return false;
    }

    // Add to mempool
    AddEntry(tx, fee);

    LogPrintf("Accepted transaction %s to mempool (fee: %lld)\n",
              tx.GetHash().GetHex(), fee);

    return true;
}
```

### 2. Block Validation Integration

```cpp
// In src/node/blockchain_storage.cpp

#include <consensus/tx_validation.h>

bool CBlockchainStorage::ConnectBlock(const CBlock& block, uint32_t height) {
    CTransactionValidator validator;

    // Validate all transactions in block
    for (size_t i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = block.vtx[i];
        std::string error;
        CAmount fee = 0;

        // Skip coinbase for input validation
        if (i == 0) {
            // Validate coinbase structure
            if (!validator.CheckTransactionBasic(tx, error)) {
                LogPrintf("Invalid coinbase in block %u: %s\n", height, error);
                return false;
            }
            continue;
        }

        // Validate regular transaction
        if (!validator.CheckTransaction(tx, utxoSet, height, fee, error)) {
            LogPrintf("Invalid transaction in block %u: %s\n", height, error);
            return false;
        }

        // Accumulate fees for coinbase reward validation
        totalFees += fee;
    }

    // Update UTXO set
    if (!utxoSet.ApplyBlock(block, height)) {
        LogPrintf("Failed to apply block %u to UTXO set\n", height);
        return false;
    }

    return true;
}
```

### 3. RPC Transaction Submission

```cpp
// In src/rpc/blockchain_rpc.cpp

#include <consensus/tx_validation.h>

std::string SendRawTransaction(const CTransaction& tx) {
    CTransactionValidator validator;
    std::string error;
    CAmount fee = 0;

    // Get current height
    uint32_t height = blockchain.GetHeight();

    // Validate transaction
    if (!validator.CheckTransaction(tx, utxoSet, height, fee, error)) {
        throw std::runtime_error("Transaction validation failed: " + error);
    }

    // Check fee is reasonable
    CAmount minFee = validator.GetMinimumFee(tx);
    if (fee < minFee) {
        throw std::runtime_error("Fee too low. Required: " +
                                std::to_string(minFee) + " ions");
    }

    // Add to mempool
    if (!mempool.AcceptToMemoryPool(tx, error)) {
        throw std::runtime_error("Failed to accept to mempool: " + error);
    }

    // Broadcast to network
    network.BroadcastTransaction(tx);

    return tx.GetHash().GetHex();
}
```

### 4. Wallet Transaction Creation

```cpp
// In src/wallet/wallet.cpp

#include <consensus/tx_validation.h>

bool CWallet::CreateTransaction(const std::vector<CRecipient>& recipients,
                                CTransaction& tx, std::string& error) {
    CTransactionValidator validator;

    // ... transaction construction logic ...

    // Validate created transaction before signing
    if (!validator.CheckTransactionBasic(tx, error)) {
        error = "Created invalid transaction: " + error;
        return false;
    }

    // Calculate fee
    CAmount fee = 0;
    uint32_t height = blockchain.GetHeight();

    if (!validator.CheckTransactionInputs(tx, utxoSet, height, fee, error)) {
        error = "Input validation failed: " + error;
        return false;
    }

    // Check if fee is acceptable
    CAmount minFee = validator.GetMinimumFee(tx);
    if (fee < minFee) {
        error = "Fee too low. Required: " + std::to_string(minFee);
        return false;
    }

    LogPrintf("Created transaction with fee: %lld ions\n", fee);
    return true;
}
```

---

## Error Handling

### Common Errors

The validator provides detailed error messages:

```cpp
// Example error messages:
"Transaction is null"
"Transaction has no inputs"
"Transaction has no outputs"
"Transaction output value must be positive"
"Transaction output total out of range"
"Transaction size (X bytes) exceeds maximum (Y bytes)"
"Transaction contains duplicate inputs"
"Input references non-existent UTXO (tx: hash, n: index)"
"Coinbase output not mature (height: X, current: Y, confirmations: Z, required: W)"
"Transaction inputs less than outputs (negative fee)"
"Transaction fee out of range"
```

### Error Handling Pattern

```cpp
CTransactionValidator validator;
std::string error;
CAmount fee = 0;

if (!validator.CheckTransaction(tx, utxoSet, height, fee, error)) {
    // Log error
    LogPrintf("Transaction %s validation failed: %s\n",
              tx.GetHash().GetHex(), error);

    // Categorize error for response
    if (error.find("non-existent UTXO") != std::string::npos) {
        // Input doesn't exist - likely spent
        return RejectTransaction("input-missing", error);
    } else if (error.find("not mature") != std::string::npos) {
        // Coinbase not mature yet
        return RejectTransaction("immature-coinbase", error);
    } else if (error.find("negative fee") != std::string::npos) {
        // Invalid fee calculation
        return RejectTransaction("bad-txns-in-belowout", error);
    } else {
        // Generic rejection
        return RejectTransaction("bad-transaction", error);
    }
}
```

---

## Performance Considerations

### 1. Batch Validation

When validating multiple transactions:

```cpp
std::vector<std::pair<CTransaction, CAmount>> validTransactions;

for (const auto& tx : transactions) {
    std::string error;
    CAmount fee = 0;

    if (validator.CheckTransaction(tx, utxoSet, height, fee, error)) {
        validTransactions.push_back({tx, fee});
    } else {
        LogPrintf("Rejected: %s\n", error);
    }
}
```

### 2. Early Exit Optimization

Use `CheckTransactionBasic` for quick structural checks:

```cpp
// Quick check before expensive UTXO lookups
if (!validator.CheckTransactionBasic(tx, error)) {
    return false;  // Fast rejection
}

// Only do UTXO lookups if basic checks pass
if (!validator.CheckTransactionInputs(tx, utxoSet, height, fee, error)) {
    return false;
}
```

### 3. UTXO Set Caching

The UTXO set has built-in caching:

```cpp
// UTXOs are cached automatically
// Multiple lookups of same UTXO are fast
for (const auto& txin : tx.vin) {
    CUTXOEntry entry;
    utxoSet.GetUTXO(txin.prevout, entry);  // Cached
}
```

---

## Validation Constants

Configure validation behavior:

```cpp
#include <consensus/tx_validation.h>

// Access constants
TxValidation::MAX_TRANSACTION_SIZE  // 1 MB
TxValidation::MAX_MONEY             // 21M coins
TxValidation::MIN_TX_FEE            // 1000 ions
TxValidation::COINBASE_MATURITY     // 100 blocks
TxValidation::MAX_TX_SIGOPS         // 20000 ops
```

---

## Testing Integration

### Unit Test Example

```cpp
#include <consensus/tx_validation.h>

void TestTransactionValidation() {
    CTransactionValidator validator;
    CUTXOSet utxoSet;

    // Setup test environment
    utxoSet.Open(".test_utxo");

    // Create test UTXO
    uint256 prevHash;
    prevHash.data[0] = 0x01;
    CTxOut testOut(100 * COIN, scriptPubKey);
    utxoSet.AddUTXO(COutPoint(prevHash, 0), testOut, 10, false);

    // Create test transaction
    CTransaction tx;
    tx.vin.push_back(CTxIn(COutPoint(prevHash, 0)));
    tx.vout.push_back(CTxOut(90 * COIN, scriptPubKey));

    // Validate
    std::string error;
    CAmount fee = 0;
    assert(validator.CheckTransaction(tx, utxoSet, 150, fee, error));
    assert(fee == 10 * COIN);

    utxoSet.Close();
}
```

---

## Future Enhancements (Phase 5.2)

### Dilithium Signature Verification

```cpp
// Future implementation in VerifyScript()
bool VerifyScript(...) {
    // Extract Dilithium signature from scriptSig
    std::vector<uint8_t> signature = ExtractSignature(scriptSig);
    std::vector<uint8_t> pubkey = ExtractPublicKey(scriptSig);

    // Extract pubkey hash from scriptPubKey
    std::vector<uint8_t> pubkeyHash = ExtractPubKeyHash(scriptPubKey);

    // Verify pubkey matches hash
    if (Hash160(pubkey) != pubkeyHash) {
        error = "Public key does not match pubkey hash";
        return false;
    }

    // Verify Dilithium signature
    if (!DilithiumVerify(signature, pubkey, tx.GetSignatureHash())) {
        error = "Dilithium signature verification failed";
        return false;
    }

    return true;
}
```

---

## Best Practices

1. **Always validate before processing:**
   ```cpp
   if (!validator.CheckTransaction(tx, utxoSet, height, fee, error)) {
       return false;
   }
   // Process transaction
   ```

2. **Use appropriate validation level:**
   - Basic: Quick structural checks
   - Inputs: UTXO verification
   - Complete: Full validation

3. **Handle errors gracefully:**
   ```cpp
   if (!validator.CheckTransaction(tx, utxoSet, height, fee, error)) {
       LogPrintf("Validation failed: %s\n", error);
       // Don't process further
       return false;
   }
   ```

4. **Cache validation results:**
   ```cpp
   // In mempool
   std::map<uint256, bool> validationCache;

   if (validationCache.count(tx.GetHash())) {
       return validationCache[tx.GetHash()];
   }
   ```

5. **Log validation decisions:**
   ```cpp
   if (!validator.CheckTransaction(tx, utxoSet, height, fee, error)) {
       LogPrintf("[REJECT] %s: %s\n", tx.GetHash().GetHex(), error);
   } else {
       LogPrintf("[ACCEPT] %s (fee: %lld)\n", tx.GetHash().GetHex(), fee);
   }
   ```

---

## Troubleshooting

### Issue: "Input references non-existent UTXO"

**Cause:** Transaction tries to spend output that doesn't exist or was already spent.

**Solution:**
```cpp
// Check if UTXO exists
if (!utxoSet.HaveUTXO(txin.prevout)) {
    // UTXO was spent or never existed
    // Check transaction ordering or double-spend
}
```

### Issue: "Coinbase output not mature"

**Cause:** Trying to spend coinbase before 100 confirmations.

**Solution:**
```cpp
// Wait for maturity
uint32_t requiredHeight = utxoEntry.nHeight + COINBASE_MATURITY;
if (currentHeight < requiredHeight) {
    // Wait until height reaches requiredHeight
}
```

### Issue: "Transaction fee out of range"

**Cause:** Fee calculation overflow or invalid input values.

**Solution:**
```cpp
// Verify input values are valid
for (const auto& txin : tx.vin) {
    CUTXOEntry entry;
    utxoSet.GetUTXO(txin.prevout, entry);
    assert(entry.out.nValue <= MAX_MONEY);
}
```

---

## Summary

The transaction validation system provides:

- ✅ Comprehensive validation pipeline
- ✅ Clear error messages
- ✅ Efficient performance
- ✅ Security guarantees
- ✅ Easy integration
- ✅ Extensible design

**Status:** Ready for production use (pending Dilithium signatures in Phase 5.2)

---

**Document Version:** 1.0
**Last Updated:** 2025-10-27
**Phase:** 5.1.3 Complete
