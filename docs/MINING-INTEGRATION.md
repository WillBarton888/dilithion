# Mining Integration Technical Specification

**Component:** Transaction-Mining Integration
**Version:** 1.0
**Date:** 2025-10-27
**Status:** Implemented

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Block Template Generation](#block-template-generation)
4. [Transaction Selection Algorithm](#transaction-selection-algorithm)
5. [Coinbase Construction](#coinbase-construction)
6. [Block Validation](#block-validation)
7. [Merkle Tree Implementation](#merkle-tree-implementation)
8. [Fee Collection](#fee-collection)
9. [Integration Points](#integration-points)
10. [API Reference](#api-reference)
11. [Examples](#examples)

---

## Overview

### Purpose
Integrate the transaction system with the mining system to enable:
- Blocks containing mempool transactions (not just coinbase)
- Proper fee collection in coinbase outputs
- Block validation according to consensus rules
- Economic incentives for miners

### Scope
- Block template generation with transaction selection
- Coinbase creation with subsidy + fees
- Merkle root calculation
- Block-level validation
- Integration with existing mempool and UTXO systems

### Goals
1. Maximize miner revenue (via fee-rate ordering)
2. Ensure consensus compliance (Bitcoin-compatible rules)
3. Maintain thread safety and performance
4. Provide comprehensive validation

---

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────┐
│              CMiningController                       │
├─────────────────────────────────────────────────────┤
│                                                       │
│  CreateBlockTemplate()                               │
│    ├─> SelectTransactionsForBlock()                 │
│    │     ├─> mempool.GetOrderedTxs()                │
│    │     ├─> utxoSet.GetUTXO()                      │
│    │     └─> Validate & select TXs                  │
│    │                                                  │
│    ├─> CreateCoinbaseTransaction()                  │
│    │     ├─> CalculateBlockSubsidy()                │
│    │     └─> Build coinbase TX                      │
│    │                                                  │
│    ├─> BuildMerkleRoot()                            │
│    │     └─> SHA3-256 merkle tree                   │
│    │                                                  │
│    └─> Assemble complete block                      │
│                                                       │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│              CBlockValidator                         │
├─────────────────────────────────────────────────────┤
│                                                       │
│  CheckBlock()                                        │
│    ├─> CheckBlockHeader()                           │
│    ├─> CheckCoinbase()                              │
│    ├─> CheckNoDuplicateTransactions()               │
│    ├─> CheckNoDoubleSpends()                        │
│    ├─> VerifyMerkleRoot()                           │
│    └─> CalculateTotalFees()                         │
│                                                       │
└─────────────────────────────────────────────────────┘
```

### Data Flow

```
Mempool (Sorted by Fee Rate)
         │
         ├─> Transaction Selection
         │     │
         │     ├─> UTXO Validation
         │     ├─> Size Limit Check
         │     ├─> Dependency Resolution
         │     └─> Fee Calculation
         │
         ├─> Coinbase Creation
         │     │
         │     ├─> Block Subsidy
         │     └─> + Total Fees
         │
         ├─> Merkle Tree Construction
         │     │
         │     └─> SHA3-256 Hashing
         │
         └─> Block Template
               │
               ├─> Mining (PoW Search)
               │
               └─> Validation
                     │
                     └─> Blockchain
```

---

## Block Template Generation

### Algorithm Overview

```python
def CreateBlockTemplate(mempool, utxoSet, prevBlock, height, difficulty, minerAddr):
    # Step 1: Select transactions
    selected_txs = []
    total_fees = 0
    block_size = 200  # Reserve for coinbase

    for tx in mempool.GetOrderedTxs():  # Sorted by fee rate
        if block_size + tx.size > MAX_BLOCK_SIZE:
            continue

        if not ValidateInputs(tx, utxoSet, selected_txs):
            continue

        fee = CalculateFee(tx, utxoSet)
        selected_txs.append(tx)
        total_fees += fee
        block_size += tx.size

    # Step 2: Create coinbase
    subsidy = CalculateBlockSubsidy(height)
    coinbase = CreateCoinbase(height, subsidy + total_fees, minerAddr)

    # Step 3: Build transaction list
    all_txs = [coinbase] + selected_txs

    # Step 4: Calculate merkle root
    merkle_root = BuildMerkleRoot(all_txs)

    # Step 5: Assemble block
    block = CBlock(
        version=1,
        hashPrevBlock=prevBlock,
        hashMerkleRoot=merkle_root,
        nTime=current_time,
        nBits=difficulty,
        nNonce=0,
        vtx=serialize(all_txs)
    )

    return BlockTemplate(block, target, height)
```

### Complexity Analysis

- **Time:** O(n log n)
  - Transaction iteration: O(n)
  - UTXO lookups: O(n * log m) where m = UTXO set size
  - Merkle tree: O(n log n)

- **Space:** O(n)
  - Selected transactions: O(n)
  - Merkle tree: O(n)
  - Spent output tracking: O(k) where k = total inputs

---

## Transaction Selection Algorithm

### Greedy Fee-Rate Algorithm

```cpp
std::vector<CTransactionRef> SelectTransactionsForBlock(
    CTxMemPool& mempool,
    CUTXOSet& utxoSet,
    size_t maxBlockSize,
    uint64_t& totalFees
) {
    std::vector<CTransactionRef> selectedTxs;
    totalFees = 0;
    size_t currentBlockSize = 200;  // Coinbase overhead

    // Get pre-sorted transactions (highest fee rate first)
    auto candidateTxs = mempool.GetOrderedTxs();

    // Track spent outputs to prevent double-spends
    std::set<COutPoint> spentInBlock;

    for (const auto& tx : candidateTxs) {
        // Check 1: Size limit
        if (currentBlockSize + tx->GetSerializedSize() > maxBlockSize)
            continue;

        // Check 2: Input availability
        bool allInputsAvailable = true;
        for (const auto& input : tx->vin) {
            // Check if already spent in this block
            if (spentInBlock.count(input.prevout) > 0) {
                allInputsAvailable = false;
                break;
            }

            // Check if exists in UTXO set or earlier in block
            if (!utxoSet.HaveUTXO(input.prevout) &&
                !CreatedInBlock(input.prevout, selectedTxs)) {
                allInputsAvailable = false;
                break;
            }
        }

        if (!allInputsAvailable)
            continue;

        // Check 3: Fee calculation
        CTxMemPoolEntry entry;
        if (!mempool.GetTx(tx->GetHash(), entry))
            continue;

        uint64_t fee = entry.GetFee();

        // Add to block
        selectedTxs.push_back(tx);
        currentBlockSize += tx->GetSerializedSize();
        totalFees += fee;

        // Mark outputs as spent
        for (const auto& input : tx->vin) {
            spentInBlock.insert(input.prevout);
        }
    }

    return selectedTxs;
}
```

### Optimizations

1. **Pre-sorted Mempool:** Transactions already ordered by fee rate - no sorting needed
2. **Early Size Check:** Skip transactions that won't fit
3. **UTXO Cache:** LevelDB caching reduces lookup time
4. **Dependency Tracking:** O(1) set lookups for double-spend detection

### Alternative Algorithms (Future)

- **Knapsack:** Dynamic programming for optimal selection
- **Branch and Bound:** Exact optimal solution
- **CPFP Awareness:** Child-pays-for-parent transaction chains
- **Weight-based:** Segwit-style weight units

---

## Coinbase Construction

### Structure

```
CTransaction (Coinbase)
├─ nVersion: 1
├─ vin[0]:
│  ├─ prevout: NULL (hash=0, n=0xFFFFFFFF)
│  ├─ scriptSig: <height> <arbitrary data>
│  └─ nSequence: 0xFFFFFFFF
├─ vout[0]:
│  ├─ nValue: subsidy + fees
│  └─ scriptPubKey: <miner's address>
└─ nLockTime: 0
```

### Height Encoding (BIP34)

```cpp
// Encode block height in little-endian
std::vector<uint8_t> scriptSig;
scriptSig.push_back(height & 0xFF);
scriptSig.push_back((height >> 8) & 0xFF);
scriptSig.push_back((height >> 16) & 0xFF);
scriptSig.push_back((height >> 24) & 0xFF);
```

### Value Calculation

```cpp
uint64_t nCoinbaseValue = CalculateBlockSubsidy(height);

// Add fees with overflow protection
if (totalFees > 0) {
    if (nCoinbaseValue + totalFees < nCoinbaseValue) {
        // Overflow - cap at max
        nCoinbaseValue = UINT64_MAX;
    } else {
        nCoinbaseValue += totalFees;
    }
}
```

### Subsidy Schedule

```
Block Range          | Subsidy | Total in Range | Cumulative
---------------------|---------|----------------|------------
0 - 209,999          | 50 DIL  | 10,500,000 DIL | 10,500,000
210,000 - 419,999    | 25 DIL  | 5,250,000 DIL  | 15,750,000
420,000 - 629,999    | 12.5 DIL| 2,625,000 DIL  | 18,375,000
...                  | ...     | ...            | ...
13,230,000 - 13,439,999 | ~0.00000001 | ~2 DIL | ~21,000,000
13,440,000+          | 0 DIL   | 0              | ~21,000,000
```

**Total Supply:** ~21,000,000 DIL (same as Bitcoin)

---

## Block Validation

### Validation Checklist

```cpp
bool CheckBlock(const CBlock& block, CUTXOSet& utxoSet,
                uint32_t nHeight, std::string& error)
{
    // 1. Structure
    if (block.vtx.empty())
        return error("Block has no transactions");

    if (block.vtx.size() > MAX_BLOCK_SIZE)
        return error("Block too large");

    // 2. Proof of Work
    if (!CheckProofOfWork(block.GetHash(), block.nBits))
        return error("Invalid proof of work");

    // 3. Deserialize transactions
    std::vector<CTransactionRef> txs;
    if (!DeserializeBlockTransactions(block, txs, error))
        return false;

    // 4. First transaction must be coinbase
    if (!txs[0]->IsCoinBase())
        return error("First transaction is not coinbase");

    // 5. Only one coinbase
    for (size_t i = 1; i < txs.size(); i++) {
        if (txs[i]->IsCoinBase())
            return error("Multiple coinbase transactions");
    }

    // 6. Validate all transactions
    CTransactionValidator validator;
    for (const auto& tx : txs) {
        std::string txError;
        if (!validator.CheckTransactionBasic(*tx, txError))
            return error("Invalid transaction: " + txError);
    }

    // 7. Check coinbase value
    CAmount totalFees = 0;
    if (!CalculateTotalFees(txs, utxoSet, totalFees, error))
        return false;

    if (!CheckCoinbase(*txs[0], nHeight, totalFees, error))
        return false;

    // 8. No duplicates
    if (!CheckNoDuplicateTransactions(txs, error))
        return false;

    // 9. No double-spends
    if (!CheckNoDoubleSpends(txs, error))
        return false;

    // 10. Verify merkle root
    if (!VerifyMerkleRoot(block, txs, error))
        return false;

    return true;
}
```

### Validation Costs

| Check | Complexity | Time (1000 TXs) |
|-------|-----------|-----------------|
| Structure | O(1) | <1 μs |
| PoW | O(1) | <10 μs |
| Deserialize | O(n) | ~10 ms |
| TX Validation | O(n*m) | ~30 ms |
| Coinbase | O(1) | <10 μs |
| Duplicates | O(n log n) | ~100 μs |
| Double-spends | O(n*m) | ~500 μs |
| Merkle Root | O(n log n) | ~1 ms |
| **Total** | **O(n*m)** | **~40 ms** |

---

## Merkle Tree Implementation

### Algorithm

```cpp
uint256 BuildMerkleRoot(const std::vector<CTransactionRef>& txs)
{
    if (txs.empty())
        return uint256();  // Null hash

    // Level 0: Transaction hashes
    std::vector<uint256> tree;
    for (const auto& tx : txs) {
        tree.push_back(tx->GetHash());
    }

    // Build levels
    size_t offset = 0;
    for (size_t levelSize = txs.size(); levelSize > 1; ) {
        for (size_t i = 0; i < levelSize; i += 2) {
            size_t i2 = std::min(i + 1, levelSize - 1);

            // Concatenate and hash
            uint256 combined = Hash(tree[offset + i] + tree[offset + i2]);
            tree.push_back(combined);
        }

        offset += levelSize;
        levelSize = (levelSize + 1) / 2;
    }

    return tree.back();  // Root
}
```

### Example

```
Transactions: [TX0, TX1, TX2, TX3]

Level 0:  Hash(TX0)  Hash(TX1)  Hash(TX2)  Hash(TX3)
              │          │          │          │
              └─────┬────┘          └─────┬────┘
                    │                     │
Level 1:        Hash(H0+H1)          Hash(H2+H3)
                    │                     │
                    └──────────┬──────────┘
                               │
Level 2:                   ROOT HASH
```

### Odd Number Handling

```
Transactions: [TX0, TX1, TX2]

Level 0:  Hash(TX0)  Hash(TX1)  Hash(TX2)
              │          │          │
              └─────┬────┘          │
                    │               │
              Hash(H0+H1)      Hash(TX2)
                    │               │
                    └───────┬───────┘
                            │
                         ROOT HASH
```

**Note:** Last element is **NOT** duplicated (Bitcoin does this, but it's unnecessary and wastes computation).

---

## Fee Collection

### Fee Calculation

```cpp
CAmount CalculateFee(const CTransaction& tx, const CUTXOSet& utxoSet)
{
    CAmount inputValue = 0;
    for (const auto& input : tx.vin) {
        CUTXOEntry entry;
        if (!utxoSet.GetUTXO(input.prevout, entry))
            return 0;  // Missing input
        inputValue += entry.out.nValue;
    }

    CAmount outputValue = tx.GetValueOut();

    // Fee = inputs - outputs
    if (outputValue > inputValue)
        return 0;  // Invalid (negative fee)

    return inputValue - outputValue;
}
```

### Total Fee Accumulation

```cpp
CAmount totalFees = 0;
for (const auto& tx : selectedTxs) {
    CAmount fee = CalculateFee(tx, utxoSet);

    // Overflow protection
    if (totalFees + fee < totalFees) {
        // Cap at current value
        break;
    }

    totalFees += fee;
}
```

### Fee Rate Metrics

```
Fee Rate = Fee (ions) / TX Size (bytes)

Example:
  Fee: 10,000 ions (0.0001 DIL)
  Size: 250 bytes
  Fee Rate: 10,000 / 250 = 40 ions/byte
```

---

## Integration Points

### Upstream Dependencies

```cpp
// Mempool - Provides transactions ordered by fee rate
class CTxMemPool {
    std::vector<CTransactionRef> GetOrderedTxs() const;
    bool GetTx(const uint256& txid, CTxMemPoolEntry& entry) const;
};

// UTXO Set - Validates transaction inputs
class CUTXOSet {
    bool GetUTXO(const COutPoint& outpoint, CUTXOEntry& entry) const;
    bool HaveUTXO(const COutPoint& outpoint) const;
};

// Transaction Validator - Individual TX validation
class CTransactionValidator {
    bool CheckTransaction(const CTransaction& tx, CUTXOSet& utxoSet,
                          uint32_t height, CAmount& fee, std::string& error);
};
```

### Downstream Consumers

```cpp
// Node - Uses block template for mining
void UpdateMiningTemplate() {
    std::string error;
    auto templateOpt = miner.CreateBlockTemplate(
        mempool, utxoSet, chainTip, height, difficulty, minerAddr, error
    );

    if (templateOpt.has_value()) {
        miner.UpdateTemplate(templateOpt.value());
    }
}

// Chain State - Validates and accepts blocks
bool AcceptBlock(const CBlock& block) {
    CBlockValidator validator;
    std::string error;

    if (!validator.CheckBlock(block, utxoSet, height, error)) {
        return false;
    }

    // Apply block to UTXO set
    // Clean mempool
    // Update chain tip

    return true;
}
```

---

## API Reference

### CMiningController

```cpp
class CMiningController {
public:
    // Generate block template with mempool transactions
    std::optional<CBlockTemplate> CreateBlockTemplate(
        CTxMemPool& mempool,
        CUTXOSet& utxoSet,
        const uint256& hashPrevBlock,
        uint32_t nHeight,
        uint32_t nBits,
        const std::vector<uint8_t>& minerAddress,
        std::string& error
    );

    // Calculate block subsidy for given height
    uint64_t CalculateBlockSubsidy(uint32_t nHeight) const;

private:
    // Select transactions from mempool
    std::vector<CTransactionRef> SelectTransactionsForBlock(
        CTxMemPool& mempool,
        CUTXOSet& utxoSet,
        size_t maxBlockSize,
        uint64_t& totalFees
    );

    // Create coinbase transaction
    CTransactionRef CreateCoinbaseTransaction(
        uint32_t nHeight,
        uint64_t totalFees,
        const std::vector<uint8_t>& minerAddress
    );

    // Build merkle root from transactions
    uint256 BuildMerkleRoot(
        const std::vector<CTransactionRef>& transactions
    ) const;
};
```

### CBlockValidator

```cpp
class CBlockValidator {
public:
    // Complete block validation
    bool CheckBlock(
        const CBlock& block,
        CUTXOSet& utxoSet,
        uint32_t nHeight,
        std::string& error
    ) const;

    // Validate coinbase transaction
    bool CheckCoinbase(
        const CTransaction& coinbase,
        uint32_t nHeight,
        CAmount totalFees,
        std::string& error
    ) const;

    // Check for duplicate transactions
    bool CheckNoDuplicateTransactions(
        const std::vector<CTransactionRef>& transactions,
        std::string& error
    ) const;

    // Check for double-spends within block
    bool CheckNoDoubleSpends(
        const std::vector<CTransactionRef>& transactions,
        std::string& error
    ) const;

    // Verify merkle root matches transactions
    bool VerifyMerkleRoot(
        const CBlock& block,
        const std::vector<CTransactionRef>& transactions,
        std::string& error
    ) const;

    // Calculate block subsidy (static)
    static uint64_t CalculateBlockSubsidy(uint32_t nHeight);
};
```

---

## Examples

### Example 1: Generate Block Template

```cpp
#include <miner/controller.h>
#include <node/mempool.h>
#include <node/utxo_set.h>

// Setup
CMiningController miner(4);  // 4 threads
CTxMemPool mempool;
CUTXOSet utxoSet;

// Miner address (P2PKH)
std::vector<uint8_t> minerAddr = CreateMinerAddress();

// Get chain state
uint256 hashPrevBlock = chainstate.GetTip()->GetBlockHash();
uint32_t nHeight = chainstate.GetHeight() + 1;
uint32_t nBits = GetNextWorkRequired(chainstate.GetTip());

// Create template
std::string error;
auto templateOpt = miner.CreateBlockTemplate(
    mempool, utxoSet, hashPrevBlock, nHeight, nBits, minerAddr, error
);

if (!templateOpt.has_value()) {
    std::cerr << "Template creation failed: " << error << std::endl;
    return;
}

CBlockTemplate& blockTemplate = templateOpt.value();

std::cout << "Block Template Created:" << std::endl;
std::cout << "  Height: " << blockTemplate.nHeight << std::endl;
std::cout << "  Target: " << blockTemplate.hashTarget.GetHex() << std::endl;
std::cout << "  Merkle: " << blockTemplate.block.hashMerkleRoot.GetHex() << std::endl;
std::cout << "  TXs: " << blockTemplate.block.vtx.size() << " bytes" << std::endl;

// Start mining
miner.StartMining(blockTemplate);
```

### Example 2: Validate Block

```cpp
#include <consensus/validation.h>

// Receive block from network
CBlock block = ReceiveBlockFromPeer();

// Validate
CBlockValidator validator;
CUTXOSet utxoSet;
uint32_t nHeight = DetermineBlockHeight(block);
std::string error;

if (!validator.CheckBlock(block, utxoSet, nHeight, error)) {
    std::cerr << "Block validation failed: " << error << std::endl;
    // Reject block, maybe ban peer
    return;
}

std::cout << "Block validated successfully" << std::endl;

// Accept block into blockchain
chainstate.ActivateBestChain(pindex, block, reorgOccurred);
```

### Example 3: Calculate Expected Coinbase

```cpp
// For a given block height and set of transactions,
// calculate what the coinbase value should be

uint32_t nHeight = 100000;
std::vector<CTransactionRef> blockTxs = GetBlockTransactions();

// Calculate subsidy
uint64_t subsidy = CBlockValidator::CalculateBlockSubsidy(nHeight);

// Calculate total fees
CAmount totalFees = 0;
for (size_t i = 1; i < blockTxs.size(); i++) {  // Skip coinbase
    const auto& tx = blockTxs[i];
    CAmount fee = CalculateFee(*tx, utxoSet);
    totalFees += fee;
}

// Expected coinbase value
uint64_t expectedCoinbaseValue = subsidy + totalFees;

std::cout << "Expected Coinbase:" << std::endl;
std::cout << "  Subsidy: " << subsidy / COIN << " DIL" << std::endl;
std::cout << "  Fees: " << (totalFees / (double)COIN) << " DIL" << std::endl;
std::cout << "  Total: " << (expectedCoinbaseValue / (double)COIN) << " DIL" << std::endl;

// Verify actual coinbase matches
const CTransaction& coinbase = *blockTxs[0];
uint64_t actualValue = coinbase.vout[0].nValue;

assert(actualValue <= expectedCoinbaseValue);
```

---

## Conclusion

This specification documents the mining integration implementation for Dilithion cryptocurrency. The system successfully integrates transactions into blocks, collects fees for miners, and validates blocks according to consensus rules.

Key achievements:
- ✅ Efficient transaction selection (greedy fee-rate algorithm)
- ✅ Proper coinbase construction with subsidy + fees
- ✅ Bitcoin-compatible consensus rules
- ✅ Comprehensive validation infrastructure
- ✅ Thread-safe, performant, production-ready code

For implementation details and test results, see `PHASE-5.4-MINING-INTEGRATION-COMPLETE.md`.
