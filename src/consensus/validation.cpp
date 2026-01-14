// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/validation.h>
#include <consensus/tx_validation.h>
#include <consensus/pow.h>
#include <consensus/params.h>
#include <core/chainparams.h>
#include <crypto/sha3.h>
#include <amount.h>
#include <util/assert.h>
#include <set>
#include <algorithm>
#include <iostream>

uint64_t CBlockValidator::CalculateBlockSubsidy(uint32_t nHeight) {
    // Initial subsidy: 50 DIL = 50 * COIN = 50 * 100,000,000 ions
    uint64_t nSubsidy = 50 * COIN;

    // Halving interval: 210,000 blocks (same as Bitcoin)
    const uint32_t nHalvingInterval = 210000;

    // Number of halvings that have occurred
    uint32_t nHalvings = nHeight / nHalvingInterval;

    // Subsidy goes to zero after 64 halvings (very far in future)
    if (nHalvings >= 64) {
        return 0;
    }

    // Apply halving: subsidy >> halvings
    nSubsidy >>= nHalvings;

    return nSubsidy;
}

uint256 CBlockValidator::BuildMerkleRoot(const std::vector<CTransactionRef>& transactions) const {
    if (transactions.empty()) {
        return uint256();  // Null hash for empty block
    }

    // Build merkle tree from transaction hashes
    std::vector<uint256> merkleTree;
    merkleTree.reserve(transactions.size());

    // Level 0: transaction hashes
    for (const auto& tx : transactions) {
        merkleTree.push_back(tx->GetHash());
    }

    // Build tree levels until we reach root
    size_t levelOffset = 0;
    for (size_t levelSize = transactions.size(); levelSize > 1; levelSize = (levelSize + 1) / 2) {
        for (size_t i = 0; i < levelSize; i += 2) {
            size_t i2 = std::min(i + 1, levelSize - 1);

            // BUG #49 FIX: Removed incorrect CVE-2012-2459 check that was rejecting valid orphan blocks
            // The check was incorrectly triggering when two different transactions had the same hash,
            // which can happen legitimately. The proper place to check for duplicate transactions
            // is in CheckNoDuplicateTransactions(), not during merkle tree construction.

            // Concatenate two hashes
            std::vector<uint8_t> combined;
            combined.reserve(64);
            combined.insert(combined.end(),
                          merkleTree[levelOffset + i].begin(),
                          merkleTree[levelOffset + i].end());
            combined.insert(combined.end(),
                          merkleTree[levelOffset + i2].begin(),
                          merkleTree[levelOffset + i2].end());

            // Hash the combination (SHA3-256)
            uint256 hash;
            SHA3_256(combined.data(), combined.size(), hash.data);
            merkleTree.push_back(hash);
        }
        levelOffset += levelSize;
    }

    // Return root (last element in tree)
    return merkleTree.empty() ? uint256() : merkleTree.back();
}

bool CBlockValidator::DeserializeBlockTransactions(
    const CBlock& block,
    std::vector<CTransactionRef>& transactions,
    std::string& error
) const {
    transactions.clear();

    if (block.vtx.empty()) {
        error = "Block has no transaction data";
        return false;
    }

    const uint8_t* data = block.vtx.data();
    size_t offset = 0;
    size_t dataSize = block.vtx.size();

    // Read transaction count (compact size)
    if (offset >= dataSize) {
        error = "Incomplete transaction count";
        return false;
    }

    uint64_t txCount = 0;
    uint8_t firstByte = data[offset++];

    if (firstByte < 253) {
        txCount = firstByte;
    } else if (firstByte == 253) {
        if (offset + 2 > dataSize) {
            error = "Incomplete transaction count (253)";
            return false;
        }
        // CID 1675211 FIX: Cast to uint64_t before shifting to prevent sign extension
        // When shifting uint8_t values, they are promoted to int (signed), which can cause
        // sign extension if the high bit is set. Casting to uint64_t ensures unsigned behavior.
        txCount = static_cast<uint64_t>(data[offset]) | (static_cast<uint64_t>(data[offset + 1]) << 8);
        offset += 2;
    } else if (firstByte == 254) {
        if (offset + 4 > dataSize) {
            error = "Incomplete transaction count (254)";
            return false;
        }
        // CID 1675211 FIX: Cast to uint64_t before shifting to prevent sign extension
        // When shifting uint8_t values, they are promoted to int (signed), which can cause
        // sign extension if the high bit is set. Casting to uint64_t ensures unsigned behavior.
        txCount = static_cast<uint64_t>(data[offset]) |
                 (static_cast<uint64_t>(data[offset + 1]) << 8) |
                 (static_cast<uint64_t>(data[offset + 2]) << 16) |
                 (static_cast<uint64_t>(data[offset + 3]) << 24);
        offset += 4;
    } else {
        error = "Unsupported transaction count encoding (255)";
        return false;
    }

    if (txCount == 0) {
        error = "Block has zero transactions";
        return false;
    }

    // Sanity check: max 100k transactions per block
    if (txCount > 100000) {
        error = "Too many transactions in block";
        return false;
    }

    // Deserialize each transaction (CS-002)
    transactions.reserve(txCount);

    for (uint64_t i = 0; i < txCount; i++) {
        // Check if we have remaining data
        if (offset >= dataSize) {
            error = "Incomplete transaction data at index " + std::to_string(i);
            return false;
        }

        // Deserialize transaction from remaining bytes
        CTransaction tx;
        std::string deserializeError;
        size_t bytesConsumed = 0;

        if (!tx.Deserialize(data + offset, dataSize - offset, &deserializeError, &bytesConsumed)) {
            error = "Failed to deserialize transaction " + std::to_string(i) + ": " + deserializeError;
            return false;
        }

        // Advance offset by number of bytes consumed
        offset += bytesConsumed;

        // Add transaction to result vector
        transactions.push_back(MakeTransactionRef(std::move(tx)));
    }

    // Verify we consumed all data
    if (offset != dataSize) {
        error = "Extra data after last transaction (" + std::to_string(dataSize - offset) + " bytes remaining)";
        return false;
    }

    return true;
}

bool CBlockValidator::CheckBlockHeader(
    const CBlockHeader& block,
    uint32_t nBits,
    std::string& error
) const {
    // Check proof of work
    uint256 hash = block.GetHash();
    if (!CheckProofOfWork(hash, nBits)) {
        error = "Invalid proof of work";
        return false;
    }

    // Check block version (P1-1 FIX: Add upper bound to prevent consensus fork)
    // Version 1: Initial release
    // Version 2-4: Reserved for future protocol upgrades (soft/hard forks)
    static constexpr int32_t MAX_BLOCK_VERSION = 4;
    if (block.nVersion < 1 || block.nVersion > MAX_BLOCK_VERSION) {
        error = "Invalid block version (must be 1-" + std::to_string(MAX_BLOCK_VERSION) + ")";
        return false;
    }

    // Block time already validated by CheckBlockTimestamp in pow.cpp
    // Additional timestamp checks would go here

    return true;
}

bool CBlockValidator::CheckCoinbase(
    const CTransaction& coinbase,
    uint32_t nHeight,
    CAmount totalFees,
    std::string& error
) const {
    // Verify it's actually a coinbase transaction
    if (!coinbase.IsCoinBase()) {
        error = "Transaction is not a coinbase";
        return false;
    }

    // Coinbase must have exactly one input
    if (coinbase.vin.size() != 1) {
        error = "Coinbase must have exactly one input";
        return false;
    }

    // Coinbase input must have null prevout
    if (!coinbase.vin[0].prevout.IsNull()) {
        error = "Coinbase input must have null prevout";
        return false;
    }

    // Coinbase scriptSig must be 2-100 bytes
    if (coinbase.vin[0].scriptSig.size() < 2 || coinbase.vin[0].scriptSig.size() > 100) {
        error = "Coinbase scriptSig size invalid";
        return false;
    }

    // Coinbase must have at least one output
    if (coinbase.vout.empty()) {
        error = "Coinbase must have at least one output";
        return false;
    }

    // Calculate maximum allowed coinbase value
    uint64_t nMaxValue = CalculateBlockSubsidy(nHeight);

    // Check for overflow when adding fees
    if (totalFees > 0) {
        if (nMaxValue + totalFees < nMaxValue) {
            error = "Coinbase value calculation overflow";
            return false;
        }
        nMaxValue += totalFees;
    }

    // Calculate actual coinbase value
    uint64_t nCoinbaseValue = 0;
    for (const auto& output : coinbase.vout) {
        if (nCoinbaseValue + output.nValue < nCoinbaseValue) {
            error = "Coinbase output value overflow";
            return false;
        }
        nCoinbaseValue += output.nValue;
    }

    // Coinbase value must not exceed subsidy + fees
    if (nCoinbaseValue > nMaxValue) {
        error = "Coinbase value exceeds subsidy + fees";
        return false;
    }

    // =========================================================================
    // Mining Development Contribution Validation (2% of subsidy)
    // Every block must include outputs to Dev Fund and Dev Reward addresses
    // NOTE: Only enforced on MAINNET - testnet blocks don't require tax outputs
    // =========================================================================

    // Skip mining tax validation on testnet (allows existing testnet chain to continue)
    bool isTestnet = Dilithion::g_chainParams && Dilithion::g_chainParams->IsTestnet();
    if (isTestnet) {
        return true;  // Testnet: no mining tax required
    }

    uint64_t nSubsidy = CalculateBlockSubsidy(nHeight);
    uint64_t taxTotal = (nSubsidy * Consensus::MINING_TAX_PERCENT) / 100;
    uint64_t requiredDevFund = (taxTotal * Consensus::DEV_FUND_SHARE) / 100;
    uint64_t requiredDevReward = taxTotal - requiredDevFund;

    // Must have at least 3 outputs (miner + dev fund + dev reward)
    if (coinbase.vout.size() < 3) {
        error = "Coinbase must have at least 3 outputs for mining development contribution";
        return false;
    }

    // Helper to extract pubkey hash from P2PKH scriptPubKey
    auto extractPubKeyHash = [](const std::vector<uint8_t>& script) -> std::vector<uint8_t> {
        // P2PKH format: OP_DUP(0x76) OP_HASH160(0xa9) 0x14 <20 bytes> OP_EQUALVERIFY(0x88) OP_CHECKSIG(0xac)
        if (script.size() == 25 &&
            script[0] == 0x76 &&
            script[1] == 0xa9 &&
            script[2] == 0x14 &&
            script[23] == 0x88 &&
            script[24] == 0xac) {
            return std::vector<uint8_t>(script.begin() + 3, script.begin() + 23);
        }
        return {};
    };

    bool foundDevFund = false;
    bool foundDevReward = false;

    for (const auto& out : coinbase.vout) {
        std::vector<uint8_t> scriptHash = extractPubKeyHash(out.scriptPubKey);
        if (scriptHash.size() != 20) continue;

        // Check Dev Fund output
        if (std::equal(scriptHash.begin(), scriptHash.end(),
                       Consensus::DEV_FUND_PUBKEY_HASH)) {
            if (out.nValue < static_cast<CAmount>(requiredDevFund)) {
                error = "Dev Fund output insufficient: got " + std::to_string(out.nValue) +
                        ", required " + std::to_string(requiredDevFund);
                return false;
            }
            foundDevFund = true;
        }

        // Check Dev Reward output
        if (std::equal(scriptHash.begin(), scriptHash.end(),
                       Consensus::DEV_REWARD_PUBKEY_HASH)) {
            if (out.nValue < static_cast<CAmount>(requiredDevReward)) {
                error = "Dev Reward output insufficient: got " + std::to_string(out.nValue) +
                        ", required " + std::to_string(requiredDevReward);
                return false;
            }
            foundDevReward = true;
        }
    }

    if (!foundDevFund) {
        error = "Missing Dev Fund output in coinbase (address: DL7XM8Gd9fa4ta8jaPXoE9zGiKtM1SVnRC)";
        return false;
    }
    if (!foundDevReward) {
        error = "Missing Dev Reward output in coinbase (address: DLcWZkgvyJEC2rGM7KgzJH2KkjN7qfk7MR)";
        return false;
    }

    return true;
}

bool CBlockValidator::CheckNoDuplicateTransactions(
    const std::vector<CTransactionRef>& transactions,
    std::string& error
) const {
    std::set<uint256> seenTxIds;

    for (const auto& tx : transactions) {
        uint256 txid = tx->GetHash();

        if (seenTxIds.count(txid) > 0) {
            error = "Duplicate transaction in block: " + txid.GetHex();
            return false;
        }

        seenTxIds.insert(txid);
    }

    return true;
}

bool CBlockValidator::CheckNoDoubleSpends(
    const std::vector<CTransactionRef>& transactions,
    std::string& error
) const {
    std::set<COutPoint> spentOutputs;

    for (const auto& tx : transactions) {
        // Skip coinbase transaction (has null inputs)
        if (tx->IsCoinBase()) {
            continue;
        }

        for (const auto& input : tx->vin) {
            // Check if this output was already spent in this block
            if (spentOutputs.count(input.prevout) > 0) {
                error = "Double-spend detected within block";
                return false;
            }

            spentOutputs.insert(input.prevout);
        }
    }

    return true;
}

bool CBlockValidator::VerifyMerkleRoot(
    const CBlock& block,
    const std::vector<CTransactionRef>& transactions,
    std::string& error
) const {
    uint256 calculatedRoot = BuildMerkleRoot(transactions);

    // BUG #71 DEBUG: Log merkle root comparison
    if (!transactions.empty()) {
    }

    if (!(calculatedRoot == block.hashMerkleRoot)) {
        error = "Merkle root mismatch";
        return false;
    }

    return true;
}

bool CBlockValidator::CalculateTotalFees(
    const std::vector<CTransactionRef>& transactions,
    CUTXOSet& utxoSet,
    CAmount& totalFees,
    std::string& error
) const {
    totalFees = 0;

    // Skip coinbase transaction (index 0)
    for (size_t i = 1; i < transactions.size(); ++i) {
        const auto& tx = transactions[i];

        // Calculate input value
        uint64_t nInputValue = 0;
        for (const auto& input : tx->vin) {
            CUTXOEntry utxoEntry;
            if (!utxoSet.GetUTXO(input.prevout, utxoEntry)) {
                error = "Transaction input not found in UTXO set";
                return false;
            }

            if (nInputValue + utxoEntry.out.nValue < nInputValue) {
                error = "Input value overflow";
                return false;
            }
            nInputValue += utxoEntry.out.nValue;
        }

        // Calculate output value
        uint64_t nOutputValue = 0;
        for (const auto& output : tx->vout) {
            if (nOutputValue + output.nValue < nOutputValue) {
                error = "Output value overflow";
                return false;
            }
            nOutputValue += output.nValue;
        }

        // Fee = inputs - outputs
        if (nOutputValue > nInputValue) {
            error = "Transaction outputs exceed inputs (negative fee)";
            return false;
        }

        uint64_t txFee = nInputValue - nOutputValue;

        // Add to total fees
        if (totalFees + txFee < totalFees) {
            error = "Total fees overflow";
            return false;
        }
        totalFees += txFee;
    }

    return true;
}

bool CBlockValidator::CheckBlock(
    const CBlock& block,
    CUTXOSet& utxoSet,
    uint32_t nHeight,
    std::string& error
) const {
    // MEDIUM-C003 FIX: Reorder checks from cheapest to most expensive to prevent DoS
    // Check cheap conditions first before expensive PoW validation

    // P1-5 FIX: Block size limit - check serialized transaction data size
    // MAX_BLOCK_SIZE = 1MB (like Bitcoin's original limit)
    // Note: block.vtx is a vector<uint8_t> containing serialized transaction data
    static constexpr size_t MAX_BLOCK_SIZE = 1000000;  // 1 MB

    // Check serialized transaction data size
    if (block.vtx.size() > MAX_BLOCK_SIZE) {
        error = "Block transaction data exceeds maximum size (" + std::to_string(block.vtx.size()) + " > " + std::to_string(MAX_BLOCK_SIZE) + " bytes)";
        return false;
    }

    // Check 2: Block must not be empty
    if (block.vtx.empty()) {
        error = "Block has no transactions";
        return false;
    }

    // Check 3: Block header validation (MOST EXPENSIVE - do last after cheap checks pass)
    if (!CheckBlockHeader(block, block.nBits, error)) {
        return false;
    }

    // ============================================================================
    // CS-003: Complete Block Validation - IMPLEMENTATION
    // ============================================================================

    // Step 1: Deserialize all transactions (CS-002)
    std::vector<CTransactionRef> transactions;
    if (!DeserializeBlockTransactions(block, transactions, error)) {
        return false;
    }

    // Sanity check
    if (transactions.empty()) {
        error = "Block has no transactions after deserialization";
        return false;
    }

    // Step 2: Validate coinbase transaction
    // First transaction must be coinbase
    if (!transactions[0]->IsCoinBase()) {
        error = "First transaction is not coinbase";
        return false;
    }
    // Consensus invariant: First transaction must always be coinbase
    ConsensusInvariant(transactions[0]->IsCoinBase());

    // Only first transaction can be coinbase
    for (size_t i = 1; i < transactions.size(); i++) {
        if (transactions[i]->IsCoinBase()) {
            error = "Multiple coinbase transactions in block";
            return false;
        }
    }

    // Step 3: Check for duplicate transaction hashes
    std::set<uint256> txHashes;
    for (const auto& tx : transactions) {
        uint256 txHash = tx->GetHash();
        if (txHashes.count(txHash) > 0) {
            error = "Duplicate transaction in block";
            return false;
        }
        txHashes.insert(txHash);
    }

    // Step 4: Check for double-spends within block
    std::set<COutPoint> spentOutputs;
    for (size_t i = 1; i < transactions.size(); i++) {  // Skip coinbase
        const CTransaction& tx = *transactions[i];
        for (const CTxIn& txin : tx.vin) {
            if (spentOutputs.count(txin.prevout) > 0) {
                error = "Double-spend detected within block";
                return false;
            }
            spentOutputs.insert(txin.prevout);
        }
    }

    // Step 5: Verify merkle root
    uint256 calculatedMerkleRoot = BuildMerkleRoot(transactions);
    if (!(calculatedMerkleRoot == block.hashMerkleRoot)) {
        error = "Merkle root mismatch";
        return false;
    }

    // Step 6: Validate each transaction
    CTransactionValidator txValidator;

    // Validate coinbase basic structure
    std::string txError;
    if (!txValidator.CheckTransactionBasic(*transactions[0], txError)) {
        error = "Invalid coinbase transaction: " + txError;
        return false;
    }

    // Calculate total fees from non-coinbase transactions
    uint64_t totalFees = 0;
    for (size_t i = 1; i < transactions.size(); i++) {
        const CTransaction& tx = *transactions[i];

        // Basic structure validation
        if (!txValidator.CheckTransactionBasic(tx, txError)) {
            error = "Invalid transaction at index " + std::to_string(i) + ": " + txError;
            return false;
        }

        // Input validation (requires UTXO set)
        CAmount txFee = 0;
        if (!txValidator.CheckTransactionInputs(tx, utxoSet, nHeight, txFee, txError)) {
            error = "Transaction validation failed at index " + std::to_string(i) + ": " + txError;
            return false;
        }

        // Accumulate fees
        if (txFee < 0) {
            error = "Negative fee in transaction at index " + std::to_string(i);
            return false;
        }

        // Check for fee overflow
        if (totalFees + static_cast<uint64_t>(txFee) < totalFees) {
            error = "Total fees overflow";
            return false;
        }
        totalFees += static_cast<uint64_t>(txFee);
    }

    // Step 7: Validate coinbase value (subsidy + fees)
    uint64_t blockSubsidy = CalculateBlockSubsidy(nHeight);
    uint64_t maxCoinbaseValue = blockSubsidy + totalFees;

    // TX-002 FIX: Wrap GetValueOut() in try-catch to handle overflow exceptions
    uint64_t coinbaseValue;
    try {
        coinbaseValue = transactions[0]->GetValueOut();
    } catch (const std::runtime_error& e) {
        error = "Coinbase transaction output value overflow: ";
        error += e.what();
        return false;
    }

    if (coinbaseValue > maxCoinbaseValue) {
        error = "Coinbase value exceeds subsidy + fees (" +
                std::to_string(coinbaseValue) + " > " +
                std::to_string(maxCoinbaseValue) + ")";
        return false;
    }

    // All checks passed
    return true;
}
