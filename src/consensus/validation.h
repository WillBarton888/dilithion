// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_VALIDATION_H
#define DILITHION_CONSENSUS_VALIDATION_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <node/utxo_set.h>
#include <amount.h>
#include <string>
#include <vector>

/**
 * CBlockValidator
 *
 * Comprehensive block-level validation for Dilithion blockchain.
 * Validates entire blocks including all transactions, coinbase rules,
 * and consensus requirements.
 *
 * Thread Safety: Not thread-safe. Caller must ensure thread safety when
 * accessing shared UTXO set.
 */
class CBlockValidator
{
public:
    CBlockValidator() = default;
    ~CBlockValidator() = default;

    /**
     * CheckBlock - Complete block validation
     *
     * Performs all consensus validation checks on a block:
     * 1. Block structure (has coinbase, etc.)
     * 2. All transactions are valid
     * 3. Coinbase amount <= subsidy + fees
     * 4. No duplicate transactions
     * 5. No double-spends within block
     * 6. Merkle root is correct
     * 7. Block size limits
     *
     * @param block The block to validate
     * @param utxoSet UTXO set for validating transaction inputs
     * @param nHeight Block height (for coinbase subsidy calculation)
     * @param error Reference to store error message if validation fails
     * @return true if valid, false otherwise
     */
    bool CheckBlock(const CBlock& block, CUTXOSet& utxoSet,
                    uint32_t nHeight, std::string& error) const;

    /**
     * CheckBlockHeader - Validate block header only
     *
     * Checks:
     * - Valid proof of work
     * - Timestamp within acceptable range
     * - Version is supported
     *
     * @param block Block header to validate
     * @param nBits Expected difficulty target
     * @param error Reference to store error message
     * @return true if valid
     */
    bool CheckBlockHeader(const CBlockHeader& block, uint32_t nBits,
                          std::string& error) const;

    /**
     * CheckCoinbase - Validate coinbase transaction
     *
     * Checks:
     * - Transaction is actually a coinbase
     * - Coinbase value <= subsidy + fees
     * - Scriptsi size is valid (2-100 bytes)
     * - Single input with null prevout
     *
     * @param coinbase The coinbase transaction
     * @param nHeight Block height (for subsidy calculation)
     * @param totalFees Total fees from all non-coinbase transactions
     * @param error Reference to store error message
     * @return true if valid
     */
    bool CheckCoinbase(const CTransaction& coinbase, uint32_t nHeight,
                       CAmount totalFees, std::string& error) const;

    /**
     * CalculateBlockSubsidy - Get block mining subsidy
     *
     * Implements halving schedule: 50 DIL initial, halving every 210,000 blocks
     *
     * @param nHeight Block height
     * @return Subsidy amount in ions (satoshis)
     */
    static uint64_t CalculateBlockSubsidy(uint32_t nHeight);

    /**
     * CheckNoDuplicateTransactions - Verify no duplicate TXs in block
     *
     * @param transactions Vector of all transactions in block
     * @param error Reference to store error message
     * @return true if no duplicates found
     */
    bool CheckNoDuplicateTransactions(const std::vector<CTransactionRef>& transactions,
                                      std::string& error) const;

    /**
     * CheckNoDoubleSpends - Verify no input spent twice within block
     *
     * @param transactions Vector of all transactions in block
     * @param error Reference to store error message
     * @return true if no double-spends found
     */
    bool CheckNoDoubleSpends(const std::vector<CTransactionRef>& transactions,
                             std::string& error) const;

    /**
     * VerifyMerkleRoot - Verify merkle root matches transactions
     *
     * @param block Block with merkle root to verify
     * @param transactions Vector of all transactions
     * @param error Reference to store error message
     * @return true if merkle root is correct
     */
    bool VerifyMerkleRoot(const CBlock& block,
                          const std::vector<CTransactionRef>& transactions,
                          std::string& error) const;

    /**
     * DeserializeBlockTransactions - Extract transactions from block.vtx
     *
     * Parses the serialized transaction data in CBlock.vtx and returns
     * a vector of CTransactionRef objects.
     *
     * @param block Block to deserialize transactions from
     * @param transactions Output vector to store deserialized transactions
     * @param error Reference to store error message
     * @return true if deserialization successful
     */
    bool DeserializeBlockTransactions(const CBlock& block,
                                       std::vector<CTransactionRef>& transactions,
                                       std::string& error) const;

    /**
     * BuildMerkleRoot - Calculate merkle root from transactions
     *
     * Made public for comprehensive unit testing of this critical consensus function.
     *
     * @param transactions Vector of all transactions (coinbase first)
     * @return Merkle root hash
     */
    uint256 BuildMerkleRoot(const std::vector<CTransactionRef>& transactions) const;

private:

    /**
     * CalculateTotalFees - Calculate total fees from all non-coinbase TXs
     *
     * @param transactions All transactions (including coinbase)
     * @param utxoSet UTXO set for looking up input values
     * @param totalFees Output parameter for calculated fees
     * @param error Reference to store error message
     * @return true if calculation successful
     */
    bool CalculateTotalFees(const std::vector<CTransactionRef>& transactions,
                            CUTXOSet& utxoSet, CAmount& totalFees,
                            std::string& error) const;
};

#endif // DILITHION_CONSENSUS_VALIDATION_H
