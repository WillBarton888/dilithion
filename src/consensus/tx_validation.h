// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_TX_VALIDATION_H
#define DILITHION_CONSENSUS_TX_VALIDATION_H

#include <primitives/transaction.h>
#include <node/utxo_set.h>
#include <amount.h>
#include <string>
#include <set>

/**
 * Transaction validation constants
 */
namespace TxValidation {
    /** Maximum transaction size (1 MB) */
    static const size_t MAX_TRANSACTION_SIZE = 1000000;

    /** Maximum total money supply (21 million coins) */
    static const CAmount MAX_MONEY = 21000000LL * COIN;

    /** Minimum transaction fee (0.00001 DIL = 1000 ions) */
    static const CAmount MIN_TX_FEE = 1000;

    /** Coinbase maturity requirement (must wait 100 blocks) */
    static const uint32_t COINBASE_MATURITY = 100;

    /** Maximum number of signature operations per transaction */
    static const size_t MAX_TX_SIGOPS = 20000;
}

/**
 * CTransactionValidator
 *
 * Comprehensive transaction validation system for Dilithion cryptocurrency.
 * Validates individual transactions against consensus rules, UTXO set, and
 * cryptographic requirements.
 *
 * Thread Safety: Not thread-safe. Caller must ensure thread safety when
 * accessing shared UTXO set.
 */
class CTransactionValidator
{
public:
    CTransactionValidator() = default;
    ~CTransactionValidator() = default;

    /**
     * CheckTransactionBasic
     *
     * Performs basic structural validation of a transaction without
     * accessing the UTXO set. This is the first validation step.
     *
     * Checks:
     * - Non-empty inputs and outputs
     * - Positive output values
     * - No value overflow
     * - Reasonable transaction size
     * - No duplicate inputs
     * - Coinbase-specific rules
     *
     * @param tx The transaction to validate
     * @param error Reference to store error message if validation fails
     * @return true if valid, false otherwise
     */
    bool CheckTransactionBasic(const CTransaction& tx, std::string& error) const;

    /**
     * CheckTransactionInputs
     *
     * Validates transaction inputs against the UTXO set.
     * Verifies all inputs exist, are spendable, and calculates the fee.
     *
     * Checks:
     * - All inputs exist in UTXO set
     * - Coinbase maturity (100 blocks)
     * - Input values are valid
     * - Fee calculation (inputs - outputs)
     * - Non-negative fee
     *
     * @param tx The transaction to validate
     * @param utxoSet UTXO set to check inputs against
     * @param currentHeight Current blockchain height
     * @param txFee Output parameter to store calculated fee
     * @param error Reference to store error message if validation fails
     * @return true if valid, false otherwise
     */
    bool CheckTransactionInputs(const CTransaction& tx, CUTXOSet& utxoSet,
                                 uint32_t currentHeight, CAmount& txFee,
                                 std::string& error) const;

    /**
     * VerifyScript
     *
     * Validates transaction scripts with full Dilithium signature verification.
     *
     * Performs complete cryptographic validation:
     * - Parse signature and public key from scriptSig
     * - Extract public key hash from scriptPubKey
     * - Verify public key hashes to expected value
     * - Verify Dilithium3 signature over transaction
     *
     * @param tx The transaction being validated (for signature message)
     * @param inputIdx Index of the input being verified
     * @param scriptSig The signature script (unlocking script)
     * @param scriptPubKey The public key script (locking script)
     * @param error Reference to store error message if validation fails
     * @return true if valid, false otherwise
     */
    bool VerifyScript(const CTransaction& tx,
                      size_t inputIdx,
                      const std::vector<uint8_t>& scriptSig,
                      const std::vector<uint8_t>& scriptPubKey,
                      std::string& error) const;

    /**
     * CheckTransaction
     *
     * Complete transaction validation - combines all validation steps.
     * This is the main entry point for transaction validation.
     *
     * Performs:
     * 1. Basic structural validation
     * 2. Input validation against UTXO set
     * 3. Script verification for all inputs
     * 4. Fee calculation
     *
     * @param tx The transaction to validate
     * @param utxoSet UTXO set to check inputs against
     * @param currentHeight Current blockchain height
     * @param txFee Output parameter to store calculated fee
     * @param error Reference to store error message if validation fails
     * @return true if valid, false otherwise
     */
    bool CheckTransaction(const CTransaction& tx, CUTXOSet& utxoSet,
                          uint32_t currentHeight, CAmount& txFee,
                          std::string& error) const;

    /**
     * IsStandardTransaction
     *
     * Check if transaction follows standard rules for relay and mempool.
     * Standard transactions are more restrictive than consensus rules.
     *
     * Checks:
     * - Transaction version is supported
     * - Output values meet dust threshold
     * - Scripts are standard types
     * - Transaction size is reasonable
     *
     * @param tx The transaction to check
     * @return true if transaction is standard
     */
    bool IsStandardTransaction(const CTransaction& tx) const;

    /**
     * GetTransactionWeight
     *
     * Calculate transaction weight for fee calculation.
     * Currently uses serialized size, but can be extended for witness data.
     *
     * @param tx The transaction
     * @return Transaction weight in weight units
     */
    size_t GetTransactionWeight(const CTransaction& tx) const;

    /**
     * GetMinimumFee
     *
     * Calculate minimum required fee for a transaction based on size.
     *
     * @param tx The transaction
     * @return Minimum fee in ions
     */
    CAmount GetMinimumFee(const CTransaction& tx) const;

    /**
     * CheckDoubleSpend
     *
     * Verify transaction does not double-spend any outputs.
     * Checks both within the transaction itself and against the UTXO set.
     *
     * @param tx The transaction to check
     * @param utxoSet UTXO set to check against
     * @return true if no double-spend detected
     */
    bool CheckDoubleSpend(const CTransaction& tx, CUTXOSet& utxoSet) const;

private:
    /**
     * MoneyRange
     *
     * Check if an amount is within valid monetary range.
     *
     * @param nValue Amount to check
     * @return true if valid
     */
    bool MoneyRange(CAmount nValue) const {
        return (nValue >= 0 && nValue <= TxValidation::MAX_MONEY);
    }

    /**
     * CheckDuplicateInputs
     *
     * Verify transaction does not spend the same output twice.
     *
     * @param tx The transaction to check
     * @return true if no duplicates found
     */
    bool CheckDuplicateInputs(const CTransaction& tx) const;

    /**
     * CalculateTotalInputValue
     *
     * Calculate the total value of all transaction inputs.
     *
     * @param tx The transaction
     * @param utxoSet UTXO set to lookup input values
     * @param totalIn Output parameter for total input value
     * @param error Reference to store error message if lookup fails
     * @return true if successful
     */
    bool CalculateTotalInputValue(const CTransaction& tx, CUTXOSet& utxoSet,
                                   CAmount& totalIn, std::string& error) const;

    /**
     * CheckCoinbaseMaturity
     *
     * Verify coinbase inputs have sufficient confirmations.
     *
     * @param tx The transaction
     * @param utxoSet UTXO set to check coinbase status
     * @param currentHeight Current blockchain height
     * @param error Reference to store error message if immature
     * @return true if all coinbase inputs are mature
     */
    bool CheckCoinbaseMaturity(const CTransaction& tx, CUTXOSet& utxoSet,
                               uint32_t currentHeight, std::string& error) const;
};

#endif // DILITHION_CONSENSUS_TX_VALIDATION_H
