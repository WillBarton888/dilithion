// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_X402_VMA_H
#define DILITHION_X402_VMA_H

#include <x402/x402_types.h>
#include <string>
#include <cstdint>

// Forward declarations
class CTransaction;
class CUTXOSet;
class CTxMemPool;
class CChainState;

namespace x402 {

/**
 * Verified Mempool Acceptance (VMA)
 *
 * Tiered payment verification for x402:
 * - Micropayments (< threshold): 0-conf — valid if tx passes mempool acceptance
 * - Standard payments (>= threshold): 1-conf — valid after first block confirmation
 *
 * The VMA runs on a full DilV node with real-time UTXO data.
 * No trusted third-party indexer is required.
 *
 * Verification steps:
 * 1. Deserialize and validate transaction structure
 * 2. Verify Dilithium signatures on all inputs
 * 3. Confirm all input UTXOs exist and are unspent
 * 4. Check no conflicting transaction in mempool (double-spend detection)
 * 5. Verify output pays correct amount to correct recipient
 * 6. For standard payments: check block confirmation count
 */
class CVerifiedMempoolAcceptance {
public:
    CVerifiedMempoolAcceptance();
    ~CVerifiedMempoolAcceptance() = default;

    // Register node components
    void RegisterUTXOSet(CUTXOSet* utxo_set) { m_utxo_set = utxo_set; }
    void RegisterMempool(CTxMemPool* mempool) { m_mempool = mempool; }
    void RegisterChainState(CChainState* chainstate) { m_chainstate = chainstate; }

    /**
     * Verify a payment without broadcasting
     *
     * Checks that the transaction is valid, properly signed, and pays
     * the correct amount to the specified recipient. Does NOT add to mempool.
     *
     * @param rawTxHex     Hex-encoded signed transaction
     * @param recipient    Expected recipient address
     * @param amount       Expected payment amount (ions)
     * @param result       Output: verification result
     * @return true if verification completed (check result.valid for payment validity)
     */
    bool VerifyPayment(const std::string& rawTxHex,
                       const std::string& recipient,
                       int64_t amount,
                       VerifyResult& result);

    /**
     * Settle a payment (verify + broadcast)
     *
     * Verifies the transaction, adds it to mempool, and broadcasts to peers.
     *
     * @param rawTxHex     Hex-encoded signed transaction
     * @param recipient    Expected recipient address
     * @param amount       Expected payment amount (ions)
     * @param result       Output: settlement result
     * @return true if settlement completed (check result.success)
     */
    bool SettlePayment(const std::string& rawTxHex,
                       const std::string& recipient,
                       int64_t amount,
                       SettlementResult& result);

    /**
     * Check confirmation status of a previously settled payment
     *
     * @param txHash       Transaction hash to check
     * @return Number of confirmations (0 = mempool only, -1 = not found)
     */
    int GetConfirmations(const std::string& txHash);

    /**
     * Determine acceptance tier for a payment amount
     *
     * @param amount  Payment amount in ions
     * @return true if amount qualifies for 0-conf (micropayment tier)
     */
    bool IsMicropayment(int64_t amount) const;

    // Configuration
    void SetMicropaymentThreshold(int64_t threshold) { m_micropayment_threshold = threshold; }
    int64_t GetMicropaymentThreshold() const { return m_micropayment_threshold; }

private:
    CUTXOSet* m_utxo_set;
    CTxMemPool* m_mempool;
    CChainState* m_chainstate;
    int64_t m_micropayment_threshold;

    /**
     * Verify a transaction pays the expected amount to the expected recipient
     *
     * @param tx          Deserialized transaction
     * @param recipient   Expected recipient address
     * @param amount      Expected amount (ions)
     * @param error       Output: error description
     * @return true if payment matches expectations
     */
    bool VerifyPaymentOutput(const CTransaction& tx,
                             const std::string& recipient,
                             int64_t amount,
                             std::string& error);

    /**
     * Check if any input has a conflicting transaction in mempool
     *
     * @param tx     Transaction to check
     * @param error  Output: conflicting txid if found
     * @return true if no conflicts (safe)
     */
    bool CheckMempoolConflicts(const CTransaction& tx, std::string& error);
};

} // namespace x402

#endif // DILITHION_X402_VMA_H
