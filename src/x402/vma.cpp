// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <x402/vma.h>
#include <primitives/transaction.h>
#include <node/utxo_set.h>
#include <node/mempool.h>
#include <consensus/chain.h>
#include <consensus/tx_validation.h>
#include <wallet/wallet.h>
#include <util/strencodings.h>

#include <iostream>
#include <sstream>
#include <chrono>

namespace x402 {

CVerifiedMempoolAcceptance::CVerifiedMempoolAcceptance()
    : m_utxo_set(nullptr)
    , m_mempool(nullptr)
    , m_chainstate(nullptr)
    , m_micropayment_threshold(MICROPAYMENT_THRESHOLD)
{
}

bool CVerifiedMempoolAcceptance::IsMicropayment(int64_t amount) const {
    return amount < m_micropayment_threshold;
}

bool CVerifiedMempoolAcceptance::VerifyPayment(const std::string& rawTxHex,
                                                const std::string& recipient,
                                                int64_t amount,
                                                VerifyResult& result) {
    result.valid = false;
    result.amount = 0;

    // Check components are available
    if (!m_utxo_set || !m_mempool || !m_chainstate) {
        result.reason = "Node not fully initialized";
        return true;
    }

    // Step 1: Decode hex to raw bytes
    std::vector<uint8_t> tx_data = ParseHex(rawTxHex);
    if (tx_data.empty()) {
        result.reason = "Invalid hex encoding";
        return true;
    }

    // Step 2: Deserialize transaction
    CTransaction tx;
    std::string deserialize_error;
    if (!tx.Deserialize(tx_data.data(), tx_data.size(), &deserialize_error)) {
        result.reason = "Failed to deserialize transaction: " + deserialize_error;
        return true;
    }

    // Step 3: Basic structural validation (non-empty, valid amounts, etc.)
    CTransactionValidator validator;
    std::string validation_error;
    if (!validator.CheckTransactionBasic(tx, validation_error)) {
        result.reason = "Transaction structure invalid: " + validation_error;
        return true;
    }

    // Step 4: Validate inputs exist in UTXO set + verify Dilithium signatures
    CAmount tx_fee = 0;
    unsigned int current_height = m_chainstate->GetHeight();
    if (!validator.CheckTransaction(tx, *m_utxo_set, current_height, tx_fee, validation_error)) {
        result.reason = "Transaction validation failed: " + validation_error;
        return true;
    }

    // Step 5: Verify payment pays correct amount to correct recipient
    std::string payment_error;
    if (!VerifyPaymentOutput(tx, recipient, amount, payment_error)) {
        result.reason = payment_error;
        return true;
    }

    // Step 6: Check for double-spend conflicts in mempool
    std::string conflict_error;
    if (!CheckMempoolConflicts(tx, conflict_error)) {
        result.reason = "Double-spend detected: " + conflict_error;
        return true;
    }

    // All checks passed
    result.valid = true;
    result.amount = amount;

    // Extract payer address from first input
    if (!tx.vin.empty()) {
        // Look up the UTXO being spent to find the payer's scriptPubKey
        CUTXOEntry entry;
        if (m_utxo_set->GetUTXO(tx.vin[0].prevout, entry)) {
            auto pubkeyHash = WalletCrypto::ExtractPubKeyHash(entry.out.scriptPubKey);
            if (!pubkeyHash.empty()) {
                // Reconstruct address from pubkey hash
                std::vector<uint8_t> addrBytes;
                addrBytes.push_back(0x1E);  // DilV mainnet version byte
                addrBytes.insert(addrBytes.end(), pubkeyHash.begin(), pubkeyHash.end());
                CDilithiumAddress payerAddr = CDilithiumAddress::FromData(addrBytes);
                result.payerAddress = payerAddr.ToString();
            }
        }
    }

    return true;
}

bool CVerifiedMempoolAcceptance::SettlePayment(const std::string& rawTxHex,
                                                const std::string& recipient,
                                                int64_t amount,
                                                SettlementResult& result) {
    result.success = false;
    result.network = NETWORK_ID;
    result.confirmations = 0;

    // First, verify the payment
    VerifyResult verifyResult;
    if (!VerifyPayment(rawTxHex, recipient, amount, verifyResult)) {
        result.error = "Verification failed";
        return true;
    }

    if (!verifyResult.valid) {
        result.error = verifyResult.reason;
        return true;
    }

    // Deserialize again for mempool submission
    std::vector<uint8_t> tx_data = ParseHex(rawTxHex);
    CTransaction tx;
    std::string deserialize_error;
    if (!tx.Deserialize(tx_data.data(), tx_data.size(), &deserialize_error)) {
        result.error = "Deserialization failed: " + deserialize_error;
        return true;
    }

    // Add to mempool
    CTransactionRef txRef = MakeTransactionRef(tx);
    result.txHash = txRef->GetHash().GetHex();
    result.payerAddress = verifyResult.payerAddress;

    // Check if already in mempool (idempotent settlement)
    if (m_mempool->Exists(txRef->GetHash())) {
        result.success = true;
        result.confirmations = 0;
        return true;
    }

    // Calculate fee for mempool entry
    CTransactionValidator validator;
    CAmount tx_fee = 0;
    std::string fee_error;
    unsigned int current_height = m_chainstate->GetHeight();
    validator.CheckTransactionInputs(tx, *m_utxo_set, current_height, tx_fee, fee_error);

    int64_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    std::string mempool_error;
    if (!m_mempool->AddTx(txRef, tx_fee, current_time, current_height, &mempool_error)) {
        result.error = "Mempool rejection: " + mempool_error;
        return true;
    }

    result.success = true;
    result.confirmations = 0;
    return true;
}

int CVerifiedMempoolAcceptance::GetConfirmations(const std::string& txHash) {
    if (!m_chainstate || !m_mempool || !m_utxo_set) {
        return -1;
    }

    uint256 hash;
    hash.SetHex(txHash);

    // Check mempool first
    if (m_mempool->Exists(hash)) {
        return 0;  // In mempool, unconfirmed
    }

    // Check if any output from this transaction exists in the UTXO set.
    // If it does, the transaction is confirmed — get height from UTXO entry.
    unsigned int tipHeight = m_chainstate->GetHeight();

    // Try outputs 0-9 (most transactions have fewer than 10 outputs)
    for (uint32_t n = 0; n < 10; n++) {
        COutPoint outpoint(hash, n);
        CUTXOEntry entry;
        if (m_utxo_set->GetUTXO(outpoint, entry)) {
            // Found a UTXO from this tx — confirmations = tip - creation height + 1
            return static_cast<int>(tipHeight - entry.nHeight + 1);
        }
    }

    return -1;  // Not found
}

bool CVerifiedMempoolAcceptance::VerifyPaymentOutput(const CTransaction& tx,
                                                      const std::string& recipient,
                                                      int64_t amount,
                                                      std::string& error) {
    // Parse recipient address
    CDilithiumAddress recipientAddr;
    if (!recipientAddr.SetString(recipient)) {
        error = "Invalid recipient address: " + recipient;
        return false;
    }

    // Get the pubkey hash from the recipient address
    const std::vector<uint8_t>& addrData = recipientAddr.GetData();
    if (addrData.size() < 21) {
        error = "Recipient address data too short";
        return false;
    }

    // Extract the 32-byte hash from the address (skip version byte)
    std::vector<uint8_t> recipientHash(addrData.begin() + 1, addrData.end());

    // Check that at least one output pays the required amount to the recipient
    int64_t totalToRecipient = 0;
    for (const auto& vout : tx.vout) {
        // Extract pubkey hash from this output's scriptPubKey
        auto outputHash = WalletCrypto::ExtractPubKeyHash(vout.scriptPubKey);
        if (outputHash.empty()) continue;

        // Compare with recipient's pubkey hash
        if (outputHash == recipientHash) {
            totalToRecipient += vout.nValue;
        }
    }

    if (totalToRecipient < amount) {
        std::ostringstream oss;
        oss << "Insufficient payment: expected " << amount
            << " ions to " << recipient
            << ", found " << totalToRecipient << " ions";
        error = oss.str();
        return false;
    }

    return true;
}

bool CVerifiedMempoolAcceptance::CheckMempoolConflicts(const CTransaction& tx,
                                                        std::string& error) {
    if (!m_mempool) {
        return true;  // No mempool = no conflicts
    }

    // Check each input against mempool's spent outpoints
    for (const auto& vin : tx.vin) {
        // Check if this outpoint is already spent by another mempool transaction
        // Use the mempool's mapSpentOutpoints for O(1) lookup
        if (m_mempool->IsSpent(vin.prevout)) {
            std::ostringstream oss;
            oss << "Input " << vin.prevout.hash.GetHex() << ":" << vin.prevout.n
                << " already spent by mempool transaction";
            error = oss.str();
            return false;
        }
    }

    return true;
}

} // namespace x402
