// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/fees.h>
#include <sstream>

namespace Consensus {

CAmount CalculateMinFee(size_t tx_size) {
    return MIN_TX_FEE + (tx_size * FEE_PER_BYTE);
}

bool CheckFee(const CTransaction& tx, CAmount fee_paid, bool check_relay, std::string* error) {
    size_t tx_size = tx.GetSerializedSize();
    CAmount min_fee = CalculateMinFee(tx_size);

    if (fee_paid < min_fee) {
        // CID 1675205/1675247 FIX: Use std::ostringstream to completely eliminate printf format specifiers
        // This ensures type safety and portability across all platforms
        // IMPORTANT: This function does NOT use printf format specifiers. It uses std::ostringstream
        // with stream insertion operators (<<), which are type-safe and do not require format specifiers.
        if (error) {
            std::ostringstream oss;
            oss << "Fee too low: " << static_cast<long long>(fee_paid) 
                << " < " << static_cast<long long>(min_fee);
            *error = oss.str();
        }
        return false;
    }

    if (check_relay && fee_paid < MIN_RELAY_TX_FEE) {
        // CID 1675205/1675247 FIX: Use std::ostringstream to completely eliminate printf format specifiers
        if (error) {
            std::ostringstream oss;
            oss << "Below relay min: " << static_cast<long long>(fee_paid);
            *error = oss.str();
        }
        return false;
    }

    if (fee_paid > MAX_REASONABLE_FEE) {
        // CID 1675205/1675247 FIX: Use std::ostringstream to completely eliminate printf format specifiers
        if (error) {
            std::ostringstream oss;
            oss << "Fee too high: " << static_cast<long long>(fee_paid);
            *error = oss.str();
        }
        return false;
    }

    return true;
}

double CalculateFeeRate(CAmount fee_paid, size_t tx_size) {
    return tx_size == 0 ? 0.0 : (double)fee_paid / (double)tx_size;
}

static size_t VarIntSize(size_t value) {
    // CompactSize varint encoding: <253=1B, <=0xFFFF=3B, <=0xFFFFFFFF=5B, else 9B.
    // The wallet estimator must match this or fail its own post-sign fee check
    // (off by the varint delta × FEE_PER_BYTE when input/output count crosses a boundary).
    if (value < 253)          return 1;
    if (value <= 0xFFFF)      return 3;
    if (value <= 0xFFFFFFFF)  return 5;
    return 9;
}

size_t EstimateDilithiumTxSize(size_t num_inputs, size_t num_outputs, size_t extra_data_size) {
    // version(4) + in_count_varint + inputs + out_count_varint + outputs + locktime(4)
    // Per input:  prevout_txid(32) + prevout_n(4) + scriptSig_varint(3) + scriptSig(5265) + sequence(4) = 5308
    //   scriptSig = sig_len(2) + Dilithium3_sig(3309) + pk_len(2) + Dilithium3_pk(1952) = 5265
    // Per output: value(8) + scriptPubKey_varint(1) + P2PKH_scriptPubKey(25) = 34
    return 4
         + VarIntSize(num_inputs)  + (num_inputs * 5308)
         + VarIntSize(num_outputs) + (num_outputs * 34)
         + 4
         + extra_data_size;
}

}
