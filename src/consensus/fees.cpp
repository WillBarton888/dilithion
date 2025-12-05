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

size_t EstimateDilithiumTxSize(size_t num_inputs, size_t num_outputs, size_t extra_data_size) {
    return 42 + (num_inputs * 3782) + (num_outputs * 40) + extra_data_size;
}

}
