// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/fees.h>
#include <util/strencodings.h>

namespace Consensus {

CAmount CalculateMinFee(size_t tx_size) {
    return MIN_TX_FEE + (tx_size * FEE_PER_BYTE);
}

bool CheckFee(const CTransaction& tx, CAmount fee_paid, bool check_relay, std::string* error) {
    size_t tx_size = tx.GetSerializedSize();
    CAmount min_fee = CalculateMinFee(tx_size);

    if (fee_paid < min_fee) {
        if (error) *error = strprintf("Fee too low: %d < %d", fee_paid, min_fee);
        return false;
    }

    if (check_relay && fee_paid < MIN_RELAY_TX_FEE) {
        if (error) *error = strprintf("Below relay min: %d", fee_paid);
        return false;
    }

    if (fee_paid > MAX_REASONABLE_FEE) {
        if (error) *error = strprintf("Fee too high: %d", fee_paid);
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
