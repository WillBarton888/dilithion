// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_FEES_H
#define DILITHION_CONSENSUS_FEES_H

#include <amount.h>
#include <primitives/transaction.h>
#include <cstddef>

namespace Consensus {

static const CAmount MIN_TX_FEE = 10000;
static const CAmount FEE_PER_BYTE = 10;
static const CAmount MIN_RELAY_TX_FEE = 50000;
static const CAmount MAX_REASONABLE_FEE = 10000000;

CAmount CalculateMinFee(size_t tx_size);
bool CheckFee(const CTransaction& tx, CAmount fee_paid, bool check_relay = true, std::string* error = nullptr);
double CalculateFeeRate(CAmount fee_paid, size_t tx_size);
size_t EstimateDilithiumTxSize(size_t num_inputs, size_t num_outputs, size_t extra_data_size = 0);

}

#endif
