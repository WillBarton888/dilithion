// Copyright (c) 2025 The Dilithion Core developers
#ifndef DILITHION_AMOUNT_H
#define DILITHION_AMOUNT_H

#include <cstdint>

typedef int64_t CAmount;

static const CAmount COIN = 100000000;
static const CAmount CENT = 1000000;

// Maximum money supply: 21 million DIL (same as Bitcoin)
// After 64 halvings (50 * 210000 blocks), subsidy reaches zero
static const CAmount MAX_MONEY = 21000000 * COIN;

// RPC-004 FIX / WALLET-005 FIX: Dust threshold (minimum economically spendable output)
// Outputs below this threshold are considered "dust" (economically unspendable)
// because the cost to spend them exceeds their value
// 50,000 ions = 0.0005 DIL = $0.005 at $10/DIL
static const CAmount DUST_THRESHOLD = 50000;  // 0.0005 DIL

// WALLET-009 FIX: Minimum transaction fee (minimum relay fee)
// Transactions with fees below this threshold will be rejected by the network
// This prevents spam attacks and ensures miners will relay the transaction
// 10,000 ions = 0.0001 DIL = $0.001 at $10/DIL
static const CAmount MIN_RELAY_FEE = 10000;  // 0.0001 DIL

// Inline validation function for monetary amounts
inline bool MoneyRange(CAmount nValue) {
    return (nValue >= 0 && nValue <= MAX_MONEY);
}

#endif
