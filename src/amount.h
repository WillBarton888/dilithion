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

// Inline validation function for monetary amounts
inline bool MoneyRange(CAmount nValue) {
    return (nValue >= 0 && nValue <= MAX_MONEY);
}

#endif
