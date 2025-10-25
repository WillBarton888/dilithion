// Copyright (c) 2025 The Dilithion Core developers
#ifndef DILITHION_UTIL_TIME_H
#define DILITHION_UTIL_TIME_H

#include <cstdint>
#include <ctime>

inline int64_t GetTime() {
    return static_cast<int64_t>(time(nullptr));
}

#endif
