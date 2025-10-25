// Copyright (c) 2025 The Dilithion Core developers
#ifndef DILITHION_UTIL_STRENCODINGS_H
#define DILITHION_UTIL_STRENCODINGS_H

#include <string>
#include <cstdarg>
#include <cstdio>

inline std::string strprintf(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    return std::string(buffer);
}

#endif
