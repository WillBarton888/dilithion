// Copyright (c) 2025 The Dilithion Core developers
#ifndef DILITHION_UTIL_STRENCODINGS_H
#define DILITHION_UTIL_STRENCODINGS_H

#include <string>
#include <vector>
#include <cstdarg>
#include <cstdio>
#include <cstdint>

inline std::string strprintf(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    return std::string(buffer);
}

/**
 * Hex String Encoding/Decoding Utilities (Task 2.1)
 *
 * Used for transaction serialization, RPC methods, and debugging.
 */

/**
 * Convert byte array to hexadecimal string
 */
std::string HexStr(const uint8_t* data, size_t len);

/**
 * Convert vector of bytes to hexadecimal string
 */
std::string HexStr(const std::vector<uint8_t>& vch);

/**
 * Parse hexadecimal string to byte array
 */
std::vector<uint8_t> ParseHex(const std::string& str);

/**
 * Check if string is valid hexadecimal
 */
bool IsHex(const std::string& str);

/**
 * Convert single hex character to its numeric value
 */
inline int8_t HexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

#endif
