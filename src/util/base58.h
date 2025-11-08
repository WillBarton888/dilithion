// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_BASE58_H
#define DILITHION_UTIL_BASE58_H

#include <string>
#include <vector>
#include <cstdint>

// Base58 encoding/decoding functions
// Used for human-readable address encoding with checksum protection

/**
 * Encode data to Base58Check format (with double SHA3-256 checksum)
 * @param data The data to encode
 * @return Base58Check-encoded string
 */
std::string EncodeBase58Check(const std::vector<uint8_t>& data);

/**
 * Decode Base58Check format (with checksum verification)
 * @param str The Base58Check string to decode
 * @param data Output vector for decoded data (without checksum)
 * @return true if decoding and checksum verification succeeded, false otherwise
 */
bool DecodeBase58Check(const std::string& str, std::vector<uint8_t>& data);

/**
 * Encode data to Base58 format (without checksum)
 * @param data The data to encode
 * @return Base58-encoded string
 */
std::string EncodeBase58(const std::vector<uint8_t>& data);

/**
 * Decode Base58 format (without checksum verification)
 * @param str The Base58 string to decode
 * @param data Output vector for decoded data
 * @return true if decoding succeeded, false otherwise
 */
bool DecodeBase58(const std::string& str, std::vector<uint8_t>& data);

#endif // DILITHION_UTIL_BASE58_H
