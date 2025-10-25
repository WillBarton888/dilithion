// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/serialize.h>
#include <cstring>

// Simple checksum calculation (double SHA256 in production)
// For now, use a simple hash for prototyping
uint32_t CDataStream::CalculateChecksum(const std::vector<uint8_t>& data) {
    uint32_t checksum = 0;

    // Simple hash: combine all bytes with mixing
    for (size_t i = 0; i < data.size(); i++) {
        checksum ^= (data[i] << ((i % 4) * 8));
        checksum = (checksum << 7) | (checksum >> 25);  // Rotate
    }

    // XOR with size for additional entropy
    checksum ^= static_cast<uint32_t>(data.size());

    return checksum;
}
