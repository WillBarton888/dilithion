// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_TEST_FUZZ_UTIL_H
#define DILITHION_TEST_FUZZ_UTIL_H

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

/**
 * Fuzz Testing Utilities
 *
 * Helper functions for consuming and manipulating fuzz input data.
 * Based on patterns from Bitcoin Core and libFuzzer best practices.
 */

/**
 * FuzzedDataProvider - Consume fuzz input in structured ways
 *
 * Provides methods to extract different types of data from the
 * fuzzer-provided buffer in a deterministic manner.
 */
class FuzzedDataProvider {
private:
    const uint8_t* data_;
    size_t size_;
    size_t offset_;

public:
    FuzzedDataProvider(const uint8_t* data, size_t size)
        : data_(data), size_(size), offset_(0) {}

    /**
     * Get remaining bytes available
     */
    size_t remaining_bytes() const {
        return size_ > offset_ ? size_ - offset_ : 0;
    }

    /**
     * Consume a single byte
     */
    uint8_t ConsumeUint8() {
        if (remaining_bytes() < 1) return 0;
        return data_[offset_++];
    }

    /**
     * Consume a 16-bit unsigned integer
     */
    uint16_t ConsumeUint16() {
        if (remaining_bytes() < 2) return 0;
        uint16_t result = (uint16_t(data_[offset_]) << 8) |
                         uint16_t(data_[offset_ + 1]);
        offset_ += 2;
        return result;
    }

    /**
     * Consume a 32-bit unsigned integer
     */
    uint32_t ConsumeUint32() {
        if (remaining_bytes() < 4) return 0;
        uint32_t result = (uint32_t(data_[offset_]) << 24) |
                         (uint32_t(data_[offset_ + 1]) << 16) |
                         (uint32_t(data_[offset_ + 2]) << 8) |
                         uint32_t(data_[offset_ + 3]);
        offset_ += 4;
        return result;
    }

    /**
     * Consume a 64-bit unsigned integer
     */
    uint64_t ConsumeUint64() {
        if (remaining_bytes() < 8) return 0;
        uint64_t result = (uint64_t(data_[offset_]) << 56) |
                         (uint64_t(data_[offset_ + 1]) << 48) |
                         (uint64_t(data_[offset_ + 2]) << 40) |
                         (uint64_t(data_[offset_ + 3]) << 32) |
                         (uint64_t(data_[offset_ + 4]) << 24) |
                         (uint64_t(data_[offset_ + 5]) << 16) |
                         (uint64_t(data_[offset_ + 6]) << 8) |
                         uint64_t(data_[offset_ + 7]);
        offset_ += 8;
        return result;
    }

    /**
     * Consume a boolean value
     */
    bool ConsumeBool() {
        return ConsumeUint8() & 1;
    }

    /**
     * Consume bytes into a vector (up to max_length)
     */
    std::vector<uint8_t> ConsumeBytes(size_t max_length) {
        size_t length = std::min(max_length, remaining_bytes());
        std::vector<uint8_t> result(data_ + offset_, data_ + offset_ + length);
        offset_ += length;
        return result;
    }

    /**
     * Consume remaining bytes into a vector
     */
    std::vector<uint8_t> ConsumeRemainingBytes() {
        return ConsumeBytes(remaining_bytes());
    }

    /**
     * Consume bytes of random length (0 to remaining)
     */
    std::vector<uint8_t> ConsumeRandomLengthByteVector(size_t max_length = SIZE_MAX) {
        if (remaining_bytes() == 0) return {};

        // Use first byte to determine length
        uint8_t length_byte = ConsumeUint8();
        size_t length = length_byte % (std::min(max_length, remaining_bytes()) + 1);

        return ConsumeBytes(length);
    }

    /**
     * Consume a string (null-terminated or fixed length)
     */
    std::string ConsumeString(size_t max_length) {
        auto bytes = ConsumeBytes(max_length);
        return std::string(bytes.begin(), bytes.end());
    }

    /**
     * Consume remaining data as string
     */
    std::string ConsumeRemainingAsString() {
        auto bytes = ConsumeRemainingBytes();
        return std::string(bytes.begin(), bytes.end());
    }

    /**
     * Consume integer of any type
     */
    template<typename T>
    T ConsumeIntegral() {
        if (sizeof(T) == 1) {
            return static_cast<T>(ConsumeUint8());
        } else if (sizeof(T) == 2) {
            return static_cast<T>(ConsumeUint16());
        } else if (sizeof(T) == 4) {
            return static_cast<T>(ConsumeUint32());
        } else if (sizeof(T) == 8) {
            return static_cast<T>(ConsumeUint64());
        } else {
            return T(0);
        }
    }

    /**
     * Consume integer in range [min, max]
     */
    template<typename T>
    T ConsumeIntegralInRange(T min, T max) {
        if (min >= max) return min;

        T range = max - min;
        T random_value = ConsumeIntegral<T>();

        return min + (random_value % (range + 1));
    }

    /**
     * Consume random length string
     */
    std::string ConsumeRandomLengthString(size_t max_length = 1000) {
        if (remaining_bytes() == 0) return "";
        uint8_t length_byte = ConsumeUint8();
        size_t length = length_byte % (std::min(max_length, remaining_bytes()) + 1);
        return ConsumeString(length);
    }

    /**
     * Consume bytes (template version)
     */
    template<typename T>
    std::vector<T> ConsumeBytes(size_t count) {
        size_t bytes_needed = count * sizeof(T);
        size_t bytes_available = std::min(bytes_needed, remaining_bytes());
        size_t items = bytes_available / sizeof(T);

        std::vector<T> result;
        result.reserve(items);

        for (size_t i = 0; i < items; ++i) {
            result.push_back(ConsumeIntegral<T>());
        }

        return result;
    }

    /**
     * Consume remaining bytes as vector of T
     */
    template<typename T>
    std::vector<T> ConsumeRemainingBytes() {
        return ConsumeBytes<T>(remaining_bytes() / sizeof(T));
    }

    /**
     * Pick an enum value from available options
     */
    template<typename T>
    T ConsumeEnum() {
        return static_cast<T>(ConsumeUint8());
    }
};

/**
 * Helper: Extract fixed-size array from fuzz input
 */
template<size_t N>
inline bool ConsumeFixedBytes(FuzzedDataProvider& provider, uint8_t (&output)[N]) {
    if (provider.remaining_bytes() < N) {
        return false;
    }
    auto bytes = provider.ConsumeBytes(N);
    std::memcpy(output, bytes.data(), N);
    return true;
}

/**
 * Helper: Consume a 256-bit hash
 */
inline std::vector<uint8_t> ConsumeHash256(FuzzedDataProvider& provider) {
    return provider.ConsumeBytes(32);
}

/**
 * Helper: Consume a public key (Dilithium3 size)
 */
inline std::vector<uint8_t> ConsumeDilithiumPublicKey(FuzzedDataProvider& provider) {
    return provider.ConsumeBytes(1952); // DILITHIUM3_PUBLICKEYBYTES
}

/**
 * Helper: Consume a signature (Dilithium3 size)
 */
inline std::vector<uint8_t> ConsumeDilithiumSignature(FuzzedDataProvider& provider) {
    return provider.ConsumeBytes(3293); // DILITHIUM3_BYTES
}

#endif // DILITHION_TEST_FUZZ_UTIL_H
