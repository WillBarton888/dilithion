// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_RPC_JSON_UTIL_H
#define DILITHION_RPC_JSON_UTIL_H

#include <3rdparty/json.hpp>
#include <string>
#include <stdexcept>

/**
 * RPC-007 FIX: Type-safe JSON parameter extraction utilities
 *
 * Replaces manual string parsing with proper JSON library (nlohmann/json)
 *
 * Benefits:
 * - Type safety: Automatic type conversion with validation
 * - Error handling: Clear error messages for missing/invalid params
 * - Security: No manual bounds checking needed
 * - Maintainability: Standard JSON API vs. custom substr() logic
 */

using json = nlohmann::json;

namespace RPCUtil {

/**
 * Get required string parameter from JSON object
 * Throws std::runtime_error if parameter is missing or wrong type
 */
inline std::string GetRequiredString(const json& params, const std::string& key) {
    if (!params.contains(key)) {
        throw std::runtime_error("Missing required parameter: " + key);
    }

    if (!params[key].is_string()) {
        throw std::runtime_error("Parameter '" + key + "' must be a string");
    }

    return params[key].get<std::string>();
}

/**
 * Get optional string parameter with default value
 */
inline std::string GetOptionalString(const json& params, const std::string& key,
                                     const std::string& default_value = "") {
    if (!params.contains(key)) {
        return default_value;
    }

    if (!params[key].is_string()) {
        throw std::runtime_error("Parameter '" + key + "' must be a string");
    }

    return params[key].get<std::string>();
}

/**
 * Get required double parameter from JSON object
 */
inline double GetRequiredDouble(const json& params, const std::string& key,
                                double min_val = -1e100, double max_val = 1e100) {
    if (!params.contains(key)) {
        throw std::runtime_error("Missing required parameter: " + key);
    }

    if (!params[key].is_number()) {
        throw std::runtime_error("Parameter '" + key + "' must be a number");
    }

    double value = params[key].get<double>();

    if (value < min_val || value > max_val) {
        throw std::runtime_error("Parameter '" + key + "' out of valid range [" +
                                std::to_string(min_val) + ", " +
                                std::to_string(max_val) + "]");
    }

    return value;
}

/**
 * Get optional double parameter with default value
 */
inline double GetOptionalDouble(const json& params, const std::string& key,
                                double default_value = 0.0,
                                double min_val = -1e100, double max_val = 1e100) {
    if (!params.contains(key)) {
        return default_value;
    }

    if (!params[key].is_number()) {
        throw std::runtime_error("Parameter '" + key + "' must be a number");
    }

    double value = params[key].get<double>();

    if (value < min_val || value > max_val) {
        throw std::runtime_error("Parameter '" + key + "' out of valid range [" +
                                std::to_string(min_val) + ", " +
                                std::to_string(max_val) + "]");
    }

    return value;
}

/**
 * Get required int64_t parameter from JSON object
 */
inline int64_t GetRequiredInt64(const json& params, const std::string& key,
                                int64_t min_val = INT64_MIN, int64_t max_val = INT64_MAX) {
    if (!params.contains(key)) {
        throw std::runtime_error("Missing required parameter: " + key);
    }

    if (!params[key].is_number_integer()) {
        throw std::runtime_error("Parameter '" + key + "' must be an integer");
    }

    int64_t value = params[key].get<int64_t>();

    if (value < min_val || value > max_val) {
        throw std::runtime_error("Parameter '" + key + "' out of valid range [" +
                                std::to_string(min_val) + ", " +
                                std::to_string(max_val) + "]");
    }

    return value;
}

/**
 * Get optional int64_t parameter with default value
 */
inline int64_t GetOptionalInt64(const json& params, const std::string& key,
                                int64_t default_value = 0,
                                int64_t min_val = INT64_MIN, int64_t max_val = INT64_MAX) {
    if (!params.contains(key)) {
        return default_value;
    }

    if (!params[key].is_number_integer()) {
        throw std::runtime_error("Parameter '" + key + "' must be an integer");
    }

    int64_t value = params[key].get<int64_t>();

    if (value < min_val || value > max_val) {
        throw std::runtime_error("Parameter '" + key + "' out of valid range [" +
                                std::to_string(min_val) + ", " +
                                std::to_string(max_val) + "]");
    }

    return value;
}

/**
 * Get required uint32_t parameter from JSON object
 */
inline uint32_t GetRequiredUInt32(const json& params, const std::string& key,
                                  uint32_t min_val = 0, uint32_t max_val = UINT32_MAX) {
    if (!params.contains(key)) {
        throw std::runtime_error("Missing required parameter: " + key);
    }

    if (!params[key].is_number_unsigned()) {
        throw std::runtime_error("Parameter '" + key + "' must be an unsigned integer");
    }

    uint32_t value = params[key].get<uint32_t>();

    if (value < min_val || value > max_val) {
        throw std::runtime_error("Parameter '" + key + "' out of valid range [" +
                                std::to_string(min_val) + ", " +
                                std::to_string(max_val) + "]");
    }

    return value;
}

/**
 * Get required boolean parameter from JSON object
 */
inline bool GetRequiredBool(const json& params, const std::string& key) {
    if (!params.contains(key)) {
        throw std::runtime_error("Missing required parameter: " + key);
    }

    if (!params[key].is_boolean()) {
        throw std::runtime_error("Parameter '" + key + "' must be a boolean");
    }

    return params[key].get<bool>();
}

/**
 * Get optional boolean parameter with default value
 */
inline bool GetOptionalBool(const json& params, const std::string& key, bool default_value = false) {
    if (!params.contains(key)) {
        return default_value;
    }

    if (!params[key].is_boolean()) {
        throw std::runtime_error("Parameter '" + key + "' must be a boolean");
    }

    return params[key].get<bool>();
}

} // namespace RPCUtil

#endif // DILITHION_RPC_JSON_UTIL_H
