// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Configuration Validation
 * Phase: User Experience Improvements
 * 
 * Validates configuration values and provides helpful error messages
 */

#ifndef DILITHION_UTIL_CONFIG_VALIDATOR_H
#define DILITHION_UTIL_CONFIG_VALIDATOR_H

#include <string>
#include <vector>
#include <cstdint>
#include <util/error_format.h>

/**
 * Configuration validation result
 */
struct ConfigValidationResult {
    bool valid;
    std::string error_message;
    std::string field_name;
    std::vector<std::string> suggestions;
    
    ConfigValidationResult() : valid(true) {}
    ConfigValidationResult(const std::string& field, const std::string& error)
        : valid(false), error_message(error), field_name(field) {}
};

/**
 * Configuration validator
 */
class CConfigValidator {
public:
    /**
     * Validate port number
     */
    static ConfigValidationResult ValidatePort(const std::string& value, const std::string& field_name);
    
    /**
     * Validate data directory path
     */
    static ConfigValidationResult ValidateDataDir(const std::string& path);
    
    /**
     * Validate mining thread count
     */
    static ConfigValidationResult ValidateMiningThreads(int64_t threads);
    
    /**
     * Validate RPC port
     */
    static ConfigValidationResult ValidateRPCPort(const std::string& value);
    
    /**
     * Validate boolean value
     */
    static ConfigValidationResult ValidateBool(const std::string& value, const std::string& field_name);
    
    /**
     * Validate addnode entries
     */
    static ConfigValidationResult ValidateAddNode(const std::string& node);
    
    /**
     * Validate all configuration values
     */
    static std::vector<ConfigValidationResult> ValidateAll(const class CConfigParser& config);
};

#endif // DILITHION_UTIL_CONFIG_VALIDATOR_H

