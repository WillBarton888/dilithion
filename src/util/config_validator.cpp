// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Configuration Validation Implementation
 */

#include <util/config_validator.h>
#include <util/config.h>
#include <consensus/params.h>
#include <filesystem>
#include <algorithm>
#include <cctype>

ConfigValidationResult CConfigValidator::ValidatePort(const std::string& value, const std::string& field_name) {
    ConfigValidationResult result;
    result.field_name = field_name;
    
    try {
        int64_t port = std::stoll(value);
        if (port < 1 || port > 65535) {
            result.valid = false;
            result.error_message = "Port must be between 1 and 65535";
            result.suggestions.push_back("Use a valid port number (1-65535)");
            result.suggestions.push_back("Common ports: 8332 (Bitcoin), 8333 (P2P)");
        }
    } catch (const std::exception&) {
        result.valid = false;
        result.error_message = "Invalid port number format";
        result.suggestions.push_back("Port must be a number between 1 and 65535");
    }
    
    return result;
}

ConfigValidationResult CConfigValidator::ValidateDataDir(const std::string& path) {
    ConfigValidationResult result;
    result.field_name = "datadir";
    
    if (path.empty()) {
        result.valid = true;  // Empty is valid (uses default)
        return result;
    }
    
    try {
        std::filesystem::path fs_path(path);
        
        // Check if parent directory exists or can be created
        std::filesystem::path parent = fs_path.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            // Check if we can create it
            try {
                std::filesystem::create_directories(parent);
            } catch (const std::exception& e) {
                result.valid = false;
                result.error_message = "Cannot create data directory: " + std::string(e.what());
                result.suggestions.push_back("Check directory permissions");
                result.suggestions.push_back("Ensure parent directory exists");
                return result;
            }
        }
        
        // Check for forbidden characters
        const std::string forbidden = "<>:\"|?*";
        std::string path_str = path;
        #ifdef _WIN32
        // Skip drive letter on Windows
        size_t start_pos = (path_str.length() >= 2 && path_str[1] == ':') ? 2 : 0;
        if (path_str.find_first_of(forbidden, start_pos) != std::string::npos) {
            result.valid = false;
            result.error_message = "Path contains forbidden characters";
            result.suggestions.push_back("Remove forbidden characters: < > : \" | ? *");
            return result;
        }
        #else
        if (path_str.find_first_of(forbidden) != std::string::npos) {
            result.valid = false;
            result.error_message = "Path contains forbidden characters";
            result.suggestions.push_back("Remove forbidden characters: < > : \" | ? *");
            return result;
        }
        #endif
        
    } catch (const std::exception& e) {
        result.valid = false;
        result.error_message = "Invalid data directory path: " + std::string(e.what());
        result.suggestions.push_back("Use an absolute path");
        result.suggestions.push_back("Check path syntax");
    }
    
    return result;
}

ConfigValidationResult CConfigValidator::ValidateMiningThreads(int64_t threads) {
    ConfigValidationResult result;
    result.field_name = "threads";
    
    if (threads < 1) {
        result.valid = false;
        result.error_message = "Mining threads must be at least 1";
        result.suggestions.push_back("Set threads to 1 or more");
        result.suggestions.push_back("Recommended: number of CPU cores");
    } else if (threads > Consensus::MAX_MINING_THREADS) {
        result.valid = false;
        result.error_message = "Mining threads cannot exceed " + std::to_string(Consensus::MAX_MINING_THREADS);
        result.suggestions.push_back("Reduce thread count to " + std::to_string(Consensus::MAX_MINING_THREADS) + " or less");
        result.suggestions.push_back("Recommended: number of CPU cores");
    }
    
    return result;
}

ConfigValidationResult CConfigValidator::ValidateRPCPort(const std::string& value) {
    return ValidatePort(value, "rpcport");
}

ConfigValidationResult CConfigValidator::ValidateBool(const std::string& value, const std::string& field_name) {
    ConfigValidationResult result;
    result.field_name = field_name;
    
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower != "0" && lower != "1" && lower != "true" && lower != "false" &&
        lower != "yes" && lower != "no" && lower != "on" && lower != "off") {
        result.valid = false;
        result.error_message = "Invalid boolean value";
        result.suggestions.push_back("Use: 0/1, true/false, yes/no, or on/off");
    }
    
    return result;
}

ConfigValidationResult CConfigValidator::ValidateAddNode(const std::string& node) {
    ConfigValidationResult result;
    result.field_name = "addnode";
    
    if (node.empty()) {
        result.valid = false;
        result.error_message = "Node address cannot be empty";
        result.suggestions.push_back("Format: IP:PORT or hostname:PORT");
        result.suggestions.push_back("Example: 192.168.1.1:8333");
        return result;
    }
    
    // Basic format check: should contain : for port
    if (node.find(':') == std::string::npos) {
        result.valid = false;
        result.error_message = "Node address must include port";
        result.suggestions.push_back("Format: IP:PORT or hostname:PORT");
        result.suggestions.push_back("Example: 192.168.1.1:8333");
    }
    
    return result;
}

std::vector<ConfigValidationResult> CConfigValidator::ValidateAll(const CConfigParser& config) {
    std::vector<ConfigValidationResult> results;
    
    // Validate ports
    std::string port = config.GetString("port", "");
    if (!port.empty()) {
        results.push_back(ValidatePort(port, "port"));
    }
    
    std::string rpcport = config.GetString("rpcport", "");
    if (!rpcport.empty()) {
        results.push_back(ValidateRPCPort(rpcport));
    }
    
    // Validate data directory
    std::string datadir = config.GetString("datadir", "");
    if (!datadir.empty()) {
        results.push_back(ValidateDataDir(datadir));
    }
    
    // Validate mining threads
    int64_t threads = config.GetInt64("threads", 0);
    if (threads > 0) {
        results.push_back(ValidateMiningThreads(threads));
    }
    
    // Validate boolean fields
    std::string testnet = config.GetString("testnet", "");
    if (!testnet.empty()) {
        results.push_back(ValidateBool(testnet, "testnet"));
    }
    
    std::string mine = config.GetString("mine", "");
    if (!mine.empty()) {
        results.push_back(ValidateBool(mine, "mine"));
    }
    
    // Validate addnode entries
    std::vector<std::string> addnodes = config.GetList("addnode");
    for (const auto& node : addnodes) {
        results.push_back(ValidateAddNode(node));
    }
    
    return results;
}

