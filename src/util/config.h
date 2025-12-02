// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Phase 10: Configuration System
 *
 * Bitcoin Core-style configuration file and environment variable support.
 * Reads from dilithion.conf and allows environment variable overrides.
 */

#ifndef DILITHION_UTIL_CONFIG_H
#define DILITHION_UTIL_CONFIG_H

#include <string>
#include <map>
#include <vector>
#include <optional>

/**
 * Configuration file parser
 * 
 * Supports:
 * - Key=value pairs
 * - Comments (# and ;)
 * - Section headers [section]
 * - Environment variable overrides (DILITHION_*)
 */
class CConfigParser {
private:
    std::map<std::string, std::string> m_settings;
    std::string m_config_file_path;
    bool m_loaded;

    // Helper: Trim whitespace
    static std::string Trim(const std::string& str);
    
    // Helper: Parse line
    bool ParseLine(const std::string& line, std::string& key, std::string& value);
    
    // Helper: Get environment variable
    static std::optional<std::string> GetEnv(const std::string& name);

public:
    CConfigParser();
    ~CConfigParser();

    /**
     * Load configuration from file
     * @param file_path Path to dilithion.conf
     * @return true if loaded successfully (or file doesn't exist), false on error
     */
    bool LoadConfigFile(const std::string& file_path);

    /**
     * Get string value
     * Priority: Environment variable > Config file > Default
     * @param key Configuration key (e.g., "rpcport")
     * @param default_value Default value if not found
     * @return Configuration value or default
     */
    std::string GetString(const std::string& key, const std::string& default_value = "") const;

    /**
     * Get integer value
     * @param key Configuration key
     * @param default_value Default value if not found
     * @return Configuration value or default
     */
    int64_t GetInt64(const std::string& key, int64_t default_value = 0) const;

    /**
     * Get boolean value
     * Supports: 1, 0, true, false, yes, no, on, off
     * @param key Configuration key
     * @param default_value Default value if not found
     * @return Configuration value or default
     */
    bool GetBool(const std::string& key, bool default_value = false) const;

    /**
     * Get list of values (for multi-value keys like addnode)
     * @param key Configuration key
     * @return Vector of values
     */
    std::vector<std::string> GetList(const std::string& key) const;

    /**
     * Check if configuration was loaded
     */
    bool IsLoaded() const { return m_loaded; }

    /**
     * Get config file path
     */
    std::string GetConfigFilePath() const { return m_config_file_path; }

    /**
     * Get all settings (for debugging)
     */
    std::map<std::string, std::string> GetAllSettings() const { return m_settings; }
};

/**
 * Get default config file path
 * @param datadir Data directory (if empty, uses default)
 * @return Path to dilithion.conf
 */
std::string GetConfigFilePath(const std::string& datadir = "");

/**
 * Get default data directory
 * @param testnet Whether testnet or mainnet
 * @return Default data directory path
 */
std::string GetDefaultDataDir(bool testnet = false);

#endif // DILITHION_UTIL_CONFIG_H

