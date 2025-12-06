// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Phase 10: Configuration System Implementation
 */

#include <util/config.h>
#include <util/logging.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdlib>

#ifdef _WIN32
    #include <windows.h>
    #include <shlobj.h>
#else
    #include <unistd.h>
    #include <pwd.h>
    #include <sys/stat.h>
#endif

CConfigParser::CConfigParser() : m_loaded(false) {
}

CConfigParser::~CConfigParser() {
}

std::string CConfigParser::Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

bool CConfigParser::ParseLine(const std::string& line, std::string& key, std::string& value) {
    // Remove comments
    std::string clean_line = line;
    size_t comment_pos = clean_line.find('#');
    if (comment_pos != std::string::npos) {
        clean_line = clean_line.substr(0, comment_pos);
    }
    comment_pos = clean_line.find(';');
    if (comment_pos != std::string::npos) {
        clean_line = clean_line.substr(0, comment_pos);
    }

    // Trim whitespace
    clean_line = Trim(clean_line);
    if (clean_line.empty()) {
        return false;  // Empty line or comment only
    }

    // Skip section headers [section]
    if (clean_line[0] == '[' && clean_line.back() == ']') {
        return false;  // Section header, ignore for now
    }

    // Parse key=value
    size_t eq_pos = clean_line.find('=');
    if (eq_pos == std::string::npos) {
        return false;  // No equals sign
    }

    key = Trim(clean_line.substr(0, eq_pos));
    value = Trim(clean_line.substr(eq_pos + 1));

    // Remove quotes if present
    if (value.length() >= 2 && value[0] == '"' && value.back() == '"') {
        value = value.substr(1, value.length() - 2);
    }

    return !key.empty();
}

std::optional<std::string> CConfigParser::GetEnv(const std::string& name) {
#ifdef _WIN32
    size_t size = 0;
    getenv_s(&size, nullptr, 0, name.c_str());
    if (size == 0) {
        return std::nullopt;
    }
    std::string value(size, '\0');
    getenv_s(&size, value.data(), size, name.c_str());
    if (size > 0) {
        value.resize(size - 1);  // Remove null terminator
        return value;
    }
    return std::nullopt;
#else
    const char* env_value = std::getenv(name.c_str());
    if (env_value == nullptr) {
        return std::nullopt;
    }
    return std::string(env_value);
#endif
}

bool CConfigParser::LoadConfigFile(const std::string& file_path) {
    m_config_file_path = file_path;
    m_settings.clear();
    m_loaded = false;

    // DB-MED-004 FIX: Check config file permissions before loading
    // Config file may contain RPC password - should be owner-readable only
#ifndef _WIN32
    struct stat file_stat;
    if (stat(file_path.c_str(), &file_stat) == 0) {
        // File exists - check permissions
        mode_t mode = file_stat.st_mode;

        // Warn if group or others can read the file
        if (mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
            LogPrintf(ALL, WARN, "Config file %s has insecure permissions (mode %o)",
                      file_path.c_str(), mode & 0777);
            LogPrintf(ALL, WARN, "Consider: chmod 600 %s", file_path.c_str());
        }

        // Warn if file is a symlink (potential attack vector)
        if (S_ISLNK(mode)) {
            LogPrintf(ALL, WARN, "Config file %s is a symlink - potential security risk",
                      file_path.c_str());
        }
    }
#endif

    std::ifstream file(file_path);
    if (!file.is_open()) {
        // File doesn't exist - this is OK, use defaults
        LogPrintf(ALL, DEBUG, "Config file not found: %s (using defaults)", file_path.c_str());
        m_loaded = true;  // Successfully loaded (with no file)
        return true;
    }

    std::string line;
    int line_num = 0;
    while (std::getline(file, line)) {
        line_num++;
        std::string key, value;
        if (ParseLine(line, key, value)) {
            // Convert key to lowercase for case-insensitive matching
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            m_settings[key] = value;
            LogPrintf(ALL, DEBUG, "Config: %s = %s", key.c_str(), value.c_str());
        }
    }

    file.close();
    m_loaded = true;
    if (m_settings.size() > 0) {
        LogPrintf(ALL, INFO, "Loaded configuration from %s (%zu settings)", 
                  file_path.c_str(), m_settings.size());
    }
    return true;
}

std::string CConfigParser::GetString(const std::string& key, const std::string& default_value) const {
    // Convert key to lowercase
    std::string key_lower = key;
    std::transform(key_lower.begin(), key_lower.end(), key_lower.begin(), ::tolower);

    // Priority 1: Environment variable (DILITHION_*)
    std::string env_key = "DILITHION_" + key;
    std::transform(env_key.begin(), env_key.end(), env_key.begin(), ::toupper);
    auto env_value = GetEnv(env_key);
    if (env_value.has_value()) {
        LogPrintf(ALL, DEBUG, "Config: %s = %s (from environment)", 
                  key.c_str(), env_value->c_str());
        return *env_value;
    }

    // Priority 2: Config file
    auto it = m_settings.find(key_lower);
    if (it != m_settings.end()) {
        return it->second;
    }

    // Priority 3: Default
    return default_value;
}

int64_t CConfigParser::GetInt64(const std::string& key, int64_t default_value) const {
    std::string value = GetString(key, "");
    if (value.empty()) {
        return default_value;
    }

    try {
        return std::stoll(value);
    } catch (const std::exception& e) {
        LogPrintf(ALL, WARN, "Config: Invalid integer value for %s: %s (using default: %lld)",
                  key.c_str(), value.c_str(), default_value);
        return default_value;
    }
}

bool CConfigParser::GetBool(const std::string& key, bool default_value) const {
    std::string value = GetString(key, "");
    if (value.empty()) {
        return default_value;
    }

    // Convert to lowercase for comparison
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);

    // True values
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }

    // False values
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }

    LogPrintf(ALL, WARN, "Config: Invalid boolean value for %s: %s (using default: %s)",
              key.c_str(), value.c_str(), default_value ? "true" : "false");
    return default_value;
}

std::vector<std::string> CConfigParser::GetList(const std::string& key) const {
    std::vector<std::string> result;

    // Convert key to lowercase
    std::string key_lower = key;
    std::transform(key_lower.begin(), key_lower.end(), key_lower.begin(), ::tolower);

    // Check for environment variable (comma-separated)
    std::string env_key = "DILITHION_" + key;
    std::transform(env_key.begin(), env_key.end(), env_key.begin(), ::toupper);
    auto env_value = GetEnv(env_key);
    if (env_value.has_value()) {
        std::stringstream ss(*env_value);
        std::string item;
        while (std::getline(ss, item, ',')) {
            item = Trim(item);
            if (!item.empty()) {
                result.push_back(item);
            }
        }
        return result;
    }

    // Check config file (multiple entries with same key)
    for (const auto& pair : m_settings) {
        if (pair.first == key_lower) {
            result.push_back(pair.second);
        }
    }

    return result;
}

std::string GetDefaultDataDir(bool testnet) {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, path) == S_OK) {
        std::string dir(path);
        if (testnet) {
            return dir + "\\.dilithion-testnet";
        } else {
            return dir + "\\.dilithion";
        }
    }
    // Fallback
    if (testnet) {
        return ".dilithion-testnet";
    } else {
        return ".dilithion";
    }
#else
    const char* home = std::getenv("HOME");
    if (home == nullptr) {
        struct passwd* pwd = getpwuid(getuid());
        if (pwd != nullptr) {
            home = pwd->pw_dir;
        }
    }
    
    if (home != nullptr) {
        std::string dir(home);
        if (testnet) {
            return dir + "/.dilithion-testnet";
        } else {
            return dir + "/.dilithion";
        }
    }
    
    // Fallback
    if (testnet) {
        return ".dilithion-testnet";
    } else {
        return ".dilithion";
    }
#endif
}

std::string GetConfigFilePath(const std::string& datadir) {
    std::string dir = datadir.empty() ? GetDefaultDataDir(false) : datadir;
    
#ifdef _WIN32
    return dir + "\\dilithion.conf";
#else
    return dir + "/dilithion.conf";
#endif
}

