// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * User-Friendly Error Formatting Implementation
 */

#include <util/error_format.h>
#include <sstream>
#include <iomanip>

std::string CErrorFormatter::FormatForUser(const ErrorMessage& error) {
    std::ostringstream oss;
    
    // Color coding based on severity
    const char* color = "";
    const char* symbol = "";
    switch (error.severity) {
        case ErrorSeverity::INFO:
            color = "\033[0;36m";  // Cyan
            symbol = "ℹ";
            break;
        case ErrorSeverity::WARNING:
            color = "\033[0;33m";  // Yellow
            symbol = "⚠";
            break;
        case ErrorSeverity::ERROR:
            color = "\033[0;31m";  // Red
            symbol = "✗";
            break;
        case ErrorSeverity::CRITICAL:
            color = "\033[1;31m";  // Bold Red
            symbol = "✗";
            break;
    }
    const char* reset = "\033[0m";

    oss << color << symbol << " " << error.title << reset << std::endl;
    oss << "  " << error.description << std::endl;
    
    if (!error.cause.empty()) {
        oss << std::endl << "  Cause: " << error.cause << std::endl;
    }

    if (!error.recovery_steps.empty()) {
        oss << std::endl << "  To resolve:" << std::endl;
        for (size_t i = 0; i < error.recovery_steps.size(); ++i) {
            oss << "    " << (i + 1) << ". " << error.recovery_steps[i] << std::endl;
        }
    }

    if (!error.error_code.empty()) {
        oss << std::endl << "  Error code: " << error.error_code << std::endl;
    }

    return oss.str();
}

std::string CErrorFormatter::FormatForLog(const ErrorMessage& error) {
    std::ostringstream oss;
    
    const char* severity_str = "";
    switch (error.severity) {
        case ErrorSeverity::INFO: severity_str = "INFO"; break;
        case ErrorSeverity::WARNING: severity_str = "WARNING"; break;
        case ErrorSeverity::ERROR: severity_str = "ERROR"; break;
        case ErrorSeverity::CRITICAL: severity_str = "CRITICAL"; break;
    }

    oss << "[" << severity_str << "] " << error.title;
    if (!error.error_code.empty()) {
        oss << " (code: " << error.error_code << ")";
    }
    oss << ": " << error.description;
    
    if (!error.cause.empty()) {
        oss << " Cause: " << error.cause;
    }

    return oss.str();
}

ErrorMessage CErrorFormatter::DatabaseError(const std::string& operation, const std::string& details) {
    ErrorMessage error(ErrorSeverity::ERROR, 
                      "Database Operation Failed",
                      "Failed to " + operation + ": " + details);
    error.cause = "Database I/O error or corruption";
    error.recovery_steps = {
        "Check disk space and permissions",
        "Verify database files are not corrupted",
        "Try restarting the node",
        "If problem persists, use --reindex to rebuild the database"
    };
    error.error_code = "DB_" + operation;
    return error;
}

ErrorMessage CErrorFormatter::NetworkError(const std::string& operation, const std::string& details) {
    ErrorMessage error(ErrorSeverity::WARNING,
                      "Network Operation Failed",
                      "Failed to " + operation + ": " + details);
    error.cause = "Network connectivity issue or peer unavailable";
    error.recovery_steps = {
        "Check your internet connection",
        "Verify firewall settings allow P2P connections",
        "Try adding more nodes with --addnode",
        "Check if the node is behind a NAT/firewall"
    };
    error.error_code = "NET_" + operation;
    return error;
}

ErrorMessage CErrorFormatter::ConfigError(const std::string& option, const std::string& details) {
    ErrorMessage error(ErrorSeverity::ERROR,
                      "Configuration Error",
                      "Invalid configuration for '" + option + "': " + details);
    error.cause = "Invalid or malformed configuration value";
    error.recovery_steps = {
        "Check dilithion.conf for syntax errors",
        "Verify the value is in the correct format",
        "See dilithion.conf.example for valid options",
        "Run with --help to see command-line options"
    };
    error.error_code = "CONFIG_" + option;
    return error;
}

ErrorMessage CErrorFormatter::ValidationError(const std::string& object, const std::string& details) {
    ErrorMessage error(ErrorSeverity::ERROR,
                      "Validation Failed",
                      "Failed to validate " + object + ": " + details);
    error.cause = "Invalid data format or corrupted data";
    error.recovery_steps = {
        "Verify the data source is correct",
        "Check for data corruption",
        "Try re-syncing the blockchain if this persists"
    };
    error.error_code = "VALID_" + object;
    return error;
}

