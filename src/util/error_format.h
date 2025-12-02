// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * User-Friendly Error Formatting
 * Phase: User Experience Improvements
 * 
 * Provides structured, user-friendly error messages with recovery guidance
 */

#ifndef DILITHION_UTIL_ERROR_FORMAT_H
#define DILITHION_UTIL_ERROR_FORMAT_H

#include <string>
#include <vector>

/**
 * Error severity levels
 */
enum class ErrorSeverity {
    INFO,      // Informational message
    WARNING,   // Warning - operation may have issues
    ERROR,     // Error - operation failed but recoverable
    CRITICAL   // Critical - operation failed, may require intervention
};

/**
 * Structured error message with context and recovery guidance
 */
struct ErrorMessage {
    ErrorSeverity severity;
    std::string title;
    std::string description;
    std::string cause;
    std::vector<std::string> recovery_steps;
    std::string error_code;  // For technical reference

    ErrorMessage(ErrorSeverity sev, const std::string& t, const std::string& desc)
        : severity(sev), title(t), description(desc) {}
};

/**
 * Format error message for user display
 */
class CErrorFormatter {
public:
    /**
     * Format error for console output (user-friendly)
     */
    static std::string FormatForUser(const ErrorMessage& error);

    /**
     * Format error for log output (technical)
     */
    static std::string FormatForLog(const ErrorMessage& error);

    /**
     * Create database error message
     */
    static ErrorMessage DatabaseError(const std::string& operation, const std::string& details);

    /**
     * Create network error message
     */
    static ErrorMessage NetworkError(const std::string& operation, const std::string& details);

    /**
     * Create configuration error message
     */
    static ErrorMessage ConfigError(const std::string& option, const std::string& details);

    /**
     * Create validation error message
     */
    static ErrorMessage ValidationError(const std::string& object, const std::string& details);
};

#endif // DILITHION_UTIL_ERROR_FORMAT_H

