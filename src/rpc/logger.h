// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_RPC_LOGGER_H
#define DILITHION_RPC_LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <memory>

/**
 * RPC Request Logger and Audit Trail
 * 
 * Provides structured logging for RPC requests and responses.
 * Supports:
 * - Request/response logging
 * - Audit trail for security events
 * - Configurable log levels
 * - Log rotation
 * - Thread-safe operation
 */
class CRPCLogger {
public:
    /**
     * Log levels
     */
    enum class LogLevel {
        DEBUG,    // All requests (verbose)
        INFO,     // Normal operations
        WARN,     // Warnings (rate limits, etc.)
        ERROR,    // Errors only
        AUDIT     // Security events only
    };

    /**
     * Request log entry
     */
    struct RequestLog {
        std::string timestamp;
        std::string client_ip;
        std::string username;
        std::string method;
        std::string params_hash;  // Hash of params for privacy
        bool success;
        int64_t duration_ms;
        std::string error_code;
        std::string error_message;
    };

    /**
     * Constructor
     * @param log_file Path to log file (empty = disabled)
     * @param audit_file Path to audit log file (empty = disabled)
     * @param level Minimum log level
     */
    CRPCLogger(const std::string& log_file = "",
               const std::string& audit_file = "",
               LogLevel level = LogLevel::INFO);

    /**
     * Destructor
     */
    ~CRPCLogger();

    /**
     * Log RPC request
     * @param log Request log entry
     */
    void LogRequest(const RequestLog& log);

    /**
     * Log security event (always logged to audit file)
     * @param event_type Type of event (e.g., "AUTH_FAILURE", "PERMISSION_DENIED")
     * @param client_ip Client IP address
     * @param username Username (if applicable)
     * @param details Additional details
     */
    void LogSecurityEvent(const std::string& event_type,
                         const std::string& client_ip,
                         const std::string& username,
                         const std::string& details);

    /**
     * Set log level
     */
    void SetLogLevel(LogLevel level) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_log_level = level;
    }

    /**
     * Get current log level
     */
    LogLevel GetLogLevel() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_log_level;
    }

    /**
     * Enable/disable logging
     */
    void SetEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enabled = enabled;
    }

    /**
     * Check if logging is enabled
     */
    bool IsEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enabled;
    }

    /**
     * Rotate log files (call periodically)
     * @param max_size Maximum log file size in bytes (0 = no rotation)
     */
    void RotateLogs(size_t max_size = 10 * 1024 * 1024);  // 10MB default

private:
    std::string m_log_file;
    std::string m_audit_file;
    std::unique_ptr<std::ofstream> m_log_stream;
    std::unique_ptr<std::ofstream> m_audit_stream;
    LogLevel m_log_level;
    bool m_enabled;
    mutable std::mutex m_mutex;

    /**
     * Get current timestamp as ISO 8601 string
     */
    std::string GetTimestamp() const;

    /**
     * Hash params for privacy (SHA-3-256, first 16 chars)
     */
    std::string HashParams(const std::string& params) const;

    /**
     * Format log entry as JSON
     */
    std::string FormatLogEntry(const RequestLog& log) const;

    /**
     * Format security event as JSON
     */
    std::string FormatSecurityEvent(const std::string& event_type,
                                    const std::string& client_ip,
                                    const std::string& username,
                                    const std::string& details) const;

    /**
     * Open log files
     */
    void OpenLogFiles();

    /**
     * Close log files
     */
    void CloseLogFiles();
};

#endif // DILITHION_RPC_LOGGER_H

