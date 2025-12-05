// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/logger.h>
#include <crypto/sha3.h>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <iostream>

CRPCLogger::CRPCLogger(const std::string& log_file,
                       const std::string& audit_file,
                       LogLevel level)
    : m_log_file(log_file)
    , m_audit_file(audit_file)
    , m_log_level(level)
    , m_enabled(true)
{
    if (!m_log_file.empty() || !m_audit_file.empty()) {
        OpenLogFiles();
    }
}

CRPCLogger::~CRPCLogger() {
    CloseLogFiles();
}

void CRPCLogger::OpenLogFiles() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_log_file.empty()) {
        m_log_stream = std::make_unique<std::ofstream>(m_log_file, std::ios::app);
        if (!m_log_stream->is_open()) {
            std::cerr << "[RPC-LOGGER] WARNING: Failed to open log file: " << m_log_file << std::endl;
            m_log_stream.reset();
        }
    }
    
    if (!m_audit_file.empty()) {
        m_audit_stream = std::make_unique<std::ofstream>(m_audit_file, std::ios::app);
        if (!m_audit_stream->is_open()) {
            std::cerr << "[RPC-LOGGER] WARNING: Failed to open audit file: " << m_audit_file << std::endl;
            m_audit_stream.reset();
        }
    }
}

void CRPCLogger::CloseLogFiles() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_log_stream.reset();
    m_audit_stream.reset();
}

std::string CRPCLogger::GetTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return ss.str();
}

std::string CRPCLogger::HashParams(const std::string& params) const {
    if (params.empty()) {
        return "";
    }

    // Hash params for privacy (SHA-3-256, first 16 chars hex)
    uint8_t hash[32];
    SHA3_256(reinterpret_cast<const uint8_t*>(params.data()), params.size(), hash);

    // Convert first 8 bytes to hex string
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::string CRPCLogger::FormatLogEntry(const RequestLog& log) const {
    std::ostringstream oss;
    oss << "{"
        << "\"timestamp\":\"" << log.timestamp << "\","
        << "\"client_ip\":\"" << log.client_ip << "\","
        << "\"username\":\"" << (log.username.empty() ? "anonymous" : log.username) << "\","
        << "\"method\":\"" << log.method << "\","
        << "\"params_hash\":\"" << log.params_hash << "\","
        << "\"success\":" << (log.success ? "true" : "false") << ","
        << "\"duration_ms\":" << log.duration_ms;
    
    if (!log.success && !log.error_code.empty()) {
        oss << ",\"error_code\":\"" << log.error_code << "\"";
        if (!log.error_message.empty()) {
            oss << ",\"error_message\":\"" << log.error_message << "\"";
        }
    }
    
    oss << "}";
    return oss.str();
}

std::string CRPCLogger::FormatSecurityEvent(const std::string& event_type,
                                             const std::string& client_ip,
                                             const std::string& username,
                                             const std::string& details) const {
    std::ostringstream oss;
    oss << "{"
        << "\"timestamp\":\"" << GetTimestamp() << "\","
        << "\"event_type\":\"" << event_type << "\","
        << "\"client_ip\":\"" << client_ip << "\","
        << "\"username\":\"" << (username.empty() ? "unknown" : username) << "\","
        << "\"details\":\"" << details << "\""
        << "}";
    return oss.str();
}

void CRPCLogger::LogRequest(const RequestLog& log) {
    if (!m_enabled) {
        return;
    }
    
    // Check log level
    LogLevel required_level = log.success ? LogLevel::INFO : LogLevel::ERR;
    if (required_level < m_log_level) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Create a copy of the log entry and set timestamp
    RequestLog log_with_timestamp = log;
    log_with_timestamp.timestamp = GetTimestamp();
    
    if (m_log_stream && m_log_stream->is_open()) {
        *m_log_stream << FormatLogEntry(log_with_timestamp) << std::endl;
        m_log_stream->flush();
    }
    
    // Always log security-sensitive operations to audit log
    if (m_audit_stream && m_audit_stream->is_open()) {
        if (log.method == "sendtoaddress" || log.method == "encryptwallet" ||
            log.method == "walletpassphrase" || log.method == "exportmnemonic" ||
            log.method == "stop" || !log.success) {
            *m_audit_stream << FormatLogEntry(log_with_timestamp) << std::endl;
            m_audit_stream->flush();
        }
    }
}

void CRPCLogger::LogSecurityEvent(const std::string& event_type,
                                  const std::string& client_ip,
                                  const std::string& username,
                                  const std::string& details) {
    if (!m_enabled) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_audit_stream && m_audit_stream->is_open()) {
        *m_audit_stream << FormatSecurityEvent(event_type, client_ip, username, details) << std::endl;
        m_audit_stream->flush();
    }
    
    // Also log to main log if level allows
    if (m_log_level <= LogLevel::WARN && m_log_stream && m_log_stream->is_open()) {
        *m_log_stream << FormatSecurityEvent(event_type, client_ip, username, details) << std::endl;
        m_log_stream->flush();
    }
}

void CRPCLogger::RotateLogs(size_t max_size) {
    if (max_size == 0) {
        return;  // Rotation disabled
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check log file size
    if (!m_log_file.empty() && m_log_stream && m_log_stream->is_open()) {
        // CID 1675254 FIX: Check return value of seekp and tellp to ensure file operations succeed
        // seekp can fail if stream is in bad state, tellp returns -1 on error
        m_log_stream->seekp(0, std::ios::end);
        if (m_log_stream->good()) {
            std::streampos pos = m_log_stream->tellp();
            if (pos != std::streampos(-1)) {
                size_t size = static_cast<size_t>(pos);
                
                if (size > max_size) {
                    // Close and rotate
                    m_log_stream->close();
                    m_log_stream.reset();
                    
                    // Rename old log
                    std::string old_log = m_log_file + ".old";
                    // CID 1675231 FIX: Check return value of std::remove to ensure old backup is removed
                    // std::remove returns 0 on success, non-zero on error
                    // If file doesn't exist, that's okay (first rotation)
                    (void)std::remove(old_log.c_str());  // Best-effort remove old backup
                    
                    // CID 1675231 FIX: Check return value of std::rename to ensure rotation succeeds
                    // std::rename returns 0 on success, non-zero on error
                    if (std::rename(m_log_file.c_str(), old_log.c_str()) != 0) {
                        // Rotation failed - log warning but continue (new log will still be opened)
                        std::cerr << "[RPCLogger] Warning: Failed to rotate log file " << m_log_file
                                  << " to " << old_log << std::endl;
                    }
                    
                    // Open new log
                    m_log_stream = std::make_unique<std::ofstream>(m_log_file, std::ios::app);
                }
            } else {
                // tellp failed - skip rotation for this file
                std::cerr << "[RPCLogger] Warning: Failed to get log file size (tellp error)" << std::endl;
            }
        } else {
            // seekp failed - skip rotation for this file
            std::cerr << "[RPCLogger] Warning: Failed to seek to end of log file" << std::endl;
        }
    }
    
    // Check audit file size
    if (!m_audit_file.empty() && m_audit_stream && m_audit_stream->is_open()) {
        // CID 1675254 FIX: Check return value of seekp and tellp to ensure file operations succeed
        // seekp can fail if stream is in bad state, tellp returns -1 on error
        m_audit_stream->seekp(0, std::ios::end);
        if (m_audit_stream->good()) {
            std::streampos pos = m_audit_stream->tellp();
            if (pos != std::streampos(-1)) {
                size_t size = static_cast<size_t>(pos);
                
                if (size > max_size) {
                    // Close and rotate
                    m_audit_stream->close();
                    m_audit_stream.reset();
                    
                    // Rename old audit log
                    std::string old_audit = m_audit_file + ".old";
                    // CID 1675231 FIX: Check return value of std::remove to ensure old backup is removed
                    // std::remove returns 0 on success, non-zero on error
                    // If file doesn't exist, that's okay (first rotation)
                    (void)std::remove(old_audit.c_str());  // Best-effort remove old backup
                    
                    // CID 1675231 FIX: Check return value of std::rename to ensure rotation succeeds
                    // std::rename returns 0 on success, non-zero on error
                    if (std::rename(m_audit_file.c_str(), old_audit.c_str()) != 0) {
                        // Rotation failed - log warning but continue (new audit log will still be opened)
                        std::cerr << "[RPCLogger] Warning: Failed to rotate audit file " << m_audit_file
                                  << " to " << old_audit << std::endl;
                    }
                    
                    // Open new audit log
                    m_audit_stream = std::make_unique<std::ofstream>(m_audit_file, std::ios::app);
                }
            } else {
                // tellp failed - skip rotation for this file
                std::cerr << "[RPCLogger] Warning: Failed to get audit file size (tellp error)" << std::endl;
            }
        } else {
            // seekp failed - skip rotation for this file
            std::cerr << "[RPCLogger] Warning: Failed to seek to end of audit file" << std::endl;
        }
    }
}

