// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_LOGGING_H
#define DILITHION_UTIL_LOGGING_H

#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#include <vector>
#include <memory>
#include <cstdint>

/**
 * Bitcoin Core-style logging system
 *
 * Features:
 * - Log categories (NET, MEMPOOL, WALLET, etc.)
 * - Log levels (ERROR, WARN, INFO, DEBUG)
 * - Thread-safe logging
 * - File and console output
 * - Log rotation
 */

/**
 * Log categories (Bitcoin Core style)
 */
enum class LogCategory : uint32_t {
    NONE = 0,
    NET = (1 << 0),           // Network/P2P messages
    MEMPOOL = (1 << 1),       // Mempool operations
    WALLET = (1 << 2),        // Wallet operations
    RPC = (1 << 3),           // RPC server
    MINING = (1 << 4),        // Mining operations
    CONSENSUS = (1 << 5),     // Consensus validation
    IBD = (1 << 6),           // Initial Block Download
    VALIDATION = (1 << 7),    // Block/transaction validation
    ALL = 0xFFFFFFFF          // All categories
};

/**
 * Log levels
 * Note: Using LVL_ prefix to avoid conflicts with Windows ERROR macro
 */
enum class LogLevel {
    LVL_ERROR = 0,
    LVL_WARN = 1,
    LVL_INFO = 2,
    LVL_DEBUG = 3
};

/**
 * Logging configuration
 */
class CLoggingConfig {
public:
    static CLoggingConfig& GetInstance();

    // Enable/disable categories
    void EnableCategory(LogCategory category);
    void DisableCategory(LogCategory category);
    bool IsCategoryEnabled(LogCategory category) const;

    // Set log level
    void SetLogLevel(LogLevel level);
    LogLevel GetLogLevel() const;

    // File logging
    void SetLogFile(const std::string& path);
    std::string GetLogFile() const;
    bool IsFileLoggingEnabled() const { return !m_logFile.empty(); }

    // Console logging
    void SetConsoleLogging(bool enable);
    bool IsConsoleLoggingEnabled() const { return m_consoleLogging; }

    // Log rotation
    void SetMaxLogSize(size_t maxSize);
    void SetMaxLogFiles(size_t maxFiles);

private:
    CLoggingConfig();
    ~CLoggingConfig() = default;

    std::atomic<uint32_t> m_enabledCategories{static_cast<uint32_t>(LogCategory::ALL)};
    std::atomic<LogLevel> m_logLevel{LogLevel::LVL_INFO};
    std::string m_logFile;
    std::atomic<bool> m_consoleLogging{true};
    size_t m_maxLogSize{10 * 1024 * 1024};  // 10 MB default
    size_t m_maxLogFiles{10};
    mutable std::mutex m_configMutex;
};

/**
 * Main logging class
 */
class CLogger {
public:
    static CLogger& GetInstance();

    // Initialize logging system
    bool Initialize(const std::string& datadir);

    // Shutdown logging system
    void Shutdown();

    // Log a message
    void Log(LogCategory category, LogLevel level, const std::string& message);

    // Convenience methods (Bitcoin Core style)
    void LogPrint(LogCategory category, LogLevel level, const std::string& str);
    void LogPrintFormat(LogCategory category, LogLevel level, const char* format, ...);

private:
    CLogger();
    ~CLogger();

    // Rotate log file if needed
    void RotateLogIfNeeded();

    // Write to file
    void WriteToFile(const std::string& message);

    // Write to console
    void WriteToConsole(LogLevel level, const std::string& message);

    // Format log message (not FormatMessage to avoid Windows API conflict)
    std::string FormatLogMsg(LogCategory category, LogLevel level, const std::string& message);

    std::unique_ptr<std::ofstream> m_logFile;
    std::mutex m_logMutex;
    std::atomic<bool> m_initialized{false};
    size_t m_currentLogSize{0};
};

// Convenience macros (Bitcoin Core style)
// Note: Using LVL_ prefix internally to avoid Windows ERROR macro conflict
#define LogPrintf(category, level, format, ...) \
    CLogger::GetInstance().LogPrintFormat(LogCategory::category, LogLevel::LVL_##level, format, ##__VA_ARGS__)

// Category-specific macros (with format string)
#define LogPrintNet(level, format, ...) LogPrintf(NET, level, format, ##__VA_ARGS__)
#define LogPrintMempool(level, format, ...) LogPrintf(MEMPOOL, level, format, ##__VA_ARGS__)
#define LogPrintWallet(level, format, ...) LogPrintf(WALLET, level, format, ##__VA_ARGS__)
#define LogPrintRPC(level, format, ...) LogPrintf(RPC, level, format, ##__VA_ARGS__)
#define LogPrintMining(level, format, ...) LogPrintf(MINING, level, format, ##__VA_ARGS__)
#define LogPrintConsensus(level, format, ...) LogPrintf(CONSENSUS, level, format, ##__VA_ARGS__)
#define LogPrintIBD(level, format, ...) LogPrintf(IBD, level, format, ##__VA_ARGS__)
#define LogPrintValidation(level, format, ...) LogPrintf(VALIDATION, level, format, ##__VA_ARGS__)

// Legacy compatibility (for gradual migration)
#define LogInfo(...) LogPrintf(ALL, INFO, __VA_ARGS__)
#define LogError(...) LogPrintf(ALL, ERROR, __VA_ARGS__)
#define LogWarn(...) LogPrintf(ALL, WARN, __VA_ARGS__)
#define LogDebug(...) LogPrintf(ALL, DEBUG, __VA_ARGS__)

#endif // DILITHION_UTIL_LOGGING_H

