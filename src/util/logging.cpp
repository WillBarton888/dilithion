// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <util/logging.h>
#include <util/system.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <cstdarg>
#include <cstdio>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>  // CID 1675220: For GetLastError and ERROR_FILE_NOT_FOUND
#else
#include <errno.h>  // CID 1675220: For errno and ENOENT
#include <cstring>  // CID 1675220: For strerror
#endif

// CLoggingConfig implementation
CLoggingConfig& CLoggingConfig::GetInstance() {
    static CLoggingConfig instance;
    return instance;
}

CLoggingConfig::CLoggingConfig() {
    // Default: enable all categories, INFO level
    m_enabledCategories = static_cast<uint32_t>(LogCategory::ALL);
    m_logLevel = LogLevel::LVL_INFO;
}

void CLoggingConfig::EnableCategory(LogCategory category) {
    uint32_t cat = static_cast<uint32_t>(category);
    uint32_t current = m_enabledCategories.load();
    m_enabledCategories.store(current | cat);
}

void CLoggingConfig::DisableCategory(LogCategory category) {
    uint32_t cat = static_cast<uint32_t>(category);
    uint32_t current = m_enabledCategories.load();
    m_enabledCategories.store(current & ~cat);
}

bool CLoggingConfig::IsCategoryEnabled(LogCategory category) const {
    uint32_t cat = static_cast<uint32_t>(category);
    uint32_t enabled = m_enabledCategories.load();
    return (enabled & cat) != 0;
}

void CLoggingConfig::SetLogLevel(LogLevel level) {
    m_logLevel.store(level);
}

LogLevel CLoggingConfig::GetLogLevel() const {
    return m_logLevel.load();
}

void CLoggingConfig::SetLogFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_configMutex);
    m_logFile = path;
}

std::string CLoggingConfig::GetLogFile() const {
    std::lock_guard<std::mutex> lock(m_configMutex);
    return m_logFile;
}

// CID 1675300 FIX: Acquire lock before reading m_logFile to prevent data race
bool CLoggingConfig::IsFileLoggingEnabled() const {
    std::lock_guard<std::mutex> lock(m_configMutex);
    return !m_logFile.empty();
}

void CLoggingConfig::SetConsoleLogging(bool enable) {
    m_consoleLogging.store(enable);
}

void CLoggingConfig::SetMaxLogSize(size_t maxSize) {
    std::lock_guard<std::mutex> lock(m_configMutex);
    m_maxLogSize = maxSize;
}

void CLoggingConfig::SetMaxLogFiles(size_t maxFiles) {
    std::lock_guard<std::mutex> lock(m_configMutex);
    m_maxLogFiles = maxFiles;
}

// CLogger implementation
CLogger& CLogger::GetInstance() {
    static CLogger instance;
    return instance;
}

CLogger::CLogger() {
}

CLogger::~CLogger() {
    Shutdown();
}

bool CLogger::Initialize(const std::string& datadir) {
    std::lock_guard<std::mutex> lock(m_logMutex);

    if (m_initialized.load()) {
        return true;  // Already initialized
    }

    CLoggingConfig& config = CLoggingConfig::GetInstance();

    // Open log file if configured
    if (config.IsFileLoggingEnabled()) {
        std::string logPath = config.GetLogFile();
        if (logPath.empty()) {
            // Default log file in datadir
            logPath = datadir + "/debug.log";
        }

        m_logFile = std::make_unique<std::ofstream>(logPath, std::ios::app);
        if (!m_logFile->is_open()) {
            std::cerr << "Warning: Failed to open log file: " << logPath << std::endl;
            return false;
        }

        // Get current file size
        m_logFile->seekp(0, std::ios::end);
        m_currentLogSize = m_logFile->tellp();
    }

    m_initialized.store(true);
    return true;
}

void CLogger::Shutdown() {
    std::lock_guard<std::mutex> lock(m_logMutex);

    if (m_logFile && m_logFile->is_open()) {
        m_logFile->flush();
        m_logFile->close();
    }

    m_initialized.store(false);
}

void CLogger::Log(LogCategory category, LogLevel level, const std::string& message) {
    CLoggingConfig& config = CLoggingConfig::GetInstance();

    // Check if category is enabled
    if (!config.IsCategoryEnabled(category)) {
        return;
    }

    // Check if log level is high enough
    if (level > config.GetLogLevel()) {
        return;
    }

    std::string formatted = FormatLogMsg(category, level, message);

    std::lock_guard<std::mutex> lock(m_logMutex);

    // Write to console
    if (config.IsConsoleLoggingEnabled()) {
        WriteToConsole(level, formatted);
    }

    // Write to file
    if (m_initialized.load() && m_logFile && m_logFile->is_open()) {
        WriteToFile(formatted);
    }
}

void CLogger::LogPrint(LogCategory category, LogLevel level, const std::string& str) {
    Log(category, level, str);
}

void CLogger::LogPrintFormat(LogCategory category, LogLevel level, const char* format, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    Log(category, level, std::string(buffer));
}

void CLogger::RotateLogIfNeeded() {
    CLoggingConfig& config = CLoggingConfig::GetInstance();

    size_t maxSize = 10 * 1024 * 1024;  // Default 10 MB
    if (m_currentLogSize < maxSize) {
        return;  // No rotation needed
    }

    if (!m_logFile || !m_logFile->is_open()) {
        return;
    }

    std::string logPath = config.GetLogFile();
    if (logPath.empty()) {
        return;
    }

    // Close current log file
    m_logFile->flush();
    m_logFile->close();

    // Rotate existing log files
    size_t maxFiles = 10;  // Default
    for (size_t i = maxFiles - 1; i > 0; i--) {
        std::string oldFile = logPath + "." + std::to_string(i);
        std::string newFile = logPath + "." + std::to_string(i + 1);
        
        // Rename old file
        // CID 1675220 FIX: Check return value of rename/MoveFileA to ensure rotation succeeds
        // If file doesn't exist, that's okay (not all rotated files may exist yet)
        #ifdef _WIN32
            if (!MoveFileA(oldFile.c_str(), newFile.c_str())) {
                DWORD error = GetLastError();
                // ERROR_FILE_NOT_FOUND is expected if rotated file doesn't exist yet
                if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                    // Actual error - log warning but continue rotation
                    std::cerr << "[Logger] Warning: Failed to rotate log file " << oldFile
                              << " to " << newFile << " (error: " << error << ")" << std::endl;
                }
            }
        #else
            if (rename(oldFile.c_str(), newFile.c_str()) != 0) {
                // ENOENT is expected if rotated file doesn't exist yet
                if (errno != ENOENT) {
                    // Actual error - log warning but continue rotation
                    std::cerr << "[Logger] Warning: Failed to rotate log file " << oldFile
                              << " to " << newFile << " (" << strerror(errno) << ")" << std::endl;
                }
            }
        #endif
    }

    // Move current log to .1
    std::string rotatedFile = logPath + ".1";
    // CID 1675220 FIX: Check return value of rename/MoveFileA to ensure rotation succeeds
    #ifdef _WIN32
        if (!MoveFileA(logPath.c_str(), rotatedFile.c_str())) {
            DWORD error = GetLastError();
            // Log error but continue - new log file will still be opened
            std::cerr << "[Logger] Warning: Failed to rotate current log file to " << rotatedFile
                      << " (error: " << error << ")" << std::endl;
        }
    #else
        if (rename(logPath.c_str(), rotatedFile.c_str()) != 0) {
            // Log error but continue - new log file will still be opened
            std::cerr << "[Logger] Warning: Failed to rotate current log file to " << rotatedFile
                      << " (" << strerror(errno) << ")" << std::endl;
        }
    #endif

    // Open new log file
    m_logFile = std::make_unique<std::ofstream>(logPath, std::ios::trunc);
    m_currentLogSize = 0;
}

void CLogger::WriteToFile(const std::string& message) {
    if (!m_logFile || !m_logFile->is_open()) {
        return;
    }

    RotateLogIfNeeded();

    *m_logFile << message << std::endl;
    m_logFile->flush();
    m_currentLogSize += message.size() + 1;  // +1 for newline
}

void CLogger::WriteToConsole(LogLevel level, const std::string& message) {
    std::ostream& stream = (level == LogLevel::LVL_ERROR) ? std::cerr : std::cout;
    stream << message << std::endl;
}

std::string CLogger::FormatLogMsg(LogCategory category, LogLevel level, const std::string& message) {
    std::ostringstream oss;

    // Timestamp
    std::time_t now = std::time(nullptr);
    std::tm* tm = std::localtime(&now);
    oss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");

    // Log level
    const char* levelStr = "";
    switch (level) {
        case LogLevel::LVL_ERROR: levelStr = "ERROR"; break;
        case LogLevel::LVL_WARN: levelStr = "WARN"; break;
        case LogLevel::LVL_INFO: levelStr = "INFO"; break;
        case LogLevel::LVL_DEBUG: levelStr = "DEBUG"; break;
    }
    oss << " [" << levelStr << "]";

    // Category
    const char* catStr = "";
    switch (category) {
        case LogCategory::NET: catStr = "NET"; break;
        case LogCategory::MEMPOOL: catStr = "MEMPOOL"; break;
        case LogCategory::WALLET: catStr = "WALLET"; break;
        case LogCategory::RPC: catStr = "RPC"; break;
        case LogCategory::MINING: catStr = "MINING"; break;
        case LogCategory::CONSENSUS: catStr = "CONSENSUS"; break;
        case LogCategory::IBD: catStr = "IBD"; break;
        case LogCategory::VALIDATION: catStr = "VALIDATION"; break;
        default: catStr = ""; break;
    }
    if (catStr[0] != '\0') {
        oss << " [" << catStr << "]";
    }

    // Message
    oss << " " << message;

    return oss.str();
}

