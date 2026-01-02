// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <util/pidfile.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
#else
    #include <unistd.h>
    #include <signal.h>
    #include <sys/stat.h>
#endif

// Platform-independent file operations
namespace {
    bool FileExists(const std::string& path) {
#ifdef _WIN32
        DWORD attrs = GetFileAttributesA(path.c_str());
        return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
#else
        struct stat st;
        return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
#endif
    }

    bool RemoveFile(const std::string& path) {
#ifdef _WIN32
        return DeleteFileA(path.c_str()) != 0;
#else
        return unlink(path.c_str()) == 0;
#endif
    }
}

CPidFile::CPidFile(const std::string& datadir)
    : m_datadir(datadir), m_acquired(false) {
    m_path = datadir + "/dilithion.pid";
}

CPidFile::~CPidFile() {
    if (m_acquired) {
        Release();
    }
}

bool CPidFile::TryAcquire() {
    if (m_acquired) {
        return true;  // Already acquired
    }

    // Check if PID file already exists
    if (FileExists(m_path)) {
        // Check if it's stale
        if (IsStale(m_path)) {
            std::cout << "[PidFile] Removing stale PID file from crashed process" << std::endl;
            RemoveFile(m_path);
        } else {
            // Another instance is running
            int pid = GetLockingPid();
            std::cerr << "[PidFile] Another instance is running (PID: " << pid << ")" << std::endl;
            return false;
        }
    }

    // Write our PID to the file
    std::ofstream file(m_path);
    if (!file.is_open()) {
        std::cerr << "[PidFile] Failed to create PID file: " << m_path << std::endl;
        return false;
    }

    file << GetCurrentPid() << std::endl;
    file.close();

    m_acquired = true;
    std::cout << "[PidFile] Acquired lock (PID: " << GetCurrentPid() << ")" << std::endl;

    return true;
}

void CPidFile::Release() {
    if (!m_acquired) {
        return;
    }

    if (FileExists(m_path)) {
        if (RemoveFile(m_path)) {
            std::cout << "[PidFile] Released lock" << std::endl;
        } else {
            std::cerr << "[PidFile] Failed to remove PID file" << std::endl;
        }
    }

    m_acquired = false;
}

int CPidFile::GetLockingPid() const {
    if (!FileExists(m_path)) {
        return 0;
    }

    std::ifstream file(m_path);
    if (!file.is_open()) {
        return 0;
    }

    int pid = 0;
    file >> pid;
    return pid;
}

bool CPidFile::IsStale(const std::string& pidfile_path) {
    if (!FileExists(pidfile_path)) {
        return false;  // No file means not stale
    }

    // Read PID from file
    std::ifstream file(pidfile_path);
    if (!file.is_open()) {
        return true;  // Can't read, assume stale
    }

    int pid = 0;
    file >> pid;
    file.close();

    if (pid <= 0) {
        return true;  // Invalid PID, assume stale
    }

    // Check if process is running
    return !IsProcessRunning(pid);
}

bool CPidFile::IsProcessRunning(int pid) {
#ifdef _WIN32
    // Windows: Use OpenProcess
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (process == NULL) {
        return false;  // Can't open - not running or no access
    }

    // Check if the process has exited
    DWORD exitCode = 0;
    BOOL result = GetExitCodeProcess(process, &exitCode);
    CloseHandle(process);

    if (!result) {
        return false;  // Can't get status
    }

    return (exitCode == STILL_ACTIVE);
#else
    // Unix: Use kill with signal 0 (doesn't actually send signal)
    if (kill(static_cast<pid_t>(pid), 0) == 0) {
        return true;  // Process exists and we have permission
    }

    // If errno is ESRCH, process doesn't exist
    // If errno is EPERM, process exists but we don't have permission
    return (errno == EPERM);
#endif
}

int CPidFile::GetCurrentPid() {
#ifdef _WIN32
    return static_cast<int>(GetCurrentProcessId());
#else
    return static_cast<int>(getpid());
#endif
}

bool CPidFile::RemoveStaleLocks(const std::string& datadir) {
    bool removed_any = false;

    // Check for stale LevelDB locks
    std::string blocks_lock = datadir + "/blocks/LOCK";
    std::string chainstate_lock = datadir + "/chainstate/LOCK";

    if (FileExists(blocks_lock)) {
        std::cout << "[PidFile] Removing stale blocks database lock" << std::endl;
        if (RemoveFile(blocks_lock)) {
            removed_any = true;
        } else {
            std::cerr << "[PidFile] Failed to remove " << blocks_lock << std::endl;
        }
    }

    if (FileExists(chainstate_lock)) {
        std::cout << "[PidFile] Removing stale chainstate database lock" << std::endl;
        if (RemoveFile(chainstate_lock)) {
            removed_any = true;
        } else {
            std::cerr << "[PidFile] Failed to remove " << chainstate_lock << std::endl;
        }
    }

    return removed_any;
}
