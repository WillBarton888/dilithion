// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <util/system.h>
#include <iostream>
#include <cstdlib>
#include <sys/stat.h>

#ifdef _WIN32
    #include <direct.h>
    #include <windows.h>
    #define mkdir(path, mode) _mkdir(path)
#else
    #include <unistd.h>
    #include <pwd.h>
    #include <fcntl.h>      // For open() flags: O_CREAT, O_EXCL, O_WRONLY
    #include <errno.h>      // For errno and EEXIST
    #include <cstring>      // For strerror()
#endif

/**
 * Get home directory in a cross-platform way
 */
static std::string GetHomeDir() {
#ifdef _WIN32
    // Windows: Use USERPROFILE environment variable
    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile) {
        return std::string(userprofile);
    }

    // Fallback: Use HOMEDRIVE + HOMEPATH
    const char* homedrive = std::getenv("HOMEDRIVE");
    const char* homepath = std::getenv("HOMEPATH");
    if (homedrive && homepath) {
        return std::string(homedrive) + std::string(homepath);
    }

    // Last resort: C:\Users\<username>
    const char* username = std::getenv("USERNAME");
    if (username) {
        return "C:\\Users\\" + std::string(username);
    }

    return "C:\\";
#else
    // Linux/Mac: Use HOME environment variable
    const char* home = std::getenv("HOME");
    if (home) {
        return std::string(home);
    }

    // Fallback: Get from passwd database
    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_dir) {
        return std::string(pw->pw_dir);
    }

    return "/tmp";
#endif
}

std::string GetDataDir() {
    // Check for environment variable override
    const char* env_datadir = std::getenv("DILITHION_DATADIR");
    if (env_datadir) {
        return std::string(env_datadir);
    }

    // Default: ~/.dilithion (or %USERPROFILE%\.dilithion on Windows)
    std::string home = GetHomeDir();

#ifdef _WIN32
    return home + "\\.dilithion";
#else
    return home + "/.dilithion";
#endif
}

std::string GetDataDir(bool testnet) {
    if (!testnet) {
        return GetDataDir();
    }

    // Check for environment variable override
    const char* env_datadir = std::getenv("DILITHION_DATADIR");
    if (env_datadir) {
        return std::string(env_datadir) + "-testnet";
    }

    // Default: ~/.dilithion-testnet
    std::string home = GetHomeDir();

#ifdef _WIN32
    return home + "\\.dilithion-testnet";
#else
    return home + "/.dilithion-testnet";
#endif
}

bool EnsureDataDirExists(const std::string& path) {
    // Check if directory already exists
    struct stat info;
    if (stat(path.c_str(), &info) == 0) {
        if (info.st_mode & S_IFDIR) {
            return true;  // Directory exists
        } else {
            std::cerr << "ERROR: " << path << " exists but is not a directory" << std::endl;
            return false;
        }
    }

    // Create directory with secure permissions (0700 on Unix)
#ifdef _WIN32
    if (mkdir(path.c_str(), 0) != 0) {
        std::cerr << "ERROR: Failed to create directory: " << path << std::endl;
        return false;
    }

    // Set restrictive permissions on Windows (deny access to other users)
    // This is a simplified approach - production code should use proper Windows ACLs

#else
    if (mkdir(path.c_str(), 0700) != 0) {
        std::cerr << "ERROR: Failed to create directory: " << path << std::endl;
        return false;
    }
#endif

    std::cout << "Created data directory: " << path << std::endl;
    return true;
}

/**
 * PERSIST-004 FIX: Atomically create a file with exclusive access
 *
 * This function prevents TOCTOU (Time-Of-Check Time-Of-Use) race conditions
 * by using atomic file creation primitives:
 *
 * - POSIX: open() with O_CREAT | O_EXCL
 *   - O_CREAT: Create file if it doesn't exist
 *   - O_EXCL: Fail if file already exists
 *   - Combined: Atomic test-and-create operation
 *
 * - Windows: CreateFile() with CREATE_NEW disposition
 *   - CREATE_NEW: Create only if file doesn't exist
 *   - Fails with ERROR_FILE_EXISTS if file already exists
 *
 * Security Properties:
 * 1. Atomicity: Check-and-create happens in single kernel operation
 * 2. Exclusivity: Only ONE process can successfully create the file
 * 3. Race-free: No window between check and creation
 *
 * Use Case Example:
 *   Process A                    Process B
 *   ----------                   ----------
 *   AtomicCreateFile(...)        AtomicCreateFile(...)
 *     -> returns true              -> returns false (file exists)
 *   Safe to proceed              Must abort
 *
 * @param file_path Path to file to create
 * @return true if this process successfully created the file
 * @return false if file already exists (another process won)
 */
bool AtomicCreateFile(const std::string& file_path) {
#ifdef _WIN32
    // Windows: Use CreateFile with CREATE_NEW disposition
    HANDLE hFile = CreateFileA(
        file_path.c_str(),
        GENERIC_WRITE,              // Desired access
        0,                          // No sharing (exclusive)
        NULL,                       // Default security
        CREATE_NEW,                 // Create only if doesn't exist (atomic!)
        FILE_ATTRIBUTE_NORMAL,      // Normal file
        NULL                        // No template
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_EXISTS) {
            // Another process already created the file
            return false;
        }
        // Other error (permissions, disk full, etc.)
        std::cerr << "ERROR: Failed to create file atomically: " << file_path << std::endl;
        std::cerr << "       Windows error code: " << error << std::endl;
        return false;
    }

    // Successfully created file - close handle
    CloseHandle(hFile);
    return true;

#else
    // POSIX: Use open() with O_CREAT | O_EXCL
    int fd = open(file_path.c_str(),
                  O_CREAT | O_EXCL | O_WRONLY,  // Create exclusively, write-only
                  0600);                         // rw------- permissions

    if (fd == -1) {
        if (errno == EEXIST) {
            // Another process already created the file
            return false;
        }
        // Other error (permissions, disk full, etc.)
        std::cerr << "ERROR: Failed to create file atomically: " << file_path << std::endl;
        std::cerr << "       errno: " << errno << " (" << strerror(errno) << ")" << std::endl;
        return false;
    }

    // Successfully created file - close descriptor
    close(fd);
    return true;
#endif
}
