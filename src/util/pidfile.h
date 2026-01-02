// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_PIDFILE_H
#define DILITHION_UTIL_PIDFILE_H

#include <string>

/**
 * CPidFile - PID file for single instance detection
 *
 * STRESS TEST FIX: Issue 3 - Database lock cleanup failure.
 * When a node crashes, it may leave behind stale LevelDB lock files
 * that prevent restart. This class manages a PID file that allows
 * detection of stale locks from crashed processes.
 *
 * Usage:
 *   CPidFile pidfile(data_dir);
 *   if (!pidfile.TryAcquire()) {
 *       if (CPidFile::IsStale(data_dir + "/dilithion.pid")) {
 *           std::cout << "Cleaning up stale locks from crashed process" << std::endl;
 *           fs::remove(data_dir + "/blocks/LOCK");
 *           pidfile.TryAcquire();  // Retry
 *       } else {
 *           std::cerr << "Another instance is running" << std::endl;
 *           return false;
 *       }
 *   }
 *
 *   // On shutdown:
 *   pidfile.Release();
 */
class CPidFile {
public:
    /**
     * Constructor
     * @param datadir Data directory path
     */
    explicit CPidFile(const std::string& datadir);

    /**
     * Destructor - releases PID file if acquired
     */
    ~CPidFile();

    // Non-copyable, non-movable
    CPidFile(const CPidFile&) = delete;
    CPidFile& operator=(const CPidFile&) = delete;

    /**
     * Try to acquire the PID file lock
     * Creates a file with the current process ID.
     * @return true if acquired, false if another instance is running
     */
    bool TryAcquire();

    /**
     * Release the PID file lock
     * Removes the PID file.
     */
    void Release();

    /**
     * Check if the PID file lock is acquired
     */
    bool IsAcquired() const { return m_acquired; }

    /**
     * Get PID of the process that holds the lock
     * @return PID if file exists and readable, 0 otherwise
     */
    int GetLockingPid() const;

    /**
     * Check if a PID file is stale (process no longer running)
     * @param pidfile_path Full path to the PID file
     * @return true if PID file exists but process is not running
     */
    static bool IsStale(const std::string& pidfile_path);

    /**
     * Check if a process is running
     * @param pid Process ID to check
     * @return true if process is running
     */
    static bool IsProcessRunning(int pid);

    /**
     * Get current process ID
     * @return Current process ID
     */
    static int GetCurrentPid();

    /**
     * Remove stale database lock files
     * @param datadir Data directory path
     * @return true if any locks were removed
     */
    static bool RemoveStaleLocks(const std::string& datadir);

private:
    std::string m_path;       // Full path to PID file
    std::string m_datadir;    // Data directory
    bool m_acquired{false};   // Whether we hold the lock
};

#endif // DILITHION_UTIL_PIDFILE_H
