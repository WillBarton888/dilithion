// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_SYSTEM_H
#define DILITHION_UTIL_SYSTEM_H

#include <string>

/**
 * Get the default data directory for Dilithion
 *
 * Returns:
 * - Windows: %USERPROFILE%\.dilithion
 * - Linux/Mac: ~/.dilithion
 *
 * Can be overridden with DILITHION_DATADIR environment variable
 */
std::string GetDataDir();

/**
 * Get the default data directory for a specific network
 *
 * @param testnet If true, returns testnet data directory
 * Returns:
 * - Mainnet: ~/.dilithion
 * - Testnet: ~/.dilithion-testnet
 */
std::string GetDataDir(bool testnet);

/**
 * Ensure data directory exists, creating it if necessary
 *
 * @param path Directory path to create
 * @return true if directory exists or was created successfully
 */
bool EnsureDataDirExists(const std::string& path);

/**
 * PERSIST-004 FIX: Atomically create a file with exclusive access
 *
 * Uses O_CREAT | O_EXCL on POSIX or CREATE_NEW on Windows to prevent TOCTOU races.
 * This ensures only ONE process can successfully create the file.
 *
 * @param file_path Path to file to create
 * @return true if file was created successfully (this process won the race)
 * @return false if file already exists (another process won the race)
 *
 * Use case: Preventing race conditions in first-run wallet initialization
 *
 * Example:
 *   if (AtomicCreateFile(sentinel_path)) {
 *       // This process won - safe to create wallet
 *   } else {
 *       // Another process is creating wallet - abort
 *   }
 */
bool AtomicCreateFile(const std::string& file_path);

#endif // DILITHION_UTIL_SYSTEM_H
