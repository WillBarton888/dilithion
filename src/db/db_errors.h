// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DB_DB_ERRORS_H
#define DILITHION_DB_DB_ERRORS_H

#include <leveldb/status.h>
#include <string>

/**
 * Database error classification and handling
 * 
 * Phase 4.2: Hardens LevelDB error paths by classifying errors
 * and providing appropriate recovery strategies.
 * 
 * Pattern from Bitcoin Core database error handling.
 */

/**
 * Database error types
 */
enum class DBErrorType {
    OK,                    // No error
    CORRUPTION,            // Data corruption detected
    IO_ERROR,              // I/O error (disk full, permission denied, etc.)
    NOT_FOUND,             // Key not found (normal for some operations)
    INVALID_ARGUMENT,      // Invalid argument passed to DB operation
    NOT_SUPPORTED,         // Operation not supported
    UNKNOWN                // Unknown error type
};

/**
 * Classify LevelDB status into error type
 * 
 * @param status LevelDB status to classify
 * @return Error type classification
 */
DBErrorType ClassifyDBError(const leveldb::Status& status);

/**
 * Check if error is recoverable
 * 
 * @param error_type Error type to check
 * @return true if error is recoverable, false otherwise
 */
bool IsRecoverableError(DBErrorType error_type);

/**
 * Get human-readable error message
 * 
 * @param status LevelDB status
 * @param error_type Classified error type
 * @return Human-readable error message
 */
std::string GetDBErrorMessage(const leveldb::Status& status, DBErrorType error_type);

/**
 * Check if error indicates corruption
 */
bool IsCorruptionError(const leveldb::Status& status);

/**
 * Check if error indicates I/O problem (disk full, permission, etc.)
 */
bool IsIOError(const leveldb::Status& status);

#endif // DILITHION_DB_DB_ERRORS_H

