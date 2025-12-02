// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <db/db_errors.h>
#include <util/logging.h>
#include <cstring>

DBErrorType ClassifyDBError(const leveldb::Status& status) {
    if (status.ok()) {
        return DBErrorType::OK;
    }
    
    if (status.IsCorruption()) {
        return DBErrorType::CORRUPTION;
    }
    
    if (status.IsIOError()) {
        return DBErrorType::IO_ERROR;
    }
    
    if (status.IsNotFound()) {
        return DBErrorType::NOT_FOUND;
    }
    
    if (status.IsInvalidArgument()) {
        return DBErrorType::INVALID_ARGUMENT;
    }
    
    if (status.IsNotSupportedError()) {
        return DBErrorType::NOT_SUPPORTED;
    }
    
    return DBErrorType::UNKNOWN;
}

bool IsRecoverableError(DBErrorType error_type) {
    switch (error_type) {
        case DBErrorType::OK:
        case DBErrorType::NOT_FOUND:
            return true;  // These are not errors or expected conditions
        
        case DBErrorType::CORRUPTION:
            return false;  // Requires -reindex
        
        case DBErrorType::IO_ERROR:
            // Some I/O errors are recoverable (e.g., temporary network issues)
            // Others are not (e.g., disk full, permission denied)
            return false;  // Conservative: assume not recoverable
        
        case DBErrorType::INVALID_ARGUMENT:
        case DBErrorType::NOT_SUPPORTED:
        case DBErrorType::UNKNOWN:
            return false;
    }
    return false;
}

std::string GetDBErrorMessage(const leveldb::Status& status, DBErrorType error_type) {
    std::string message;
    
    switch (error_type) {
        case DBErrorType::OK:
            message = "Success";
            break;
        
        case DBErrorType::CORRUPTION:
            message = "Database corruption detected: " + status.ToString();
            message += " (use -reindex to rebuild)";
            break;
        
        case DBErrorType::IO_ERROR:
            message = "I/O error: " + status.ToString();
            message += " (check disk space and permissions)";
            break;
        
        case DBErrorType::NOT_FOUND:
            message = "Key not found (this may be normal)";
            break;
        
        case DBErrorType::INVALID_ARGUMENT:
            message = "Invalid argument: " + status.ToString();
            break;
        
        case DBErrorType::NOT_SUPPORTED:
            message = "Operation not supported: " + status.ToString();
            break;
        
        case DBErrorType::UNKNOWN:
            message = "Unknown database error: " + status.ToString();
            break;
    }
    
    return message;
}

bool IsCorruptionError(const leveldb::Status& status) {
    return status.IsCorruption();
}

bool IsIOError(const leveldb::Status& status) {
    return status.IsIOError();
}

