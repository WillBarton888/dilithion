// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <util/assert.h>
#include <iostream>
#include <cstdlib>
#include <sstream>

void AssertionFailure(const char* condition, const char* file, int line, const char* function) {
    std::cerr << "ASSERTION FAILED: " << condition << std::endl;
    std::cerr << "  File: " << file << ":" << line << std::endl;
    std::cerr << "  Function: " << function << std::endl;
    std::cerr << "  This indicates a programming error. Please report this bug." << std::endl;
    std::abort();
}

void InvariantFailure(const char* condition, const char* file, int line, const char* function) {
    std::cerr << "INVARIANT VIOLATION: " << condition << std::endl;
    std::cerr << "  File: " << file << ":" << line << std::endl;
    std::cerr << "  Function: " << function << std::endl;
    std::cerr << "  This indicates a serious bug. The program state may be corrupted." << std::endl;
    std::cerr << "  Please report this bug immediately." << std::endl;
    std::abort();
}

void ConsensusInvariantFailure(const char* condition, const char* file, int line, const char* function) {
    std::cerr << "CONSENSUS INVARIANT VIOLATION: " << condition << std::endl;
    std::cerr << "  File: " << file << ":" << line << std::endl;
    std::cerr << "  Function: " << function << std::endl;
    std::cerr << "  CRITICAL: This could cause a consensus fork!" << std::endl;
    std::cerr << "  The blockchain state may be inconsistent." << std::endl;
    std::cerr << "  Please report this bug immediately and do not continue running the node." << std::endl;
    std::abort();
}

