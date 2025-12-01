// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_ASSERT_H
#define DILITHION_UTIL_ASSERT_H

#include <cassert>
#include <string>

/**
 * Bitcoin Core-style assertion macros for validation and debugging
 *
 * These macros provide better error messages and can be disabled in release builds
 * for performance, while still catching bugs during development.
 */

/**
 * Assert that a condition is true
 * In debug builds, aborts with error message if condition is false
 * In release builds, compiles to nothing (no performance cost)
 */
#ifdef NDEBUG
#define Assert(condition) ((void)0)
#else
#define Assert(condition) \
    do { \
        if (!(condition)) { \
            AssertionFailure(#condition, __FILE__, __LINE__, __func__); \
        } \
    } while (0)
#endif

/**
 * Assert that a mutex is held by the current thread
 * Used to verify thread safety assumptions
 */
#define AssertLockHeld(cs) Assert((cs).owns_lock() || (cs).try_lock())

/**
 * Assert that a mutex is NOT held by the current thread
 * Used to prevent deadlocks
 */
#define AssertLockNotHeld(cs) Assert(!(cs).owns_lock())

/**
 * Assert that a pointer is not null
 */
#define AssertNotNull(ptr) Assert((ptr) != nullptr)

/**
 * Assert that a value is within a valid range
 */
#define AssertRange(value, min, max) \
    Assert((value) >= (min) && (value) <= (max))

/**
 * Assert that a container is not empty
 */
#define AssertNotEmpty(container) Assert(!(container).empty())

/**
 * Assert that an index is valid for a container
 */
#define AssertIndexValid(container, index) \
    Assert((index) >= 0 && (index) < (container).size())

/**
 * Invariant check - should always be true if code is correct
 * Unlike Assert, invariants should never be disabled, even in release builds
 * These catch serious bugs that could cause consensus failures
 */
#define Invariant(condition) \
    do { \
        if (!(condition)) { \
            InvariantFailure(#condition, __FILE__, __LINE__, __func__); \
        } \
    } while (0)

/**
 * Consensus invariant - must be true for consensus correctness
 * These are the most critical checks and should never be disabled
 */
#define ConsensusInvariant(condition) \
    do { \
        if (!(condition)) { \
            ConsensusInvariantFailure(#condition, __FILE__, __LINE__, __func__); \
        } \
    } while (0)

// Internal functions (implemented in assert.cpp)
void AssertionFailure(const char* condition, const char* file, int line, const char* function);
void InvariantFailure(const char* condition, const char* file, int line, const char* function);
void ConsensusInvariantFailure(const char* condition, const char* file, int line, const char* function);

#endif // DILITHION_UTIL_ASSERT_H

