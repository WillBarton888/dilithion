// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * MinGW C11 Compatibility Layer
 *
 * GCC 15+ requires C11 functions (at_quick_exit, quick_exit, timespec_get)
 * that are not available in MinGW64's C runtime. This header provides
 * these functions to satisfy the libstdc++ requirements.
 *
 * This must be included BEFORE any C++ standard library headers.
 */

#ifndef DILITHION_MINGW_C11_COMPAT_H
#define DILITHION_MINGW_C11_COMPAT_H

#if defined(__MINGW32__) || defined(__MINGW64__)

// Only apply if these functions are not already defined
#ifndef __MINGW_C11_COMPAT_APPLIED
#define __MINGW_C11_COMPAT_APPLIED

#ifdef __cplusplus
#include <cstdlib>  // For std::exit
#include <ctime>    // For time_t, timespec
#else
#include <stdlib.h>
#include <time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// C11 at_quick_exit - register a function to be called at quick_exit
// MinGW doesn't have this, so we provide a no-op stub
#if !defined(at_quick_exit) && !defined(__at_quick_exit_defined)
#define __at_quick_exit_defined 1
inline int at_quick_exit(void (*func)(void)) {
    (void)func;
    return 0;  // Success
}
#endif

// C11 quick_exit - similar to exit but calls different atexit handlers
// MinGW doesn't have this, so we fall back to regular exit
#if !defined(quick_exit) && !defined(__quick_exit_defined)
#define __quick_exit_defined 1
#ifdef __cplusplus
[[noreturn]]
#else
_Noreturn
#endif
inline void quick_exit(int status) {
#ifdef __cplusplus
    std::exit(status);
#else
    exit(status);
#endif
}
#endif

// C11 timespec_get - get current calendar time in timespec format
// MinGW doesn't have this, so we implement using time()
#if !defined(timespec_get) && !defined(__timespec_get_defined)
#define __timespec_get_defined 1
#ifndef TIME_UTC
#define TIME_UTC 1
#endif
inline int timespec_get(struct timespec* ts, int base) {
    if (ts && base == TIME_UTC) {
        ts->tv_sec = time(NULL);
        ts->tv_nsec = 0;
        return base;  // Return base to indicate success
    }
    return 0;  // Failure
}
#endif

#ifdef __cplusplus
}
#endif

#endif // __MINGW_C11_COMPAT_APPLIED
#endif // __MINGW32__ || __MINGW64__

#endif // DILITHION_MINGW_C11_COMPAT_H
