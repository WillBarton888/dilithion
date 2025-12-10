// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_COMPAT_H
#define DILITHION_UTIL_COMPAT_H

// Workaround for GCC 15.2.0 mingw64 compatibility issues
// These C11 functions are not available in some mingw64 configurations

#ifdef __MINGW32__
#include <cstdlib>
#include <ctime>

// Stub implementations for missing C11 functions
#ifndef __MINGW64_VERSION_MAJOR
// These are already defined in newer mingw64
#endif

// MinGW may not have at_quick_exit and quick_exit
// We provide no-op stubs since they're not critical for our use
#ifdef __cplusplus
extern "C" {
#endif

#ifndef at_quick_exit
inline int at_quick_exit(void (*)(void)) { return 0; }
#endif

#ifndef quick_exit
[[noreturn]] inline void quick_exit(int status) { std::exit(status); }
#endif

#ifndef timespec_get
inline int timespec_get(struct timespec* ts, int base) {
    (void)base;
    if (ts) {
        ts->tv_sec = 0;
        ts->tv_nsec = 0;
    }
    return 0;
}
#endif

#ifdef __cplusplus
}
#endif

#endif // __MINGW32__

#endif // DILITHION_UTIL_COMPAT_H
