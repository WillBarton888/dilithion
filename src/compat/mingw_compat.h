// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

// This header provides compatibility stubs for GCC 15.2.0 with mingw64
// These C11 functions are not available in mingw64's C runtime

#ifndef DILITHION_MINGW_COMPAT_H
#define DILITHION_MINGW_COMPAT_H

#if defined(__MINGW32__) || defined(__MINGW64__)

#include <cstdlib>
#include <ctime>

// Provide stubs for missing C11 functions in mingw
#ifdef __cplusplus
extern "C" {
#endif

// at_quick_exit - register function to call on quick_exit
// Stub: just return success (we don't use quick_exit anyway)
#ifndef at_quick_exit
static inline int at_quick_exit(void (*func)(void)) {
    (void)func;
    return 0;
}
#endif

// quick_exit - terminate immediately without cleanup
// Stub: just call regular exit
#ifndef quick_exit
static inline void quick_exit(int status) {
    exit(status);
}
#endif

// timespec_get - get current time with timespec
// Stub: use time() for seconds, 0 for nanoseconds
#ifndef timespec_get
static inline int timespec_get(struct timespec* ts, int base) {
    (void)base;
    if (ts) {
        ts->tv_sec = time(NULL);
        ts->tv_nsec = 0;
    }
    return base; // Return base to indicate success
}
#endif

#ifdef __cplusplus
}
#endif

#endif // __MINGW32__ || __MINGW64__

#endif // DILITHION_MINGW_COMPAT_H
