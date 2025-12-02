// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_STACKTRACE_H
#define DILITHION_UTIL_STACKTRACE_H

#include <string>
#include <vector>

/**
 * Stack trace utilities for crash diagnostics
 * 
 * Provides stack trace capture and formatting for debug builds.
 * On release builds, provides minimal information.
 * 
 * Pattern from Bitcoin Core crash reporting utilities.
 */

/**
 * Capture current stack trace
 * 
 * @param skip_frames Number of frames to skip from the top
 * @return Vector of stack frame strings
 */
std::vector<std::string> CaptureStackTrace(int skip_frames = 0);

/**
 * Format stack trace as a single string
 * 
 * @param frames Stack frames from CaptureStackTrace()
 * @return Formatted stack trace string
 */
std::string FormatStackTrace(const std::vector<std::string>& frames);

/**
 * Get a formatted stack trace string (convenience function)
 * 
 * @param skip_frames Number of frames to skip from the top
 * @return Formatted stack trace string
 */
std::string GetStackTrace(int skip_frames = 0);

#endif // DILITHION_UTIL_STACKTRACE_H

