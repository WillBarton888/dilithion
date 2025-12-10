// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_VERSION_H
#define DILITHION_VERSION_H

// Version is managed by git tags - don't hardcode here
// Use GetVersionString() which reads from git or falls back to build date

#include <string>

/**
 * Get version string from git tag or build info
 * Returns format: "vX.Y.Z" or "dev-YYYYMMDD" if no tag
 */
std::string GetVersionString();

/**
 * Get full version info for display
 * Returns: "Dilithion Node vX.Y.Z" or "Dilithion Node (dev build)"
 */
std::string GetFullVersionString();

#endif // DILITHION_VERSION_H
