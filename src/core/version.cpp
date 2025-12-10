// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <core/version.h>

// These are set by the build system (Makefile)
// If not defined, fall back to "dev"
#ifndef DILITHION_VERSION
#define DILITHION_VERSION "dev"
#endif

#ifndef DILITHION_BUILD_DATE
#define DILITHION_BUILD_DATE __DATE__
#endif

std::string GetVersionString() {
    return DILITHION_VERSION;
}

std::string GetFullVersionString() {
    std::string version = GetVersionString();
    if (version == "dev") {
        return "Dilithion Node (dev build - " + std::string(DILITHION_BUILD_DATE) + ")";
    }
    return "Dilithion Node " + version;
}
