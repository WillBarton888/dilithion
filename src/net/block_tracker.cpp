// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// IBD Redesign: CBlockTracker implementation
// Single source of truth for block download state

#include <net/block_tracker.h>
#include <util/logging.h>

// Most methods are inline in block_tracker.h
// This file exists for:
// 1. Explicit template instantiation if needed
// 2. Any future non-inline methods
// 3. Ensuring the header compiles correctly

