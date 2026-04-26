// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.3 — RegtestOnly<T> accessor (CONCERN α v1.4 hardening).
//
// Wraps a constant that is ONLY safe to read in regtest mode. Calling
// .Get(chainparams) outside regtest fires assert(false) in debug builds
// and returns a safe sentinel (T{}) in release builds.
//
// Per v1.5 plan §3.4: every .Get(chainparams) call site MUST be lexically
// inside an `if (chainparams.IsRegtest())` block, OR the directly-enclosing
// function must carry an explicit `// REGTEST-ONLY-CALLER` annotation
// AND every call site of that function is itself inside an
// `if (chainparams.IsRegtest())` block.
//
// CI gate: `grep '\.Get(chainparams)' src/` returns matches; for each match,
// verify (a) it's within an `if (chainparams.IsRegtest())` lexical block in
// the same function, OR (b) the enclosing function has the
// `// REGTEST-ONLY-CALLER` annotation.

#ifndef DILITHION_NET_PORT_REGTEST_ONLY_H
#define DILITHION_NET_PORT_REGTEST_ONLY_H

#include <cassert>
#include <core/chainparams.h>

namespace dilithion {
namespace net {
namespace port {

template <typename T>
class RegtestOnly {
public:
    explicit constexpr RegtestOnly(T value) : m_value(value) {}

    T Get(const ::Dilithion::ChainParams& params) const {
        if (!params.IsRegtest()) {
            // Debug build: fatal abort. Release build: log + return T{}.
            assert(false && "RegtestOnly<T>::Get() called outside regtest mode");
            return T{};
        }
        return m_value;
    }

private:
    T m_value;
};

// ===== Regtest-only knobs (v1.5 §3.4 table) =====
//
// All knobs below are gated. Touching them outside an
// `if (chainparams.IsRegtest())` block (or transitively from a
// `// REGTEST-ONLY-CALLER` function) fails CI.

// Block-download timeout in seconds. Mainnet/testnet defaults are
// owned by their respective consumers; this is the regtest override.
constexpr RegtestOnly<int> REGTEST_BLOCK_DOWNLOAD_TIMEOUT_SEC{5};

// Per-peer in-flight block budget for regtest.
constexpr RegtestOnly<int> REGTEST_MAX_BLOCKS_IN_TRANSIT_PER_PEER{4};

// Stale-tip check cadence for regtest.
constexpr RegtestOnly<int> REGTEST_STALE_TIP_CHECK_INTERVAL_SEC{30};

// Single-peer minimum (regtest only — production minimum is 8 / 117).
constexpr RegtestOnly<int> REGTEST_SINGLE_PEER_MINIMUM{1};

}  // namespace port
}  // namespace net
}  // namespace dilithion

#endif  // DILITHION_NET_PORT_REGTEST_ONLY_H
