// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// SHA-3 bucket-hash helper for the AddrMan port.
//
// Bitcoin Core's addrman.cpp uses HashWriter (double-SHA256) plus GetCheapHash
// to compute a uint64_t bucket-selection hash from (nKey || group || extra).
// Dilithion brand is post-quantum; we use SHA-3 throughout (decision recorded
// in port_phase_1_implementation_plan.md §3.2).
//
// Used at four call sites in addrman_v2.cpp:
//   1. AddrInfo::GetTriedBucket  — hash(nKey || group || hash1)
//   2. AddrInfo::GetNewBucket    — hash(nKey || source_group || hash1)
//   3. AddrInfo::GetBucketPosition — hash(nKey || tried_flag || bucket || addr_key)
//   4. (helper used in tests)
//
// Header-only; small enough to inline at every call site.

#ifndef DILITHION_NET_PORT_ADDRMAN_HASH_H
#define DILITHION_NET_PORT_ADDRMAN_HASH_H

#include <crypto/sha3.h>      // SHA3_256
#include <primitives/block.h> // uint256

#include <cstdint>
#include <cstring>
#include <vector>

namespace dilithion::net::port {

// ============================================================================
// BucketHash64
// ============================================================================
//
// SHA-3-256 of the concatenated input bytes; returns the first 8 bytes
// interpreted as a uint64_t little-endian. Equivalent semantically to
// Bitcoin Core's `HashWriter().GetCheapHash()` but using SHA-3 instead
// of double-SHA256.
//
// The KISS contract: pass any number of byte spans; this concatenates them
// internally and SHA-3-hashes the concatenation. If you have a uint256 to
// pass, get its 32-byte raw form via `key.data` (Dilithion convention).
inline uint64_t BucketHash64(const std::vector<std::vector<uint8_t>>& parts)
{
    // Concatenate into a single buffer. AddrMan call sites are 3-4 small
    // parts (key=32 bytes, group=4-16 bytes, extras=4-12 bytes), so the
    // total is always under 100 bytes. No allocation performance concern.
    size_t total = 0;
    for (const auto& p : parts) total += p.size();
    std::vector<uint8_t> buf;
    buf.reserve(total);
    for (const auto& p : parts) {
        buf.insert(buf.end(), p.begin(), p.end());
    }

    uint8_t out[32];
    SHA3_256(buf.data(), buf.size(), out);

    // First 8 bytes as little-endian uint64. Matches Bitcoin Core's
    // GetCheapHash() byte order so all the bucket-arithmetic constants
    // upstream (% ADDRMAN_TRIED_BUCKET_COUNT etc.) port over unchanged.
    uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result |= static_cast<uint64_t>(out[i]) << (i * 8);
    }
    return result;
}

// ============================================================================
// Convenience helpers for common patterns
// ============================================================================

// Pack a uint256 (32 bytes raw) into a byte vector for BucketHash64.
inline std::vector<uint8_t> AsBytes(const uint256& k)
{
    return std::vector<uint8_t>(k.data, k.data + 32);
}

// Pack a uint8_t (or any small integer) as a single-byte vector.
inline std::vector<uint8_t> AsBytes(uint8_t b)
{
    return std::vector<uint8_t>{b};
}

// Pack a uint32_t as 4 little-endian bytes.
inline std::vector<uint8_t> AsBytes(uint32_t x)
{
    return std::vector<uint8_t>{
        static_cast<uint8_t>(x & 0xff),
        static_cast<uint8_t>((x >> 8) & 0xff),
        static_cast<uint8_t>((x >> 16) & 0xff),
        static_cast<uint8_t>((x >> 24) & 0xff),
    };
}

// Pack a uint64_t as 8 little-endian bytes.
inline std::vector<uint8_t> AsBytes(uint64_t x)
{
    std::vector<uint8_t> out(8);
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>((x >> (i * 8)) & 0xff);
    }
    return out;
}

// Pass-through for already-byte-vector data (e.g. CNetAddr::GetGroup() result).
inline std::vector<uint8_t> AsBytes(const std::vector<uint8_t>& v)
{
    return v;
}

}  // namespace dilithion::net::port

#endif  // DILITHION_NET_PORT_ADDRMAN_HASH_H
