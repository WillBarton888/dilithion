// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Legacy peers.dat (v1) reader + migration applier. See addrman_migrator.h
// for the public contract. Internal layout reverse-engineered from
// src/net/addrman.cpp::Serialize and src/net/addrman.h CNetworkAddr/CAddrInfo
// at the v4.0.x line of code:
//
//   File:
//     [1 byte]   version (= ADDRMAN_SERIALIZE_VERSION = 1)
//     [32 bytes] nKey
//     [4 bytes]  count       (int32 LE — total mapInfo size)
//     [4 bytes]  nNew        (int32 LE)
//     [4 bytes]  nTried      (int32 LE)
//     count × CAddrInfo records
//     ... bucket section (we deliberately skip; bucketing is recomputed)
//
//   CAddrInfo record (variable-but-fixed-per-record bytes):
//     CNetworkAddr:
//       [1 byte]  version (= 1)
//       [4 bytes] nTimeLow    (uint32 LE)
//       [8 bytes] nServices   (uint64 LE — native-write of uint64; LE on x86_64)
//       [16 bytes] m_addr     (raw IPv6, IPv4-mapped if applicable)
//       [2 bytes] port        (BIG-ENDIAN per CService::Serialize) ← careful!
//     [16 bytes] source.m_addr
//     [8 bytes]  nLastSuccess  (int64 LE — native-write; LE on x86_64)
//     [4 bytes]  nAttempts     (int32 LE — native-write; LE on x86_64)
//
// Endianness note: legacy CAddrMan uses raw `s.write(&native_int, sizeof)`
// for everything except the port (which is explicitly converted to
// big-endian network byte order). On the only platforms Dilithion ships
// (x86_64 Linux / Windows / macOS), native ints are little-endian, so the
// migrator matches LE for those fields and BE for the port.

#include <net/port/addrman_migrator.h>
#include <net/netaddress_dilithion.h>  // ToService / ToNetAddr

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace dilithion::net::port {

namespace {

// ----------------------------------------------------------------------------
// Little-endian read helpers (mirrors the helpers in addrman_v2.cpp;
// duplicated here rather than exported because the migrator is independent).
// ----------------------------------------------------------------------------

uint8_t ReadU8(std::istream& is)
{
    char b = 0;
    is.read(&b, 1);
    return static_cast<uint8_t>(b);
}

uint32_t ReadU32LE(std::istream& is)
{
    char b[4] = {};
    is.read(b, 4);
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
        v |= static_cast<uint32_t>(static_cast<uint8_t>(b[i])) << (i * 8);
    }
    return v;
}

int32_t ReadI32LE(std::istream& is)
{
    return static_cast<int32_t>(ReadU32LE(is));
}

uint64_t ReadU64LE(std::istream& is)
{
    char b[8] = {};
    is.read(b, 8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(static_cast<uint8_t>(b[i])) << (i * 8);
    }
    return v;
}

int64_t ReadI64LE(std::istream& is)
{
    return static_cast<int64_t>(ReadU64LE(is));
}

// Big-endian uint16 — matches legacy CService::Serialize port encoding.
uint16_t ReadU16BE(std::istream& is)
{
    char b[2] = {};
    is.read(b, 2);
    return (static_cast<uint16_t>(static_cast<uint8_t>(b[0])) << 8) |
            static_cast<uint16_t>(static_cast<uint8_t>(b[1]));
}

// Read 16 raw bytes into a CNetAddr. Uses the CNetAddr::Unserialize template
// via an inline stream adapter so DetectNetwork() runs (IPv4-mapped detection).
struct LocalReader {
    std::istream& is;
    void read(char* data, size_t len) { is.read(data, len); }
};

CNetAddr ReadCNetAddr(std::istream& is)
{
    LocalReader r{is};
    CNetAddr a;
    a.Unserialize(r);
    return a;
}

int64_t NowSecs()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Promote-to-tried window: addresses with a successful connection in the
// last 7 days are "recent enough" to skip the new table on import. Mirrors
// port_phase_1_implementation_plan.md §2.3 step 6.
constexpr int64_t kPromoteWindowSecs = 7 * 24 * 3600;

}  // anonymous namespace

// ============================================================================
// ReadLegacyPeersDat
// ============================================================================

std::optional<std::vector<MigrationEntry>>
ReadLegacyPeersDat(const std::string& path)
{
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f.is_open()) {
        return std::nullopt;  // file missing — caller falls back to empty
    }

    try {
        // Header: version byte. ADDRMAN_SERIALIZE_VERSION = 1 in legacy.
        const uint8_t file_version = ReadU8(f);
        if (!f.good()) return std::nullopt;
        if (file_version != 1) {
            // Not a legacy file. Caller checks new-format dispatch separately.
            return std::nullopt;
        }

        // 32-byte nKey — we don't use it (re-bucketing under new secret).
        f.ignore(32);
        if (!f.good()) return std::nullopt;

        // count, nNew, nTried — only count gates the read loop. Sanity-bound
        // count to combined-table capacity (1024×64 + 256×64 = 81920) plus
        // a generous safety margin.
        const int32_t count = ReadI32LE(f);
        ReadI32LE(f);  // nNew (unused)
        ReadI32LE(f);  // nTried (unused)
        if (!f.good()) return std::nullopt;

        constexpr int32_t kMaxEntries = 100000;
        if (count < 0 || count > kMaxEntries) {
            std::cerr << "[AddrMan migrator] Legacy file count=" << count
                      << " out of bounds; refusing to read\n";
            return std::nullopt;
        }

        std::vector<MigrationEntry> out;
        out.reserve(static_cast<size_t>(count));

        for (int32_t i = 0; i < count; ++i) {
            MigrationEntry e;

            // CNetworkAddr block:
            //   1 byte version, 4 byte nTimeLow, 8 byte nServices,
            //   16 byte ip, 2 byte port (big-endian).
            const uint8_t na_version = ReadU8(f);
            if (!f.good()) break;
            if (na_version != 1) {
                // Unknown CNetworkAddr version — bail out gracefully on what
                // we've parsed so far rather than corrupting the whole import.
                break;
            }

            const uint32_t time_low = ReadU32LE(f);
            const uint64_t services = ReadU64LE(f);

            uint8_t ip_bytes[16] = {};
            f.read(reinterpret_cast<char*>(ip_bytes), 16);
            const uint16_t port = ReadU16BE(f);

            // Pack into NetProtocol::CAddress.
            e.addr.time = time_low;
            e.addr.services = services;
            std::memcpy(e.addr.ip, ip_bytes, 16);
            e.addr.port = port;

            // source CNetAddr — 16 raw bytes (legacy uses CNetAddr::Serialize
            // which is just the m_addr write).
            e.source = ReadCNetAddr(f);

            // Tracking state.
            e.last_success_secs = ReadI64LE(f);
            e.n_attempts = static_cast<int>(ReadI32LE(f));

            if (!f.good()) {
                // Truncated mid-record — keep what we got.
                break;
            }
            out.push_back(e);
        }

        return out;

    } catch (...) {
        // Any throw — treat as parse failure; caller falls back to empty.
        return std::nullopt;
    }
}

// ============================================================================
// ApplyMigration
// ============================================================================

MigrationResult
ApplyMigration(IAddressManager& target,
               const std::vector<MigrationEntry>& entries)
{
    MigrationResult result;
    result.total_seen = entries.size();

    const int64_t now = NowSecs();

    for (const auto& e : entries) {
        // IAddressManager::Add wants source as a CAddress. Wrap source
        // CNetAddr — port and services don't matter for source-grouping.
        NetProtocol::CAddress source_as_addr;
        std::memcpy(source_as_addr.ip, e.source.GetAddrBytes(), 16);
        source_as_addr.port = 0;
        source_as_addr.services = 0;
        source_as_addr.time = static_cast<uint32_t>(now);

        const bool added = target.Add(e.addr, source_as_addr);
        if (!added) continue;
        ++result.total_added;

        // If the entry has a recent-enough success, push it into tried.
        // RecordAttempt(Success) does ConnectedInternal + GoodInternal which
        // will promote unless the tried slot collides — collisions get
        // queued for ResolveTriedCollisions, so the placement is honored
        // eventually.
        if (e.last_success_secs > 0 &&
            (now - e.last_success_secs) < kPromoteWindowSecs) {
            target.RecordAttempt(e.addr, ConnectionOutcome::Success);
            ++result.to_tried;
        } else {
            ++result.to_new;
        }
    }

    return result;
}

// ============================================================================
// BackupLegacyFile
// ============================================================================

bool
BackupLegacyFile(const std::string& path, std::string& out_backup_path)
{
    std::ostringstream ss;
    ss << path << ".v1.bak." << NowSecs();
    out_backup_path = ss.str();

    // Atomic rename — same semantics as our Save(): on Windows, std::rename
    // does not replace existing, so we remove the dest first if it exists.
#ifdef _WIN32
    if (std::remove(out_backup_path.c_str()) != 0) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
            std::cerr << "[AddrMan migrator] Warning: pre-rename remove of "
                      << out_backup_path << " (err=" << err << ")\n";
            // Fall through; rename may still succeed.
        }
    }
#endif

    if (std::rename(path.c_str(), out_backup_path.c_str()) != 0) {
        std::cerr << "[AddrMan migrator] Failed to rename "
                  << path << " -> " << out_backup_path << "\n";
        return false;
    }

    return true;
}

}  // namespace dilithion::net::port
