// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// One-shot migrator from the legacy CAddrMan peers.dat format (v1) to the
// new IAddressManager-implementing CAddrMan_v2 (v2 on-disk).
//
// Per port_phase_1_implementation_plan.md §2 (Cursor OVERRIDE applied):
// existing seeds keep their address book through the upgrade. Migration is
// best-effort: on any failure, caller falls back to fresh-empty AddrMan plus
// DNS seeds rather than blocking startup.
//
// Used by PR1.3 cutover (Day 3) — Phase 1 standalone code, NOT yet wired
// into the runtime.

#ifndef DILITHION_NET_PORT_ADDRMAN_MIGRATOR_H
#define DILITHION_NET_PORT_ADDRMAN_MIGRATOR_H

#include <net/iaddress_manager.h>
#include <net/netaddress.h>     // CNetAddr
#include <net/protocol.h>       // NetProtocol::CAddress

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dilithion::net::port {

// One legacy CAddrInfo distilled into the minimum the new manager needs.
// Memory-only fields (last_try, ref_count, random_pos) are deliberately
// omitted; they reset to zero on import.
struct MigrationEntry {
    NetProtocol::CAddress addr;        // wire-format address (services + time + ip + port)
    CNetAddr              source;       // /16 or /32 group identity for new-bucket placement
    int64_t               last_success_secs = 0;
    int                   n_attempts = 0;
};

// Outcome counters for diagnostics / log line.
struct MigrationResult {
    size_t total_seen   = 0;   // entries read from legacy file
    size_t total_added  = 0;   // ones the new manager accepted into its tables
    size_t to_tried     = 0;   // promoted into tried (recent-success path)
    size_t to_new       = 0;   // landed in new (default path)
};

// Read the legacy peers.dat at `path`. Returns nullopt if the file is
// missing, version-byte != 1 (i.e. not legacy), or any I/O / parse failure.
//
// The reader stops after the top-level address list (the legacy format also
// includes a bucket section after that, but we don't need it — placement in
// the new manager is recomputed under the new bucket secret).
//
// Best-effort: on partial corruption, returns whatever was read successfully
// before the failure point. Callers can compare result.size() to the file's
// declared count to detect truncation.
std::optional<std::vector<MigrationEntry>>
ReadLegacyPeersDat(const std::string& path);

// Apply a migration vector into the target IAddressManager. For each entry:
//   1. target.Add(addr, source_as_CAddress)
//   2. If last_success_secs > now - 7*24*3600, target.RecordAttempt(Success)
//      to promote into tried (preserves operator-built peer history).
//
// Returns counters describing what was placed where.
MigrationResult
ApplyMigration(IAddressManager& target,
               const std::vector<MigrationEntry>& entries);

// Rename `path` to `path.v1.bak.<unix_timestamp>` so subsequent boots don't
// re-detect the legacy file. On failure, returns false (caller decides
// whether to retry, log, or proceed without backup).
//
// `out_backup_path` receives the backup pathname on success.
bool
BackupLegacyFile(const std::string& path, std::string& out_backup_path);

}  // namespace dilithion::net::port

#endif  // DILITHION_NET_PORT_ADDRMAN_MIGRATOR_H
