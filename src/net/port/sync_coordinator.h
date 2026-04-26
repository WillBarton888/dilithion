// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5a — ISyncCoordinator adapter interface.
//
// Stable surface used by ~37 production touch sites that previously
// called CIbdCoordinator directly. Both CIbdCoordinator (legacy path,
// --usenewpeerman=0) and CPeerManager (new path, --usenewpeerman=1)
// implement this interface. PR6.5a wires legacy backing for both
// flag values (compile-safe, behavior-neutral). PR6.5b adds the
// PeerManager backing for flag=1.
//
// See `.claude/contracts/port_phase_6_call_site_compatibility_table.md`
// for the full call-site map and parity test naming.

#ifndef DILITHION_NET_PORT_SYNC_COORDINATOR_H
#define DILITHION_NET_PORT_SYNC_COORDINATOR_H

namespace dilithion {
namespace net {
namespace port {

class ISyncCoordinator {
public:
    virtual ~ISyncCoordinator() = default;

    // ===== State queries (read-only, thread-safe) =====
    virtual bool IsInitialBlockDownload() const = 0;
    virtual bool IsSynced() const = 0;
    virtual int GetHeadersSyncPeer() const = 0;

    // ===== Mutation hooks =====
    virtual void OnOrphanBlockReceived() = 0;
    virtual void OnBlockConnected() = 0;

    // ===== Maintenance (called from main loop, ~1 Hz) =====
    virtual void Tick() = 0;
};

}  // namespace port
}  // namespace net
}  // namespace dilithion

#endif  // DILITHION_NET_PORT_SYNC_COORDINATOR_H
