// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5a — ISyncCoordinator adapter interface.
//
// Stable surface used by ~37 production touch sites that previously
// called CIbdCoordinator directly. The interface is implemented by
// CIbdCoordinatorAdapter (which wraps the legacy CIbdCoordinator) —
// the sole production implementation post v4.3.4 cut (Block 7 retired
// the alternate port::CPeerManager-backed implementation; Block 8
// retired the --usenewpeerman flag that selected between the two).
// The interface is preserved as a stable abstraction for future
// architectural work (cf. v5_architecture_decision_prep.md).
//
// See `.claude/contracts/port_phase_6_call_site_compatibility_table.md`
// for the full call-site map and parity test naming, and
// `.claude/contracts/option_c_architectural_cut_contract.md` for the
// v4.3.4 retirement of the CPeerManager-backed alternative.

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
