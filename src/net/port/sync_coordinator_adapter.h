// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5a — IBDCoordinator → ISyncCoordinator adapter.
//
// Wraps an existing CIbdCoordinator instance and exposes it through the
// ISyncCoordinator interface. PR6.5a uses this for BOTH flag values
// (legacy backing for both); PR6.5b will add a CPeerManager-backed
// implementation for flag=1.

#ifndef DILITHION_NET_PORT_SYNC_COORDINATOR_ADAPTER_H
#define DILITHION_NET_PORT_SYNC_COORDINATOR_ADAPTER_H

#include <net/port/sync_coordinator.h>

class CIbdCoordinator;  // fwd decl from <node/ibd_coordinator.h>

namespace dilithion {
namespace net {
namespace port {

// Thin adapter. Owns NO state; forwards every call to the wrapped
// CIbdCoordinator. Lifetime contract: the wrapped CIbdCoordinator MUST
// outlive this adapter (today, both are owned by the main() stack frame
// in dilithion-node.cpp / dilv-node.cpp).
class CIbdCoordinatorAdapter : public ISyncCoordinator {
public:
    explicit CIbdCoordinatorAdapter(CIbdCoordinator& impl) : m_impl(impl) {}

    bool IsInitialBlockDownload() const override;
    bool IsSynced() const override;
    int GetHeadersSyncPeer() const override;
    void OnOrphanBlockReceived() override;
    void OnBlockConnected() override;
    void Tick() override;

private:
    CIbdCoordinator& m_impl;
};

}  // namespace port
}  // namespace net
}  // namespace dilithion

#endif  // DILITHION_NET_PORT_SYNC_COORDINATOR_ADAPTER_H
