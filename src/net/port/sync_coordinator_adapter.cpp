// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5a — IBDCoordinator → ISyncCoordinator adapter implementation.

#include <net/port/sync_coordinator_adapter.h>
#include <node/ibd_coordinator.h>

namespace dilithion {
namespace net {
namespace port {

bool CIbdCoordinatorAdapter::IsInitialBlockDownload() const {
    return m_impl.IsInitialBlockDownload();
}

bool CIbdCoordinatorAdapter::IsSynced() const {
    return m_impl.IsSynced();
}

int CIbdCoordinatorAdapter::GetHeadersSyncPeer() const {
    return m_impl.GetHeadersSyncPeer();
}

void CIbdCoordinatorAdapter::OnOrphanBlockReceived() {
    m_impl.OnOrphanBlockReceived();
}

void CIbdCoordinatorAdapter::OnBlockConnected() {
    m_impl.OnBlockConnected();
}

void CIbdCoordinatorAdapter::Tick() {
    m_impl.Tick();
}

}  // namespace port
}  // namespace net
}  // namespace dilithion
