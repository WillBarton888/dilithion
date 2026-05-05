// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/port/peer_manager.h>

#include <consensus/ichain_selector.h>
#include <core/node_context.h>
#include <net/headers_manager.h>

#include <chrono>

namespace dilithion {
namespace net {
namespace port {

CPeerManager::CPeerManager(::dilithion::consensus::IChainSelector& chain_selector,
                           const ::Dilithion::ChainParams& chainparams)
    : m_chain_selector(chain_selector),
      m_chainparams(chainparams)
{}

CPeerManager::~CPeerManager() = default;

bool CPeerManager::IsInitialBlockDownload() const {
    return !m_synced.load(std::memory_order_acquire);
}

bool CPeerManager::IsSynced() const {
    return m_synced.load(std::memory_order_acquire);
}

int CPeerManager::GetHeadersSyncPeer() const {
    return -1;
}

void CPeerManager::OnOrphanBlockReceived() {
    m_consecutive_orphan_blocks.fetch_add(1, std::memory_order_relaxed);
}

void CPeerManager::OnBlockConnected() {
    m_consecutive_orphan_blocks.store(0, std::memory_order_relaxed);
    const auto now_ticks = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
    m_last_block_connected_ticks.store(static_cast<int64_t>(now_ticks),
                                       std::memory_order_relaxed);
}

void CPeerManager::Tick() {
    int header_height = 0;
    if (CHeadersManager* hdr_mgr = g_node_context.headers_manager.get()) {
        header_height = hdr_mgr->GetBestHeight();
    }
    const int chain_height = m_chain_selector.GetActiveHeight();
    const int blocks_behind = header_height - chain_height;
    const bool synced = (header_height > 0 && blocks_behind <= 2);
    m_synced.store(synced, std::memory_order_release);
}

void CPeerManager::OnPeerConnected(NodeId peer) {
    (void)peer;
}

void CPeerManager::OnPeerDisconnected(NodeId peer) {
    (void)peer;
}

}  // namespace port
}  // namespace net
}  // namespace dilithion
