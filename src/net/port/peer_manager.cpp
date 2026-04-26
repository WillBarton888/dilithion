// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b — PeerManager skeleton implementation.
//
// STATUS (v1.5 / overnight handoff): SKELETON ONLY. Every method
// is stubbed. Method bodies are PR6.5b body work for subsequent
// sessions; today's deliverable is the class declaration so
// reviewers can audit the surface against ISyncCoordinator (§1.5)
// and the v1.5 plan §2.1.
//
// To unstub: see upstream Bitcoin Core v28 net_processing.cpp +
// the v1.5 plan §2.1 / §2.2 / §2.3 (CPeer, BlockDownloadState).
//
// All stubs return safe defaults that match legacy IBDCoordinator
// semantics — IsSynced() returns false (= "not synced, behave
// conservatively"), IsInitialBlockDownload() returns true (= "in
// IBD, don't relay"). This means a node accidentally constructed
// with CPeerManager (instead of CIbdCoordinatorAdapter) before the
// body lands won't relay/mine — safest fallback.

#include <net/port/peer_manager.h>

#include <consensus/ichain_selector.h>

namespace dilithion {
namespace net {
namespace port {

CPeerManager::CPeerManager(::dilithion::net::IConnectionManager& connman,
                           ::dilithion::net::IAddressManager& addrman,
                           ::dilithion::net::IPeerScorer& scorer,
                           ::dilithion::consensus::IChainSelector& chain_selector,
                           const ::Dilithion::ChainParams& chainparams)
    : m_connman(connman),
      m_addrman(addrman),
      m_scorer(scorer),
      m_chain_selector(chain_selector),
      m_chainparams(chainparams)
{}

CPeerManager::~CPeerManager() = default;

// ===== ISyncCoordinator overrides =====

bool CPeerManager::IsInitialBlockDownload() const {
    // STUB: safe default = "yes, in IBD" so callers behave conservatively
    // until the body lands.
    return true;
}

bool CPeerManager::IsSynced() const {
    // STUB: safe default = "no, not synced".
    return false;
}

int CPeerManager::GetHeadersSyncPeer() const {
    // STUB: -1 sentinel = "no peer selected".
    return -1;
}

void CPeerManager::OnOrphanBlockReceived() {
    // STUB: no-op. PR6.5b body will track per-peer orphan counts
    // and dispatch misbehavior penalties via m_scorer.
}

void CPeerManager::OnBlockConnected() {
    // STUB: no-op. PR6.5b body will reset stall counters and update
    // last-block-arrival timestamps in per-peer state.
}

void CPeerManager::Tick() {
    // STUB: no-op. PR6.5b body will run sync-peer rotation, stall
    // detection, in-flight cleanup, and RequestNextBlocks dispatch.
}

// ===== PeerManager-specific API =====

bool CPeerManager::ProcessMessage(NodeId /*peer*/,
                                  const std::string& /*strCommand*/,
                                  CDataStream& /*vRecv*/) {
    // STUB: return false = "message not handled". Body work in PR6.5b.
    return false;
}

void CPeerManager::SendMessages(NodeId /*peer*/) {
    // STUB: no-op. Body work in PR6.5b.
}

void CPeerManager::RequestNextBlocks() {
    // STUB: no-op. Body work in PR6.5b.
}

int CPeerManager::GetPeerCount() const {
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    return static_cast<int>(m_peers.size());
}

std::vector<PeerInfo> CPeerManager::GetPeerInfo() const {
    std::vector<PeerInfo> out;
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    out.reserve(m_peers.size());
    for (const auto& kv : m_peers) {
        const CPeer& p = *kv.second;
        out.push_back(PeerInfo{p.id, p.nVersion, p.nServices,
                               p.nTimeConnected, p.m_is_chosen_sync_peer});
    }
    return out;
}

void CPeerManager::OnPeerConnected(NodeId peer) {
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    if (m_peers.find(peer) != m_peers.end()) return;  // already connected
    m_peers.emplace(peer, std::make_unique<CPeer>(peer));
}

void CPeerManager::OnPeerDisconnected(NodeId peer) {
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    m_peers.erase(peer);
}

}  // namespace port
}  // namespace net
}  // namespace dilithion
