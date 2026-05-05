// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/port/peer_manager.h>

#include <consensus/ichain_selector.h>
#include <core/node_context.h>
#include <net/headers_manager.h>
#include <net/serialize.h>
#include <primitives/block.h>

#include <chrono>
#include <utility>

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

bool CPeerManager::ProcessMessage(NodeId peer,
                                  const std::string& strCommand,
                                  CDataStream& vRecv) {
    if (strCommand == "block") {
        return HandleBlock(peer, vRecv);
    }
    return false;
}

void CPeerManager::SendMessages(NodeId peer) {
    (void)peer;
}

bool CPeerManager::HandleBlock(NodeId peer, CDataStream& vRecv) {
    auto block = std::make_shared<CBlock>();
    block->nVersion       = vRecv.ReadInt32();
    block->hashPrevBlock  = vRecv.ReadUint256();
    block->hashMerkleRoot = vRecv.ReadUint256();
    block->nTime          = vRecv.ReadUint32();
    block->nBits          = vRecv.ReadUint32();
    block->nNonce         = vRecv.ReadUint32();

    if (block->IsVDFBlock()) {
        block->vdfOutput    = vRecv.ReadUint256();
        block->vdfProofHash = vRecv.ReadUint256();
    }

    const uint64_t vtx_size = vRecv.ReadCompactSize();
    static constexpr uint64_t kMaxBlockVtxBytes = 4ull * 1024ull * 1024ull;
    if (vtx_size > kMaxBlockVtxBytes) {
        throw std::runtime_error("block vtx size exceeds maximum");
    }
    block->vtx.resize(static_cast<size_t>(vtx_size));
    if (vtx_size > 0) {
        vRecv.read(block->vtx.data(), vtx_size);
    }

    const uint256 block_hash = block->GetFastHash();
    RemoveBlockInFlight(peer, block_hash);
    (void)m_chain_selector.ProcessNewBlock(block, /*force_processing=*/false, nullptr);
    return true;
}

void CPeerManager::MarkBlockInFlight(NodeId peer, const uint256& hash) {
    (void)peer;
    (void)hash;
}

void CPeerManager::RemoveBlockInFlight(NodeId peer, const uint256& hash) {
    (void)peer;
    (void)hash;
}

int CPeerManager::GetBlocksInFlightForPeer(NodeId peer) const {
    (void)peer;
    return 0;
}

int CPeerManager::GetPeerCount() const {
    return 0;
}

std::vector<PeerInfo> CPeerManager::GetPeerInfo() const {
    return {};
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
