// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/ibd_coordinator.h>

#include <iostream>
#include <vector>

#include <consensus/chain.h>
#include <core/node_context.h>
#include <net/block_fetcher.h>
#include <net/headers_manager.h>
#include <net/net.h>  // CNetMessageProcessor
#include <net/connman.h>  // Phase 5: CConnman
#include <net/peers.h>
#include <net/protocol.h>
#include <util/logging.h>
#include <util/bench.h>  // Performance: Benchmarking

CIbdCoordinator::CIbdCoordinator(CChainState& chainstate, NodeContext& node_context)
    : m_chainstate(chainstate),
      m_node_context(node_context),
      m_last_ibd_attempt(std::chrono::steady_clock::time_point()) {}

void CIbdCoordinator::Tick() {
    // Phase 5.1: Update state machine
    UpdateState();

    // Check if IBD components are available
    if (!m_node_context.headers_manager || !m_node_context.block_fetcher) {
        return;
    }

    int header_height = m_node_context.headers_manager->GetBestHeight();
    int chain_height = m_chainstate.GetHeight();

    // If headers are not ahead, we're synced (IDLE or COMPLETE)
    if (header_height <= chain_height) {
        if (m_state != IBDState::IDLE && m_state != IBDState::COMPLETE) {
            m_state = IBDState::COMPLETE;
        }
        return;
    }

    ResetBackoffOnNewHeaders(header_height);

    auto now = std::chrono::steady_clock::now();
    if (!ShouldAttemptDownload()) {
        return;
    }

    size_t peer_count = m_node_context.peer_manager ? m_node_context.peer_manager->GetConnectionCount() : 0;

    if (peer_count == 0) {
        HandleNoPeers(now);
        return;
    }

    if (m_ibd_no_peer_cycles > 0) {
        m_ibd_no_peer_cycles = 0;
    }

    BENCHMARK_START("ibd_tick");
    DownloadBlocks(header_height, chain_height, now);
    BENCHMARK_END("ibd_tick");
}

void CIbdCoordinator::UpdateState() {
    if (!m_node_context.headers_manager) {
        m_state = IBDState::IDLE;
        return;
    }

    int header_height = m_node_context.headers_manager->GetBestHeight();
    int chain_height = m_chainstate.GetHeight();
    size_t peer_count = m_node_context.peer_manager ? m_node_context.peer_manager->GetConnectionCount() : 0;

    // Determine state based on current conditions
    if (header_height <= chain_height) {
        if (m_state != IBDState::IDLE && m_state != IBDState::COMPLETE) {
            m_state = IBDState::COMPLETE;
        }
    } else if (peer_count == 0) {
        m_state = IBDState::WAITING_FOR_PEERS;
    } else if (header_height > chain_height + 10) {
        // If headers are significantly ahead, we're in headers sync phase
        // (though headers sync happens in headers_manager, not here)
        m_state = IBDState::BLOCKS_DOWNLOAD;
    } else {
        m_state = IBDState::BLOCKS_DOWNLOAD;
    }
}

std::string CIbdCoordinator::GetStateName() const {
    switch (m_state) {
        case IBDState::IDLE: return "IDLE";
        case IBDState::WAITING_FOR_PEERS: return "WAITING_FOR_PEERS";
        case IBDState::HEADERS_SYNC: return "HEADERS_SYNC";
        case IBDState::BLOCKS_DOWNLOAD: return "BLOCKS_DOWNLOAD";
        case IBDState::COMPLETE: return "COMPLETE";
        default: return "UNKNOWN";
    }
}

void CIbdCoordinator::ResetBackoffOnNewHeaders(int header_height) {
    if (header_height > m_last_header_height) {
        m_ibd_no_peer_cycles = 0;
        m_last_ibd_attempt = std::chrono::steady_clock::time_point();
    }
    m_last_header_height = header_height;
}

bool CIbdCoordinator::ShouldAttemptDownload() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_ibd_attempt);

    // BUG #147 FIX: During active IBD (blocks download), be aggressive - minimal backoff
    // Only use exponential backoff when truly stuck (no work available, no peers)
    int backoff_seconds;
    if (m_state == IBDState::BLOCKS_DOWNLOAD) {
        // During IBD: 1 second between attempts, even if peer selection failed once
        backoff_seconds = 1;
    } else {
        // Not in IBD: use exponential backoff (1, 2, 4, 8, 16, 30 seconds)
        backoff_seconds = std::min(30, (1 << std::min(m_ibd_no_peer_cycles, 5)));
    }

    return elapsed.count() >= backoff_seconds;
}

void CIbdCoordinator::HandleNoPeers(std::chrono::steady_clock::time_point now) {
    if (m_ibd_no_peer_cycles == 0) {
        LogPrintIBD(WARN, "No peers available for block download - entering backoff mode");
    }
    m_ibd_no_peer_cycles++;
    m_last_ibd_attempt = now;

    if (m_ibd_no_peer_cycles % 10 == 0) {
        int backoff_seconds = std::min(30, (1 << std::min(m_ibd_no_peer_cycles, 5)));
        LogPrintIBD(INFO, "Still waiting for peers (backoff: %ds, attempts: %d)", backoff_seconds, m_ibd_no_peer_cycles);
    }
}

void CIbdCoordinator::DownloadBlocks(int header_height, int chain_height,
                                     std::chrono::steady_clock::time_point now) {
    BENCHMARK_START("ibd_download_blocks");
    m_last_ibd_attempt = now;

    LogPrintIBD(INFO, "Headers ahead of chain - downloading blocks (header=%d chain=%d)", header_height, chain_height);

    int blocks_to_queue = std::min(100, header_height - chain_height);
    LogPrintIBD(INFO, "Queueing %d blocks for download...", blocks_to_queue);

    BENCHMARK_START("ibd_queue_blocks");
    QueueMissingBlocks(chain_height, blocks_to_queue);
    BENCHMARK_END("ibd_queue_blocks");

    BENCHMARK_START("ibd_fetch_blocks");
    bool any_requested = FetchBlocks();
    BENCHMARK_END("ibd_fetch_blocks");
    if (!any_requested) {
        m_ibd_no_peer_cycles++;
        LogPrintIBD(WARN, "Could not send any block requests (no suitable peers)");
    }

    RetryTimeoutsAndStalls();
    BENCHMARK_END("ibd_download_blocks");
}

void CIbdCoordinator::QueueMissingBlocks(int chain_height, int blocks_to_queue) {
    if (!m_node_context.headers_manager || !m_node_context.block_fetcher) {
        return;
    }

    for (int h = chain_height + 1; h <= chain_height + blocks_to_queue; h++) {
        std::vector<uint256> hashes_at_height = m_node_context.headers_manager->GetHeadersAtHeight(h);
        for (const uint256& hash : hashes_at_height) {
            if (!m_chainstate.HasBlockIndex(hash) &&
                !m_node_context.block_fetcher->IsQueued(hash) &&
                !m_node_context.block_fetcher->IsDownloading(hash)) {
                m_node_context.block_fetcher->QueueBlockForDownload(hash, h, false);
                LogPrintIBD(DEBUG, "Queued block %s... at height %d", hash.GetHex().substr(0, 16).c_str(), h);
            }
        }
    }
}

bool CIbdCoordinator::FetchBlocks() {
    if (!m_node_context.block_fetcher || !m_node_context.message_processor || !m_node_context.connman) {
        return false;
    }

    // BUG #147 FIX: Request more blocks per tick (128, matching Bitcoin Core)
    auto blocks_to_fetch = m_node_context.block_fetcher->GetNextBlocksToFetch(128);
    if (blocks_to_fetch.empty() && m_node_context.block_fetcher->GetBlocksInFlight() == 0) {
        m_ibd_no_peer_cycles++;
        LogPrintIBD(WARN, "No blocks could be fetched (no suitable peers?)");
        return false;
    }

    if (blocks_to_fetch.empty()) {
        return true;  // Work in flight already, nothing new to request.
    }

    LogPrintIBD(INFO, "Fetching %zu blocks...", blocks_to_fetch.size());

    // BUG #147 FIX: Batch GETDATA messages by peer instead of one per block
    // BUG #148 PERF: Assign sequential blocks to SAME peer to reduce orphan creation
    // When blocks 5,6,7,8 go to the same peer, they arrive in order → no orphans
    // Step 1: Assign blocks to peers with sequential preference
    std::map<NodeId, std::vector<std::pair<uint256, int>>> peer_blocks;
    std::vector<std::pair<uint256, int>> requeue_blocks;

    NodeId lastPeer = -1;
    int lastHeight = -1;

    for (const auto& [hash, height] : blocks_to_fetch) {
        NodeId preferred = m_node_context.block_fetcher->GetPreferredPeer(hash);

        // PERF: If this block is sequential (height = lastHeight + 1), prefer same peer
        // This reduces orphan creation by keeping blocks in order from same source
        if (lastPeer != -1 && height == lastHeight + 1 && preferred == -1) {
            // Check if last peer still has capacity
            auto lastPeerObj = m_node_context.peer_manager ?
                               m_node_context.peer_manager->GetPeer(lastPeer) : nullptr;
            if (lastPeerObj && lastPeerObj->nBlocksInFlight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
                preferred = lastPeer;  // Prefer continuing with same peer
            }
        }

        NodeId peer = m_node_context.block_fetcher->SelectPeerForDownload(hash, preferred);
        if (peer != -1 && m_node_context.block_fetcher->RequestBlock(peer, hash, height)) {
            peer_blocks[peer].emplace_back(hash, height);
            lastPeer = peer;
            lastHeight = height;
        } else {
            // BUG #63 FIX: Re-queue block if no peer available
            requeue_blocks.emplace_back(hash, height);
        }
    }

    // Re-queue failed blocks
    for (const auto& [hash, height] : requeue_blocks) {
        m_node_context.block_fetcher->QueueBlockForDownload(hash, height, -1, true);
    }

    // Step 2: Send ONE batched GETDATA per peer
    int successful_requests = 0;
    for (const auto& [peer, blocks] : peer_blocks) {
        std::vector<NetProtocol::CInv> getdata;
        getdata.reserve(blocks.size());
        for (const auto& [hash, height] : blocks) {
            getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
        }
        CNetMessage msg = m_node_context.message_processor->CreateGetDataMessage(getdata);
        m_node_context.connman->PushMessage(peer, msg);
        successful_requests += blocks.size();
        LogPrintIBD(DEBUG, "Sent batched GETDATA for %zu blocks to peer %d", blocks.size(), peer);
    }

    return successful_requests > 0;
}

void CIbdCoordinator::RetryTimeoutsAndStalls() {
    if (!m_node_context.block_fetcher || !m_node_context.connman) {
        return;
    }

    auto timed_out = m_node_context.block_fetcher->CheckTimeouts();
    if (!timed_out.empty()) {
        LogPrintIBD(WARN, "%zu block(s) timed out, retrying...", timed_out.size());
        m_node_context.block_fetcher->RetryTimedOutBlocks(timed_out);
    }

    // Phase C: CPeerManager is now the single source of truth for stall detection
    std::vector<NodeId> stalling_peers;
    if (m_node_context.peer_manager) {
        stalling_peers = m_node_context.peer_manager->CheckForStallingPeers();
    }

    for (NodeId peer : stalling_peers) {
        LogPrintIBD(WARN, "Disconnecting stalling peer %d", peer);
        m_node_context.connman->DisconnectNode(peer, "stalling block download");
    }
}

