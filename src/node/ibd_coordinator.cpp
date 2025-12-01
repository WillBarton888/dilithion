// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/ibd_coordinator.h>

#include <algorithm>
#include <iostream>
#include <vector>

#include <consensus/chain.h>
#include <net/block_fetcher.h>
#include <net/headers_manager.h>
#include <net/net.h>  // CConnectionManager, CNetMessageProcessor
#include <net/node_state.h>
#include <net/peers.h>
#include <net/protocol.h>

CIbdCoordinator::CIbdCoordinator(CChainState& chainstate,
                                 CHeadersManager& headers_manager,
                                 CBlockFetcher& block_fetcher,
                                 CPeerManager& peer_manager,
                                 CConnectionManager& connection_manager,
                                 CNetMessageProcessor& message_processor)
    : m_chainstate(chainstate),
      m_headers_manager(headers_manager),
      m_block_fetcher(block_fetcher),
      m_peer_manager(peer_manager),
      m_connection_manager(connection_manager),
      m_message_processor(message_processor),
      m_last_ibd_attempt(std::chrono::steady_clock::time_point()) {}

void CIbdCoordinator::Tick() {
    int header_height = m_headers_manager.GetBestHeight();
    int chain_height = m_chainstate.GetHeight();

    if (header_height <= chain_height) {
        return;
    }

    ResetBackoffOnNewHeaders(header_height);

    auto now = std::chrono::steady_clock::now();
    if (!ShouldAttemptDownload()) {
        return;
    }

    size_t peer_count = m_peer_manager.GetConnectionCount();
    if (peer_count == 0) {
        HandleNoPeers(now);
        return;
    }

    if (m_ibd_no_peer_cycles > 0) {
        std::cout << "[IBD] Peers available - resuming block download" << std::endl;
        m_ibd_no_peer_cycles = 0;
    }

    DownloadBlocks(header_height, chain_height, now);
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
    int backoff_seconds = std::min(30, (1 << std::min(m_ibd_no_peer_cycles, 5)));
    return elapsed.count() >= backoff_seconds;
}

void CIbdCoordinator::HandleNoPeers(std::chrono::steady_clock::time_point now) {
    if (m_ibd_no_peer_cycles == 0) {
        std::cout << "[IBD] No peers available for block download - entering backoff mode" << std::endl;
    }
    m_ibd_no_peer_cycles++;
    m_last_ibd_attempt = now;

    if (m_ibd_no_peer_cycles % 10 == 0) {
        int backoff_seconds = std::min(30, (1 << std::min(m_ibd_no_peer_cycles, 5)));
        std::cout << "[IBD] Still waiting for peers (backoff: " << backoff_seconds
                  << "s, attempts: " << m_ibd_no_peer_cycles << ")" << std::endl;
    }
}

void CIbdCoordinator::DownloadBlocks(int header_height, int chain_height,
                                     std::chrono::steady_clock::time_point now) {
    m_last_ibd_attempt = now;

    std::cout << "[IBD] Headers ahead of chain - downloading blocks (header="
              << header_height << " chain=" << chain_height << ")" << std::endl;

    int blocks_to_queue = std::min(100, header_height - chain_height);
    std::cout << "[IBD] Queueing " << blocks_to_queue << " blocks for download..." << std::endl;

    QueueMissingBlocks(chain_height, blocks_to_queue);

    bool any_requested = FetchBlocks();
    if (!any_requested) {
        m_ibd_no_peer_cycles++;
        std::cout << "[IBD] Could not send any block requests (no suitable peers)" << std::endl;
    }

    RetryTimeoutsAndStalls();
}

void CIbdCoordinator::QueueMissingBlocks(int chain_height, int blocks_to_queue) {
    for (int h = chain_height + 1; h <= chain_height + blocks_to_queue; h++) {
        std::vector<uint256> hashes_at_height = m_headers_manager.GetHeadersAtHeight(h);
        for (const uint256& hash : hashes_at_height) {
            if (!m_chainstate.HasBlockIndex(hash) &&
                !m_block_fetcher.IsQueued(hash) &&
                !m_block_fetcher.IsDownloading(hash)) {
                m_block_fetcher.QueueBlockForDownload(hash, h, false);
                std::cout << "[IBD] Queued block " << hash.GetHex().substr(0, 16)
                          << "... at height " << h << std::endl;
            }
        }
    }
}

bool CIbdCoordinator::FetchBlocks() {
    auto blocks_to_fetch = m_block_fetcher.GetNextBlocksToFetch(16);
    if (blocks_to_fetch.empty() && m_block_fetcher.GetBlocksInFlight() == 0) {
        m_ibd_no_peer_cycles++;
        std::cout << "[IBD] No blocks could be fetched (no suitable peers?)" << std::endl;
        return false;
    }

    if (blocks_to_fetch.empty()) {
        return true;  // Work in flight already, nothing new to request.
    }

    std::cout << "[IBD] Fetching " << blocks_to_fetch.size()
              << " blocks (max 16 in-flight)..." << std::endl;

    int successful_requests = 0;
    for (const auto& [hash, height] : blocks_to_fetch) {
        NodeId preferred = m_block_fetcher.GetPreferredPeer(hash);
        NodeId peer = m_block_fetcher.SelectPeerForDownload(hash, preferred);
        if (peer != -1 && m_block_fetcher.RequestBlock(peer, hash, height)) {
            std::vector<NetProtocol::CInv> getdata;
            getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
            CNetMessage msg = m_message_processor.CreateGetDataMessage(getdata);
            m_connection_manager.SendMessage(peer, msg);
            std::cout << "[IBD] Sent GETDATA for block " << hash.GetHex().substr(0, 16)
                      << "... (height " << height << ") to peer " << peer << std::endl;
            successful_requests++;
        } else {
            m_block_fetcher.QueueBlockForDownload(hash, height, -1, true);
        }
    }

    return successful_requests > 0;
}

void CIbdCoordinator::RetryTimeoutsAndStalls() {
    auto timed_out = m_block_fetcher.CheckTimeouts();
    if (!timed_out.empty()) {
        std::cout << "[BlockFetcher] " << timed_out.size()
                  << " block(s) timed out, retrying..." << std::endl;
        m_block_fetcher.RetryTimedOutBlocks(timed_out);
    }

    auto stalling_peers = CNodeStateManager::Get().CheckForStallingPeers();
    for (NodeId peer : stalling_peers) {
        std::cout << "[NodeState] Disconnecting stalling peer " << peer << std::endl;
        m_connection_manager.DisconnectPeer(peer, "stalling block download");
    }
}

