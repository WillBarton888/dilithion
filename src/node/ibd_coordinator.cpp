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
#include <node/block_validation_queue.h>  // Phase 2: Async block validation
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

    // IBD HANG FIX #1: Gradual backpressure instead of binary stop
    // Previously: queue > 80 = complete stop (binary)
    // Now: gradual rate reduction based on queue depth
    // - Queue 0-70: Full speed (1.0x)
    // - Queue 70-80: Reduced speed (0.5x)
    // - Queue 80-90: Further reduced (0.25x)
    // - Queue 90-95: Minimal speed (0.1x)
    // - Queue 95+: Complete stop
    if (m_node_context.validation_queue && m_node_context.validation_queue->IsRunning()) {
        size_t queue_depth = m_node_context.validation_queue->GetQueueDepth();
        if (queue_depth >= 95) {
            // Queue nearly full - complete stop
            m_last_hang_cause = HangCause::VALIDATION_QUEUE_FULL;
            LogPrintIBD(DEBUG, "Validation queue depth %zu - stopping downloads (queue nearly full)", queue_depth);
            return false;
        }
        // For queue 70-95, we'll use rate multiplier in DownloadBlocks()
        // Still return true here, but rate will be reduced
    }

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

    bool should_attempt = elapsed.count() >= backoff_seconds;
    if (!should_attempt) {
        m_last_hang_cause = HangCause::NONE;  // Just waiting for backoff
    }
    return should_attempt;
}

double CIbdCoordinator::GetDownloadRateMultiplier() const {
    // IBD HANG FIX #1: Gradual backpressure - returns multiplier (0.0-1.0)
    // Used to reduce request rate gradually instead of binary stop
    
    if (!m_node_context.validation_queue || !m_node_context.validation_queue->IsRunning()) {
        return 1.0;  // No validation queue - full speed
    }
    
    size_t queue_depth = m_node_context.validation_queue->GetQueueDepth();
    
    // Gradual backpressure zones
    if (queue_depth < 70) {
        return 1.0;  // Full speed
    } else if (queue_depth < 80) {
        return 0.5;  // Half speed
    } else if (queue_depth < 90) {
        return 0.25;  // Quarter speed
    } else if (queue_depth < 95) {
        return 0.1;  // Minimal speed
    } else {
        return 0.0;  // Should have been caught by ShouldAttemptDownload(), but return 0 for safety
    }
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

    // Phase 3: Initialize the 1024-block sliding window for IBD
    if (!m_node_context.block_fetcher->IsWindowInitialized()) {
        m_node_context.block_fetcher->InitializeWindow(chain_height, header_height);
        LogPrintIBD(INFO, "Initialized download window: %s", m_node_context.block_fetcher->GetWindowStatus().c_str());
    }

    // IBD HANG FIX #1: Apply gradual backpressure rate multiplier
    // Reduces request rate gradually as validation queue fills, preventing binary stop/resume cycle
    double rate_multiplier = GetDownloadRateMultiplier();
    
    // IBD BOTTLENECK FIX #4: Match queue size to request rate for better pipeline utilization
    // Previously queued up to 1024 blocks but only requested 16 per peer per tick
    // Now queues in smaller batches that match request capacity, keeping pipeline full
    // Get peer count for sizing
    size_t peer_count = m_node_context.peer_manager ? m_node_context.peer_manager->GetConnectionCount() : 1;
    int expected_peers = static_cast<int>(peer_count);
    int base_blocks_to_queue = std::min(MAX_BLOCKS_PER_CHUNK * std::max(1, expected_peers * 2), 
                                        header_height - chain_height);
    base_blocks_to_queue = std::min(base_blocks_to_queue, BLOCK_DOWNLOAD_WINDOW_SIZE);  // Cap at window size
    
    // Apply rate multiplier for gradual backpressure
    int blocks_to_queue = static_cast<int>(base_blocks_to_queue * rate_multiplier);
    blocks_to_queue = std::max(1, blocks_to_queue);  // Always queue at least 1 block
    
    if (rate_multiplier < 1.0) {
        LogPrintIBD(INFO, "Queueing %d blocks for download (peers=%d, rate=%.0f%%)...", 
                    blocks_to_queue, expected_peers, rate_multiplier * 100.0);
    } else {
        LogPrintIBD(INFO, "Queueing %d blocks for download (peers=%d)...", blocks_to_queue, expected_peers);
    }

    BENCHMARK_START("ibd_queue_blocks");
    QueueMissingBlocks(chain_height, blocks_to_queue);
    BENCHMARK_END("ibd_queue_blocks");

    BENCHMARK_START("ibd_fetch_blocks");
    bool any_requested = FetchBlocks();
    BENCHMARK_END("ibd_fetch_blocks");
    if (!any_requested) {
        m_ibd_no_peer_cycles++;
        // IBD HANG FIX #6: Log specific hang cause
        std::string cause_str = "unknown";
        switch (m_last_hang_cause) {
            case HangCause::VALIDATION_QUEUE_FULL: cause_str = "validation queue full"; break;
            case HangCause::NO_PEERS_AVAILABLE: cause_str = "no peers available"; break;
            case HangCause::WINDOW_EMPTY: cause_str = "window empty (no pending heights)"; break;
            case HangCause::PEERS_AT_CAPACITY: cause_str = "all peers at capacity"; break;
            case HangCause::NONE: cause_str = "no suitable peers"; break;
        }
        LogPrintIBD(WARN, "Could not send any block requests - %s", cause_str.c_str());
    } else {
        m_last_hang_cause = HangCause::NONE;  // Clear hang cause on success
    }

    RetryTimeoutsAndStalls();
    BENCHMARK_END("ibd_download_blocks");
}

void CIbdCoordinator::QueueMissingBlocks(int chain_height, int blocks_to_queue) {
    if (!m_node_context.headers_manager || !m_node_context.block_fetcher) {
        return;
    }

    for (int h = chain_height + 1; h <= chain_height + blocks_to_queue; h++) {
        // IBD OPTIMIZATION: Use GetRandomXHashAtHeight to get the hash for block requests
        // During IBD, headers are stored by FastHash, but GETDATA needs RandomX hash
        uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
        if (hash.IsNull()) {
            continue;  // No header at this height
        }

        if (!m_chainstate.HasBlockIndex(hash) &&
            !m_node_context.block_fetcher->IsQueued(hash) &&
            !m_node_context.block_fetcher->IsDownloading(hash)) {
            m_node_context.block_fetcher->QueueBlockForDownload(hash, h, false);
            LogPrintIBD(DEBUG, "Queued block %s... at height %d", hash.GetHex().substr(0, 16).c_str(), h);
        }
    }
}

bool CIbdCoordinator::FetchBlocks() {
    if (!m_node_context.block_fetcher || !m_node_context.message_processor ||
        !m_node_context.connman || !m_node_context.peer_manager || !m_node_context.headers_manager) {
        return false;
    }

    // Phase 2+3: Bitcoin Core-style chunk assignment with 1024-block window
    // Assign CONSECUTIVE heights to SAME peer → blocks arrive in order → no orphans

    // Get available peers for download
    std::vector<int> available_peers = m_node_context.peer_manager->GetValidPeersForDownload();
    if (available_peers.empty()) {
        m_ibd_no_peer_cycles++;
        m_last_hang_cause = HangCause::NO_PEERS_AVAILABLE;  // IBD HANG FIX #6
        LogPrintIBD(WARN, "No peers available for block download");
        return false;
    }
    
    // IBD HANG FIX #6: Check if all peers are at capacity
    bool all_peers_at_capacity = true;
    for (int peer_id : available_peers) {
        auto peer = m_node_context.peer_manager->GetPeer(peer_id);
        if (peer && peer->nBlocksInFlight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
            all_peers_at_capacity = false;
            break;
        }
    }
    if (all_peers_at_capacity && !available_peers.empty()) {
        m_last_hang_cause = HangCause::PEERS_AT_CAPACITY;  // IBD HANG FIX #6
        LogPrintIBD(DEBUG, "All peers at capacity (%d peers, all have %d blocks in-flight)", 
                    available_peers.size(), CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER);
    }

    int chain_height = m_chainstate.GetHeight();
    int header_height = m_node_context.headers_manager->GetBestHeight();
    int total_chunks_assigned = 0;

    // For each peer with capacity, assign chunks (Phase 1 FIX: allow multiple chunks per peer)
    for (int peer_id : available_peers) {
        auto peer = m_node_context.peer_manager->GetPeer(peer_id);
        if (!peer) continue;

        // Skip if peer at capacity (AssignChunkToPeer will extend existing chunks)
        if (peer->nBlocksInFlight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
            continue;
        }

        // Phase 3: Get next chunk from the window (respects 1024-block limit)
        std::vector<int> chunk_heights;
        if (m_node_context.block_fetcher->IsWindowInitialized()) {
            chunk_heights = m_node_context.block_fetcher->GetWindowPendingHeights(MAX_BLOCKS_PER_CHUNK);
        } else {
            // Fallback to old method if window not initialized
            chunk_heights = m_node_context.block_fetcher->GetNextChunkHeights(MAX_BLOCKS_PER_CHUNK);
        }

        if (chunk_heights.empty()) {
            // IBD HANG FIX #6: Track hang cause
            m_last_hang_cause = HangCause::WINDOW_EMPTY;
            LogPrintIBD(DEBUG, "No pending heights in window - window may be stalled");
            break;  // No more heights to assign
        }

        // Filter heights: only include those we have headers for and don't have blocks for
        std::vector<int> valid_heights;
        for (int h : chunk_heights) {
            if (h > header_height) break;  // Don't request beyond headers
            if (h <= chain_height) continue;  // Already have this block

            uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
            if (hash.IsNull()) continue;  // No header
            if (m_chainstate.HasBlockIndex(hash)) continue;  // Already have block

            valid_heights.push_back(h);
        }

        if (valid_heights.empty()) {
            continue;  // No valid heights in this chunk
        }

        // Assign chunk to peer
        int start = valid_heights.front();
        int end = valid_heights.back();
        if (!m_node_context.block_fetcher->AssignChunkToPeer(peer_id, start, end)) {
            continue;  // Assignment failed
        }

        // Phase 3: Mark these heights as in-flight in the window
        m_node_context.block_fetcher->MarkWindowHeightsInFlight(valid_heights);

        // Build GETDATA message for this chunk
        std::vector<NetProtocol::CInv> getdata;
        getdata.reserve(valid_heights.size());

        std::cout << "[GETDATA-DEBUG] Building GETDATA for chunk " << start << "-" << end << ", valid_heights=" << valid_heights.size() << std::endl;

        for (int h : valid_heights) {
            uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
            if (!hash.IsNull()) {
                // Also track in the old per-block system for timeout handling
                bool request_ok = m_node_context.block_fetcher->RequestBlock(peer_id, hash, h);
                getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
                // Only log every 4th block to reduce spam
                if (h % 4 == 0) {
                    std::cout << "[GETDATA-DEBUG]   Height " << h << ": request_ok=" << request_ok << std::endl;
                }
            } else {
                std::cout << "[GETDATA-ERROR]   Height " << h << ": hash is null!" << std::endl;
            }
        }

        std::cout << "[GETDATA-DEBUG] Built " << getdata.size() << " entries for peer " << peer_id << std::endl;

        // Send single batched GETDATA for entire chunk
        if (!getdata.empty()) {
            CNetMessage msg = m_node_context.message_processor->CreateGetDataMessage(getdata);
            std::cout << "[GETDATA-DEBUG] Sending to peer " << peer_id << std::endl;

            // BUG #154 FIX: Check if message was sent successfully
            bool sent = m_node_context.connman->PushMessage(peer_id, msg);
            if (!sent) {
                LogPrintIBD(WARN, "GETDATA send failed for peer %d - cancelling chunk", peer_id);
                m_node_context.block_fetcher->CancelStalledChunk(peer_id);
                continue;  // Try next peer
            }

            // BUG #155 FIX: Update activity timer after successful GETDATA send
            // This prevents false stall detection when network is slow
            m_node_context.block_fetcher->UpdateChunkActivity(peer_id);

            total_chunks_assigned++;

            LogPrintIBD(INFO, "Assigned chunk %d-%d (%zu blocks) to peer %d [%s]",
                        start, end, getdata.size(), peer_id,
                        m_node_context.block_fetcher->GetWindowStatus().c_str());
        } else {
            LogPrintIBD(WARN, "GETDATA is empty for peer %d!", peer_id);
        }
    }

    // Legacy per-block fallback removed - chunk system is now the only path

    return total_chunks_assigned > 0;
}

void CIbdCoordinator::RetryTimeoutsAndStalls() {
    if (!m_node_context.block_fetcher || !m_node_context.connman) {
        return;
    }

    // Check for block-level timeouts (60 second)
    auto timed_out = m_node_context.block_fetcher->CheckTimeouts();
    if (!timed_out.empty()) {
        LogPrintIBD(WARN, "%zu block(s) timed out, retrying...", timed_out.size());
        m_node_context.block_fetcher->RetryTimedOutBlocks(timed_out);
    }

    // Phase 2: Check for stalled chunks (2 second stall detection)
    auto stalled_chunks = m_node_context.block_fetcher->CheckStalledChunks();
    for (const auto& [peer_id, chunk] : stalled_chunks) {
        bool reassigned = false;

        // Find an alternative peer to reassign the chunk to
        if (m_node_context.peer_manager) {
            std::vector<int> valid_peers = m_node_context.peer_manager->GetValidPeersForDownload();
            for (int new_peer : valid_peers) {
                if (new_peer != peer_id) {
                    auto new_peer_obj = m_node_context.peer_manager->GetPeer(new_peer);
                    if (new_peer_obj && new_peer_obj->nBlocksInFlight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
                        if (m_node_context.block_fetcher->ReassignChunk(peer_id, new_peer)) {
                            LogPrintIBD(INFO, "Reassigned stalled chunk from peer %d to peer %d", peer_id, new_peer);

                            // Re-send GETDATA for the reassigned chunk
                            std::vector<NetProtocol::CInv> getdata;
                            for (int h = chunk.height_start; h <= chunk.height_end; h++) {
                                uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
                                if (!hash.IsNull()) {
                                    getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
                                }
                            }
                            if (!getdata.empty()) {
                                CNetMessage msg = m_node_context.message_processor->CreateGetDataMessage(getdata);
                                m_node_context.connman->PushMessage(new_peer, msg);
                            }
                            reassigned = true;
                            break;
                        }
                    }
                }
            }
        }

        // If reassignment failed (e.g., all peers have active chunks), cancel the stalled chunk
        // This makes the heights available for re-request on the next FetchBlocks() call
        if (!reassigned) {
            std::cout << "[STALL-FIX] Cancelling stalled chunk from peer " << peer_id << std::endl;
            std::cout.flush();
            LogPrintIBD(WARN, "Could not reassign stalled chunk from peer %d - cancelling chunk", peer_id);
            m_node_context.block_fetcher->CancelStalledChunk(peer_id);
        }
    }

    // Legacy: Disconnect stalling peers
    std::vector<NodeId> stalling_peers;
    if (m_node_context.peer_manager) {
        stalling_peers = m_node_context.peer_manager->CheckForStallingPeers();
    }

    for (NodeId peer : stalling_peers) {
        LogPrintIBD(WARN, "Disconnecting stalling peer %d", peer);
        m_node_context.connman->DisconnectNode(peer, "stalling block download");
    }
}

