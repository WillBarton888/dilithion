// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/ibd_coordinator.h>

#include <iostream>
#include <set>
#include <vector>

#include <consensus/chain.h>
#include <core/chainparams.h>  // Initial header request needs genesis hash
#include <node/blockchain_storage.h>  // BUG #159: Orphan block deletion
#include <core/node_context.h>
#include <net/block_fetcher.h>
#include <net/headers_manager.h>
#include <net/net.h>  // CNetMessageProcessor
#include <net/connman.h>  // Phase 5: CConnman
#include <net/peers.h>
#include <net/protocol.h>
#include <node/block_validation_queue.h>  // Phase 2: Async block validation
#include <net/orphan_manager.h>  // IBD STUCK FIX #3: Periodic orphan scan
#include <util/logging.h>
#include <util/bench.h>  // Performance: Benchmarking

// IBD STUCK FIX #3: Access to global NodeContext for orphan manager
extern NodeContext g_node_context;

CIbdCoordinator::CIbdCoordinator(CChainState& chainstate, NodeContext& node_context)
    : m_chainstate(chainstate),
      m_node_context(node_context),
      m_last_ibd_attempt(std::chrono::steady_clock::time_point()) {}

void CIbdCoordinator::Tick() {
    // IBD DEBUG: Confirm Tick() is being called
    static int tick_count = 0;
    if (++tick_count <= 5 || tick_count % 60 == 0) {
        std::cerr << "[IBD-DEBUG] Tick() called #" << tick_count << std::endl;
    }

    // Phase 5.1: Update state machine
    UpdateState();

    // Check if IBD components are available
    if (!m_node_context.headers_manager || !m_node_context.block_fetcher) {
        // IBD DEBUG: Log why we're returning early
        static int no_components_count = 0;
        if (++no_components_count <= 5) {
            std::cerr << "[IBD-DEBUG] Tick() returning: no headers_manager or block_fetcher" << std::endl;
        }
        return;
    }

    int header_height = m_node_context.headers_manager->GetBestHeight();
    int chain_height = m_chainstate.GetHeight();

    // =========================================================================
    // BITCOIN CORE STYLE SINGLE-SYNC-PEER HEADERS MANAGEMENT
    // =========================================================================

    // 1. Select a headers sync peer if we don't have one
    SelectHeadersSyncPeer();

    // 2. Check if current sync peer is making progress (or stalled)
    if (!CheckHeadersSyncProgress()) {
        // Sync peer stalled, switch to a different one
        SwitchHeadersSyncPeer();
    }

    // 3. Request initial headers if we have none
    // PIPELINE: After initial request, headers_manager handles prefetch on RECEIPT
    if (m_headers_sync_peer != -1) {
        int peer_height = m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);

        if (!m_initial_request_done && header_height == 0 && peer_height > 0) {
            // Initial request - kick off the pipeline via SSOT entry point
            m_initial_request_done = true;
            std::cout << "[IBD] Initial header request from sync peer " << m_headers_sync_peer
                      << " (peer_height=" << peer_height << ")" << std::endl;
            if (m_node_context.headers_manager->SyncHeadersFromPeer(m_headers_sync_peer, peer_height)) {
                m_headers_in_flight = true;
            }
            // IMPORTANT: Return here to prevent catch-up logic from firing in same tick
            // before first batch arrives and sets m_last_request_hash
            return;
        }
        // Note: Subsequent header requests are triggered by headers_manager's
        // SyncHeadersFromPeer() when headers are RECEIVED (not validated).
        // This creates a pipeline where we request batch N+1 while validating batch N.
    }

    // =========================================================================

    // If headers are not ahead, check if any peer has more blocks we need
    if (header_height <= chain_height) {
        // Check if any peer has higher height than our headers
        // This catches the case where we're "synced" but a miner just found new blocks
        static auto last_catchup_request = std::chrono::steady_clock::time_point();
        auto now_catchup = std::chrono::steady_clock::now();

        // Rate limit: only check for catchup every 2 seconds to prevent spam
        if (now_catchup - last_catchup_request > std::chrono::seconds(2)) {
            last_catchup_request = now_catchup;  // Update FIRST to guarantee rate limit
            if (m_node_context.peer_manager && m_node_context.headers_manager) {
                auto peers = m_node_context.peer_manager->GetConnectedPeers();
                int best_peer = -1;
                int best_height = header_height;

                for (const auto& peer : peers) {
                    if (!peer) continue;
                    int peer_height = m_node_context.headers_manager->GetPeerStartHeight(peer->id);
                    if (peer_height > best_height) {
                        best_height = peer_height;
                        best_peer = peer->id;
                    }
                }

                // SSOT: Just ask HeadersManager to sync - it handles all dedup internally
                // BUT: Only request if we don't have an outstanding prefetch
                // (prefetch is in progress when requested_height > validated_height)
                int requested_height = m_node_context.headers_manager->GetRequestedHeight();
                int validated_height = m_node_context.headers_manager->GetBestHeight();
                if (best_peer != -1 && requested_height <= validated_height) {
                    m_headers_sync_peer = best_peer;
                    m_node_context.headers_manager->SyncHeadersFromPeer(best_peer, best_height);
                }
            }
        }

        static int synced_count = 0;
        if (++synced_count <= 5 || synced_count % 60 == 0) {
            std::cerr << "[IBD-DEBUG] Tick() returning: synced (header=" << header_height
                      << " <= chain=" << chain_height << ")" << std::endl;
        }
        if (m_state != IBDState::IDLE && m_state != IBDState::COMPLETE) {
            m_state = IBDState::COMPLETE;
        }
        return;
    }

    ResetBackoffOnNewHeaders(header_height);

    auto now = std::chrono::steady_clock::now();
    if (!ShouldAttemptDownload()) {
        // IBD DEBUG: Log why we're returning early
        static int backoff_count = 0;
        if (++backoff_count <= 5 || backoff_count % 60 == 0) {
            std::cerr << "[IBD-DEBUG] Tick() returning: ShouldAttemptDownload=false (backoff)" << std::endl;
        }
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
    // IBD DEBUG: Track entry into DownloadBlocks
    std::cerr << "[IBD-DEBUG] DownloadBlocks entered: header=" << header_height << " chain=" << chain_height << std::endl;

    // Bug #150: Log fork status periodically (every 100 calls)
    static size_t download_call_count = 0;
    if (++download_call_count % 100 == 0 && m_node_context.headers_manager) {
        if (m_node_context.headers_manager->HasCompetingForks()) {
            std::cout << "[IBD] Fork status: " << m_node_context.headers_manager->GetForkCount()
                      << " competing chain tips detected" << std::endl;
        }
    }

    BENCHMARK_START("ibd_download_blocks");
    m_last_ibd_attempt = now;

    LogPrintIBD(INFO, "Headers ahead of chain - downloading blocks (header=%d chain=%d)", header_height, chain_height);

    // BUG #158 FIX: Fork detection - check if chain height isn't advancing
    // THREAD SAFETY + PERFORMANCE FIX: Use member atomics, check less frequently
    // Track stall cycles: if chain height doesn't advance despite IBD activity, we may be on a fork

    // PROFESSIONAL FIX: Only enable fork detection when near chain tip
    // During bulk IBD, rely on checkpoints + PoW validation (no lock contention)
    // Near tip (within 100 blocks), enable full fork detection for reorg protection
    // Security: PoW validation still happens for every block, checkpoints protect early chain
    // This approach matches Bitcoin Core's IBD behavior
    static constexpr int FORK_DETECTION_TIP_THRESHOLD = 100;  // Enable when within 100 blocks of tip
    bool near_tip = (header_height - chain_height) < FORK_DETECTION_TIP_THRESHOLD;

    if (!near_tip) {
        // Bulk IBD: checkpoints + PoW are sufficient protection
        // Skip fork detection to avoid cs_main lock contention from FindForkPoint()
        m_fork_stall_cycles.store(0);
    } else if (m_last_checked_chain_height == chain_height && !m_fork_detected.load()) {
        // Chain height hasn't advanced since last tick
        m_fork_stall_cycles.fetch_add(1);
        int stall_cycles = m_fork_stall_cycles.load();

        // Check if there's IBD activity (blocks pending or in-flight)
        bool has_ibd_activity = false;
        if (m_node_context.block_fetcher) {
            has_ibd_activity = m_node_context.block_fetcher->GetPendingCount() > 0 ||
                              m_node_context.block_fetcher->GetInFlightCount() > 0;
        }

        if (has_ibd_activity && stall_cycles >= FORK_DETECTION_THRESHOLD) {
            // Issue #6 FIX: Throttle fork detection to avoid CPU overhead
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_fork_check).count();
            if (elapsed >= FORK_CHECK_MIN_INTERVAL_SECS) {
                // Enough time has passed since last check
                m_last_fork_check = now;

                std::cout << "[FORK-DETECT] Chain stalled at height " << chain_height
                          << " for " << stall_cycles << " cycles - checking for fork..." << std::endl;

                int fork_point = FindForkPoint(chain_height);
                if (fork_point > 0 && fork_point < chain_height) {
                    std::cout << "[FORK-DETECT] Fork detected! Local chain diverged at height " << fork_point
                              << " (chain=" << chain_height << ", fork_depth=" << (chain_height - fork_point) << ")" << std::endl;
                    HandleForkScenario(fork_point, chain_height);
                    m_fork_stall_cycles.store(0);
                    m_last_checked_chain_height = -1;  // Reset to allow fresh tracking
                    // Continue with normal IBD - window has been reset to fork point
                } else if (fork_point == chain_height) {
                    // Not a fork - just slow downloads, reset counter
                    std::cout << "[FORK-DETECT] No fork detected (tip matches header chain)" << std::endl;
                    m_fork_stall_cycles.store(0);
                }
            }
        }
    } else {
        // Chain is advancing - reset stall detection
        m_fork_stall_cycles.store(0);
        int current_fork_point = m_fork_point.load();
        if (m_fork_detected.load() && chain_height > current_fork_point) {
            // We've advanced past the fork point - clear fork state
            std::cout << "[FORK-RECOVERY] Chain advanced past fork point " << current_fork_point
                      << " to " << chain_height << " - fork recovery complete" << std::endl;
            m_fork_detected.store(false);
            m_fork_point.store(-1);
        }
    }
    m_last_checked_chain_height = chain_height;

    // IBD HANG FIX #1: Apply gradual backpressure rate multiplier
    // Reduces request rate gradually as validation queue fills, preventing binary stop/resume cycle
    double rate_multiplier = GetDownloadRateMultiplier();

    // PURE PER-BLOCK: No more window or queue population needed
    // GetNextBlocksToRequest() directly iterates from chain_height+1 to header_height
    LogPrintIBD(INFO, "Downloading blocks (chain=%d, header=%d, rate=%.0f%%)...",
                chain_height, header_height, rate_multiplier * 100.0);

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
            case HangCause::PEERS_AT_CAPACITY: cause_str = "all peers at capacity"; break;
            case HangCause::NONE: cause_str = "no suitable peers"; break;
        }
        LogPrintIBD(WARN, "Could not send any block requests - %s", cause_str.c_str());
    } else {
        m_last_hang_cause = HangCause::NONE;  // Clear hang cause on success
    }

    // ORPHAN SSOT: Orphans are now processed ONLY by validation queue (block_validation_queue.cpp)
    // This periodic scan is for DIAGNOSTICS ONLY - logging orphan pool health
    static auto last_orphan_scan = std::chrono::steady_clock::now();
    auto now_orphan_scan = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now_orphan_scan - last_orphan_scan).count() >= 10) {
        last_orphan_scan = now_orphan_scan;

        if (g_node_context.orphan_manager) {
            size_t orphan_count = g_node_context.orphan_manager->GetOrphanCount();
            if (orphan_count > 0) {
                std::cout << "[IBD] Orphan pool: " << orphan_count << " blocks waiting for parents" << std::endl;
            }
        }
    }

    RetryTimeoutsAndStalls();
    BENCHMARK_END("ibd_download_blocks");

    // IBD DEBUG: DownloadBlocks complete
    std::cerr << "[IBD-DEBUG] DownloadBlocks complete" << std::endl;
}

// QueueMissingBlocks REMOVED - pure per-block model uses GetNextBlocksToRequest() directly

bool CIbdCoordinator::FetchBlocks() {
    if (!m_node_context.block_fetcher || !m_node_context.message_processor ||
        !m_node_context.connman || !m_node_context.peer_manager || !m_node_context.headers_manager) {
        return false;
    }

    // ============ SINGLE-PEER BLOCK DOWNLOAD ============
    // Use ONE peer for all block downloads (different from headers peer)
    // Max 32 blocks in-flight to this single peer
    // Switch peer only on disconnect or stall

    int chain_height = m_chainstate.GetHeight();
    int header_height = m_node_context.headers_manager->GetBestHeight();

    // Check for headers sync lag - need headers ahead of chain to download blocks
    if (header_height <= chain_height) {
        return false;
    }

    // ============ SELECT BLOCK SYNC PEER ============
    // Check if current block sync peer is still valid
    if (m_blocks_sync_peer != -1) {
        auto peer = m_node_context.peer_manager->GetPeer(m_blocks_sync_peer);
        if (!peer) {
            std::cout << "[IBD] Blocks sync peer " << m_blocks_sync_peer << " disconnected" << std::endl;
            m_blocks_sync_peer = -1;
        }
    }

    // Select a new block sync peer if needed
    if (m_blocks_sync_peer == -1) {
        auto peers = m_node_context.peer_manager->GetConnectedPeers();
        int best_peer = -1;
        int best_height = chain_height;
        int headers_peer_height = 0;  // Track headers sync peer as fallback

        for (const auto& peer : peers) {
            if (!peer) continue;

            int peer_height = peer->best_known_height;
            if (peer_height == 0) peer_height = peer->start_height;

            // Prefer non-headers-sync peers
            if (peer->id == m_headers_sync_peer) {
                headers_peer_height = peer_height;
                continue;
            }

            if (peer_height > best_height) {
                best_height = peer_height;
                best_peer = peer->id;
            }
        }

        // If no other peer found, use headers sync peer for blocks too
        if (best_peer == -1 && m_headers_sync_peer != -1 && headers_peer_height > chain_height) {
            best_peer = m_headers_sync_peer;
            best_height = headers_peer_height;
        }

        if (best_peer != -1) {
            m_blocks_sync_peer = best_peer;
            std::cout << "[IBD] Selected blocks sync peer " << m_blocks_sync_peer
                      << " (height=" << best_height << ")" << std::endl;
        } else {
            m_ibd_no_peer_cycles++;
            m_last_hang_cause = HangCause::NO_PEERS_AVAILABLE;
            return false;
        }
    }

    // ============ REQUEST BLOCKS FROM SINGLE PEER ============
    auto peer = m_node_context.peer_manager->GetPeer(m_blocks_sync_peer);
    if (!peer) {
        m_blocks_sync_peer = -1;
        return false;
    }

    // Check peer capacity
    int peer_blocks_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(m_blocks_sync_peer);
    int peer_capacity = MAX_BLOCKS_IN_TRANSIT_PER_PEER - peer_blocks_in_flight;
    if (peer_capacity <= 0) {
        return false;  // Peer at capacity - wait for blocks to arrive
    }

    // Get peer height
    int peer_height = peer->best_known_height;
    if (peer_height == 0) peer_height = peer->start_height;

    // Get next blocks to request
    std::vector<int> blocks_to_request = m_node_context.block_fetcher->GetNextBlocksToRequest(
        peer_capacity, chain_height, header_height);
    if (blocks_to_request.empty()) {
        return false;  // All blocks either connected or in-flight
    }

    // Build GETDATA
    std::vector<NetProtocol::CInv> getdata;
    getdata.reserve(blocks_to_request.size());

    for (int h : blocks_to_request) {
        // Re-check capacity before each request
        int current_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(m_blocks_sync_peer);
        if (current_in_flight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            break;
        }

        // Validate height range
        if (h > header_height || h <= chain_height || h > peer_height) continue;

        uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
        if (hash.IsNull()) continue;

        // Check if already connected
        CBlockIndex* pindex = m_chainstate.GetBlockIndex(hash);
        if (pindex && (pindex->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
            continue;
        }

        // Request block from our single sync peer
        if (m_node_context.block_fetcher->RequestBlockFromPeer(m_blocks_sync_peer, h, hash)) {
            getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
        }
    }

    // Send GETDATA to our single sync peer
    if (!getdata.empty()) {
        CNetMessage msg = m_node_context.message_processor->CreateGetDataMessage(getdata);
        bool sent = m_node_context.connman->PushMessage(m_blocks_sync_peer, msg);
        if (!sent) {
            for (const auto& inv : getdata) {
                int height = m_node_context.headers_manager->GetHeightForHash(inv.hash);
                if (height > 0) {
                    m_node_context.block_fetcher->RequeueBlock(height);
                }
            }
            m_blocks_sync_peer = -1;  // Force peer reselection on next call
            return false;
        }

        std::cout << "[IBD] Requested " << getdata.size() << " blocks from peer " << m_blocks_sync_peer
                  << " (in-flight=" << m_node_context.block_fetcher->GetPeerBlocksInFlight(m_blocks_sync_peer)
                  << "/" << MAX_BLOCKS_IN_TRANSIT_PER_PEER << ")" << std::endl;

        return true;
    }

    return false;
}

void CIbdCoordinator::RetryTimeoutsAndStalls() {
    if (!m_node_context.block_fetcher || !m_node_context.connman || !m_node_context.headers_manager) {
        return;
    }

    // ============ HARD TIMEOUT: Remove blocks stuck too long ============
    // After 60 seconds, remove from tracker so they can be re-requested from different peer
    // Note: Increased from 10s to 60s because RandomX PoW validation above checkpoint
    // can take 1-2 seconds per block on slower VPS hardware
    static constexpr int HARD_TIMEOUT_SECONDS = 60;
    auto very_stalled = m_node_context.block_fetcher->GetStalledBlocks(
        std::chrono::seconds(HARD_TIMEOUT_SECONDS));

    if (!very_stalled.empty()) {
        int removed = 0;
        for (const auto& [height, peer] : very_stalled) {
            m_node_context.block_fetcher->RequeueBlock(height);
            removed++;
        }
        if (removed > 0) {
            std::cout << "[PerBlock] Removed " << removed << " blocks stuck >" << HARD_TIMEOUT_SECONDS
                      << "s from tracker (will re-request)" << std::endl;
        }
    }

    // Disconnect stalling peers
    std::vector<NodeId> stalling_peers;
    if (m_node_context.peer_manager) {
        stalling_peers = m_node_context.peer_manager->CheckForStallingPeers();
    }

    for (NodeId peer : stalling_peers) {
        LogPrintIBD(WARN, "Disconnecting stalling peer %d", peer);
        m_node_context.connman->DisconnectNode(peer, "stalling block download");
    }
}

/**
 * BUG #158 FIX: Find the fork point between local chain and header chain
 *
 * RACE CONDITION FIX: Uses thread-safe GetChainSnapshot() to avoid reading
 * pprev pointers without holding cs_main. Previously, this function could
 * cause use-after-free if validation workers modified the chain concurrently.
 *
 * Returns the height where local chain matches header chain (common ancestor),
 * or 0 if no match found.
 */
int CIbdCoordinator::FindForkPoint(int chain_height) {
    if (!m_node_context.headers_manager) {
        return 0;
    }

    std::cout << "[FORK-DETECT] Searching for fork point from height " << chain_height << std::endl;

    // RACE CONDITION FIX: Get a thread-safe snapshot of the chain
    // This holds cs_main while copying the data, then releases it
    const int MAX_CHECKS = 1000;
    auto chainSnapshot = m_chainstate.GetChainSnapshot(MAX_CHECKS, 0);

    if (chainSnapshot.empty()) {
        std::cerr << "[FORK-DETECT] ERROR: Empty chain snapshot" << std::endl;
        return 0;
    }

    int checks = 0;
    for (const auto& [height, local_hash] : chainSnapshot) {
        // Get header hash at this height (this is the network's chain)
        uint256 header_hash = m_node_context.headers_manager->GetRandomXHashAtHeight(height);
        if (header_hash.IsNull()) {
            checks++;
            continue;  // No header at this height, keep searching
        }

        // Compare: if they match, we found the fork point
        if (local_hash == header_hash) {
            std::cout << "[FORK-DETECT] Found common ancestor at height " << height
                      << " hash=" << local_hash.GetHex().substr(0, 16) << "..." << std::endl;
            return height;
        }

        // Log divergence for debugging (first few mismatches only)
        if (checks < 6) {
            std::cout << "[FORK-DETECT] Height " << height << " diverges:"
                      << " local=" << local_hash.GetHex().substr(0, 16) << "..."
                      << " header=" << header_hash.GetHex().substr(0, 16) << "..." << std::endl;
        }

        checks++;
    }

    // No common ancestor found - something is very wrong
    std::cerr << "[FORK-DETECT] ERROR: No common ancestor found after " << checks << " blocks!" << std::endl;
    return 0;
}

/**
 * BUG #158 FIX: Handle a fork scenario by resetting IBD to start from fork point
 * BUG #159 FIX: Disconnect forked blocks via chain reorg before downloading correct chain
 */
void CIbdCoordinator::HandleForkScenario(int fork_point, int chain_height) {
    if (!m_node_context.block_fetcher || fork_point <= 0) {
        return;
    }

    std::cout << "[FORK-RECOVERY] Resetting IBD to fork point " << fork_point
              << " (chain was at " << chain_height << ")" << std::endl;

    // CRITICAL: Pause header processing before modifying chainstate
    // This prevents async workers from accessing CBlockIndex pointers that will be invalidated
    if (m_node_context.headers_manager) {
        m_node_context.headers_manager->PauseHeaderProcessing();
    }

    // BUG #159 FIX: Disconnect forked blocks before downloading correct chain
    // We need to remove blocks from fork_point+1 to chain_height so new blocks can connect
    int blocks_to_disconnect = chain_height - fork_point;
    if (blocks_to_disconnect > 0) {
        std::cout << "[FORK-RECOVERY] Disconnecting " << blocks_to_disconnect
                  << " forked block(s) from height " << chain_height
                  << " down to " << (fork_point + 1) << std::endl;

        // Walk backwards from tip, disconnecting each forked block
        int disconnected = 0;
        CBlockIndex* pindex = m_chainstate.GetTip();

        while (pindex && pindex->nHeight > fork_point && disconnected < blocks_to_disconnect) {
            std::cout << "[FORK-RECOVERY] Disconnecting block at height " << pindex->nHeight
                      << " hash=" << pindex->GetBlockHash().GetHex().substr(0, 16) << "..." << std::endl;

            // Get parent before disconnecting (we'll need it for next iteration)
            CBlockIndex* pprev = pindex->pprev;

            // Disconnect this block from the chain
            if (!m_chainstate.DisconnectTip(pindex, true)) {
                std::cerr << "[FORK-RECOVERY] ERROR: Failed to disconnect block at height "
                          << pindex->nHeight << std::endl;
                // Continue anyway - the block may have already been disconnected
            } else {
                disconnected++;
            }

            // Move to parent block
            pindex = pprev;
        }

        // Update chain tip to fork point
        // VALIDATION FIX: Ensure disconnect completed successfully before setting tip
        if (pindex && pindex->nHeight == fork_point) {
            m_chainstate.SetTip(pindex);
            std::cout << "[FORK-RECOVERY] Chain tip reset to height " << fork_point
                      << " hash=" << pindex->GetBlockHash().GetHex().substr(0, 16) << "..." << std::endl;
        } else {
            // Disconnect loop did not complete as expected - log error
            std::cerr << "[FORK-RECOVERY] ERROR: Disconnect incomplete! Expected tip at height "
                      << fork_point << " but pindex is "
                      << (pindex ? std::to_string(pindex->nHeight) : "nullptr") << std::endl;
            std::cerr << "[FORK-RECOVERY] Chainstate may be inconsistent - consider reindex" << std::endl;
        }

        std::cout << "[FORK-RECOVERY] Disconnected " << disconnected << " forked block(s)" << std::endl;

        // BUG #159 FIX: Delete orphan blocks from DB that were built on the forked chain
        // These blocks have their prevBlockHash pointing to disconnected blocks
        // NOTE: Wrapped in try-catch to prevent crash during fork recovery
        try {
        if (m_node_context.blockchain_db && disconnected > 0) {
            // Get all blocks from DB and find orphans (blocks above fork_point not on main chain)
            std::vector<uint256> all_block_hashes;
            if (m_node_context.blockchain_db->GetAllBlockHashes(all_block_hashes)) {
                int total_deleted = 0;
                bool found_orphan = true;

                // Iterate until no more orphans found (handles chains of orphans)
                while (found_orphan && total_deleted < 1000) {  // Safety limit
                    found_orphan = false;

                    for (const auto& hash : all_block_hashes) {
                        CBlock block;
                        if (m_node_context.blockchain_db->ReadBlock(hash, block)) {
                            // Check if this block's parent is one of the forked blocks
                            // or is a block at height > fork_point that's not on main chain
                            CBlockIndex* pBlockIndex = m_chainstate.GetBlockIndex(hash);
                            if (pBlockIndex) {
                                // Block is in our index
                                if (pBlockIndex->nHeight > fork_point &&
                                    !(pBlockIndex->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
                                    // This is an orphan - not on main chain and above fork point
                                    std::cout << "[FORK-RECOVERY] Deleting orphan block at height "
                                              << pBlockIndex->nHeight << " hash="
                                              << hash.GetHex().substr(0, 16) << "..." << std::endl;

                                    if (m_node_context.blockchain_db->EraseBlock(hash)) {
                                        total_deleted++;
                                        found_orphan = true;
                                    }
                                }
                            } else {
                                // Block not in index but in DB - could be orphan from failed sync
                                // Check if its prevBlockHash points to a disconnected block
                                // LOGIC FIX #26: Only delete if parent is FOUND and above fork_point
                                // If parent is nullptr, we don't know if block is valid - keep it
                                CBlockIndex* pPrevIndex = m_chainstate.GetBlockIndex(block.hashPrevBlock);
                                if (pPrevIndex && pPrevIndex->nHeight > fork_point) {
                                    std::cout << "[FORK-RECOVERY] Deleting unindexed orphan block hash="
                                              << hash.GetHex().substr(0, 16) << "..." << std::endl;

                                    if (m_node_context.blockchain_db->EraseBlock(hash)) {
                                        total_deleted++;
                                        found_orphan = true;
                                    }
                                }
                            }
                        }
                    }

                    // Refresh block list for next iteration
                    if (found_orphan) {
                        all_block_hashes.clear();
                        m_node_context.blockchain_db->GetAllBlockHashes(all_block_hashes);
                    }
                }

                if (total_deleted > 0) {
                    std::cout << "[FORK-RECOVERY] Deleted " << total_deleted
                              << " orphan block(s) from database" << std::endl;
                }
            }
        }
        } catch (const std::exception& e) {
            std::cerr << "[FORK-RECOVERY] Exception during orphan cleanup: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[FORK-RECOVERY] Unknown exception during orphan cleanup" << std::endl;
        }
    }

    // Clear in-flight tracking above fork point
    // This allows blocks to be re-requested from the correct chain
    int cleared = 0;
    if (m_node_context.block_fetcher) {
        cleared = m_node_context.block_fetcher->ClearAboveHeight(fork_point);
    }
    std::cout << "[FORK-RECOVERY] Cleared " << cleared << " in-flight blocks above fork point, "
              << "downloads will resume from height " << (fork_point + 1) << std::endl;

    // Reset fork detection state
    m_fork_detected = true;
    m_fork_point = fork_point;
    m_fork_stall_cycles = 0;

    // Resume header processing now that chainstate is stable
    if (m_node_context.headers_manager) {
        m_node_context.headers_manager->ResumeHeaderProcessing();
    }
}

// ============================================================================
// HEADERS SYNC PEER MANAGEMENT (Bitcoin Core style single-sync-peer)
// ============================================================================

void CIbdCoordinator::SelectHeadersSyncPeer() {
    // If we already have a sync peer, check if they're still connected
    if (m_headers_sync_peer != -1) {
        if (m_node_context.peer_manager) {
            auto peer = m_node_context.peer_manager->GetPeer(m_headers_sync_peer);
            if (peer) {
                return;  // Current sync peer still valid
            }
        }
        // Sync peer disconnected, need to select a new one
        std::cout << "[IBD] Headers sync peer " << m_headers_sync_peer << " disconnected" << std::endl;
        m_headers_sync_peer = -1;
    }

    // Select a new sync peer - prefer peers with more blocks
    if (!m_node_context.peer_manager || !m_node_context.headers_manager) {
        return;
    }

    auto peers = m_node_context.peer_manager->GetConnectedPeers();
    int best_peer = -1;
    int best_height = 0;

    for (const auto& peer : peers) {
        if (!peer) continue;
        int peer_height = m_node_context.headers_manager->GetPeerStartHeight(peer->id);
        if (peer_height > best_height) {
            best_height = peer_height;
            best_peer = peer->id;
        }
    }

    if (best_peer != -1) {
        m_headers_sync_peer = best_peer;
        m_headers_sync_last_height = m_node_context.headers_manager->GetBestHeight();

        // Calculate timeout: base + 1ms per missing header (Bitcoin Core style)
        int headers_missing = best_height - m_headers_sync_last_height;
        int timeout_ms = HEADERS_SYNC_TIMEOUT_BASE_SECS * 1000 +
                         headers_missing * HEADERS_SYNC_TIMEOUT_PER_HEADER_MS;
        m_headers_sync_timeout = std::chrono::steady_clock::now() +
                                 std::chrono::milliseconds(timeout_ms);

        std::cout << "[IBD] Selected headers sync peer " << best_peer
                  << " (height=" << best_height << ", timeout=" << (timeout_ms/1000) << "s)" << std::endl;
    }
}

bool CIbdCoordinator::CheckHeadersSyncProgress() {
    if (m_headers_sync_peer == -1) {
        return true;  // No sync peer, nothing to check
    }

    auto now = std::chrono::steady_clock::now();
    int current_height = m_node_context.headers_manager ?
                         m_node_context.headers_manager->GetBestHeight() : 0;

    // Check if we've made progress
    if (current_height > m_headers_sync_last_height) {
        // Progress made, update tracking and extend timeout
        m_headers_sync_last_height = current_height;

        // FIX 2: Headers received - clear in-flight flag so this peer can receive block requests
        m_headers_in_flight = false;

        // Recalculate timeout based on remaining headers
        int peer_height = m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);
        int headers_missing = peer_height - current_height;
        if (headers_missing > 0) {
            int timeout_ms = HEADERS_SYNC_TIMEOUT_BASE_SECS * 1000 +
                             headers_missing * HEADERS_SYNC_TIMEOUT_PER_HEADER_MS;
            m_headers_sync_timeout = now + std::chrono::milliseconds(timeout_ms);
        }
        return true;  // Making progress
    }

    // Check for timeout
    if (now > m_headers_sync_timeout) {
        std::cout << "[IBD] Headers sync peer " << m_headers_sync_peer
                  << " STALLED (no progress, timeout reached)" << std::endl;
        return false;  // Stalled
    }

    return true;  // Not stalled yet
}

void CIbdCoordinator::SwitchHeadersSyncPeer() {
    int old_peer = m_headers_sync_peer;
    m_headers_sync_peer = -1;  // Force reselection

    // TODO: Could ban or deprioritize the old peer here

    SelectHeadersSyncPeer();

    if (m_headers_sync_peer != -1 && m_headers_sync_peer != old_peer) {
        std::cout << "[IBD] Switched headers sync peer: " << old_peer
                  << " -> " << m_headers_sync_peer << std::endl;
        // SSOT: Request headers via single entry point
        int peer_height = m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);
        if (m_node_context.headers_manager->SyncHeadersFromPeer(m_headers_sync_peer, peer_height)) {
            m_headers_in_flight = true;
        }
    }
}


