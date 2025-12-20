// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/ibd_coordinator.h>

#include <iostream>
#include <set>
#include <vector>

#include <consensus/chain.h>
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

    // If headers are not ahead, we're synced (IDLE or COMPLETE)
    if (header_height <= chain_height) {
        // IBD DEBUG: Log why we're returning early
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

    BENCHMARK_START("ibd_download_blocks");
    m_last_ibd_attempt = now;

    LogPrintIBD(INFO, "Headers ahead of chain - downloading blocks (header=%d chain=%d)", header_height, chain_height);

    // BUG #158 FIX: Fork detection - check if chain height isn't advancing
    // Track stall cycles: if chain height doesn't advance despite IBD activity, we may be on a fork
    static int s_last_chain_height = -1;
    static int s_stall_cycles = 0;
    const int FORK_DETECTION_THRESHOLD = 5;  // Cycles before triggering fork detection

    if (s_last_chain_height == chain_height && !m_fork_detected) {
        // Chain height hasn't advanced since last tick
        s_stall_cycles++;

        // Check if there's IBD activity (blocks pending or in-flight)
        bool has_ibd_activity = false;
        if (m_node_context.block_fetcher) {
            has_ibd_activity = m_node_context.block_fetcher->GetPendingCount() > 0 ||
                              m_node_context.block_fetcher->GetInFlightCount() > 0;
        }

        if (has_ibd_activity && s_stall_cycles >= FORK_DETECTION_THRESHOLD) {
            std::cout << "[FORK-DETECT] Chain stalled at height " << chain_height
                      << " for " << s_stall_cycles << " cycles - checking for fork..." << std::endl;

            int fork_point = FindForkPoint(chain_height);
            if (fork_point > 0 && fork_point < chain_height) {
                std::cout << "[FORK-DETECT] Fork detected! Local chain diverged at height " << fork_point
                          << " (chain=" << chain_height << ", fork_depth=" << (chain_height - fork_point) << ")" << std::endl;
                HandleForkScenario(fork_point, chain_height);
                s_stall_cycles = 0;
                s_last_chain_height = -1;  // Reset to allow fresh tracking
                // Continue with normal IBD - window has been reset to fork point
            } else if (fork_point == chain_height) {
                // Not a fork - just slow downloads, reset counter
                std::cout << "[FORK-DETECT] No fork detected (tip matches header chain)" << std::endl;
                s_stall_cycles = 0;
            }
        }
    } else {
        // Chain is advancing - reset stall detection
        s_stall_cycles = 0;
        if (m_fork_detected && chain_height > m_fork_point) {
            // We've advanced past the fork point - clear fork state
            std::cout << "[FORK-RECOVERY] Chain advanced past fork point " << m_fork_point
                      << " to " << chain_height << " - fork recovery complete" << std::endl;
            m_fork_detected = false;
            m_fork_point = -1;
        }
    }
    s_last_chain_height = chain_height;

    // IBD DEBUG: Before window check
    std::cerr << "[IBD-DEBUG] DownloadBlocks: checking window initialization..." << std::endl;

    // Phase 3: Initialize the 1024-block sliding window for IBD
    if (!m_node_context.block_fetcher->IsWindowInitialized()) {
        std::cerr << "[IBD-DEBUG] DownloadBlocks: calling InitializeWindow..." << std::endl;
        m_node_context.block_fetcher->InitializeWindow(chain_height, header_height);
        std::cerr << "[IBD-DEBUG] DownloadBlocks: InitializeWindow returned" << std::endl;
        LogPrintIBD(INFO, "Initialized download window: %s", m_node_context.block_fetcher->GetWindowStatus().c_str());
    } else {
        std::cerr << "[IBD-DEBUG] DownloadBlocks: window already initialized, updating target..." << std::endl;
        // IBD HANG FIX #15: Update window target as new headers arrive
        // Without this, the window becomes "complete" when header_height grows past initial target
        m_node_context.block_fetcher->UpdateWindowTarget(header_height);
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

    // IBD STUCK FIX #3: Periodic orphan scan to process orphans whose parents are now in chain
    // This handles cases where orphans were stored after their parent validated, or orphan chains
    // where only direct children are processed initially
    static auto last_orphan_scan = std::chrono::steady_clock::now();
    auto now_orphan_scan = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now_orphan_scan - last_orphan_scan).count() >= 10) {
        last_orphan_scan = now_orphan_scan;
        
        if (g_node_context.orphan_manager) {
            // Get all orphans
            std::vector<uint256> all_orphans = g_node_context.orphan_manager->GetAllOrphans();
            int processed_count = 0;
            int no_parent_count = 0;
            int parent_not_connected_count = 0;

            // Debug: log scan start (always log to diagnose issue)
            std::cout << "[IBD STUCK FIX #3] Orphan scan triggered - found " << all_orphans.size() << " orphans in pool" << std::endl;

            // BUG #167 DEBUG: Log chain tip hash for comparison
            if (m_chainstate.GetTip()) {
                std::cout << "[BUG #167 DEBUG] Chain tip height=" << m_chainstate.GetHeight()
                          << " hash=" << m_chainstate.GetTip()->GetBlockHash().GetHex().substr(0, 16) << "..." << std::endl;
            }

            for (const uint256& orphanHash : all_orphans) {
                CBlock orphanBlock;
                if (g_node_context.orphan_manager->GetOrphanBlock(orphanHash, orphanBlock)) {
                    // Check if parent is now in chain and connected
                    CBlockIndex* parent = m_chainstate.GetBlockIndex(orphanBlock.hashPrevBlock);
                    if (!parent) {
                        no_parent_count++;
                        // BUG #167 DEBUG: Log the hashPrevBlock we're looking for
                        if (no_parent_count <= 3) {
                            std::cout << "[BUG #167 DEBUG] Orphan " << orphanHash.GetHex().substr(0, 16)
                                      << " looking for parent " << orphanBlock.hashPrevBlock.GetHex().substr(0, 16) << "..."
                                      << " - NOT FOUND in chainstate" << std::endl;
                        }
                        continue;
                    }
                    if (!(parent->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
                        parent_not_connected_count++;
                        // Debug: log first few cases
                        if (parent_not_connected_count <= 3) {
                            std::cout << "[IBD STUCK FIX #3] Orphan parent at height " << parent->nHeight
                                      << " has status 0x" << std::hex << parent->nStatus
                                      << " (needs BLOCK_VALID_CHAIN=0x" << CBlockIndex::BLOCK_VALID_CHAIN << ")" << std::dec << std::endl;
                        }
                        continue;
                    }
                    if (parent && (parent->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
                        // Parent is connected - trigger orphan processing
                        // Use the same logic as in block_validation_queue.cpp orphan resolution
                        uint256 orphanBlockHash = orphanBlock.GetHash();
                        int orphanHeight = parent->nHeight + 1;
                        
                        // Check if already processed
                        CBlockIndex* existing = m_chainstate.GetBlockIndex(orphanBlockHash);
                        if (existing && existing->HaveData() && (existing->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
                            // Already processed - remove from orphan pool
                            g_node_context.orphan_manager->EraseOrphanBlock(orphanHash);
                            continue;
                        }
                        
                        // Create block index for orphan
                        auto pOrphanIndex = std::make_unique<CBlockIndex>(orphanBlock);
                        pOrphanIndex->phashBlock = orphanBlockHash;
                        pOrphanIndex->nStatus = CBlockIndex::BLOCK_HAVE_DATA;
                        pOrphanIndex->pprev = parent;
                        pOrphanIndex->nHeight = orphanHeight;
                        pOrphanIndex->BuildChainWork();
                        
                        // Add to chain state (orphan block already saved to DB when stored)
                        CBlockIndex* pOrphanIndexRaw = pOrphanIndex.get();
                        if (m_chainstate.AddBlockIndex(orphanBlockHash, std::move(pOrphanIndex))) {
                            // Queue for async validation
                            if (g_node_context.validation_queue && 
                                g_node_context.validation_queue->IsRunning() &&
                                g_node_context.validation_queue->QueueBlock(-1, orphanBlock, orphanHeight, pOrphanIndexRaw)) {
                                LogPrintIBD(DEBUG, "IBD STUCK FIX #3: Queued orphan %s... at height %d (parent now available)", 
                                           orphanBlockHash.GetHex().substr(0, 16).c_str(), orphanHeight);
                                // Successfully queued - remove from orphan pool
                                g_node_context.orphan_manager->EraseOrphanBlock(orphanHash);
                                processed_count++;
                            } else {
                                // Queue failed - keep orphan for retry
                                // Note: Block index remains in chainstate - will be cleaned up later if needed
                            }
                        }
                    }
                }
            }
            
            // Log summary (always log)
            std::cout << "[IBD STUCK FIX #3] Scan complete - processed=" << processed_count
                      << ", no_parent=" << no_parent_count
                      << ", parent_not_connected=" << parent_not_connected_count
                      << ", total=" << all_orphans.size() << std::endl;
            if (processed_count > 0) {
                LogPrintIBD(INFO, "IBD STUCK FIX #3: Processed %d orphan(s) whose parents are now available", processed_count);
            }
        }
    }

    RetryTimeoutsAndStalls();
    BENCHMARK_END("ibd_download_blocks");

    // IBD DEBUG: DownloadBlocks complete
    std::cerr << "[IBD-DEBUG] DownloadBlocks complete" << std::endl;
}

void CIbdCoordinator::QueueMissingBlocks(int chain_height, int blocks_to_queue) {
    if (!m_node_context.headers_manager || !m_node_context.block_fetcher) {
        return;
    }

    // IBD SLOW FIX #1: Collect heights to add to window's pending set
    // Previously only added to old priority queue, causing window/queue disconnect
    std::vector<int> heights_to_add;
    heights_to_add.reserve(blocks_to_queue);

    for (int h = chain_height + 1; h <= chain_height + blocks_to_queue; h++) {
        // IBD OPTIMIZATION: Use GetRandomXHashAtHeight to get the hash for block requests
        // During IBD, headers are stored by FastHash, but GETDATA needs RandomX hash
        uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
        if (hash.IsNull()) {
            continue;  // No header at this height
        }

        // IBD SLOW FIX #7: Check if block is CONNECTED, not just if we have an index
        // During async validation, BlockIndex is created before validation completes
        CBlockIndex* pindex = m_chainstate.GetBlockIndex(hash);
        if (pindex && (pindex->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
            continue;  // Block is actually connected to chain - skip
        }

        // BUG #160 FIX: Check BLOCK_HAVE_DATA instead of HasBlockIndex
        // Headers-first sync creates index WITHOUT data, so HasBlockIndex returns true
        // but block still needs to be downloaded. Only skip download if we have actual data.
        // Without this fix, blocks with header-only index were skipped, causing IBD stall.
        bool has_data = pindex && (pindex->nStatus & CBlockIndex::BLOCK_HAVE_DATA);

        if (has_data) {
            // BUG #160 FIX (COMPLETE): Block data exists but not connected (pending validation or orphan)
            // Mark as RECEIVED in window, NOT pending - these blocks don't need re-download
            // Previously incorrectly added to heights_to_add which went to pending set, causing IBD stall
            m_node_context.block_fetcher->OnWindowBlockReceived(h);
            LogPrintIBD(DEBUG, "Block %s... at height %d has data, marked as received", hash.GetHex().substr(0, 16).c_str(), h);
        } else if (!m_node_context.block_fetcher->IsQueued(hash) &&
                   !m_node_context.block_fetcher->IsDownloading(hash)) {
            // No data (header-only or no index) - queue for download
            m_node_context.block_fetcher->QueueBlockForDownload(hash, h, false);
            heights_to_add.push_back(h);
            LogPrintIBD(DEBUG, "Queued block %s... at height %d for download", hash.GetHex().substr(0, 16).c_str(), h);
        }
    }

    // IBD SLOW FIX #1: Add heights to window's pending set
    // This ensures GetWindowPendingHeights() has heights available
    if (!heights_to_add.empty() && m_node_context.block_fetcher->IsWindowInitialized()) {
        m_node_context.block_fetcher->AddHeightsToWindowPending(heights_to_add);
        LogPrintIBD(DEBUG, "Added %zu heights to window pending set", heights_to_add.size());
    }
}

bool CIbdCoordinator::FetchBlocks() {
    if (!m_node_context.block_fetcher || !m_node_context.message_processor ||
        !m_node_context.connman || !m_node_context.peer_manager || !m_node_context.headers_manager) {
        return false;
    }

    // ============ Bitcoin Core Per-Block Download Model ============
    // Up to 16 individual blocks per peer (not chunks)
    // 3-second stall timeout per block
    // Blocks assigned individually, not as consecutive chunks

    // Get available peers for download
    std::vector<int> available_peers = m_node_context.peer_manager->GetValidPeersForDownload();
    if (available_peers.empty()) {
        m_ibd_no_peer_cycles++;
        m_last_hang_cause = HangCause::NO_PEERS_AVAILABLE;
        LogPrintIBD(WARN, "No peers available for block download");
        return false;
    }

    int chain_height = m_chainstate.GetHeight();
    int header_height = m_node_context.headers_manager->GetBestHeight();

    // Check for headers sync lag
    if (header_height <= chain_height) {
        static int lag_warnings = 0;
        if (lag_warnings++ < 5) {
            LogPrintIBD(WARN, "Headers sync lag: header=%d <= chain=%d", header_height, chain_height);
        }
    }

    int total_blocks_requested = 0;

    // For each peer with capacity, assign individual blocks
    for (int peer_id : available_peers) {
        auto peer = m_node_context.peer_manager->GetPeer(peer_id);
        if (!peer) continue;

        // Check peer capacity using per-block tracking
        int peer_blocks_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(peer_id);
        int peer_capacity = MAX_BLOCKS_IN_TRANSIT_PER_PEER - peer_blocks_in_flight;
        if (peer_capacity <= 0) {
            continue;  // Peer at capacity
        }

        // Skip peers that are behind us
        int peer_height = peer->start_height;
        if (peer_height <= chain_height) {
            continue;
        }

        // Get next blocks to request (up to peer's remaining capacity)
        std::vector<int> blocks_to_request = m_node_context.block_fetcher->GetNextBlocksToRequest(peer_capacity);
        if (blocks_to_request.empty()) {
            m_last_hang_cause = HangCause::WINDOW_EMPTY;
            break;  // No more blocks to request
        }

        // Filter and build GETDATA
        std::vector<NetProtocol::CInv> getdata;
        getdata.reserve(blocks_to_request.size());

        for (int h : blocks_to_request) {
            // Filter: within header range, not already have, peer has it
            if (h > header_height) continue;
            if (h <= chain_height) continue;
            if (h > peer_height) continue;

            uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
            if (hash.IsNull()) continue;

            // Check if already connected
            CBlockIndex* pindex = m_chainstate.GetBlockIndex(hash);
            if (pindex && (pindex->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
                continue;
            }

            // Request this block from peer using per-block API
            if (m_node_context.block_fetcher->RequestBlockFromPeer(peer_id, h, hash)) {
                getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
                total_blocks_requested++;
            }
        }

        // Send batched GETDATA for all blocks assigned to this peer
        if (!getdata.empty()) {
            CNetMessage msg = m_node_context.message_processor->CreateGetDataMessage(getdata);
            bool sent = m_node_context.connman->PushMessage(peer_id, msg);
            if (!sent) {
                // Requeue all blocks on send failure
                for (int h : blocks_to_request) {
                    m_node_context.block_fetcher->RequeueBlock(h);
                }
                LogPrintIBD(WARN, "GETDATA send failed for peer %d", peer_id);
                continue;
            }

            std::cout << "[PerBlock] Requested " << getdata.size() << " blocks from peer " << peer_id
                      << " (peer now has " << m_node_context.block_fetcher->GetPeerBlocksInFlight(peer_id)
                      << "/" << MAX_BLOCKS_IN_TRANSIT_PER_PEER << " in-flight)" << std::endl;

            LogPrintIBD(INFO, "Requested %zu blocks from peer %d [%s]",
                        getdata.size(), peer_id,
                        m_node_context.block_fetcher->GetWindowStatus().c_str());
        }
    }

    return total_blocks_requested > 0;
}

void CIbdCoordinator::RetryTimeoutsAndStalls() {
    if (!m_node_context.block_fetcher || !m_node_context.connman || !m_node_context.headers_manager) {
        return;
    }

    // ============ Per-Block PARALLEL DOWNLOAD (Bitcoin Core Style) ============
    // On stall: request from ANOTHER peer in parallel, don't cancel original
    auto stalled_blocks = m_node_context.block_fetcher->GetStalledBlocks(
        std::chrono::seconds(BLOCK_STALL_TIMEOUT_SECONDS));

    if (!stalled_blocks.empty()) {
        // Get available peers for parallel download
        std::vector<int> available_peers;
        if (m_node_context.peer_manager) {
            available_peers = m_node_context.peer_manager->GetValidPeersForDownload();
        }

        int parallel_started = 0;
        for (const auto& [height, original_peer] : stalled_blocks) {
            // Get block hash
            uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(height);
            if (hash.IsNull()) continue;

            // Try to add parallel download from a different peer
            for (int new_peer : available_peers) {
                if (new_peer == original_peer) continue;  // Skip original peer

                // RequestBlockFromPeer will reject if this peer already has it
                if (m_node_context.block_fetcher->RequestBlockFromPeer(new_peer, height, hash)) {
                    // Send GETDATA to new peer
                    std::vector<NetProtocol::CInv> getdata;
                    getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
                    CNetMessage msg = m_node_context.message_processor->CreateGetDataMessage(getdata);
                    m_node_context.connman->PushMessage(new_peer, msg);
                    parallel_started++;
                    break;  // One parallel peer is enough
                }
            }
        }

        if (parallel_started > 0) {
            std::cout << "[PerBlock] Started " << parallel_started << " parallel downloads for "
                      << stalled_blocks.size() << " stalled blocks" << std::endl;
        }
    }

    // Legacy cleanup (still needed for transition period)
    m_node_context.block_fetcher->CleanupCancelledChunks();
    m_node_context.block_fetcher->CleanupUnsuitablePeers();

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

/**
 * BUG #158 FIX: Find the fork point between local chain and header chain
 *
 * Walks back from chain tip comparing local block hashes to header hashes.
 * Returns the height where they match (common ancestor), or 0 if no match found.
 */
int CIbdCoordinator::FindForkPoint(int chain_height) {
    if (!m_node_context.headers_manager) {
        return 0;
    }

    std::cout << "[FORK-DETECT] Searching for fork point from height " << chain_height << std::endl;

    // Walk back from current chain tip using pprev pointers
    CBlockIndex* pindex = m_chainstate.GetTip();
    int checks = 0;
    const int MAX_CHECKS = 1000;  // Don't walk back more than 1000 blocks

    while (pindex && pindex->nHeight > 0 && checks < MAX_CHECKS) {
        int h = pindex->nHeight;

        // Get header hash at this height (this is the network's chain)
        uint256 header_hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
        if (header_hash.IsNull()) {
            pindex = pindex->pprev;
            checks++;
            continue;  // No header at this height, keep searching
        }

        // Get our local block hash
        uint256 local_hash = pindex->GetBlockHash();

        // Compare: if they match, we found the fork point
        if (local_hash == header_hash) {
            std::cout << "[FORK-DETECT] Found common ancestor at height " << h
                      << " hash=" << local_hash.GetHex().substr(0, 16) << "..." << std::endl;
            return h;
        }

        // Log divergence for debugging (first few mismatches only)
        if (checks < 6) {
            std::cout << "[FORK-DETECT] Height " << h << " diverges:"
                      << " local=" << local_hash.GetHex().substr(0, 16) << "..."
                      << " header=" << header_hash.GetHex().substr(0, 16) << "..." << std::endl;
        }

        pindex = pindex->pprev;
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
        if (pindex && pindex->nHeight == fork_point) {
            m_chainstate.SetTip(pindex);
            std::cout << "[FORK-RECOVERY] Chain tip reset to height " << fork_point
                      << " hash=" << pindex->GetBlockHash().GetHex().substr(0, 16) << "..." << std::endl;
        }

        std::cout << "[FORK-RECOVERY] Disconnected " << disconnected << " forked block(s)" << std::endl;

        // BUG #159 FIX: Delete orphan blocks from DB that were built on the forked chain
        // These blocks have their prevBlockHash pointing to disconnected blocks
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
                                // Check if its prevBlockHash points to a disconnected/unknown block
                                CBlockIndex* pPrevIndex = m_chainstate.GetBlockIndex(block.hashPrevBlock);
                                if (!pPrevIndex || pPrevIndex->nHeight >= fork_point) {
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
    }

    // Reset the IBD window to start from fork_point + 1
    // This will cause blocks to be downloaded starting from the divergence point
    int header_height = m_node_context.headers_manager ?
                        m_node_context.headers_manager->GetBestHeight() : chain_height;

    // BUG #159 FIX: Force reinitialize the window starting from fork point
    // Pass fork_point as chain_height so nNextChunkHeight = fork_point + 1
    m_node_context.block_fetcher->InitializeWindow(fork_point, header_height, true);

    // Queue blocks for download starting from fork point + 1
    int blocks_to_queue = std::min(header_height - fork_point, 1024);

    std::vector<int> heights_to_add;
    heights_to_add.reserve(blocks_to_queue);

    for (int h = fork_point + 1; h <= fork_point + blocks_to_queue && h <= header_height; h++) {
        uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
        if (!hash.IsNull()) {
            // Queue block for download
            m_node_context.block_fetcher->QueueBlockForDownload(hash, h, false);
            heights_to_add.push_back(h);
        }
    }

    // Add heights to window's pending set
    if (!heights_to_add.empty()) {
        m_node_context.block_fetcher->AddHeightsToWindowPending(heights_to_add);
        std::cout << "[FORK-RECOVERY] Queued " << heights_to_add.size()
                  << " blocks for download starting at height " << (fork_point + 1) << std::endl;
    }

    // Reset fork detection state
    m_fork_detected = true;
    m_fork_point = fork_point;
    m_fork_stall_cycles = 0;
}


