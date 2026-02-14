// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/ibd_coordinator.h>

#include <iostream>
#include <set>
#include <vector>

// Bug #191: Platform-specific terminal detection
#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#define STDIN_FILENO 0
#else
#include <unistd.h>
#endif

#include <consensus/chain.h>
#include <consensus/pow.h>  // BUG #245: ChainWorkGreaterThan for fork work comparison
#include <core/chainparams.h>  // Initial header request needs genesis hash
#include <node/genesis.h>      // Genesis::GetGenesisHash()
#include <node/blockchain_storage.h>  // BUG #159: Orphan block deletion
#include <core/node_context.h>
#include <net/block_fetcher.h>
#include <net/block_tracker.h>  // BUG FIX: Clear in-flight blocks on peer rotation
#include <net/headers_manager.h>
#include <net/net.h>  // CNetMessageProcessor
#include <net/connman.h>  // Phase 5: CConnman
#include <net/peers.h>
#include <net/protocol.h>
#include <node/block_validation_queue.h>  // Phase 2: Async block validation
#include <node/fork_manager.h>  // Validate-before-disconnect fork handling
#include <net/orphan_manager.h>  // IBD STUCK FIX #3: Periodic orphan scan
#include <util/logging.h>
#include <util/bench.h>  // Performance: Benchmarking
#include <api/metrics.h>  // Fork detection metrics

// IBD STUCK FIX #3: Access to global NodeContext for orphan manager
extern NodeContext g_node_context;

CIbdCoordinator::CIbdCoordinator(CChainState& chainstate, NodeContext& node_context)
    : m_chainstate(chainstate),
      m_node_context(node_context),
      m_last_ibd_attempt(std::chrono::steady_clock::time_point()),
      m_creation_time(std::chrono::steady_clock::now()) {}

void CIbdCoordinator::Tick() {
    // IBD DEBUG: Confirm Tick() is being called
    static int tick_count = 0;
    if (g_verbose.load(std::memory_order_relaxed) && (++tick_count <= 5 || tick_count % 60 == 0)) {
        std::cerr << "[IBD-DEBUG] Tick() called #" << tick_count << std::endl;
    }

    // Phase 5.1: Update state machine
    UpdateState();

    // BUG #248: Check if block validation signaled that we're syncing to a wrong chain.
    // When blocks fail MIK validation, it means we got headers from a peer on a different
    // chain. We need to switch to a different headers sync peer.
    if (g_node_context.headers_chain_invalid.exchange(false)) {
        std::cout << "[IBD] Headers chain invalid flag set - switching headers sync peer" << std::endl;

        // Mark current sync peer as bad - they sent us headers leading to invalid blocks
        if (m_headers_sync_peer != -1) {
            std::cout << "[IBD] Marking peer " << m_headers_sync_peer << " as bad (sent invalid chain headers)" << std::endl;
            m_headers_bad_peers.insert(m_headers_sync_peer);
        }

        // Clear headers above current chain height - they led to invalid blocks
        int chain_height = m_chainstate.GetHeight();
        if (m_node_context.headers_manager) {
            // Get the hash at chain_height to use as preferred (matches our valid chain)
            uint256 chainTipHash;
            CBlockIndex* pTip = m_chainstate.GetTip();
            if (pTip) {
                chainTipHash = pTip->GetBlockHash();
            }
            m_node_context.headers_manager->ClearAboveHeight(chain_height, chainTipHash);
        }

        // Reset sync state and switch to a different peer
        m_headers_sync_peer = -1;
        m_headers_sync_peer_consecutive_stalls = 0;
        m_initial_request_done = false;
        m_headers_in_flight = false;

        // SwitchHeadersSyncPeer will select a new peer (excluding bad peers) and request headers
        SwitchHeadersSyncPeer();
    }

    // Check if IBD components are available
    if (!m_node_context.headers_manager || !m_node_context.block_fetcher) {
        // IBD DEBUG: Log why we're returning early
        static int no_components_count = 0;
        if (g_verbose.load(std::memory_order_relaxed) && ++no_components_count <= 5) {
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
        // BUG FIX: Use best_known_height for dynamic peer height
        auto sync_peer = m_node_context.peer_manager ? m_node_context.peer_manager->GetPeer(m_headers_sync_peer) : nullptr;
        int peer_height = sync_peer ? (sync_peer->best_known_height > 0 ? sync_peer->best_known_height : sync_peer->start_height)
                                    : m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);

        if (!m_initial_request_done && header_height <= 0 && peer_height > 0) {
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
                    // BUG FIX: Use best_known_height (updated dynamically) instead of
                    // GetPeerStartHeight (static from connection time). After reorg,
                    // peers may have advanced but start_height wouldn't reflect that.
                    int peer_height = peer->best_known_height;
                    if (peer_height == 0) peer_height = peer->start_height;
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
        if (g_verbose.load(std::memory_order_relaxed) && (++synced_count <= 5 || synced_count % 60 == 0)) {
            std::cerr << "[IBD-DEBUG] Tick() returning: synced (header=" << header_height
                      << " <= chain=" << chain_height << ")" << std::endl;
        }
        if (m_state != IBDState::IDLE && m_state != IBDState::COMPLETE) {
            m_state = IBDState::COMPLETE;

            // Show resync completion summary if we just finished a resync
            if (m_resync_in_progress) {
                m_resync_in_progress = false;
                int blocks_recovered = m_resync_fork_point;  // Blocks that were on both chains
                int blocks_lost = m_resync_original_height - m_resync_fork_point;  // Forked blocks

                std::cout << "\n" << std::endl;
                std::cout << "════════════════════════════════════════════════════════════" << std::endl;
                std::cout << "                    RESYNC COMPLETE" << std::endl;
                std::cout << "════════════════════════════════════════════════════════════" << std::endl;
                std::cout << std::endl;
                std::cout << "  Chain Status:" << std::endl;
                std::cout << "    Current height:    " << chain_height << " blocks" << std::endl;
                std::cout << "    Synced with:       " << header_height << " network headers" << std::endl;
                std::cout << std::endl;
                std::cout << "  Fork Recovery Summary:" << std::endl;
                std::cout << "    Fork point:        Block " << m_resync_fork_point << std::endl;
                std::cout << "    Blocks preserved:  " << blocks_recovered << " (heights 0-" << m_resync_fork_point << ")" << std::endl;
                std::cout << "    Blocks discarded:  " << blocks_lost << " (were on fork)" << std::endl;
                std::cout << std::endl;
                std::cout << "  Wallet Status:" << std::endl;
                std::cout << "    Private keys:      SAFE (unchanged)" << std::endl;
                std::cout << "    Balance:           Recalculated from correct chain" << std::endl;
                std::cout << "    Mining rewards from forked blocks are no longer valid." << std::endl;
                std::cout << "    Your balance now reflects only confirmed transactions" << std::endl;
                std::cout << "    on the main network chain." << std::endl;
                std::cout << std::endl;
                std::cout << "════════════════════════════════════════════════════════════" << std::endl;
                std::cout << std::endl;
            }
        }
        return;
    }

    ResetBackoffOnNewHeaders(header_height);

    auto now = std::chrono::steady_clock::now();
    if (!ShouldAttemptDownload()) {
        // IBD DEBUG: Log why we're returning early
        static int backoff_count = 0;
        if (g_verbose.load(std::memory_order_relaxed) && (++backoff_count <= 5 || backoff_count % 60 == 0)) {
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
        m_synced.store(false, std::memory_order_release);
        return;
    }

    int header_height = m_node_context.headers_manager->GetBestHeight();
    int chain_height = m_chainstate.GetHeight();
    size_t peer_count = m_node_context.peer_manager ? m_node_context.peer_manager->GetConnectionCount() : 0;

    // =========================================================================
    // SYNC STATE DETECTION WITH HYSTERESIS
    // =========================================================================
    // Uses different thresholds for entering vs leaving synced state to prevent
    // flapping when chain height oscillates near header height.
    //
    // - Become synced: chain within SYNC_TOLERANCE_BLOCKS (2) of headers
    // - Become un-synced: chain more than UNSYNC_THRESHOLD_BLOCKS (10) behind
    //
    // This is thread-safe: m_synced is atomic, only written here (main thread).
    // =========================================================================

    bool currently_synced = m_synced.load(std::memory_order_acquire);
    int blocks_behind = header_height - chain_height;

    if (currently_synced) {
        // Already synced - only become un-synced if significantly behind
        if (blocks_behind > UNSYNC_THRESHOLD_BLOCKS) {
            m_synced.store(false, std::memory_order_release);
            std::cout << "[IBD] Sync state: SYNCED -> NOT SYNCED (chain " << blocks_behind
                      << " blocks behind headers)" << std::endl;
        }
    } else {
        // Not synced - become synced if within tolerance
        if (blocks_behind <= SYNC_TOLERANCE_BLOCKS && header_height > 0) {
            m_synced.store(true, std::memory_order_release);
            std::cout << "[IBD] Sync state: NOT SYNCED -> SYNCED (chain within "
                      << SYNC_TOLERANCE_BLOCKS << " blocks of headers)" << std::endl;
        }
    }

    // Determine IBD state based on current conditions
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

bool CIbdCoordinator::IsSynced() const {
    return m_synced.load(std::memory_order_acquire);
}

bool CIbdCoordinator::IsInitialBlockDownload() const {
    return !IsSynced();
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
    if (g_verbose.load(std::memory_order_relaxed))
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

    // ============================================================================
    // LAYER 1: PROACTIVE CHAIN MISMATCH DETECTION (O(1) - runs every tick)
    // ============================================================================
    // This catches the case where we're on a stale fork IMMEDIATELY, without
    // waiting for stall detection. Critical for nodes that synced to a fork.
    //
    // BUG #250 FIX: Only run Layer 1 when near tip (same guard as Layer 3).
    // During bulk IBD, fresh nodes are thousands of blocks behind and will
    // always have mismatched hashes. This causes false-positive fork detection.
    // Checkpoints + PoW validation are sufficient protection during IBD.
    //
    // BUG #261 FIX: Skip Layer 1 during startup grace period.
    // During the first 10 seconds after coordinator creation, headers from the
    // local blockchain may not be fully indexed. This causes false fork detection
    // when GetRandomXHashAtHeight() returns the wrong hash.
    static constexpr int LAYER1_TIP_THRESHOLD = 100;  // Same as Layer 3
    bool layer1_near_tip = (header_height - chain_height) < LAYER1_TIP_THRESHOLD;

    // BUG #261: Check if we're still in the startup grace period
    auto elapsed_secs = std::chrono::duration_cast<std::chrono::seconds>(now - m_creation_time).count();
    bool past_startup_grace = (elapsed_secs >= STARTUP_GRACE_PERIOD_SECS);

    // BUG #261 FIX (Part 2): Only run Layer 1 when EXACTLY synced
    // If headers are ahead of chain (even by 1 block), the headers manager's
    // "best chain" might include blocks we don't have yet. This causes false
    // fork detection when GetRandomXHashAtHeight returns a hash from a peer's
    // chain that diverges from ours at the tip. Wait until we're fully synced.
    bool exactly_synced = (header_height == chain_height);

    if (past_startup_grace && exactly_synced && layer1_near_tip && chain_height > 0 && m_node_context.headers_manager && !m_fork_detected.load()) {
        CBlockIndex* tip = m_chainstate.GetTip();
        if (tip) {  // Only check if we have a valid tip
            uint256 our_tip_hash = tip->GetBlockHash();
            uint256 header_hash_at_our_height = m_node_context.headers_manager->GetRandomXHashAtHeight(chain_height);

            if (!header_hash_at_our_height.IsNull() && !our_tip_hash.IsNull() && our_tip_hash != header_hash_at_our_height) {
            // CHAIN MISMATCH: Our tip doesn't match the header chain at the same height
            // This means we're on a fork - trigger immediate detection
            std::cout << "\n[FORK-DETECT] ════════════════════════════════════════════════════" << std::endl;
            std::cout << "[FORK-DETECT] CHAIN MISMATCH DETECTED (Layer 1 - Proactive)" << std::endl;
            std::cout << "[FORK-DETECT] Our chain tip at height " << chain_height << ":" << std::endl;
            std::cout << "[FORK-DETECT]   Local:  " << our_tip_hash.GetHex().substr(0, 16) << "..." << std::endl;
            std::cout << "[FORK-DETECT]   Header: " << header_hash_at_our_height.GetHex().substr(0, 16) << "..." << std::endl;
            std::cout << "[FORK-DETECT] Finding fork point..." << std::endl;

            int fork_point = FindForkPoint(chain_height);
            // BUG #189 FIX: Allow fork_point up to chain_height + 1 to handle race conditions
            // where chain advances during fork detection
            if (fork_point > 0 && fork_point <= chain_height + 1) {
                // fork_depth can be 0 or negative if chain advanced during detection (race condition)
                // In that case, no blocks need to be disconnected
                int fork_depth = std::max(0, chain_height - fork_point);
                std::cout << "[FORK-DETECT] Fork point found at height " << fork_point
                          << " (depth=" << fork_depth << " blocks)" << std::endl;

                // Check if fork is too deep for automatic recovery
                if (fork_depth > MAX_AUTO_REORG_DEPTH) {
                    // Temporarily disable verbose output while user reads the prompt
                    bool was_verbose = g_verbose.load(std::memory_order_relaxed);
                    g_verbose.store(false, std::memory_order_relaxed);

                    std::cerr << "\n[FORK-DETECT] ════════════════════════════════════════════════════" << std::endl;
                    std::cerr << "[FORK-DETECT] CRITICAL: Fork too deep for automatic recovery!" << std::endl;
                    std::cerr << "[FORK-DETECT]   Fork depth: " << fork_depth << " blocks" << std::endl;
                    std::cerr << "[FORK-DETECT]   Maximum: " << MAX_AUTO_REORG_DEPTH << " blocks" << std::endl;
                    std::cerr << "[FORK-DETECT] Possible causes:" << std::endl;
                    std::cerr << "[FORK-DETECT]   1. Extended network partition" << std::endl;
                    std::cerr << "[FORK-DETECT]   2. Corrupted local blockchain data" << std::endl;
                    std::cerr << "[FORK-DETECT]   3. Potential chain attack" << std::endl;
                    std::cerr << "[FORK-DETECT] ════════════════════════════════════════════════════" << std::endl;
                    std::cerr << std::endl;
                    std::cerr << "Would you like to resync from the network? This will:" << std::endl;
                    std::cerr << "  - Clear your local chain data (blocks on the fork)" << std::endl;
                    std::cerr << "  - Download the correct chain from peers" << std::endl;
                    std::cerr << std::endl;
                    std::cerr << "WALLET IMPACT:" << std::endl;
                    std::cerr << "  - Your private keys are SAFE (stored separately)" << std::endl;
                    std::cerr << "  - Mining rewards from blocks 0-" << fork_point << " are PRESERVED" << std::endl;
                    std::cerr << "  - Mining rewards from forked blocks " << (fork_point + 1) << "-" << chain_height << " will be LOST" << std::endl;
                    std::cerr << "    (These " << fork_depth << " blocks were never accepted by the network)" << std::endl;
                    std::cerr << "  - Your balance will be recalculated from the correct chain" << std::endl;
                    std::cerr << std::endl;
                    // Bug #191: Check if stdin is a terminal before prompting
                    bool user_accepted = false;
                    if (!isatty(STDIN_FILENO)) {
                        // Running as daemon or with redirected input - require explicit consent
                        std::cerr << "[FORK-DETECT] Cannot prompt for resync - not running in interactive mode" << std::endl;
                        std::cerr << "[FORK-DETECT] To resync manually, restart the node interactively or use --resync flag" << std::endl;
                        std::cerr << "[FORK-DETECT] Node will continue on current chain (may be on a fork)" << std::endl;
                        user_accepted = false;
                        g_verbose.store(was_verbose, std::memory_order_relaxed);  // Restore verbose
                    } else {
                        std::cout << "Resync from network? [Y/n]: " << std::flush;

                        std::string response;
                        std::getline(std::cin, response);

                        // Restore verbose output after user responds
                        g_verbose.store(was_verbose, std::memory_order_relaxed);

                        // Default to yes on empty input (just hitting Enter) - only for interactive terminals
                        user_accepted = (response.empty() || response[0] == 'Y' || response[0] == 'y');
                    }

                    if (user_accepted) {
                        std::cout << "\n[RESYNC] ════════════════════════════════════════════════════" << std::endl;
                        std::cout << "[RESYNC] Starting network resync..." << std::endl;
                        std::cout << "[RESYNC] ════════════════════════════════════════════════════" << std::endl;
                        std::cout << "[RESYNC] Discarding " << fork_depth << " forked blocks (heights " << (fork_point + 1) << "-" << chain_height << ")" << std::endl;
                        std::cout << "[RESYNC] Preserving blocks 0-" << fork_point << " (common ancestor)" << std::endl;
                        std::cout << "[RESYNC] Clearing forked chain data..." << std::endl;

                        // Track resync for completion message
                        m_resync_in_progress = true;
                        m_resync_fork_point = fork_point;
                        m_resync_original_height = chain_height;
                        m_resync_target_height = header_height;

                        // Bug #192: Reset to fork point, NOT genesis (preserves valid blocks 0-fork_point)
                        // Walk backwards from current tip to find the fork point block
                        CBlockIndex* pForkPointIndex = nullptr;
                        CBlockIndex* pindex = m_chainstate.GetTip();
                        while (pindex && pindex->nHeight > fork_point) {
                            pindex = pindex->pprev;
                        }
                        if (pindex && pindex->nHeight == fork_point) {
                            pForkPointIndex = pindex;
                        }

                        // Fallback to genesis only if fork point block not found (shouldn't happen)
                        if (!pForkPointIndex) {
                            std::cerr << "[RESYNC] WARNING: Could not find block at fork point " << fork_point << std::endl;
                            std::cerr << "[RESYNC] Falling back to genesis block" << std::endl;
                            uint256 genesisHash = Genesis::GetGenesisHash();
                            pForkPointIndex = m_chainstate.GetBlockIndex(genesisHash);
                        }

                        if (pForkPointIndex) {
                            // Reset tip to fork point (preserves blocks 0 to fork_point)
                            m_chainstate.SetTip(pForkPointIndex);
                            std::cout << "[RESYNC] Chain reset to fork point at height " << pForkPointIndex->nHeight << std::endl;

                            // BUG #194 FIX: Pass chainstate's hash at fork point so ClearAboveHeight
                            // selects the correct header when multiple exist at that height
                            uint256 chainstateHashAtForkPoint = pForkPointIndex->GetBlockHash();

                            // Clear only headers above fork point (preserves common ancestor chain)
                            if (m_node_context.headers_manager) {
                                m_node_context.headers_manager->ClearAboveHeight(fork_point, chainstateHashAtForkPoint);
                                std::cout << "[RESYNC] Headers above fork point cleared - will re-download from peers" << std::endl;
                            }

                            // Reset fork detection state
                            m_fork_detected.store(false);
                            g_node_context.fork_detected.store(false);  // Clear global flag so mining can resume
                            g_metrics.ClearForkDetected();  // Clear Prometheus metrics
                            m_fork_point.store(-1);
                            m_fork_stall_cycles.store(0);
                            m_consecutive_orphan_blocks.store(0);
                            m_requires_reindex = false;

                            // Reset IBD state to allow fresh sync
                            m_state = IBDState::WAITING_FOR_PEERS;
                            m_last_header_height = 0;
                            m_ibd_no_peer_cycles = 0;

                            // Reset headers sync peer tracking
                            m_headers_sync_peer = -1;
                            m_headers_sync_last_height = 0;
                            m_headers_in_flight = false;
                            m_initial_request_done = false;  // Allow new initial headers request

                            std::cout << "[RESYNC] IBD state reset - will sync from peers" << std::endl;
                            std::cout << "[RESYNC] ════════════════════════════════════════════════════\n" << std::endl;
                            return;  // Let next tick start fresh IBD
                        } else {
                            std::cerr << "[RESYNC] ERROR: Could not find genesis block!" << std::endl;
                            std::cerr << "[RESYNC] Please restart with --reindex flag" << std::endl;
                        }
                    } else {
                        std::cout << "\n[FORK-DETECT] Resync declined. Node will not sync until resolved." << std::endl;
                        std::cout << "[FORK-DETECT] You can restart with --reindex flag later." << std::endl;
                    }

                    m_requires_reindex = true;
                    m_fork_detected.store(true);
                    m_fork_point.store(fork_point);
                    g_metrics.SetForkDetected(true, chain_height - fork_point, fork_point);  // Set Prometheus metrics
                    return;  // Don't proceed with downloads until reindex
                }

                // VALIDATE-BEFORE-DISCONNECT: Use ForkManager staging approach
                // Instead of immediately disconnecting (HandleForkScenario), we:
                // 1. Create a ForkCandidate to stage incoming blocks
                // 2. Pre-validate all fork blocks (PoW + MIK) before any chain changes
                // 3. Only switch chains via ActivateBestChain after all blocks validated

                ForkManager& forkMgr = ForkManager::GetInstance();

                // Check if we already have an active fork
                if (forkMgr.HasActiveFork()) {
                    if (forkMgr.CheckTimeout()) {
                        std::cout << "[FORK-DETECT] Existing fork timed out, canceling and starting new" << std::endl;
                        forkMgr.CancelFork("Timeout - 60s without blocks");
                        forkMgr.ClearInFlightState(m_node_context, fork_point);
                        // Clear fork detection flags so node can continue normally
                        m_fork_detected.store(false);
                        g_node_context.fork_detected.store(false);
                        g_metrics.ClearForkDetected();
                        m_fork_point.store(-1);
                    } else {
                        std::cout << "[FORK-DETECT] Fork already active, waiting for blocks..." << std::endl;
                        std::cout << "[FORK-DETECT] ════════════════════════════════════════════════════\n" << std::endl;
                        return;
                    }
                }

                // Get the expected fork tip height from headers manager
                int headerTipHeight = header_height;
                if (m_node_context.headers_manager) {
                    headerTipHeight = m_node_context.headers_manager->GetBestHeight();
                }

                // Get fork tip from competing tips (storage hash domain)
                // This is critical: we need storage hashes, not RandomX hashes
                uint256 forkTipHash;
                std::map<int32_t, uint256> expectedHashes;

                if (m_node_context.headers_manager) {
                    const auto& tipsTracker = m_node_context.headers_manager->GetChainTipsTracker();
                    auto competingTips = tipsTracker.GetCompetingTips();

                    // Find a competing tip that's not on our current chain
                    // The best tip should be the fork tip we want
                    for (const auto& tip : competingTips) {
                        if (tip.height == headerTipHeight) {
                            forkTipHash = tip.hash;  // Storage hash from tracker
                            std::cout << "[FORK-DETECT] Found fork tip from competing tips: "
                                      << forkTipHash.GetHex().substr(0, 16)
                                      << "... at height " << tip.height << std::endl;
                            break;
                        }
                    }

                    // Build ancestry hashes if we found a fork tip
                    if (!forkTipHash.IsNull()) {
                        if (!m_node_context.headers_manager->BuildForkAncestryHashes(
                                forkTipHash, fork_point, expectedHashes)) {
                            std::cerr << "[FORK-DETECT] Failed to build fork ancestry, proceeding with height-only checks" << std::endl;
                            // Continue with empty expectedHashes - will fall back to height-only checks
                        }
                    } else {
                        // Fallback: use RandomX hash (less reliable but better than nothing)
                        forkTipHash = m_node_context.headers_manager->GetRandomXHashAtHeight(headerTipHeight);
                        std::cerr << "[FORK-DETECT] Warning: Could not find fork tip in competing tips, using RandomX hash" << std::endl;
                    }
                }

                std::cout << "[FORK-DETECT] Creating fork staging candidate..." << std::endl;
                std::cout << "[FORK-DETECT] Fork point=" << fork_point
                          << " chain=" << chain_height
                          << " expected_tip=" << headerTipHeight
                          << " expected_hashes=" << expectedHashes.size() << std::endl;

                // Create fork candidate for staging with expected hashes
                auto forkCandidate = forkMgr.CreateForkCandidate(
                    forkTipHash,
                    chain_height,  // Current chain height for reorg depth check
                    fork_point,
                    headerTipHeight,
                    expectedHashes
                );

                if (forkCandidate) {
                    // Set fork detection flags (for mining pause, etc.)
                    m_fork_detected.store(true);
                    g_node_context.fork_detected.store(true);
                    m_fork_point.store(fork_point);

                    std::cout << "[FORK-DETECT] Fork candidate created, blocks will be staged for pre-validation" << std::endl;
                    std::cout << "[FORK-DETECT] Original chain remains ACTIVE until fork is fully validated" << std::endl;
                } else {
                    std::cerr << "[FORK-DETECT] Failed to create fork candidate" << std::endl;
                }

                std::cout << "[FORK-DETECT] ════════════════════════════════════════════════════\n" << std::endl;
                return;  // Let next tick handle downloads
            } else {
                std::cout << "[FORK-DETECT] Could not find fork point (fork_point=" << fork_point << ")" << std::endl;
                std::cout << "[FORK-DETECT] ════════════════════════════════════════════════════\n" << std::endl;
            }
            }
        }
    }

    // ============================================================================
    // LAYER 2: ORPHAN BLOCK DETECTION (checked via m_consecutive_orphan_blocks)
    // ============================================================================
    // If we've received many consecutive orphan blocks, this is conclusive evidence
    // of being on a stale fork. Trigger fork recovery immediately - don't wait for
    // Layer 3's 60-cycle stall threshold (which can deadlock due to counter resets).
    //
    // BUG #261 FIX: Skip Layer 2 during startup grace period
    bool force_fork_check = m_consecutive_orphan_blocks.load() >= ORPHAN_FORK_THRESHOLD;
    if (past_startup_grace && force_fork_check && !m_fork_detected.load()) {
        std::cout << "[FORK-DETECT] Layer 2 triggered: " << m_consecutive_orphan_blocks.load()
                  << " consecutive orphan blocks received - attempting immediate fork recovery" << std::endl;
        m_consecutive_orphan_blocks.store(0);  // Reset counter

        if (AttemptForkRecovery(chain_height, header_height)) {
            // Fork recovery initiated or already active - skip Layer 3
        }
    } else if (force_fork_check) {
        m_consecutive_orphan_blocks.store(0);  // Reset even if fork already detected
    }

    // ============================================================================
    // LAYER 3: STALL-BASED DETECTION (safety net for cases Layer 2 doesn't catch)
    // ============================================================================
    static constexpr int FORK_DETECTION_TIP_THRESHOLD = 100;
    bool near_tip = (header_height - chain_height) < FORK_DETECTION_TIP_THRESHOLD;

    if (!near_tip && !force_fork_check) {
        // Bulk IBD: checkpoints + PoW + Layer 1 are sufficient protection
        // Skip expensive stall detection to avoid cs_main lock contention
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

        // BUG #261 FIX: Skip Layer 3 during startup grace period
        if (past_startup_grace && has_ibd_activity && stall_cycles >= FORK_DETECTION_THRESHOLD) {
            // Issue #6 FIX: Throttle fork detection to avoid CPU overhead
            auto now_check = std::chrono::steady_clock::now();
            auto elapsed_check = std::chrono::duration_cast<std::chrono::seconds>(now_check - m_last_fork_check).count();
            if (elapsed_check >= FORK_CHECK_MIN_INTERVAL_SECS) {
                m_last_fork_check = now_check;

                std::cout << "[FORK-DETECT] Layer 3: Chain stalled at height " << chain_height
                          << " for " << stall_cycles << " cycles - attempting fork recovery..." << std::endl;

                AttemptForkRecovery(chain_height, header_height);
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
            g_node_context.fork_detected.store(false);  // Clear global flag so mining can resume
            g_metrics.ClearForkDetected();  // Clear Prometheus metrics
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

    // FORK FIX: Check if fork is ready for chain switch after feeding blocks from DB
    // This handles the case where all fork blocks were already in DB (arrived as orphans
    // before fork detection). FetchBlocks above feeds them to ForkManager; now check
    // if the fork has enough work to trigger a chain switch.
    {
        ForkManager& forkMgr = ForkManager::GetInstance();
        if (forkMgr.HasActiveFork()) {
            auto fork = forkMgr.GetActiveFork();
            if (fork && fork->AllReceivedBlocksPrevalidated()) {
                int32_t tipHeight = fork->GetHighestPrevalidatedHeight();
                if (tipHeight > 0) {
                    ForkBlock* tipBlock = fork->GetBlockAtHeight(tipHeight);
                    if (tipBlock) {
                        CBlockIndex* forkIndex = m_chainstate.GetBlockIndex(tipBlock->hash);
                        CBlockIndex* currentTip = m_chainstate.GetTip();
                        if (forkIndex && currentTip &&
                            currentTip->nChainWork < forkIndex->nChainWork) {
                            std::cout << "[IBD] Fork ready with more work (fork="
                                      << forkIndex->nChainWork.GetHex().substr(0, 16) << " current="
                                      << currentTip->nChainWork.GetHex().substr(0, 16)
                                      << ") - triggering chain switch" << std::endl;
                            if (m_node_context.blockchain_db &&
                                forkMgr.TriggerChainSwitch(m_node_context, *m_node_context.blockchain_db)) {
                                std::cout << "[IBD] Fork chain switch SUCCESSFUL!" << std::endl;
                                m_fork_detected.store(false);
                                g_node_context.fork_detected.store(false);
                                g_metrics.ClearForkDetected();
                            }
                        }
                    }
                }
            }
        }
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
    if (g_verbose.load(std::memory_order_relaxed))
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
    // Check if current block sync peer is still valid AND has blocks we need
    if (m_blocks_sync_peer != -1) {
        auto peer = m_node_context.peer_manager->GetPeer(m_blocks_sync_peer);
        // BUG FIX: Also check IsConnected() - GetPeer returns stale objects
        if (!peer || !peer->IsConnected()) {
            std::cout << "[IBD] Blocks sync peer " << m_blocks_sync_peer << " disconnected" << std::endl;
            // BUG FIX: Clear in-flight blocks from disconnected peer
            if (g_node_context.block_tracker) {
                auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                if (!cleared.empty()) {
                    std::cout << "[IBD] Cleared " << cleared.size()
                              << " stale in-flight blocks from disconnected peer " << m_blocks_sync_peer << std::endl;
                }
            }
            m_blocks_sync_peer = -1;
        } else {
            // BUG FIX: Re-select peer if their height is too low for blocks we need
            // This happens when:
            // 1. Peer selected during IBD with height N
            // 2. Network advances, we need block N+1
            // 3. Peer's best_known_height wasn't updated (or is stale)
            // Without this check, we'd be stuck requesting from a peer that can't serve us
            int peer_height = peer->best_known_height;
            if (peer_height == 0) peer_height = peer->start_height;

            // BUG FIX #2: Also reselect if current peer is far below header height
            // This helps when better peers connect while we're stuck on a lower-height peer
            bool should_reselect = false;
            if (peer_height <= chain_height) {
                std::cout << "[IBD] Blocks sync peer " << m_blocks_sync_peer
                          << " height (" << peer_height << ") too low (need > " << chain_height
                          << "), reselecting" << std::endl;
                should_reselect = true;
            } else if (peer_height < header_height && (header_height - peer_height) > 10) {
                // Current peer can't serve all headers - check if better peer exists
                auto all_peers = m_node_context.peer_manager->GetConnectedPeers();
                int better_peer_id = -1;
                int better_peer_height = peer_height;
                for (const auto& p : all_peers) {
                    if (!p || p->id == m_blocks_sync_peer) continue;
                    // BUG #256: Skip timed-out peer during cooldown
                    if (p->id == m_timed_out_peer && m_timed_out_peer != -1) {
                        auto elapsed = std::chrono::steady_clock::now() - m_timed_out_peer_time;
                        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() < TIMED_OUT_PEER_COOLDOWN_SEC) {
                            continue;
                        }
                    }
                    int ph = p->best_known_height;
                    if (ph == 0) ph = p->start_height;
                    if (ph > better_peer_height + 5) {  // Better peer with >5 blocks advantage
                        better_peer_id = p->id;
                        better_peer_height = ph;
                    }
                }
                if (better_peer_id != -1) {
                    std::cout << "[IBD] Found better peer " << better_peer_id << " (height=" << better_peer_height
                              << ") vs current sync peer " << m_blocks_sync_peer
                              << " (height=" << peer_height << "), switching directly" << std::endl;

                    // BUG FIX: Clear in-flight blocks from old peer before switching
                    if (g_node_context.block_tracker && m_blocks_sync_peer != -1) {
                        auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                        if (!cleared.empty()) {
                            std::cout << "[IBD] Cleared " << cleared.size()
                                      << " stale in-flight blocks from old peer " << m_blocks_sync_peer << std::endl;
                        }
                    }

                    m_blocks_sync_peer = better_peer_id;
                    m_blocks_sync_peer_consecutive_timeouts = 0;
                    should_reselect = false;  // Already switched
                }
            }

            if (should_reselect) {
                // BUG FIX: Clear in-flight blocks from old peer before reselecting
                if (g_node_context.block_tracker && m_blocks_sync_peer != -1) {
                    auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                    if (!cleared.empty()) {
                        std::cout << "[IBD] Cleared " << cleared.size()
                                  << " stale in-flight blocks from reselected peer " << m_blocks_sync_peer << std::endl;
                    }
                }
                m_blocks_sync_peer = -1;
            }
        }
    }

    // Select a new block sync peer if needed
    if (m_blocks_sync_peer == -1) {
        auto peers = m_node_context.peer_manager->GetConnectedPeers();
        int best_peer = -1;
        int best_height = chain_height;

        // BUG #249: Check if we have an active fork - if so, we need peers on the fork chain
        ForkManager& forkMgr = ForkManager::GetInstance();
        bool has_active_fork = forkMgr.HasActiveFork();

        // BUG #249 DEBUG: Log available peers during fork
        if (has_active_fork) {
            std::cout << "[IBD-FORK] Selecting fork block peer (chain=" << chain_height << " peers=" << peers.size() << ")" << std::endl;
        }

        for (const auto& peer : peers) {
            if (!peer) continue;

            // BUG #256: Skip timed-out peer during cooldown period
            if (peer->id == m_timed_out_peer && m_timed_out_peer != -1) {
                auto elapsed = std::chrono::steady_clock::now() - m_timed_out_peer_time;
                auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
                if (elapsed_sec < TIMED_OUT_PEER_COOLDOWN_SEC) {
                    continue;  // Still in cooldown, skip this peer
                } else {
                    // Cooldown expired, clear the timed-out peer tracking
                    std::cout << "[IBD] Peer " << m_timed_out_peer << " cooldown expired after "
                              << elapsed_sec << " seconds, eligible for selection again" << std::endl;
                    m_timed_out_peer = -1;
                }
            }

            int peer_height = peer->best_known_height;
            if (peer_height == 0) peer_height = peer->start_height;

            // BUG #249 DEBUG: Log peer heights during fork
            if (has_active_fork && peer_height > chain_height) {
                std::cout << "[IBD-FORK]   peer=" << peer->id << " height=" << peer_height
                          << " (best_known=" << peer->best_known_height << " start=" << peer->start_height << ")" << std::endl;
            }

            // Skip headers sync peer in first pass - prefer other peers for block download
            // EXCEPT during active fork: the headers_sync_peer sent us the fork headers,
            // so they HAVE the fork blocks. Other peers on our chain don't have them.
            if (peer->id == m_headers_sync_peer && !has_active_fork) {
                continue;
            }

            if (peer_height > best_height) {
                best_height = peer_height;
                best_peer = peer->id;
            }
        }

        // If no other peer found, use headers sync peer for blocks too
        // BUG #249b FIX: During active fork, we SHOULD use headers_sync_peer as fallback
        // because they sent us the fork headers and therefore have the fork blocks.
        // Other peers on our chain don't have these blocks.
        // BUG FIX: Use header_height from headers manager (authoritative) instead of
        // peer->best_known_height which may be stale due to async header processing.
        // The headers sync peer sent us headers up to header_height, so they have those blocks.
        if (best_peer == -1 && m_headers_sync_peer != -1 && header_height > chain_height) {
            best_peer = m_headers_sync_peer;
            best_height = header_height;

            // BUG FIX: Also update the peer's best_known_height so subsequent checks
            // don't reselect based on stale start_height. The headers sync peer must
            // have blocks up to header_height since they sent us those headers.
            m_node_context.peer_manager->UpdatePeerBestKnownHeight(m_headers_sync_peer, header_height);
        }

        if (best_peer != -1) {
            m_blocks_sync_peer = best_peer;
            m_blocks_sync_peer_consecutive_timeouts = 0;  // Reset timeout counter for new peer
            std::cout << "[IBD] Selected blocks sync peer " << m_blocks_sync_peer
                      << " (height=" << best_height << ")" << std::endl;
        } else {
            // BUG #246b FIX: Before giving up, check for stale in-flight blocks from
            // disconnected peers. This can happen when a peer disconnects after being
            // selected but before blocks are delivered, and m_blocks_sync_peer was reset.
            if (g_node_context.block_tracker) {
                int total_in_flight = g_node_context.block_tracker->GetTotalInFlight();
                if (total_in_flight > 0) {
                    // There are in-flight blocks but no peers - they must be from disconnected peers
                    // Get the peers that have blocks assigned
                    auto tracked = g_node_context.block_tracker->GetTrackedHeights();
                    std::set<NodeId> peers_with_blocks;
                    for (const auto& [height, peer_id] : tracked) {
                        peers_with_blocks.insert(peer_id);
                    }

                    // Check each peer and clear if disconnected
                    for (NodeId peer_id : peers_with_blocks) {
                        auto peer = m_node_context.peer_manager->GetPeer(peer_id);
                        if (!peer || !peer->IsConnected()) {
                            auto cleared = g_node_context.block_tracker->OnPeerDisconnected(peer_id);
                            if (!cleared.empty()) {
                                std::cout << "[IBD] Cleared " << cleared.size()
                                          << " stale in-flight blocks from orphaned peer " << peer_id << std::endl;
                            }
                        }
                    }
                }
            }

            m_ibd_no_peer_cycles++;
            m_last_hang_cause = HangCause::NO_PEERS_AVAILABLE;
            return false;
        }
    }

    // ============ REQUEST BLOCKS FROM SINGLE PEER ============
    auto peer = m_node_context.peer_manager->GetPeer(m_blocks_sync_peer);
    // BUG FIX: Also check IsConnected() - GetPeer returns stale objects
    if (!peer || !peer->IsConnected()) {
        // BUG FIX: Clear in-flight blocks from disconnected peer
        if (g_node_context.block_tracker && m_blocks_sync_peer != -1) {
            auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
            if (!cleared.empty()) {
                std::cout << "[IBD] Cleared " << cleared.size()
                          << " stale in-flight blocks from gone peer " << m_blocks_sync_peer << std::endl;
            }
        }
        m_blocks_sync_peer = -1;
        return false;
    }

    // Check peer capacity
    int peer_blocks_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(m_blocks_sync_peer);
    int peer_capacity = MAX_BLOCKS_IN_TRANSIT_PER_PEER - peer_blocks_in_flight;
    if (peer_capacity <= 0) {
        m_last_hang_cause = HangCause::PEERS_AT_CAPACITY;
        return false;  // Peer at capacity - wait for blocks to arrive
    }

    // Get peer height
    // BUG FIX: If this peer is our headers sync peer, they have blocks up to header_height
    // (they sent us the headers). Use header_height instead of stale best_known_height.
    int peer_height = peer->best_known_height;
    if (peer_height == 0) peer_height = peer->start_height;
    if (m_blocks_sync_peer == m_headers_sync_peer) {
        // Headers sync peer definitely has blocks up to header_height
        peer_height = std::max(peer_height, header_height);
    }

    // Get next blocks to request
    int in_flight_before = g_node_context.block_tracker ? g_node_context.block_tracker->GetTotalInFlight() : 0;
    std::vector<int> blocks_to_request = m_node_context.block_fetcher->GetNextBlocksToRequest(
        peer_capacity, chain_height, header_height);

    // Diagnostic: show what we're about to request
    if (!blocks_to_request.empty() && (header_height - chain_height) > 5) {
        std::cout << "[IBD] FetchBlocks: chain=" << chain_height << " headers=" << header_height
                  << " peer=" << m_blocks_sync_peer << " inflight=" << in_flight_before
                  << " toRequest=" << blocks_to_request.size()
                  << " range=[" << blocks_to_request.front() << ".." << blocks_to_request.back() << "]"
                  << std::endl;
    }

    if (blocks_to_request.empty()) {
        // BUG #246b FIX: If no blocks to request, check if in-flight blocks are from
        // disconnected peers. This can cause "stuck" scenarios where we have blocks
        // in-flight from a peer that no longer exists.
        if (g_node_context.block_tracker) {
            int total_in_flight = g_node_context.block_tracker->GetTotalInFlight();
            if (total_in_flight > 0 && header_height > chain_height) {
                // Blocks in-flight but none to request - check for stale peer assignments
                auto tracked = g_node_context.block_tracker->GetTrackedHeights();
                std::set<NodeId> peers_with_blocks;
                for (const auto& [height, peer_id] : tracked) {
                    peers_with_blocks.insert(peer_id);
                }

                for (NodeId peer_id : peers_with_blocks) {
                    auto peer = m_node_context.peer_manager->GetPeer(peer_id);
                    if (!peer || !peer->IsConnected()) {
                        auto cleared = g_node_context.block_tracker->OnPeerDisconnected(peer_id);
                        if (!cleared.empty()) {
                            std::cout << "[IBD] Cleared " << cleared.size()
                                      << " stale in-flight blocks from dead peer " << peer_id << std::endl;
                        }
                    }
                }
            }
        }
        return false;  // All blocks either connected or in-flight
    }

    // Build GETDATA
    std::vector<NetProtocol::CInv> getdata;
    getdata.reserve(blocks_to_request.size());

    // BUG #247 FIX: During fork recovery, use fork_point as the lower bound
    // instead of chain_height. This ensures block 1068 is requested when
    // fork_point=1067 and chain_height=1068.
    int effective_lower_bound = chain_height;
    {
        ForkManager& forkMgr = ForkManager::GetInstance();
        if (forkMgr.HasActiveFork()) {
            auto fork = forkMgr.GetActiveFork();
            if (fork) {
                effective_lower_bound = fork->GetForkPointHeight();
            }
        }
    }

    int null_hash_count = 0;
    int first_null_hash_height = -1;
    int already_have_count = 0;
    for (int h : blocks_to_request) {
        // Re-check capacity before each request
        int current_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(m_blocks_sync_peer);
        if (current_in_flight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            break;
        }

        // Validate height range
        // BUG #247 FIX: Use effective_lower_bound (fork_point during fork, chain_height otherwise)
        if (h > header_height || h <= effective_lower_bound || h > peer_height) {
            continue;
        }

        // BUG #247 FIX: During fork recovery, use the ForkCandidate's expected hashes
        // to ensure we request the FORK chain's blocks, not our (wrong) chain's blocks.
        uint256 hash;
        {
            ForkManager& forkMgr = ForkManager::GetInstance();
            if (forkMgr.HasActiveFork()) {
                auto fork = forkMgr.GetActiveFork();
                if (fork) {
                    hash = fork->GetExpectedHashAtHeight(h);
                    if (!hash.IsNull()) {
                        std::cout << "[IBD] Fork recovery: requesting block " << h
                                  << " hash=" << hash.GetHex().substr(0, 16) << "..." << std::endl;
                    }
                }
            }
        }

        // Fall back to headers manager if not in fork mode or no expected hash
        if (hash.IsNull()) {
            hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
        }

        if (hash.IsNull()) {
            null_hash_count++;
            if (first_null_hash_height == -1) first_null_hash_height = h;
            continue;
        }

        // Check if already connected or marked as failed
        CBlockIndex* pindex = m_chainstate.GetBlockIndex(hash);
        if (pindex) {
            // Skip already connected blocks
            if (pindex->nStatus & CBlockIndex::BLOCK_VALID_CHAIN) {
                continue;
            }
            // BUG #255: Skip blocks marked as permanently failed
            // These failed authoritative validation in ConnectTip - no point retrying
            if (pindex->IsInvalid()) {
                std::cout << "[IBD] Skipping failed block at height " << h
                          << " (status=" << pindex->nStatus << ")" << std::endl;
                continue;
            }
            // BUG #255: Skip blocks whose parent is marked failed (BLOCK_FAILED_CHILD logic)
            // If parent failed, this block can never connect - don't waste bandwidth
            if (pindex->pprev && pindex->pprev->IsInvalid()) {
                std::cout << "[IBD] Skipping block at height " << h
                          << " - parent is marked failed" << std::endl;
                // Mark this block as failed child
                pindex->nStatus |= CBlockIndex::BLOCK_FAILED_CHILD;
                continue;
            }
            // BUG FIX: Skip blocks we already have data for (orphans awaiting parents)
            // Without this, orphan blocks get re-requested indefinitely since they have
            // a CBlockIndex (created on first arrival) but null pprev (parent not connected).
            // The old code only checked BLOCK_VALID_CHAIN and IsInvalid, missing this case.
            if (pindex->nStatus & CBlockIndex::BLOCK_HAVE_DATA) {
                // FORK FIX: If this is a fork block already in DB, feed it to ForkManager
                // for pre-validation. This handles the case where fork blocks arrived as
                // orphans before the fork was detected - they need to be pre-validated
                // so TriggerChainSwitch can activate the better chain.
                ForkManager& forkMgr2 = ForkManager::GetInstance();
                if (forkMgr2.HasActiveFork()) {
                    auto fork2 = forkMgr2.GetActiveFork();
                    if (fork2 && fork2->IsExpectedBlock(hash, h)) {
                        ForkBlock* existing = fork2->GetBlockAtHeight(h);
                        if (!existing || existing->status == ForkBlockStatus::PENDING) {
                            CBlock blockData;
                            if (m_node_context.blockchain_db &&
                                m_node_context.blockchain_db->ReadBlock(hash, blockData)) {
                                std::cout << "[IBD] Fork block at height " << h
                                          << " already in DB - feeding to ForkManager for pre-validation" << std::endl;
                                forkMgr2.AddBlockToFork(blockData, hash, h);
                                ForkBlock* forkBlock = fork2->GetBlockAtHeight(h);
                                if (forkBlock && forkBlock->status == ForkBlockStatus::PENDING) {
                                    forkMgr2.PreValidateBlock(*forkBlock, *m_node_context.blockchain_db);
                                }
                            }
                        }
                    }
                }
                already_have_count++;
                continue;
            }
        }

        // Request block from our single sync peer
        if (m_node_context.block_fetcher->RequestBlockFromPeer(m_blocks_sync_peer, h, hash)) {
            getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
        }
    }

    // Diagnostic: log when heights have null hashes (indicates header chain gap)
    if (null_hash_count > 0) {
        std::cout << "[IBD] WARNING: " << null_hash_count << " heights had null hashes (first=" << first_null_hash_height
                  << " chain=" << chain_height << " headers=" << header_height << ")" << std::endl;
    }
    if (already_have_count > 0) {
        std::cout << "[IBD] Skipped " << already_have_count << " blocks already in DB (orphans awaiting parents)" << std::endl;
    }

    // Send GETDATA to our single sync peer
    if (!getdata.empty()) {
        CNetMessage msg = m_node_context.message_processor->CreateGetDataMessage(getdata);
        bool sent = m_node_context.connman->PushMessage(m_blocks_sync_peer, msg);
        if (!sent) {
            // BUG FIX: Clear ALL in-flight blocks from this peer, not just the ones we tried to send
            // The peer might have other blocks tracked from a previous batch
            if (g_node_context.block_tracker && m_blocks_sync_peer != -1) {
                auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                if (!cleared.empty()) {
                    std::cout << "[IBD] Cleared " << cleared.size()
                              << " stale in-flight blocks from failed send peer " << m_blocks_sync_peer << std::endl;
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
        bool current_peer_timed_out = false;
        for (const auto& [height, peer] : very_stalled) {
            m_node_context.block_fetcher->RequeueBlock(height);
            removed++;
            // Track if current blocks sync peer had timeouts
            if (peer == m_blocks_sync_peer) {
                current_peer_timed_out = true;
            }
        }
        if (removed > 0) {
            std::cout << "[PerBlock] Removed " << removed << " blocks stuck >" << HARD_TIMEOUT_SECONDS
                      << "s from tracker (will re-request)" << std::endl;
        }

        // BAD PEER DETECTION: If current sync peer has consecutive timeout cycles, rotate to new peer
        if (current_peer_timed_out && m_blocks_sync_peer != -1) {
            m_blocks_sync_peer_consecutive_timeouts++;
            if (m_blocks_sync_peer_consecutive_timeouts >= MAX_PEER_CONSECUTIVE_TIMEOUTS) {
                std::cout << "[IBD] Blocks sync peer " << m_blocks_sync_peer
                          << " not delivering blocks (" << m_blocks_sync_peer_consecutive_timeouts
                          << " consecutive timeout cycles), forcing reselection" << std::endl;

                // BUG #256: Track this peer to avoid re-selecting it for 1 hour
                m_timed_out_peer = m_blocks_sync_peer;
                m_timed_out_peer_time = std::chrono::steady_clock::now();
                std::cout << "[IBD] Peer " << m_timed_out_peer << " excluded from selection for "
                          << TIMED_OUT_PEER_COOLDOWN_SEC << " seconds" << std::endl;

                // BUG FIX: Clear in-flight blocks from this peer before reselecting
                // Without this, blocks would stay tracked until 60s timeout, causing
                // "all peers at capacity" errors when we accumulate stale entries
                if (g_node_context.block_tracker) {
                    auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                    if (!cleared.empty()) {
                        std::cout << "[IBD] Cleared " << cleared.size()
                                  << " stale in-flight blocks from bad peer " << m_blocks_sync_peer << std::endl;
                    }
                }

                m_blocks_sync_peer = -1;
                m_blocks_sync_peer_consecutive_timeouts = 0;
            }
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
 * BUG #194 FIX: Walk FORWARD from genesis to find true divergence point
 *
 * RACE CONDITION FIX: Uses thread-safe GetChainSnapshot() to avoid reading
 * pprev pointers without holding cs_main. Previously, this function could
 * cause use-after-free if validation workers modified the chain concurrently.
 *
 * CHAIN BREAK FIX: Uses GetHeadersAtHeight() instead of GetRandomXHashAtHeight()
 * to avoid chain walk issues when headers don't fully connect.
 *
 * Returns the height of the last common block (fork_point), or 0 if no match found.
 */
int CIbdCoordinator::FindForkPoint(int chain_height) {
    if (!m_node_context.headers_manager) {
        return 0;
    }

    std::cout << "[FORK-DETECT] Searching for fork point from height " << chain_height << std::endl;

    // RACE CONDITION FIX: Get a thread-safe snapshot of the chain
    // This holds cs_main while copying the data, then releases it
    const int MAX_CHECKS = chain_height + 1;  // +1 to include genesis if needed
    auto chainSnapshot = m_chainstate.GetChainSnapshot(MAX_CHECKS, 0);

    if (chainSnapshot.empty()) {
        std::cerr << "[FORK-DETECT] ERROR: Empty chain snapshot" << std::endl;
        return 0;
    }

    // BUG #194 FIX: Build height->hash map for forward iteration
    // chainSnapshot is tip-downward, we need to walk genesis-upward
    std::map<int, uint256> chainstateByHeight;
    for (const auto& [height, hash] : chainSnapshot) {
        chainstateByHeight[height] = hash;
    }

    // Step 1: Verify genesis matches
    auto genesisIt = chainstateByHeight.find(0);
    if (genesisIt != chainstateByHeight.end()) {
        std::vector<uint256> headersAtGenesis = m_node_context.headers_manager->GetHeadersAtHeight(0);
        bool genesisFound = false;
        for (const auto& h : headersAtGenesis) {
            if (h == genesisIt->second) {
                genesisFound = true;
                break;
            }
        }
        if (!genesisFound && !headersAtGenesis.empty()) {
            std::cerr << "[FORK-DETECT] CRITICAL: Genesis mismatch! Different chains." << std::endl;
            return 0;
        }
    }

    // Step 2: Walk FORWARD from genesis to find first divergence
    // The fork point is the LAST height where chains UNAMBIGUOUSLY match
    int last_common_height = 0;
    int first_divergence = -1;
    int logged_divergences = 0;

    for (int h = 0; h <= chain_height; h++) {
        auto it = chainstateByHeight.find(h);
        if (it == chainstateByHeight.end()) {
            continue;  // No chainstate block at this height (shouldn't happen)
        }

        uint256 local_hash = it->second;

        // BUG #194 FIX: Use GetHeadersAtHeight instead of GetRandomXHashAtHeight
        // This queries mapHeightIndex directly, avoiding chain walk issues
        std::vector<uint256> headers_at_height = m_node_context.headers_manager->GetHeadersAtHeight(h);

        if (headers_at_height.empty()) {
            // No headers at this height - network chain doesn't have this block yet
            // This is OK during IBD, continue checking
            continue;
        }

        // BUG #194 FIX: If there are MULTIPLE headers at this height, it means
        // competing forks exist. Even if our hash is among them, we can't be sure
        // we're on the same chain as the network. Treat as potential divergence.
        if (headers_at_height.size() > 1) {
            // Multiple competing headers = fork point
            if (first_divergence < 0) {
                first_divergence = h;
                std::cout << "[FORK-DETECT] Competing forks at height " << h
                          << " (" << headers_at_height.size() << " headers)"
                          << " - treating as divergence point" << std::endl;
            }
            continue;  // Don't update last_common_height
        }

        // Exactly one header at this height - check if it matches chainstate
        if (headers_at_height[0] == local_hash) {
            last_common_height = h;
        } else {
            // Single header but doesn't match chainstate = divergence
            if (first_divergence < 0) {
                first_divergence = h;
                std::cout << "[FORK-DETECT] Chain diverges at height " << h
                          << " local=" << local_hash.GetHex().substr(0, 16) << "..."
                          << " header=" << headers_at_height[0].GetHex().substr(0, 16) << "..." << std::endl;
            }
            if (logged_divergences < 5) {
                std::cout << "[FORK-DETECT] Height " << h << " diverges: local="
                          << local_hash.GetHex().substr(0, 16) << "..." << std::endl;
                logged_divergences++;
            }
        }
    }

    if (first_divergence >= 0) {
        // Chains diverge - fork point is the last UNAMBIGUOUS common height
        std::cout << "[FORK-DETECT] Found fork point at height " << last_common_height
                  << " (first divergence/fork at " << first_divergence << ")" << std::endl;
        return last_common_height;
    }

    // No divergence found - chains match completely
    std::cout << "[FORK-DETECT] No fork detected - chains match up to height " << chain_height << std::endl;
    return chain_height;
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

        // FORK SAFETY FIX: Do NOT delete orphan blocks from database
        // Keep disconnected blocks in DB so they can be re-activated if they become best chain.
        // This prevents the corruption issue where nodes end up on different forks after restart
        // if block data was deleted before the replacement chain was fully downloaded.
        //
        // The blocks are:
        // - Disconnected from chain (UTXO undone, pnext cleared, BLOCK_VALID_CHAIN cleared)
        // - Still have BLOCK_HAVE_DATA set (data exists in DB)
        // - Can be re-activated by ActivateBestChain if they become best chain
        // - Will be pruned later by deferred cleanup (optional)
        //
        // This matches Bitcoin Core's approach: keep fork blocks, let chain work decide.
        std::cout << "[FORK-RECOVERY] Keeping " << disconnected
                  << " disconnected block(s) in database for safety" << std::endl;
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
// FORK RECOVERY: Shared logic for Layer 2 and Layer 3
// ============================================================================

bool CIbdCoordinator::AttemptForkRecovery(int chain_height, int header_height) {
    int fork_point = FindForkPoint(chain_height);

    // BUG #189 FIX: Allow fork_point up to chain_height + 1 to handle race conditions
    if (fork_point <= 0 || fork_point > chain_height + 1) {
        if (fork_point == 0) {
            std::cout << "[FORK-DETECT] No common ancestor found" << std::endl;
        } else {
            std::cout << "[FORK-DETECT] Could not find valid fork point" << std::endl;
        }
        m_fork_stall_cycles.store(0);
        return false;
    }

    int fork_depth = std::max(0, chain_height - fork_point);
    std::cout << "[FORK-DETECT] Fork point found at height " << fork_point
              << " (depth=" << fork_depth << " blocks)" << std::endl;

    // Check reorg depth limit
    if (fork_depth > MAX_AUTO_REORG_DEPTH) {
        std::cerr << "[FORK-DETECT] Fork too deep (" << fork_depth
                  << " > " << MAX_AUTO_REORG_DEPTH << ") for automatic recovery" << std::endl;
        m_fork_stall_cycles.store(0);
        return false;
    }

    // BUG #245 FIX: Only fork recover if incoming chain has MORE work than ours
    uint256 localChainWork;
    CBlockIndex* pTip = m_chainstate.GetTip();
    if (pTip) {
        localChainWork = pTip->nChainWork;
    }

    uint256 headerChainWork;
    if (m_node_context.headers_manager) {
        headerChainWork = m_node_context.headers_manager->GetChainTipsTracker().GetBestChainWork();
    }

    // If chainwork data is available for both sides, use it for the comparison.
    // If either is null (chain tips tracker may not track chainwork for competing
    // tips after a partial fork switch), skip the check - we already know we're
    // on a stale fork because we're receiving consecutive orphan blocks.
    if (!localChainWork.IsNull() && !headerChainWork.IsNull()) {
        if (!ChainWorkGreaterThan(headerChainWork, localChainWork)) {
            std::string localHex = localChainWork.GetHex();
            std::string headerHex = headerChainWork.GetHex();
            std::cout << "[FORK-DETECT] Incoming fork has LESS work than our chain - NOT switching" << std::endl;
            std::cout << "[FORK-DETECT] Local work=..." << localHex.substr(localHex.length() > 16 ? localHex.length() - 16 : 0)
                      << " Header work=..." << headerHex.substr(headerHex.length() > 16 ? headerHex.length() - 16 : 0) << std::endl;
            m_fork_stall_cycles.store(0);
            return false;
        }
    } else {
        // Chainwork unavailable - proceed with fork recovery anyway.
        // Layer 2's 10+ consecutive orphan blocks is strong evidence of a stale fork.
        std::cout << "[FORK-DETECT] ChainWork unavailable (local="
                  << (localChainWork.IsNull() ? "null" : "set")
                  << " header=" << (headerChainWork.IsNull() ? "null" : "set")
                  << ") - proceeding based on orphan block evidence" << std::endl;
    }

    // VALIDATE-BEFORE-DISCONNECT: Use ForkManager staging approach
    ForkManager& forkMgr = ForkManager::GetInstance();

    // Check if we already have an active fork
    if (forkMgr.HasActiveFork()) {
        if (forkMgr.CheckTimeout()) {
            std::cout << "[FORK-DETECT] Existing fork timed out, canceling and starting new" << std::endl;
            forkMgr.CancelFork("Timeout - 60s without blocks");
            forkMgr.ClearInFlightState(m_node_context, fork_point);
            m_fork_detected.store(false);
            g_node_context.fork_detected.store(false);
            g_metrics.ClearForkDetected();
            m_fork_point.store(-1);
        } else {
            std::cout << "[FORK-DETECT] Fork already active, waiting for blocks..." << std::endl;
            m_fork_stall_cycles.store(0);
            return true;  // Fork is active, caller should not proceed further
        }
    }

    // Get the expected fork tip height from headers manager
    int headerTipHeight = header_height;
    if (m_node_context.headers_manager) {
        headerTipHeight = m_node_context.headers_manager->GetBestHeight();
    }

    // Get fork tip from competing tips (storage hash domain)
    uint256 forkTipHash;
    std::map<int32_t, uint256> expectedHashes;

    if (m_node_context.headers_manager) {
        const auto& tipsTracker = m_node_context.headers_manager->GetChainTipsTracker();
        auto competingTips = tipsTracker.GetCompetingTips();

        for (const auto& tip : competingTips) {
            if (tip.height == headerTipHeight) {
                forkTipHash = tip.hash;
                std::cout << "[FORK-DETECT] Found fork tip from competing tips: "
                          << forkTipHash.GetHex().substr(0, 16)
                          << "... at height " << tip.height << std::endl;
                break;
            }
        }

        if (!forkTipHash.IsNull()) {
            if (!m_node_context.headers_manager->BuildForkAncestryHashes(
                    forkTipHash, fork_point, expectedHashes)) {
                std::cerr << "[FORK-DETECT] Failed to build fork ancestry" << std::endl;
            }
        } else {
            forkTipHash = m_node_context.headers_manager->GetRandomXHashAtHeight(headerTipHeight);
            std::cerr << "[FORK-DETECT] Warning: Using RandomX hash fallback" << std::endl;
        }
    }

    std::cout << "[FORK-DETECT] Creating fork staging candidate..." << std::endl;
    std::cout << "[FORK-DETECT] Fork point=" << fork_point
              << " chain=" << chain_height
              << " expected_tip=" << headerTipHeight
              << " expected_hashes=" << expectedHashes.size() << std::endl;

    auto forkCandidate = forkMgr.CreateForkCandidate(
        forkTipHash,
        chain_height,
        fork_point,
        headerTipHeight,
        expectedHashes
    );

    if (forkCandidate) {
        m_fork_detected.store(true);
        g_node_context.fork_detected.store(true);
        m_fork_point.store(fork_point);

        std::cout << "[FORK-DETECT] Fork candidate created, blocks will be staged for pre-validation" << std::endl;
        std::cout << "[FORK-DETECT] Original chain remains ACTIVE until fork is fully validated" << std::endl;
    } else {
        std::cerr << "[FORK-DETECT] Failed to create fork candidate" << std::endl;
    }

    m_fork_stall_cycles.store(0);
    m_last_checked_chain_height = -1;  // Reset to allow fresh tracking
    return forkCandidate != nullptr;
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
        // Skip peers that have been marked as bad (repeatedly failed to deliver headers)
        if (m_headers_bad_peers.count(peer->id) > 0) {
            continue;
        }
        // BUG FIX: Use best_known_height (dynamic) instead of GetPeerStartHeight (static)
        int peer_height = peer->best_known_height;
        if (peer_height == 0) peer_height = peer->start_height;
        if (peer_height > best_height) {
            best_height = peer_height;
            best_peer = peer->id;
        }
    }

    if (best_peer != -1) {
        m_headers_sync_peer = best_peer;
        m_headers_sync_peer_consecutive_stalls = 0;  // Reset stall counter for new peer
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

    // Skip stall check if already synced (header_height >= peer_height)
    if (m_node_context.headers_manager && m_node_context.peer_manager) {
        int header_height = m_node_context.headers_manager->GetBestHeight();
        // BUG FIX: Use best_known_height for dynamic peer height
        auto sync_peer = m_node_context.peer_manager->GetPeer(m_headers_sync_peer);
        int peer_height = sync_peer ? (sync_peer->best_known_height > 0 ? sync_peer->best_known_height : sync_peer->start_height)
                                    : m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);
        if (header_height >= peer_height && peer_height > 0) {
            return true;  // Already synced with this peer
        }
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
        // BUG FIX: Use best_known_height for dynamic peer height
        auto progress_peer = m_node_context.peer_manager ? m_node_context.peer_manager->GetPeer(m_headers_sync_peer) : nullptr;
        int peer_height = progress_peer ? (progress_peer->best_known_height > 0 ? progress_peer->best_known_height : progress_peer->start_height)
                                        : m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);
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

    // BAD PEER TRACKING: Track consecutive stalls for this peer
    if (old_peer != -1) {
        m_headers_sync_peer_consecutive_stalls++;
        if (m_headers_sync_peer_consecutive_stalls >= MAX_HEADERS_CONSECUTIVE_STALLS) {
            std::cout << "[IBD] Headers sync peer " << old_peer
                      << " repeatedly failed to deliver headers (" << m_headers_sync_peer_consecutive_stalls
                      << " stalls), marking as bad peer" << std::endl;
            m_headers_bad_peers.insert(old_peer);
            m_headers_sync_peer_consecutive_stalls = 0;
        }
    }

    m_headers_sync_peer = -1;  // Force reselection

    SelectHeadersSyncPeer();

    if (m_headers_sync_peer != -1) {
        if (m_headers_sync_peer != old_peer) {
            std::cout << "[IBD] Switched headers sync peer: " << old_peer
                      << " -> " << m_headers_sync_peer << std::endl;
        } else {
            std::cout << "[IBD] Retrying headers sync with same peer " << m_headers_sync_peer << std::endl;
        }

        // BUG #195 FIX: Clear pending sync state when switching peers after a stall.
        // This ensures the new request uses our validated tip (hashBestHeader) instead of
        // a stale m_last_request_hash that the new peer may not recognize.
        m_node_context.headers_manager->ClearPendingSync();

        // SSOT: Request headers via single entry point
        // BUG FIX: Use best_known_height for dynamic peer height
        auto new_peer = m_node_context.peer_manager ? m_node_context.peer_manager->GetPeer(m_headers_sync_peer) : nullptr;
        int peer_height = new_peer ? (new_peer->best_known_height > 0 ? new_peer->best_known_height : new_peer->start_height)
                                   : m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);
        if (m_node_context.headers_manager->SyncHeadersFromPeer(m_headers_sync_peer, peer_height)) {
            m_headers_in_flight = true;
        }
    }
}


