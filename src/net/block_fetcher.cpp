// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/block_fetcher.h>
#include <net/peers.h>
#include <net/block_tracker.h>
#include <core/node_context.h>
#include <node/block_validation_queue.h>
#include <consensus/chain.h>
#include <algorithm>
#include <sstream>
#include <set>  // BUG #165 FIX: For std::set in CleanupUnsuitablePeers

// Forward declaration
extern NodeContext g_node_context;

/**
 * @file block_fetcher.cpp
 * @brief Implementation of parallel block downloading for IBD
 *
 * Implements Bitcoin Core's parallel block download strategy with intelligent
 * peer selection, timeout handling, and priority-based fetching.
 */

CBlockFetcher::CBlockFetcher(CPeerManager* peer_manager)
    : m_peer_manager(peer_manager), nBlocksReceivedTotal(0)
{
    lastBlockReceived = std::chrono::steady_clock::now();
}

void CBlockFetcher::QueueBlockForDownload(const uint256& hash, int height,
                                          NodeId announcing_peer, bool highPriority)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Don't queue if already in-flight or already queued
    if (mapBlocksInFlight.count(hash) > 0) {
        return;
    }

    if (setQueuedHashes.count(hash) > 0) {
        return;
    }

    // Add to priority queue
    queueBlocksToFetch.push(BlockDownloadRequest(hash, height, announcing_peer, highPriority));
    setQueuedHashes.insert(hash);

    // BUG #64: Track which peer announced this block for preferred download
    if (announcing_peer != -1) {
        mapPreferredPeers[hash] = announcing_peer;
    }

}

NodeId CBlockFetcher::GetPreferredPeer(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    auto it = mapPreferredPeers.find(hash);
    if (it != mapPreferredPeers.end()) {
        return it->second;
    }
    return -1;
}

bool CBlockFetcher::RequestBlock(NodeId peer, const uint256& hash, int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Check peer manager and peer validity
    if (!m_peer_manager) {
        return false;
    }

    auto peer_obj = m_peer_manager->GetPeer(peer);
    if (!peer_obj) {
        return false;
    }

    // Check peer capacity
    int blocks_in_flight = m_peer_manager->GetBlocksInFlightForPeer(peer);
    if (blocks_in_flight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        return false;
    }

    // IBD BOTTLENECK FIX: Skip hash-based duplicate check for mapBlocksInFlight
    // The hash-based check fails when header hash doesn't match received block hash.
    // CBlockTracker handles deduplication by HEIGHT through AssignChunkToPeer.
    // We only check if height is already CONNECTED (block already in chain).
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
        BlockState state = g_node_context.block_tracker->GetState(height);
        if (state == BlockState::CONNECTED) {
            // Block already connected to chain - no need to request
            return false;
        }
        // PENDING and IN_FLIGHT are OK - AssignChunkToPeer manages those transitions
    }
    // Note: Removed mapBlocksInFlight.count(hash) check - hash mismatch causes stale entries

    // Create in-flight entry (for timeout tracking only)
    CBlockInFlight inFlight(hash, peer, height);
    mapBlocksInFlight[hash] = inFlight;

    // Track peer's blocks (for disconnect handling)
    mapPeerBlocks[peer].insert(hash);

    // SSOT Phase 3: Use CBlockTracker for assignment
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
        g_node_context.block_tracker->SetHash(height, hash);
        g_node_context.block_tracker->AssignToPeer(height, peer);
    }

    // Remove from queue if present
    setQueuedHashes.erase(hash);

    return true;
}

bool CBlockFetcher::MarkBlockReceived(NodeId peer, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Check if block was in-flight in local tracking
    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        // Not in hash-based tracking - check height-based tracking (per-block API)
        // BUG #167 FIX: Blocks from RequestBlockFromPeer are in mapBlocksInFlightByHeight, not mapBlocksInFlight
        for (auto height_it = mapBlocksInFlightByHeight.begin(); height_it != mapBlocksInFlightByHeight.end(); ++height_it) {
            if (height_it->second.hash == hash) {
                // Found in height-based tracking - clean it up
                int height = height_it->first;
                const std::set<NodeId>& all_peers = height_it->second.peers;

                // Remove from all peers' tracking
                for (NodeId p : all_peers) {
                    auto peer_it = mapPeerBlocksInFlightByHeight.find(p);
                    if (peer_it != mapPeerBlocksInFlightByHeight.end()) {
                        peer_it->second.erase(height);
                        if (peer_it->second.empty()) {
                            mapPeerBlocksInFlightByHeight.erase(peer_it);
                        }
                    }
                }

                // Remove from height tracking
                mapBlocksInFlightByHeight.erase(height_it);

                // SSOT: Notify CBlockTracker
                if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
                    g_node_context.block_tracker->OnBlockReceived(height, peer);
                }

                // Notify CPeerManager
                if (m_peer_manager) {
                    m_peer_manager->MarkBlockAsReceived(peer, hash);
                }

                nBlocksReceivedTotal++;
                lastBlockReceived = std::chrono::steady_clock::now();
                return true;
            }
        }

        // Not tracked in either map - notify CPeerManager anyway
        if (m_peer_manager) {
            m_peer_manager->MarkBlockAsReceived(peer, hash);
        }
        return false;
    }

    // Block was in local tracking - notify CPeerManager
    if (m_peer_manager) {
        m_peer_manager->MarkBlockAsReceived(peer, hash);
    }

    int height = it->second.nHeight;

    // Calculate response time and update CPeerManager stats
    auto timeReceived = std::chrono::steady_clock::now();
    auto responseTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        timeReceived - it->second.timeRequested
    );

    // Phase 1: Delegate peer stats update to CPeerManager
    if (m_peer_manager) {
        m_peer_manager->UpdatePeerStats(peer, true, responseTime);
    }

    // Remove from local in-flight tracking
    NodeId requestedPeer = it->second.peer;
    mapBlocksInFlight.erase(it);

    // BUG #167 FIX: Also clean up height-based tracking (mapBlocksInFlightByHeight)
    // Without this, orphan blocks never decrement the height-based in-flight count,
    // causing GetNextBlocksToRequest() to return empty when 128 heights are in-flight.
    if (height > 0) {
        mapBlocksInFlightByHeight.erase(height);
        // Also clean up per-peer height tracking
        auto peer_it = mapPeerBlocksInFlightByHeight.find(requestedPeer);
        if (peer_it != mapPeerBlocksInFlightByHeight.end()) {
            peer_it->second.erase(height);
            if (peer_it->second.empty()) {
                mapPeerBlocksInFlightByHeight.erase(peer_it);
            }
        }
        // SSOT: Also notify CBlockTracker
        if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
            g_node_context.block_tracker->OnBlockReceived(height, requestedPeer);
        }
    }

    // Update peer's block set (for disconnect handling)
    if (mapPeerBlocks.count(requestedPeer) > 0) {
        mapPeerBlocks[requestedPeer].erase(hash);
        if (mapPeerBlocks[requestedPeer].empty()) {
            mapPeerBlocks.erase(requestedPeer);
        }
    }

    // NOTE: Chunk tracking is now handled by OnChunkBlockReceived() which is
    // called explicitly by the caller alongside MarkBlockReceived().
    // This avoids double-counting of blocks_pending decrements.
    // Window tracking is also done in OnChunkBlockReceived().

    // Update global statistics
    nBlocksReceivedTotal++;
    lastBlockReceived = timeReceived;

    // BUG #64: Clean up preferred peer tracking
    mapPreferredPeers.erase(hash);

    return true;
}

std::vector<std::pair<uint256, int>> CBlockFetcher::GetNextBlocksToFetch(int maxBlocks)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<std::pair<uint256, int>> result;

    int availableSlots = GetAvailableSlots();
    int blocksToFetch = std::min(availableSlots, maxBlocks);

    if (blocksToFetch <= 0) {
        return result;
    }

    // Temporary queue to rebuild priority queue after extraction
    std::priority_queue<BlockDownloadRequest> tempQueue;

    // Extract blocks from priority queue
    while (!queueBlocksToFetch.empty() && result.size() < static_cast<size_t>(blocksToFetch)) {
        BlockDownloadRequest req = queueBlocksToFetch.top();
        queueBlocksToFetch.pop();

        // Skip if already in-flight (shouldn't happen, but safety check)
        if (mapBlocksInFlight.count(req.hash) > 0) {
            continue;
        }

        result.push_back(std::make_pair(req.hash, req.nHeight));

        // Don't add back to temp queue (it's being fetched now)
        setQueuedHashes.erase(req.hash);
    }

    // Rebuild queue with remaining items
    while (!queueBlocksToFetch.empty()) {
        tempQueue.push(queueBlocksToFetch.top());
        queueBlocksToFetch.pop();
    }
    queueBlocksToFetch = tempQueue;

    // MAINNET FIX: Return without std::move to allow RVO
    return result;
}

std::vector<uint256> CBlockFetcher::CheckTimeouts()
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<uint256> timedOut;
    auto now = std::chrono::steady_clock::now();

    for (const auto& entry : mapBlocksInFlight) {
        auto timeSinceRequest = std::chrono::duration_cast<std::chrono::seconds>(
            now - entry.second.timeRequested
        );

        if (timeSinceRequest >= BLOCK_DOWNLOAD_TIMEOUT) {
            timedOut.push_back(entry.first);
        }
    }

    return timedOut;
}

void CBlockFetcher::RetryTimedOutBlocks(const std::vector<uint256>& timedOutHashes)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    for (const uint256& hash : timedOutHashes) {
        auto it = mapBlocksInFlight.find(hash);
        if (it == mapBlocksInFlight.end()) {
            continue;  // Already removed
        }

        CBlockInFlight& inFlight = it->second;
        NodeId stalledPeer = inFlight.peer;
        int height = inFlight.nHeight;
        int retries = inFlight.nRetries;

        // Phase 1: Mark peer as stalled via CPeerManager
        if (m_peer_manager) {
            m_peer_manager->UpdatePeerStats(stalledPeer, false, std::chrono::milliseconds(0));
        }

        // Remove from local in-flight tracking
        mapBlocksInFlight.erase(it);

        // Update peer's block set
        if (mapPeerBlocks.count(stalledPeer) > 0) {
            mapPeerBlocks[stalledPeer].erase(hash);
            if (mapPeerBlocks[stalledPeer].empty()) {
                mapPeerBlocks.erase(stalledPeer);
            }
        }

        // Phase 1: Notify CPeerManager of block removal
        if (m_peer_manager) {
            m_peer_manager->RemoveBlockFromFlight(hash);
        }

        // Re-queue if not exceeded max retries
        if (retries < MAX_RETRIES) {
            // Re-queue with high priority and incremented retry count
            queueBlocksToFetch.push(BlockDownloadRequest(hash, height, -1, true));  // High priority for retries
            setQueuedHashes.insert(hash);
        } else {
            std::cerr << "[BlockFetcher] Block exceeded max retries, dropping: "
                      << hash.GetHex().substr(0, 16) << "..." << std::endl;
        }
    }
}

NodeId CBlockFetcher::SelectPeerForDownload(const uint256& hash, NodeId preferred_peer)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Phase 1: CPeerManager is single source of truth for peer selection
    if (!m_peer_manager) {
        return -1;  // Cannot operate without peer manager
    }

    // Try the preferred peer first (the one that announced the block)
    if (preferred_peer != -1 && m_peer_manager->IsPeerSuitableForDownload(preferred_peer)) {
        // IBD STUCK FIX #9: Use GetBlocksInFlightForPeer() instead of stale counter
        int peer_in_flight = m_peer_manager->GetBlocksInFlightForPeer(preferred_peer);
        if (peer_in_flight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
            return preferred_peer;
        }
    }

    // Get all valid peers from CPeerManager
    std::vector<int> valid_peers = m_peer_manager->GetValidPeersForDownload();

    NodeId bestPeer = -1;
    NodeId fallbackPeer = -1;
    int bestScore = -1;

    for (int peer_id : valid_peers) {
        auto peer = m_peer_manager->GetPeer(peer_id);
        if (!peer) {
            continue;
        }

        // IBD STUCK FIX #9: Must have capacity (use SSOT not stale counter)
        int in_flight = m_peer_manager->GetBlocksInFlightForPeer(peer_id);
        if (in_flight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
            continue;
        }

        // Check if suitable (uses CPeer::IsSuitableForDownload)
        bool suitable = peer->IsSuitableForDownload();
        if (!suitable) {
            if (fallbackPeer == -1) {
                fallbackPeer = peer_id;
            }
            continue;
        }

        // Calculate score (higher is better)
        int score = 1000;

        // Preferred peers get bonus
        if (peer->fPreferredDownload) {
            score += 500;
        }

        // Penalize for stalls
        score -= peer->nStallingCount * 100;

        // Bonus for fast response time (inverse of time in ms)
        if (peer->avgResponseTime.count() > 0) {
            score += 1000 / (peer->avgResponseTime.count() / 100 + 1);
        }

        // Bonus for successful downloads
        score += peer->nBlocksDownloaded * 10;

        // Penalize if already has many blocks in-flight (spread load)
        score -= peer->nBlocksInFlight * 50;

        if (score > bestScore) {
            bestScore = score;
            bestPeer = peer_id;
        }
    }

    // Use fallback if no suitable peer found
    if (bestPeer == -1 && fallbackPeer != -1) {
        return fallbackPeer;
    }

    return bestPeer;
}

void CBlockFetcher::UpdatePeerStats(NodeId peer, bool success, std::chrono::milliseconds responseTime)
{
    // Note: Caller should hold lock
    // Phase 1: Delegate entirely to CPeerManager (single source of truth)
    if (m_peer_manager) {
        m_peer_manager->UpdatePeerStats(peer, success, responseTime);
    }
}

bool CBlockFetcher::IsDownloading(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    return mapBlocksInFlight.count(hash) > 0;
}

bool CBlockFetcher::IsQueued(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    return setQueuedHashes.count(hash) > 0;
}

int CBlockFetcher::GetBlocksInFlight() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    return mapBlocksInFlight.size();
}

int CBlockFetcher::GetBlocksInFlightForPeer(NodeId peer) const
{
    // Phase 1: Delegate to CPeerManager (single source of truth)
    if (m_peer_manager) {
        return m_peer_manager->GetBlocksInFlightForPeer(peer);
    }
    return 0;
}

size_t CBlockFetcher::GetPendingCount() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    // BUG #158: Return pending count from window or queue
    if (m_window_initialized) {
        return m_download_window.PendingCount();
    }
    return setQueuedHashes.size();
}

size_t CBlockFetcher::GetInFlightCount() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    // BUG #158: Return in-flight count from mapBlocksInFlight
    return mapBlocksInFlight.size();
}

std::vector<uint256> CBlockFetcher::GetQueuedBlocks() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<uint256> result;
    result.reserve(setQueuedHashes.size());

    for (const uint256& hash : setQueuedHashes) {
        result.push_back(hash);
    }

    // MAINNET FIX: Return without std::move to allow RVO
    return result;
}

void CBlockFetcher::RemoveFromQueue(const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Remove from queued set
    setQueuedHashes.erase(hash);

    // BUG #64: Clean up preferred peer tracking
    mapPreferredPeers.erase(hash);

    // Note: We can't efficiently remove from priority_queue without rebuilding it
    // The item will be skipped when popped in GetNextBlocksToFetch
    // This is acceptable performance-wise as the queue is typically small

}

void CBlockFetcher::OnPeerDisconnected(NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Re-queue all blocks that were in-flight from this peer
    if (mapPeerBlocks.count(peer) > 0) {
        const std::set<uint256>& peerBlocks = mapPeerBlocks[peer];

        for (const uint256& hash : peerBlocks) {
            auto it = mapBlocksInFlight.find(hash);
            if (it != mapBlocksInFlight.end()) {
                int height = it->second.nHeight;
                int retries = it->second.nRetries;

                // Remove from in-flight
                mapBlocksInFlight.erase(it);

                // Phase 1: Notify CPeerManager
        if (m_peer_manager) {
            m_peer_manager->RemoveBlockFromFlight(hash);
        }

                // Re-queue with high priority
                if (retries < MAX_RETRIES) {
                    queueBlocksToFetch.push(BlockDownloadRequest(hash, height, -1, true));
                    setQueuedHashes.insert(hash);
                }
            }
        }

        mapPeerBlocks.erase(peer);
    }

    // IBD Redesign Phase 3: Shadow-track with CBlockTracker
    if (g_node_context.block_tracker) {
        g_node_context.block_tracker->OnPeerDisconnected(peer);
    }

    // Phase 1: CPeerManager handles peer state cleanup - we don't track locally
}

void CBlockFetcher::OnPeerConnected(NodeId peer)
{
    // Phase 1: CPeerManager handles peer state initialization - we don't track locally
    // This method is kept for API compatibility but now a no-op
}

bool CBlockFetcher::IsStaleTip() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    auto now = std::chrono::steady_clock::now();
    auto timeSinceLastBlock = std::chrono::duration_cast<std::chrono::minutes>(
        now - lastBlockReceived
    );

    // Consider stale if no blocks received for 5 minutes and we have queued/in-flight blocks
    bool hasWork = !queueBlocksToFetch.empty() || !mapBlocksInFlight.empty();

    return hasWork && (timeSinceLastBlock >= STALE_TIP_TIMEOUT);
}

void CBlockFetcher::ResetStaleTipTimer()
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    lastBlockReceived = std::chrono::steady_clock::now();
}

std::string CBlockFetcher::GetDownloadStatus() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::ostringstream ss;
    ss << "BlockFetcher Status:\n";
    ss << "  Blocks in-flight: " << mapBlocksInFlight.size() << "/" << MAX_BLOCKS_IN_FLIGHT << "\n";
    ss << "  Blocks queued: " << setQueuedHashes.size() << "\n";
    ss << "  Total blocks received: " << nBlocksReceivedTotal << "\n";

    // Phase 1: Peer breakdown from CPeerManager
    if (m_peer_manager) {
        auto peers = m_peer_manager->GetValidPeersForDownload();
        ss << "  Active peers: " << peers.size() << "\n";
        ss << "  Per-peer status:\n";
        for (int peer_id : peers) {
            auto peer = m_peer_manager->GetPeer(peer_id);
            if (peer) {
                ss << "    Peer " << peer_id << ": "
                   << peer->nBlocksInFlight << " in-flight, "
                   << peer->nBlocksDownloaded << " downloaded, "
                   << peer->nStallingCount << " stalls, "
                   << "avg " << peer->avgResponseTime.count() << "ms"
                   << (peer->fPreferredDownload ? " [PREFERRED]" : "")
                   << "\n";
            }
        }
    }

    return ss.str();
}

double CBlockFetcher::GetDownloadSpeed() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Simple calculation: total blocks / time elapsed
    // More sophisticated: could use sliding window
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - lastBlockReceived
    );

    if (elapsed.count() == 0 || nBlocksReceivedTotal == 0) {
        return 0.0;
    }

    return static_cast<double>(nBlocksReceivedTotal) / elapsed.count();
}

void CBlockFetcher::Clear()
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    mapBlocksInFlight.clear();
    mapPeerBlocks.clear();

    // Clear priority queue
    while (!queueBlocksToFetch.empty()) {
        queueBlocksToFetch.pop();
    }
    setQueuedHashes.clear();
    mapPreferredPeers.clear();

    // Phase 1: Peer state is in CPeerManager, not cleared here
    nBlocksReceivedTotal = 0;
    lastBlockReceived = std::chrono::steady_clock::now();
}

// Private helper methods

int CBlockFetcher::GetAvailableSlots() const
{
    // Caller should hold lock
    int inFlight = mapBlocksInFlight.size();
    return MAX_BLOCKS_IN_FLIGHT - inFlight;
}

// Phase 1: GetAvailableSlotsForPeer, MarkPeerStalled, IsPeerSuitable removed
// All peer management is now delegated to CPeerManager

void CBlockFetcher::UpdateDownloadSpeed()
{
    // Placeholder for future implementation of sliding window speed calculation
    // Currently speed is calculated on-demand in GetDownloadSpeed()
}

// ============ Per-Block Block Tracking ============

NodeId CBlockFetcher::OnChunkBlockReceived(int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Pure per-block tracking (Bitcoin Core style)
    auto it = mapBlocksInFlightByHeight.find(height);
    if (it == mapBlocksInFlightByHeight.end()) {
        // Block not in tracking - already received or never requested
        return -1;
    }

    uint256 hash = it->second.hash;
    const std::set<NodeId>& all_peers = it->second.peers;
    NodeId first_peer = all_peers.empty() ? -1 : *all_peers.begin();

    // Remove from ALL peers' tracking (handles parallel downloads)
    for (NodeId p : all_peers) {
        auto peer_it = mapPeerBlocksInFlightByHeight.find(p);
        if (peer_it != mapPeerBlocksInFlightByHeight.end()) {
            peer_it->second.erase(height);
            if (peer_it->second.empty()) {
                mapPeerBlocksInFlightByHeight.erase(peer_it);
            }
        }
    }

    // Remove from per-block tracking
    mapBlocksInFlightByHeight.erase(it);

    // Notify CPeerManager
    if (m_peer_manager && first_peer >= 0) {
        m_peer_manager->MarkBlockAsReceived(first_peer, hash);
    }

    // Update stats
    nBlocksReceivedTotal++;
    lastBlockReceived = std::chrono::steady_clock::now();

    return first_peer;
}

// ============ Window Implementation (for backpressure only) ============

void CBlockFetcher::InitializeWindow(int chain_height, int target_height, bool force)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // IBD Redesign Phase 4: CBlockTracker is now PRIMARY source of truth
    // Skip if already initialized with same target (unless forced for fork recovery)
    if (g_node_context.block_tracker) {
        if (!force && g_node_context.block_tracker->IsInitialized() &&
            g_node_context.block_tracker->GetTargetHeight() == target_height) {
            return;
        }
    } else if (!force && m_window_initialized && m_download_window.GetTargetHeight() == target_height) {
        return;  // Fallback to old check if block_tracker not available
    }

    // Clear existing state when force reinitializing for fork recovery
    if (force) {
        mapBlocksInFlight.clear();
        mapBlocksInFlightByHeight.clear();
        mapPeerBlocksInFlightByHeight.clear();
    }

    // Initialize CBlockTracker as PRIMARY
    if (g_node_context.block_tracker) {
        g_node_context.block_tracker->Initialize(chain_height, target_height);
    }

    // Initialize window for backpressure
    m_download_window.Initialize(chain_height, target_height);
    m_window_initialized = true;
}

std::vector<int> CBlockFetcher::GetWindowPendingHeights(int max_count)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // IBD Redesign Phase 4: Use CBlockTracker as PRIMARY
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
        return g_node_context.block_tracker->GetPendingHeights(max_count);
    }

    // Fallback to legacy window
    if (!m_window_initialized) {
        return {};
    }
    return m_download_window.GetNextPendingHeights(max_count);
}

void CBlockFetcher::MarkWindowHeightsInFlight(const std::vector<int>& heights)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_window_initialized) {
        return;
    }

    m_download_window.MarkAsInFlight(heights);
}

void CBlockFetcher::OnWindowBlockReceived(int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_window_initialized) {
        return;
    }

    m_download_window.OnBlockReceived(height);
}

void CBlockFetcher::OnWindowBlockConnected(int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Clean up mapBlocksInFlight by HEIGHT when block is connected
    for (auto it = mapBlocksInFlight.begin(); it != mapBlocksInFlight.end(); ) {
        if (it->second.nHeight == height) {
            // Clean up peer tracking
            if (mapPeerBlocks.count(it->second.peer) > 0) {
                mapPeerBlocks[it->second.peer].erase(it->first);
                if (mapPeerBlocks[it->second.peer].empty()) {
                    mapPeerBlocks.erase(it->second.peer);
                }
            }
            // Notify CPeerManager
            if (m_peer_manager) {
                m_peer_manager->RemoveBlockFromFlight(it->first);
            }
            it = mapBlocksInFlight.erase(it);
        } else {
            ++it;
        }
    }

    if (!m_window_initialized) {
        return;
    }

    // IBD HANG FIX #2: Pass callback to check if height is queued for validation
    // This allows window to advance past blocks that are queued (processing) vs stuck
    // IBD STUCK FIX #6: Pass callback to check if height is in-flight via chunk tracking
    // This prevents window from advancing past heights that are still being fetched
    auto is_height_queued = [](int h) -> bool {
        if (g_node_context.validation_queue && g_node_context.validation_queue->IsRunning()) {
            return g_node_context.validation_queue->IsHeightQueued(h);
        }
        return false;
    };

    // Check if height is in-flight (per-block tracking)
    auto is_height_in_flight = [this](int h) -> bool {
        // Note: cs_fetcher already held by caller
        return mapBlocksInFlightByHeight.count(h) > 0;
    };

    // BUG #162 FIX: Check if height is connected to the chain
    // This is the authoritative check - a height is complete only if it's at or below chain tip
    auto is_height_connected = [](int h) -> bool {
        if (g_node_context.chainstate) {
            int chain_height = g_node_context.chainstate->GetHeight();
            return h <= chain_height;
        }
        return false;
    };

    // IBD Redesign Phase 3: Shadow-track with CBlockTracker
    if (g_node_context.block_tracker) {
        g_node_context.block_tracker->OnBlockConnected(height);
    }

    m_download_window.OnBlockConnected(height, is_height_queued, is_height_in_flight, is_height_connected);
}

void CBlockFetcher::AddHeightsToWindowPending(const std::vector<int>& heights)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_window_initialized) {
        return;
    }

    // Add heights to window's pending set (skip those already in-flight)
    for (int h : heights) {
        if (mapBlocksInFlightByHeight.count(h) > 0) {
            // Height is already in-flight - don't add to pending
            continue;
        }
        m_download_window.AddToPending(h);

        // Phase 5: Also add to CBlockTracker if height is beyond current window
        // This handles heights added by QueueMissingBlocks that weren't in initial window
        if (g_node_context.block_tracker) {
            g_node_context.block_tracker->AddPendingHeight(h);
        }
    }
}

bool CBlockFetcher::IsWindowInitialized() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // IBD Redesign Phase 4: Use CBlockTracker as PRIMARY
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->IsInitialized();
    }
    return m_window_initialized;
}

std::string CBlockFetcher::GetWindowStatus() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // IBD Redesign Phase 4: Use CBlockTracker as PRIMARY
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
        return g_node_context.block_tracker->GetStatus();
    }

    if (!m_window_initialized) {
        return "Window not initialized";
    }
    return m_download_window.GetStatus();
}

bool CBlockFetcher::IsWindowComplete() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // IBD Redesign Phase 4: Use CBlockTracker as PRIMARY
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
        return g_node_context.block_tracker->IsComplete();
    }

    if (!m_window_initialized) {
        return false;
    }
    return m_download_window.IsComplete();
}

bool CBlockFetcher::UpdateWindowTarget(int new_target_height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // IBD Redesign Phase 4: Use CBlockTracker as PRIMARY
    if (g_node_context.block_tracker) {
        g_node_context.block_tracker->UpdateTarget(new_target_height);
    }

    if (!m_window_initialized) {
        return false;
    }

    return m_download_window.UpdateTargetHeight(new_target_height);
}

// ============ Per-Block Download API (Bitcoin Core Style) ============

std::vector<int> CBlockFetcher::GetNextBlocksToRequest(int max_blocks, int chain_height, int header_height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<int> result;
    result.reserve(max_blocks);

    // Pure per-block: no window, just iterate from chain_height+1 to header_height
    // Limit total in-flight to prevent requesting too far ahead
    static constexpr int MAX_TOTAL_IN_FLIGHT = 128;
    int total_in_flight = static_cast<int>(mapBlocksInFlightByHeight.size());

    if (total_in_flight >= MAX_TOTAL_IN_FLIGHT) {
        return result;  // Already have enough in-flight
    }

    int available_slots = MAX_TOTAL_IN_FLIGHT - total_in_flight;
    int blocks_to_get = std::min(max_blocks, available_slots);

    for (int h = chain_height + 1; h <= header_height && static_cast<int>(result.size()) < blocks_to_get; h++) {
        // Skip if already in-flight
        if (mapBlocksInFlightByHeight.count(h) > 0) {
            continue;
        }
        result.push_back(h);
    }

    return result;
}

bool CBlockFetcher::RequestBlockFromPeer(NodeId peer_id, int height, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Check if height already in-flight (PARALLEL DOWNLOAD path)
    // This check comes BEFORE capacity check - parallel downloads bypass capacity limits
    auto block_it = mapBlocksInFlightByHeight.find(height);
    if (block_it != mapBlocksInFlightByHeight.end()) {
        // PARALLEL DOWNLOAD: Height already in-flight from another peer
        // Check if THIS peer already has it (reject duplicate)
        if (block_it->second.HasPeer(peer_id)) {
            return false;  // This peer already downloading this block
        }
        // Add this peer as parallel downloader (bypasses capacity limit)
        block_it->second.AddPeer(peer_id);
        mapPeerBlocksInFlightByHeight[peer_id].insert(height);

        return true;
    }

    // SSOT Phase 3: Check peer capacity using CBlockTracker
    int peer_in_flight = 0;
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
        peer_in_flight = g_node_context.block_tracker->GetPeerInFlightCount(peer_id);
    } else {
        // Legacy fallback
        auto peer_it = mapPeerBlocksInFlightByHeight.find(peer_id);
        if (peer_it != mapPeerBlocksInFlightByHeight.end()) {
            peer_in_flight = static_cast<int>(peer_it->second.size());
        }
    }
    if (peer_in_flight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
        return false;  // Peer at capacity for new blocks
    }

    // SSOT Phase 3: Use CBlockTracker for assignment
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
        g_node_context.block_tracker->SetHash(height, hash);
        g_node_context.block_tracker->AssignToPeer(height, peer_id);
    }

    // Shadow tracking
    mapBlocksInFlightByHeight[height] = BlockInFlightByHeight(height, hash, peer_id);
    mapPeerBlocksInFlightByHeight[peer_id].insert(height);

    return true;
}

bool CBlockFetcher::OnBlockReceived(NodeId peer_id, int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Find in per-block tracking
    auto it = mapBlocksInFlightByHeight.find(height);
    if (it == mapBlocksInFlightByHeight.end()) {
        // Not in per-block tracking - try legacy chunk system
        return false;
    }

    uint256 hash = it->second.hash;
    const std::set<NodeId>& all_peers = it->second.peers;

    // PARALLEL DOWNLOAD: Remove from ALL peers' tracking (they were all racing)
    for (NodeId p : all_peers) {
        auto peer_it = mapPeerBlocksInFlightByHeight.find(p);
        if (peer_it != mapPeerBlocksInFlightByHeight.end()) {
            peer_it->second.erase(height);
            if (peer_it->second.empty()) {
                mapPeerBlocksInFlightByHeight.erase(peer_it);
            }
        }
        // Notify CPeerManager for each peer
        if (m_peer_manager && p != peer_id) {
            m_peer_manager->RemoveBlockFromFlight(hash);  // Clean up other peers
        }
    }

    // Remove from per-block tracking
    mapBlocksInFlightByHeight.erase(it);

    // SSOT: Notify CBlockTracker (single source of truth)
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
        g_node_context.block_tracker->OnBlockReceived(height, peer_id);
    }

    // Update stats
    nBlocksReceivedTotal++;
    lastBlockReceived = std::chrono::steady_clock::now();

    return true;
}

std::vector<std::pair<int, NodeId>> CBlockFetcher::GetStalledBlocks(std::chrono::seconds timeout)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<std::pair<int, NodeId>> stalled;
    auto now = std::chrono::steady_clock::now();

    for (const auto& [height, info] : mapBlocksInFlightByHeight) {
        // Only flag blocks with 1 peer - blocks with 2+ peers already have parallel downloads
        if (info.peers.size() >= 2) {
            continue;  // Already has parallel download, skip
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - info.first_request_time);
        if (elapsed >= timeout) {
            // Return first peer for logging, but caller should add parallel peer, not requeue
            NodeId first_peer = info.peers.empty() ? -1 : *info.peers.begin();
            stalled.push_back({height, first_peer});
        }
    }

    return stalled;
}

void CBlockFetcher::RequeueBlock(int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Remove from per-block tracking if present
    auto it = mapBlocksInFlightByHeight.find(height);
    if (it != mapBlocksInFlightByHeight.end()) {
        uint256 hash = it->second.hash;
        const std::set<NodeId>& peers = it->second.peers;

        // Remove from ALL peers' tracking (parallel download support)
        for (NodeId peer : peers) {
            auto peer_it = mapPeerBlocksInFlightByHeight.find(peer);
            if (peer_it != mapPeerBlocksInFlightByHeight.end()) {
                peer_it->second.erase(height);
                if (peer_it->second.empty()) {
                    mapPeerBlocksInFlightByHeight.erase(peer_it);
                }
            }
        }

        // Remove from in-flight map
        mapBlocksInFlightByHeight.erase(it);

        // Notify CPeerManager
        if (m_peer_manager) {
            m_peer_manager->RemoveBlockFromFlight(hash);
        }
    }

    // Add back to pending
    m_download_window.MarkAsPending(height);
}

int CBlockFetcher::GetPeerBlocksInFlight(NodeId peer_id) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    auto it = mapPeerBlocksInFlightByHeight.find(peer_id);
    if (it != mapPeerBlocksInFlightByHeight.end()) {
        return static_cast<int>(it->second.size());
    }
    return 0;
}

bool CBlockFetcher::IsHeightInFlight(int height) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    return mapBlocksInFlightByHeight.count(height) > 0;
}
