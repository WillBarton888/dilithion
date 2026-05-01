// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/block_fetcher.h>
#include <net/peers.h>
#include <net/block_tracker.h>
#include <core/node_context.h>
#include <node/fork_manager.h>  // BUG #246c FIX: For fork-aware block requesting

// Forward declaration
extern NodeContext g_node_context;

/**
 * @file block_fetcher.cpp
 * @brief Thin wrapper around CBlockTracker for IBD block downloads
 *
 * CBlockTracker is the SSOT for all block download tracking.
 * This class provides integration with CPeerManager and a simple API.
 */

CBlockFetcher::CBlockFetcher(CPeerManager* peer_manager)
    : m_peer_manager(peer_manager), nBlocksReceivedTotal(0)
{
    lastBlockReceived = std::chrono::steady_clock::now();
}

bool CBlockFetcher::MarkBlockReceived(NodeId peer, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker handles all tracking - just delegate to it
    int height = -1;
    if (g_node_context.block_tracker) {
        height = g_node_context.block_tracker->OnBlockReceived(hash);
    }

    // Update stats
    nBlocksReceivedTotal++;
    lastBlockReceived = std::chrono::steady_clock::now();

    // Notify CPeerManager for peer stats (downloads count, etc.)
    if (m_peer_manager) {
        m_peer_manager->MarkBlockAsReceived(peer, hash);
    }

    return (height > 0);
}

size_t CBlockFetcher::GetPendingCount() const
{
    // SSOT: CBlockTracker doesn't track pending separately
    // Return 0 - callers should check header_height vs chain_height
    return 0;
}

size_t CBlockFetcher::GetInFlightCount() const
{
    // SSOT: Delegate to CBlockTracker
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->GetTotalInFlight();
    }
    return 0;
}

void CBlockFetcher::OnPeerConnected(NodeId peer)
{
    // Phase 1: CPeerManager handles peer state initialization - we don't track locally
    // This method is kept for API compatibility but now a no-op
    (void)peer;
}

// ============ Per-Block Download API ============

std::vector<int> CBlockFetcher::GetNextBlocksToRequest(int max_blocks, int chain_height, int header_height)
{
    std::vector<int> result;

    // Issue #18 FIX: Validate height range - nothing to request if already synced
    if (chain_height >= header_height || max_blocks <= 0) {
        return result;
    }

    result.reserve(max_blocks);

    // SSOT: Use CBlockTracker for all tracking
    if (!g_node_context.block_tracker) {
        return result;
    }

    int total_in_flight = g_node_context.block_tracker->GetTotalInFlight();
    if (total_in_flight >= CBlockTracker::MAX_TOTAL) {
        return result;  // Already at capacity
    }

    int available_slots = CBlockTracker::MAX_TOTAL - total_in_flight;
    int blocks_to_get = std::min(max_blocks, available_slots);

    // BUG #246c FIX: During a fork, we need to request blocks starting from
    // fork_point+1, not chain_height+1. This is because:
    // - We already have block chain_height (e.g., 1068) on our chain
    // - But the fork has a DIFFERENT block at that height
    // - GetNextBlocksToRequest was skipping the fork's version of that block!
    //
    // Example: fork_point=1067, chain_height=1068
    // - Old code: requested 1069+ (skipped fork's 1068!)
    // - New code: if fork active, request from fork_point+1=1068
    int start_height = chain_height + 1;

    // Check if there's an active fork that starts earlier.
    //
    // Phase 10 PR10.3 — fork-bias activation transition logging.
    // Closes Phase 8 PR8.6-RT-MEDIUM-3: previously the harness covered
    // this path only at outcome-level (convergence + reorg ≤ 1 + Undo
    // Block grep), with no mechanism-isolation. We now emit a unique
    // marker line "[BlockFetcher] FORK-BIAS-ACTIVATED" on transitions
    // (first activation; fork_point change; deactivation) — the
    // four_node_local.sh stress scenario greps this marker to assert
    // the fork-bias path was specifically exercised, not just the
    // overall convergence outcome.
    //
    // State transitions logged once each (no per-cycle spam):
    //   inactive    -> fork_point=N    : "ACTIVATED fork_point=N"
    //   fork_point=A -> fork_point=B (A != B) : "CHANGED A -> B"
    //   fork_point=N -> inactive       : "DEACTIVATED last_fork_point=N"
    int observed_fork_point = -1;  // -1 = no fork-bias active this cycle
    ForkManager& forkMgr = ForkManager::GetInstance();
    if (forkMgr.HasActiveFork()) {
        auto fork = forkMgr.GetActiveFork();
        if (fork) {
            int fork_point = fork->GetForkPointHeight();
            // During fork, we need blocks from fork_point+1 onwards
            // This includes the block at chain_height if fork_point < chain_height
            if (fork_point < chain_height) {
                start_height = fork_point + 1;
                observed_fork_point = fork_point;
            }
        }
    }

    // Transition-log under cs_fetcher to avoid log-storm if multiple
    // threads enter GetNextBlocksToRequest concurrently.
    {
        std::lock_guard<std::mutex> lock(cs_fetcher);
        if (observed_fork_point != m_last_fork_bias_logged_fork_point) {
            if (observed_fork_point >= 0 && m_last_fork_bias_logged_fork_point < 0) {
                std::cout << "[BlockFetcher] FORK-BIAS-ACTIVATED fork_point="
                          << observed_fork_point << " chain_height="
                          << chain_height << " start_height=" << start_height
                          << std::endl;
            } else if (observed_fork_point >= 0 && m_last_fork_bias_logged_fork_point >= 0) {
                std::cout << "[BlockFetcher] FORK-BIAS-CHANGED prev_fork_point="
                          << m_last_fork_bias_logged_fork_point
                          << " new_fork_point=" << observed_fork_point
                          << std::endl;
            } else {
                // observed_fork_point == -1 && m_last_... >= 0
                std::cout << "[BlockFetcher] FORK-BIAS-DEACTIVATED last_fork_point="
                          << m_last_fork_bias_logged_fork_point
                          << std::endl;
            }
            m_last_fork_bias_logged_fork_point = observed_fork_point;
        }
    }

    // Pure per-block: iterate from start_height, skip tracked heights
    for (int h = start_height; h <= header_height && static_cast<int>(result.size()) < blocks_to_get; h++) {
        if (!g_node_context.block_tracker->IsTracked(h)) {
            result.push_back(h);
        }
    }

    return result;
}

bool CBlockFetcher::RequestBlockFromPeer(NodeId peer_id, int height, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker handles all tracking - just delegate to it
    if (!g_node_context.block_tracker) {
        return false;
    }

    // v4.0.21 — Patch D: enforce scheduler-level per-peer cap.
    // CBlockTracker::AddBlock has its own MAX_PER_PEER (128) ceiling, but the
    // IBD coordinator gates new requests on MAX_BLOCKS_IN_TRANSIT_PER_PEER (32)
    // and reports HangCause::PEERS_AT_CAPACITY when the live in-flight count
    // is >= that limit. Parent-fetch and other direct callers of this function
    // bypassed the 32-cap and could push in-flight to 33-128. Once that
    // happened, the coordinator's capacity gate stayed closed until timeout
    // requeue (120s) drained the surplus — the operator-visible "sync peer
    // stuck at capacity" symptom from the 2026-04-25 incident.
    // Reject early so the scheduler stays consistent with the in-flight count
    // it later reads back via GetPeerBlocksInFlight().
    int in_flight = g_node_context.block_tracker->GetPeerInFlightCount(peer_id);
    if (in_flight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
        return false;
    }

    // AddBlock handles capacity checks and duplicate detection
    return g_node_context.block_tracker->AddBlock(height, hash, peer_id);
}

bool CBlockFetcher::OnBlockReceived(NodeId peer_id, int height, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker handles all tracking - just delegate to it
    if (!g_node_context.block_tracker) {
        return false;
    }

    bool found = g_node_context.block_tracker->OnBlockReceivedByHeight(height);

    if (found) {
        // Update stats
        nBlocksReceivedTotal++;
        lastBlockReceived = std::chrono::steady_clock::now();

        // BUG #254 FIX: Update peer's best known tip (Bitcoin-style tracking)
        // When a peer sends us a block at height N, they have blocks up to N.
        // This ensures ibd_coordinator's peer_height check stays current
        // and fork divergence detection has hash data to compare.
        if (m_peer_manager && peer_id >= 0) {
            m_peer_manager->UpdatePeerBestKnownTip(peer_id, height, hash);
        }
    }

    return found;
}

std::vector<std::pair<int, NodeId>> CBlockFetcher::GetStalledBlocks(std::chrono::seconds timeout)
{
    // SSOT: Delegate to CBlockTracker with caller's timeout
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->CheckTimeouts(static_cast<int>(timeout.count()));
    }
    return {};
}

void CBlockFetcher::RequeueBlock(int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker handles all tracking
    if (g_node_context.block_tracker) {
        g_node_context.block_tracker->RemoveTimedOut(height);
    }
    // Block will be re-requested on next iteration of download loop
}

int CBlockFetcher::GetPeerBlocksInFlight(NodeId peer_id) const
{
    // SSOT: Delegate to CBlockTracker
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->GetPeerInFlightCount(peer_id);
    }
    return 0;
}

bool CBlockFetcher::IsHeightInFlight(int height) const
{
    // SSOT: Delegate to CBlockTracker
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->IsTracked(height);
    }
    return false;
}

int CBlockFetcher::ClearAboveHeight(int fork_point)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: Delegate to CBlockTracker
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->ClearAboveHeight(fork_point);
    }
    return 0;
}
