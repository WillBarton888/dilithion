// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/node_state.h>
#include <iostream>

/**
 * @file node_state.cpp
 * @brief Implementation of CNodeStateManager
 *
 * Provides thread-safe per-peer state management with bidirectional
 * block tracking. Ported from Bitcoin Core's net_processing.cpp.
 */

CNodeState* CNodeStateManager::CreateState(NodeId nodeid) {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    // Remove any existing state for this peer (shouldn't happen, but be safe)
    auto it = mapNodeState.find(nodeid);
    if (it != mapNodeState.end()) {
        // Clean up in-flight blocks for old state
        for (const auto& block : it->second.vBlocksInFlight) {
            mapBlocksInFlight.erase(block.hash);
        }
        mapNodeState.erase(it);
    }

    // Create new state
    auto result = mapNodeState.emplace(nodeid, CNodeState(nodeid));
    return &result.first->second;
}

bool CNodeStateManager::CreateStateWithHandshake(NodeId nodeid, int nStartingHeight, bool fPreferredDownload) {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    // BUG #85 FIX: This is the Bitcoin Core pattern - all state modifications
    // happen atomically while holding the lock. The caller never gets a pointer
    // that could become dangling due to concurrent RemoveState() calls.

    // Remove any existing state for this peer (shouldn't happen, but be safe)
    auto it = mapNodeState.find(nodeid);
    if (it != mapNodeState.end()) {
        // Clean up in-flight blocks for old state
        for (const auto& block : it->second.vBlocksInFlight) {
            mapBlocksInFlight.erase(block.hash);
        }
        mapNodeState.erase(it);
    }

    // Create new state AND initialize handshake fields atomically
    auto result = mapNodeState.emplace(nodeid, CNodeState(nodeid));
    CNodeState& state = result.first->second;

    // Set handshake complete fields while still holding lock
    state.fHandshakeComplete = true;
    state.nStartingHeight = nStartingHeight;
    state.fPreferredDownload = fPreferredDownload;

    return true;
}

CNodeState* CNodeStateManager::GetState(NodeId nodeid) {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    auto it = mapNodeState.find(nodeid);
    if (it == mapNodeState.end()) {
        return nullptr;
    }
    return &it->second;
}

void CNodeStateManager::RemoveState(NodeId nodeid) {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    auto it = mapNodeState.find(nodeid);
    if (it == mapNodeState.end()) {
        return;
    }

    // Remove all in-flight block mappings for this peer
    for (const auto& block : it->second.vBlocksInFlight) {
        mapBlocksInFlight.erase(block.hash);
        std::cout << "[NodeState] Peer " << nodeid << " disconnected - block "
                  << block.hash.GetHex().substr(0, 16) << "... no longer in flight" << std::endl;
    }

    mapNodeState.erase(it);
}

bool CNodeStateManager::MarkBlockAsInFlight(NodeId nodeid, const uint256& hash, const CBlockIndex* pindex) {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    // Check if block is already in flight from any peer
    if (mapBlocksInFlight.find(hash) != mapBlocksInFlight.end()) {
        return false;  // Already downloading
    }

    // Get peer state
    auto it = mapNodeState.find(nodeid);
    if (it == mapNodeState.end()) {
        return false;  // Unknown peer
    }

    CNodeState& state = it->second;

    // Check per-peer limit
    if (state.nBlocksInFlight >= MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        return false;  // Peer at capacity
    }

    // Check total limit
    if (mapBlocksInFlight.size() >= static_cast<size_t>(MAX_BLOCKS_IN_FLIGHT_TOTAL)) {
        return false;  // Global capacity reached
    }

    // Add to peer's in-flight list
    state.vBlocksInFlight.emplace_back(hash, pindex);
    state.nBlocksInFlight++;

    // Get iterator to the new entry
    auto blockIt = std::prev(state.vBlocksInFlight.end());

    // Add to global tracking map
    mapBlocksInFlight[hash] = std::make_pair(nodeid, blockIt);

    // Update download timestamp
    state.m_downloading_since = std::chrono::steady_clock::now();

    return true;
}

NodeId CNodeStateManager::MarkBlockAsReceived(const uint256& hash) {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        return -1;  // Not tracked
    }

    NodeId nodeid = it->second.first;
    auto blockIt = it->second.second;

    // Get peer state
    auto stateIt = mapNodeState.find(nodeid);
    if (stateIt != mapNodeState.end()) {
        CNodeState& state = stateIt->second;

        // Remove from peer's in-flight list
        state.vBlocksInFlight.erase(blockIt);
        state.nBlocksInFlight--;

        // Reset stalling count on successful download
        state.nStallingCount = 0;
    }

    // Remove from global tracking
    mapBlocksInFlight.erase(it);

    return nodeid;
}

bool CNodeStateManager::IsBlockInFlight(const uint256& hash) const {
    std::lock_guard<std::mutex> lock(cs_nodestate);
    return mapBlocksInFlight.find(hash) != mapBlocksInFlight.end();
}

NodeId CNodeStateManager::GetBlockPeer(const uint256& hash) const {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        return -1;
    }
    return it->second.first;
}

std::vector<std::pair<uint256, NodeId>> CNodeStateManager::GetBlocksInFlight() const {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    std::vector<std::pair<uint256, NodeId>> result;
    result.reserve(mapBlocksInFlight.size());

    for (const auto& entry : mapBlocksInFlight) {
        result.emplace_back(entry.first, entry.second.first);
    }

    // P5-LOW FIX: Return without std::move to allow RVO
    return result;
}

int CNodeStateManager::GetBlocksInFlightForPeer(NodeId nodeid) const {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    auto it = mapNodeState.find(nodeid);
    if (it == mapNodeState.end()) {
        return 0;
    }
    return it->second.nBlocksInFlight;
}

std::vector<uint256> CNodeStateManager::GetAndClearPeerBlocks(NodeId nodeid) {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    std::vector<uint256> result;

    auto it = mapNodeState.find(nodeid);
    if (it == mapNodeState.end()) {
        return result;
    }

    CNodeState& state = it->second;
    result.reserve(state.vBlocksInFlight.size());

    // Collect all block hashes
    for (const auto& block : state.vBlocksInFlight) {
        result.push_back(block.hash);
        mapBlocksInFlight.erase(block.hash);
    }

    // Clear peer's list
    state.vBlocksInFlight.clear();
    state.nBlocksInFlight = 0;

    // P5-LOW FIX: Return without std::move to allow RVO
    return result;
}

std::vector<NodeId> CNodeStateManager::CheckForStallingPeers() {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    std::vector<NodeId> stallingPeers;
    auto now = std::chrono::steady_clock::now();

    for (auto& [nodeid, state] : mapNodeState) {
        if (state.vBlocksInFlight.empty()) {
            continue;  // No downloads in progress
        }

        // Check oldest in-flight block
        const auto& oldest = state.vBlocksInFlight.front();
        auto download_time = now - oldest.time;
        auto timeout = state.GetBlockTimeout();

        if (download_time > timeout) {
            // BUG #93 FIX: Only count ONE stall per timeout period
            // Previously we incremented nStallingCount on EVERY tick after timeout,
            // causing peers to hit the 5-stall disconnect threshold within seconds.
            // Now we check if we've already recorded a stall for this timeout period.
            auto time_since_last_stall = now - state.m_stalling_since;

            // Only increment stall count if this is a NEW stall (more than one timeout period has passed)
            // This means: first stall detected, OR the previous timeout period has fully elapsed
            if (state.nStallingCount == 0 || time_since_last_stall >= timeout) {
                state.nStallingCount++;
                state.m_stalling_since = now;

                std::cout << "[NodeState] Peer " << nodeid << " stalling on block "
                          << oldest.hash.GetHex().substr(0, 16) << "... "
                          << "(attempt " << state.nStallingCount
                          << ", timeout was " << timeout.count() << "s)" << std::endl;
            }

            // If stalling too many times, mark for disconnection
            // With adaptive timeouts (10s -> 20s -> 40s -> 80s -> 160s -> 320s),
            // 5 stalls = minimum ~610 seconds (10+ minutes) of stalling behavior
            if (state.nStallingCount >= 5) {
                stallingPeers.push_back(nodeid);
            }
        }
    }

    return stallingPeers;
}

size_t CNodeStateManager::GetHandshakeCompleteCount() const {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    size_t count = 0;
    for (const auto& [nodeid, state] : mapNodeState) {
        if (state.fHandshakeComplete) {
            count++;
        }
    }
    return count;
}

int CNodeStateManager::GetBestPeerHeight() const {
    std::lock_guard<std::mutex> lock(cs_nodestate);

    int best = 0;
    for (const auto& [nodeid, state] : mapNodeState) {
        if (state.fHandshakeComplete && state.nStartingHeight > best) {
            best = state.nStartingHeight;
        }
    }
    return best;
}

void CNodeStateManager::Clear() {
    std::lock_guard<std::mutex> lock(cs_nodestate);
    mapNodeState.clear();
    mapBlocksInFlight.clear();
}
