// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/tx_relay.h>
#include <iostream>

CTxRelayManager::CTxRelayManager() {
    // Constructor - initialize empty
}

CTxRelayManager::~CTxRelayManager() {
    std::lock_guard<std::mutex> lock(cs);
    // Cleanup all tracking structures
    tx_inv_sent.clear();
    tx_in_flight.clear();
    tx_request_time.clear();
    recently_announced.clear();
}

bool CTxRelayManager::ShouldAnnounce(int64_t peer_id, const uint256& txid) {
    std::lock_guard<std::mutex> lock(cs);

    // Check if we've already announced to this peer
    auto it = tx_inv_sent.find(peer_id);
    if (it != tx_inv_sent.end()) {
        if (it->second.count(txid) > 0) {
            return false;  // Already announced to this peer
        }
    }

    // Allow announcements to different peers
    // The recently_announced map is used for cleanup only, not for blocking announcements
    // This allows proper peer distribution while still preventing immediate re-announcements
    // to the same peer (handled by tx_inv_sent check above)

    return true;
}

void CTxRelayManager::MarkAnnounced(int64_t peer_id, const uint256& txid) {
    std::lock_guard<std::mutex> lock(cs);

    // Add to peer's announced set
    tx_inv_sent[peer_id].insert(txid);

    // Mark as recently announced
    recently_announced[txid] = std::chrono::steady_clock::now();
}

bool CTxRelayManager::AlreadyHave(const uint256& txid, CTxMemPool& mempool) {
    std::lock_guard<std::mutex> lock(cs);

    // Check if we already have it in mempool
    if (mempool.Exists(txid)) {
        return true;
    }

    // Check if we've already requested it
    if (tx_in_flight.count(txid) > 0) {
        return true;
    }

    // Check if we recently rejected it (prevents relay loops)
    if (recently_rejected.count(txid) > 0) {
        return true;
    }

    return false;
}

void CTxRelayManager::MarkRequested(const uint256& txid, int64_t peer_id) {
    std::lock_guard<std::mutex> lock(cs);

    // Track in-flight request
    tx_in_flight[txid] = peer_id;
    tx_request_time[txid] = std::chrono::steady_clock::now();
}

void CTxRelayManager::MarkRejected(const uint256& txid) {
    std::lock_guard<std::mutex> lock(cs);
    recently_rejected[txid] = std::chrono::steady_clock::now();
}

void CTxRelayManager::RemoveInFlight(const uint256& txid) {
    std::lock_guard<std::mutex> lock(cs);

    // Remove from in-flight tracking
    tx_in_flight.erase(txid);
    tx_request_time.erase(txid);
}

void CTxRelayManager::CleanupExpired() {
    std::lock_guard<std::mutex> lock(cs);

    auto now = std::chrono::steady_clock::now();

    // Cleanup timed-out in-flight requests
    auto req_it = tx_request_time.begin();
    while (req_it != tx_request_time.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - req_it->second
        ).count();

        if (elapsed >= TX_REQUEST_TIMEOUT) {
            const uint256& txid = req_it->first;

            // Remove from both maps
            tx_in_flight.erase(txid);
            req_it = tx_request_time.erase(req_it);

            std::cout << "[TX-RELAY] Cleaned up timed-out request for tx "
                      << txid.GetHex().substr(0, 16) << "..." << std::endl;
        } else {
            ++req_it;
        }
    }

    // Cleanup expired recently_announced entries
    auto recent_it = recently_announced.begin();
    while (recent_it != recently_announced.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - recent_it->second
        ).count();

        if (elapsed >= TX_ANNOUNCE_TTL) {
            recent_it = recently_announced.erase(recent_it);
        } else {
            ++recent_it;
        }
    }

    // Cleanup expired recently_rejected entries (allow retry after TX_REJECT_TTL)
    auto reject_it = recently_rejected.begin();
    while (reject_it != recently_rejected.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - reject_it->second
        ).count();

        if (elapsed >= TX_REJECT_TTL) {
            reject_it = recently_rejected.erase(reject_it);
        } else {
            ++reject_it;
        }
    }

    // Limit memory usage - if tx_inv_sent grows too large, clear oldest entries
    // Keep track of at most 100 peers worth of announcements
    if (tx_inv_sent.size() > 100) {
        std::cout << "[TX-RELAY] Warning: tx_inv_sent has " << tx_inv_sent.size()
                  << " entries, cleaning up" << std::endl;

        // Simple cleanup: remove entries for peers with many announcements
        size_t removed = 0;
        auto inv_it = tx_inv_sent.begin();
        while (inv_it != tx_inv_sent.end() && tx_inv_sent.size() > 50) {
            if (inv_it->second.size() > 100) {
                inv_it = tx_inv_sent.erase(inv_it);
                removed++;
            } else {
                ++inv_it;
            }
        }

        if (removed > 0) {
            std::cout << "[TX-RELAY] Cleaned up " << removed
                      << " peer announcement entries" << std::endl;
        }
    }
}

void CTxRelayManager::PeerDisconnected(int64_t peer_id) {
    std::lock_guard<std::mutex> lock(cs);

    // Remove all announcements for this peer
    auto it = tx_inv_sent.find(peer_id);
    if (it != tx_inv_sent.end()) {
        size_t count = it->second.size();
        tx_inv_sent.erase(it);

        if (count > 0) {
            std::cout << "[TX-RELAY] Peer " << peer_id << " disconnected, "
                      << "removed " << count << " announcement entries" << std::endl;
        }
    }

    // Remove any in-flight requests from this peer
    auto req_it = tx_in_flight.begin();
    while (req_it != tx_in_flight.end()) {
        if (req_it->second == peer_id) {
            const uint256& txid = req_it->first;
            tx_request_time.erase(txid);
            req_it = tx_in_flight.erase(req_it);
        } else {
            ++req_it;
        }
    }
}

void CTxRelayManager::GetStats(size_t& announced_count,
                                 size_t& in_flight_count,
                                 size_t& recent_count) const {
    std::lock_guard<std::mutex> lock(cs);

    // Count total announcements across all peers
    announced_count = 0;
    for (const auto& pair : tx_inv_sent) {
        announced_count += pair.second.size();
    }

    in_flight_count = tx_in_flight.size();
    recent_count = recently_announced.size();
}
