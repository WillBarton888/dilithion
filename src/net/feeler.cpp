// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/feeler.h>
#include <net/peers.h>
#include <net/net.h>
#include <util/logging.h>
#include <algorithm>

CFeelerManager::CFeelerManager(CPeerManager& peer_manager, CConnectionManager& connection_manager)
    : m_peer_manager(peer_manager),
      m_connection_manager(connection_manager),
      m_last_feeler_time(std::chrono::steady_clock::now()) {
}

bool CFeelerManager::ProcessFeelerConnections() {
    auto now = std::chrono::steady_clock::now();
    auto time_since_last = std::chrono::duration_cast<std::chrono::minutes>(now - m_last_feeler_time);

    // Check if enough time has passed
    if (time_since_last < FEELER_INTERVAL) {
        return false;  // Too soon for next feeler
    }

    // Check if we already have an active feeler
    {
        std::lock_guard<std::mutex> lock(m_feeler_mutex);
        if (!m_active_feelers.empty()) {
            return false;  // Already have active feeler
        }
    }

    // Select an address from "new" table (addresses we haven't tried)
    auto addresses = m_peer_manager.SelectAddressesToConnect(1);
    if (addresses.empty()) {
        LogPrintNet(DEBUG, "No addresses available for feeler connection");
        return false;
    }

    NetProtocol::CAddress addr = addresses[0];

    // Initiate feeler connection
    int peer_id = m_connection_manager.ConnectToPeer(addr);
    if (peer_id < 0) {
        LogPrintNet(DEBUG, "Failed to initiate feeler connection to %s", addr.ToString().c_str());
        return false;
    }

    // Track this as a feeler connection
    {
        std::lock_guard<std::mutex> lock(m_feeler_mutex);
        m_active_feelers[peer_id] = now;
    }

    m_last_feeler_time = now;
    LogPrintNet(DEBUG, "Initiated feeler connection to %s (peer %d)", addr.ToString().c_str(), peer_id);

    return true;
}

bool CFeelerManager::IsFeelerConnection(int peer_id) const {
    std::lock_guard<std::mutex> lock(m_feeler_mutex);
    return m_active_feelers.count(peer_id) > 0;
}

void CFeelerManager::FeelerConnectionComplete(int peer_id, bool success) {
    std::lock_guard<std::mutex> lock(m_feeler_mutex);
    
    auto it = m_active_feelers.find(peer_id);
    if (it == m_active_feelers.end()) {
        return;  // Not a feeler connection
    }

    // Get peer address before removing
    auto peer = m_peer_manager.GetPeer(peer_id);
    if (peer) {
        if (success) {
            // Mark as good (moves to tried table)
            m_peer_manager.MarkAddressGood(peer->addr);
            LogPrintNet(INFO, "Feeler connection to %s succeeded, marked as good", peer->addr.ToString().c_str());
        } else {
            // Mark as tried (increments attempt counter)
            m_peer_manager.MarkAddressTried(peer->addr);
            LogPrintNet(DEBUG, "Feeler connection to %s failed", peer->addr.ToString().c_str());
        }
    }

    // Remove from active feelers
    m_active_feelers.erase(it);

    // Disconnect feeler immediately (they're short-lived)
    m_connection_manager.DisconnectPeer(peer_id, "Feeler connection complete");
}

