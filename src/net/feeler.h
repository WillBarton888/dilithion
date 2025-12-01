// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_FEELER_H
#define DILITHION_NET_FEELER_H

#include <net/protocol.h>
#include <chrono>
#include <map>
#include <mutex>

class CPeerManager;
class CConnectionManager;

/**
 * Feeler Connection Manager
 *
 * Bitcoin Core-style feeler connections for eclipse attack protection.
 * Feeler connections are short-lived test connections to addresses we haven't
 * connected to recently. They help discover new peers and prevent eclipse attacks.
 *
 * Key features:
 * - Periodic feeler connections (every 2 minutes)
 * - Short timeout (30 seconds)
 * - Only to addresses in "new" table (not tried)
 * - Disconnect immediately after handshake
 * - Mark address as "tried" if successful
 */
class CFeelerManager {
public:
    CFeelerManager(CPeerManager& peer_manager, CConnectionManager& connection_manager);
    ~CFeelerManager() = default;

    /**
     * @brief Process feeler connections
     *
     * Should be called periodically (every 2 minutes) from main loop.
     * Initiates a feeler connection if enough time has passed since last one.
     *
     * @return true if a feeler connection was initiated
     */
    bool ProcessFeelerConnections();

    /**
     * @brief Check if a peer is a feeler connection
     *
     * @param peer_id Peer ID to check
     * @return true if this is a feeler connection
     */
    bool IsFeelerConnection(int peer_id) const;

    /**
     * @brief Mark feeler connection as complete
     *
     * Called when handshake completes or connection fails.
     *
     * @param peer_id Peer ID of feeler connection
     * @param success true if handshake succeeded
     */
    void FeelerConnectionComplete(int peer_id, bool success);

private:
    CPeerManager& m_peer_manager;
    CConnectionManager& m_connection_manager;

    // Track active feeler connections
    std::map<int, std::chrono::steady_clock::time_point> m_active_feelers;
    mutable std::mutex m_feeler_mutex;

    // Last feeler connection time
    std::chrono::steady_clock::time_point m_last_feeler_time;

    // Feeler connection timeout (30 seconds)
    static constexpr std::chrono::seconds FEELER_TIMEOUT{30};

    // Minimum time between feeler connections (2 minutes)
    static constexpr std::chrono::minutes FEELER_INTERVAL{2};
};

#endif // DILITHION_NET_FEELER_H

