#ifndef PEER_MIK_TRACKER_H
#define PEER_MIK_TRACKER_H

/**
 * Sybil Defense Phase 1: Block Relay Source Tracking
 *
 * Tracks which peer first relayed blocks from each MIK identity.
 * A single peer relaying blocks from many distinct MIKs is a strong
 * Sybil indicator (one entity mining with multiple identities).
 *
 * Tiered response (multi-signal corroboration, not single-signal ban):
 *   >5 unique MIKs from one peer  = INFO log
 *   >15 unique MIKs from one peer = WARN log + flag
 *   Auto-ban only when combined with other signals (DNA, correlation)
 */

#include <map>
#include <set>
#include <string>
#include <mutex>
#include <cstdint>
#include <chrono>

class CPeerMIKTracker {
public:
    static constexpr int INFO_THRESHOLD = 5;     // Log at INFO level
    static constexpr int WARN_THRESHOLD = 15;    // Log at WARN level + flag
    static constexpr int WINDOW_SECONDS = 86400; // 24-hour rolling window

    /**
     * Record that a peer relayed an accepted block from a specific MIK.
     * @param peerId   The peer that relayed the block
     * @param mikHex   The MIK identity hex string (40 chars)
     * @param peerAddr The peer's IP:port string (for logging)
     */
    void RecordMIKRelay(int peerId, const std::string& mikHex, const std::string& peerAddr = "");

    /**
     * Get the number of unique MIKs relayed by a peer in the current window.
     */
    int GetUniqueMIKCount(int peerId) const;

    /**
     * Get all peer relay data for RPC reporting.
     * Returns: map of peerId -> {unique_mik_count, peer_addr, mik_list}
     */
    struct PeerRelayInfo {
        int uniqueMIKs;
        std::string peerAddr;
        std::set<std::string> miks;
    };
    std::map<int, PeerRelayInfo> GetAllRelayData() const;

    /**
     * Clean up stale entries (peers that disconnected, old windows).
     */
    void Cleanup();

private:
    mutable std::mutex m_mutex;

    struct PeerWindow {
        std::chrono::steady_clock::time_point windowStart;
        std::set<std::string> miks;  // unique MIK hex strings
        std::string peerAddr;
        bool warnLogged{false};      // avoid log spam
    };

    std::map<int, PeerWindow> m_peerWindows;
};

#endif // PEER_MIK_TRACKER_H
