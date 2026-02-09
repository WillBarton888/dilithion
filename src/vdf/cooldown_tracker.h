#ifndef COOLDOWN_TRACKER_H
#define COOLDOWN_TRACKER_H

#include <array>
#include <map>
#include <set>
#include <mutex>
#include <cstdint>

/**
 * CCooldownTracker - VDF lottery rate limiter.
 *
 * After a miner wins a block, they enter a cooldown period during which
 * they cannot win again.  The cooldown length scales with the number of
 * active miners so that rotation is fair regardless of network size.
 *
 * Thread-safe: all public methods acquire m_mutex.
 */
class CCooldownTracker {
public:
    using Address = std::array<uint8_t, 20>;

    // Consensus-level bounds (matching chainparams in Phase 4).
    static constexpr int MIN_COOLDOWN = 10;   // blocks
    static constexpr int MAX_COOLDOWN = 100;  // blocks
    static constexpr int ACTIVE_WINDOW = 360; // blocks (~6 hours at 60s blocks)

    // --- Query interface ---

    /** Is this address currently in cooldown at the given height? */
    bool IsInCooldown(const Address& addr, int height) const;

    /** Current cooldown length (clamped active miner count). */
    int GetCooldownBlocks() const;

    /** Number of unique miners seen in the last ACTIVE_WINDOW blocks. */
    int GetActiveMiners() const;

    /** Height at which this address last won (or -1 if never). */
    int GetLastWinHeight(const Address& addr) const;

    // --- Mutation interface (called from block connect/disconnect) ---

    /** Record that `winner` mined the block at `height`. */
    void OnBlockConnected(int height, const Address& winner);

    /** Undo the block at `height` (reorg support). */
    void OnBlockDisconnected(int height);

    /** Reset all state (e.g. on full chain resync). */
    void Clear();

private:
    mutable std::mutex m_mutex;

    // address → height of most recent win
    std::map<Address, int> m_lastWinHeight;

    // height → winner address (for undo on disconnect)
    std::map<int, Address> m_heightToWinner;

    /** Recount active miners up to `height`.  Caller must hold m_mutex. */
    void RecalcActiveMiners(int height) const;

    // Lazy cache for active miner count (mutable for const query methods).
    mutable int m_cachedActiveMinersMut{0};
    mutable int m_cachedAtHeightMut{-1};
};

#endif // COOLDOWN_TRACKER_H
