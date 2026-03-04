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
 * Formula: cooldown = activeMiners - max(3, activeMiners/10)
 *   10 miners  →  7 blocks  (max ~14.3% share, fair = 10%)
 *   50 miners  → 45 blocks  (max ~2.2% share,  fair = 2%)
 *  100 miners  → 90 blocks  (max ~1.1% share,  fair = 1%)
 *
 * With MIN_COOLDOWN=0, a solo miner (n=1..3) gets cooldown=0 — they can
 * mine every block unimpeded, keeping the chain alive during the early
 * network phase.  Cooldown kicks in from n=4 onwards.
 *
 * Thread-safe: all public methods acquire m_mutex.
 */
class CCooldownTracker {
public:
    using Address = std::array<uint8_t, 20>;

    // Consensus-level bounds.
    static constexpr int MIN_COOLDOWN = 0;    // blocks (0 = solo miners never stall)
    static constexpr int MAX_COOLDOWN = 100;  // blocks

    // Default active window — kept for backward compatibility.
    // DIL mainnet/testnet: 360 blocks (~24h at 240s/block)
    // DilV: pass 1920 to constructor   (~24h at 45s/block)
    static constexpr int ACTIVE_WINDOW = 360;

    /** Constructor.  activeWindow sets how many recent blocks define "active miners". */
    explicit CCooldownTracker(int activeWindow = ACTIVE_WINDOW)
        : m_activeWindow(activeWindow) {}

    /** Compute cooldown from active miner count. */
    static int CalculateCooldown(int activeMiners);

    /** Active window size this instance was constructed with. */
    int GetActiveWindow() const { return m_activeWindow; }

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

    int m_activeWindow{ACTIVE_WINDOW};  // how many blocks back to count active miners

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
