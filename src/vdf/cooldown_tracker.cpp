#include "cooldown_tracker.h"
#include <algorithm>

int CCooldownTracker::CalculateCooldown(int activeMiners)
{
    // Formula: cooldown = floor(activeMiners * 0.67)
    // At 22 miners → 14 blocks cooldown (8 miners eligible per round)
    // At 10 miners →  6 blocks cooldown (4 miners eligible per round)
    // At 50 miners → 33 blocks cooldown (17 miners eligible per round)
    // Keeps ~33% of miners eligible at any given height, providing
    // randomness from the VDF distribution while still rate-limiting.
    int cooldown = static_cast<int>(activeMiners * 67 / 100);
    return std::clamp(cooldown, MIN_COOLDOWN, MAX_COOLDOWN);
}

int CCooldownTracker::ComputeEffectiveCooldown(int height) const
{
    // Caller must hold m_mutex.
    RecalcActiveMiners(height);
    int longCooldown = CalculateCooldown(m_cachedActiveMinersMut);

    if (height >= m_stabilizationHeight && m_shortWindow > 0) {
        RecalcShortActiveMiners(height);
        int shortMiners = m_cachedShortActiveMinersMut;
        // Solo-mode floor: ≤2 miners in short window treated as 1 (cooldown=0).
        // With VDF, only one miner wins per height (deterministic), so two miners
        // with cooldown=0 simply alternate — no conflict.
        if (shortMiners <= 2) shortMiners = 1;
        int shortCooldown = CalculateCooldown(shortMiners);
        return std::min(longCooldown, shortCooldown);
    }

    return longCooldown;
}

bool CCooldownTracker::IsInCooldown(const Address& addr, int height, int64_t currentTimestamp) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_lastWinHeight.find(addr);
    if (it == m_lastWinHeight.end())
        return false;

    int cooldown = ComputeEffectiveCooldown(height);
    int blockGap = height - it->second;

    // Block-gap expiry: not in cooldown if enough blocks have passed
    if (blockGap >= cooldown)
        return false;

    // Time-based expiry (post-stabilization, when timestamp provided).
    // Cooldown also expires when enough wall-clock time has passed,
    // handling chain stalls where height doesn't advance.
    // Fail-closed: when currentTimestamp == 0, time-based expiry is not applied.
    if (height >= m_stabilizationHeight && currentTimestamp > 0) {
        auto tsIt = m_lastWinTimestamp.find(addr);
        if (tsIt != m_lastWinTimestamp.end() && tsIt->second > 0) {
            int64_t timeGap = currentTimestamp - tsIt->second;
            int64_t timeCooldown = static_cast<int64_t>(cooldown) * m_targetBlockTime;
            if (timeGap >= timeCooldown)
                return false;  // time-based expiry
        }
    }

    return true;  // still in cooldown
}

int CCooldownTracker::GetCooldownBlocks() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // Use the most recent cached count; caller should have triggered
    // a RecalcActiveMiners via IsInCooldown or OnBlockConnected first.
    return CalculateCooldown(m_cachedActiveMinersMut);
}

int CCooldownTracker::GetActiveMiners() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_cachedActiveMinersMut;
}

int CCooldownTracker::GetShortActiveMiners() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_cachedShortActiveMinersMut;
}

std::vector<CCooldownTracker::Address> CCooldownTracker::GetKnownAddresses() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<Address> result;
    result.reserve(m_lastWinHeight.size());
    for (const auto& [addr, _] : m_lastWinHeight) {
        result.push_back(addr);
    }
    return result;
}

int CCooldownTracker::GetLastWinHeight(const Address& addr) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_lastWinHeight.find(addr);
    return (it != m_lastWinHeight.end()) ? it->second : -1;
}

int CCooldownTracker::GetEffectiveCooldown(int height) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return ComputeEffectiveCooldown(height);
}

void CCooldownTracker::OnBlockConnected(int height, const Address& winner, int64_t blockTimestamp)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_lastWinHeight[winner] = height;
    m_heightToWinner[height] = winner;

    // Store timestamp for time-based expiry
    if (blockTimestamp > 0) {
        m_lastWinTimestamp[winner] = blockTimestamp;
        m_heightToTimestamp[height] = blockTimestamp;
    }

    // Evict entries outside the active window [height - m_activeWindow + 1, height].
    int cutoff = height - m_activeWindow + 1;
    auto it = m_heightToWinner.begin();
    while (it != m_heightToWinner.end() && it->first < cutoff) {
        // Only remove from m_lastWinHeight if this was their most recent win.
        auto lwh = m_lastWinHeight.find(it->second);
        if (lwh != m_lastWinHeight.end() && lwh->second == it->first) {
            m_lastWinHeight.erase(lwh);
            m_lastWinTimestamp.erase(it->second);
        }
        m_heightToTimestamp.erase(it->first);
        it = m_heightToWinner.erase(it);
    }

    // Recalc active miners at this height.
    RecalcActiveMiners(height);
    // Invalidate short cache (will be recomputed on next query)
    m_cachedShortAtHeightMut = -1;
}

void CCooldownTracker::OnBlockDisconnected(int height)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_heightToWinner.find(height);
    if (it == m_heightToWinner.end())
        return;

    Address winner = it->second;
    m_heightToWinner.erase(it);
    m_heightToTimestamp.erase(height);

    // Recompute the address's last win height from remaining entries.
    // Scan backwards from the end of m_heightToWinner.
    int lastWin = -1;
    for (auto rit = m_heightToWinner.rbegin(); rit != m_heightToWinner.rend(); ++rit) {
        if (rit->second == winner) {
            lastWin = rit->first;
            break;
        }
    }

    if (lastWin >= 0) {
        m_lastWinHeight[winner] = lastWin;
        // Recover timestamp from height→timestamp map
        auto tsIt = m_heightToTimestamp.find(lastWin);
        if (tsIt != m_heightToTimestamp.end()) {
            m_lastWinTimestamp[winner] = tsIt->second;
        } else {
            m_lastWinTimestamp.erase(winner);
        }
    } else {
        m_lastWinHeight.erase(winner);
        m_lastWinTimestamp.erase(winner);
    }

    // Invalidate caches so next query recalculates.
    m_cachedAtHeightMut = -1;
    m_cachedShortAtHeightMut = -1;
}

void CCooldownTracker::Clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lastWinHeight.clear();
    m_heightToWinner.clear();
    m_lastWinTimestamp.clear();
    m_heightToTimestamp.clear();
    m_cachedActiveMinersMut = 0;
    m_cachedAtHeightMut = -1;
    m_cachedShortActiveMinersMut = 0;
    m_cachedShortAtHeightMut = -1;
}

void CCooldownTracker::RecalcActiveMiners(int height) const
{
    // Caller must hold m_mutex.
    if (m_cachedAtHeightMut == height)
        return;

    int cutoff = height - m_activeWindow + 1;
    std::set<Address> unique;
    for (auto it = m_heightToWinner.lower_bound(cutoff);
         it != m_heightToWinner.end() && it->first <= height; ++it) {
        unique.insert(it->second);
    }

    m_cachedActiveMinersMut = static_cast<int>(unique.size());
    m_cachedAtHeightMut = height;
}

void CCooldownTracker::RecalcShortActiveMiners(int height) const
{
    // Caller must hold m_mutex.
    if (m_cachedShortAtHeightMut == height)
        return;

    if (m_shortWindow <= 0) {
        m_cachedShortActiveMinersMut = 0;
        m_cachedShortAtHeightMut = height;
        return;
    }

    int cutoff = height - m_shortWindow + 1;
    std::set<Address> unique;
    for (auto it = m_heightToWinner.lower_bound(cutoff);
         it != m_heightToWinner.end() && it->first <= height; ++it) {
        unique.insert(it->second);
    }

    m_cachedShortActiveMinersMut = static_cast<int>(unique.size());
    m_cachedShortAtHeightMut = height;
}
