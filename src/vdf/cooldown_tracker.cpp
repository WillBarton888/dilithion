#include "cooldown_tracker.h"
#include <algorithm>

int CCooldownTracker::CalculateCooldown(int activeMiners)
{
    // Formula: cooldown = miners - max(3, miners/10)
    // Allows a small buffer above fair share — generous at low miner
    // counts (~1.43x at 10 miners), tight at scale (~1.11x at 50+).
    int reduction = std::max(3, activeMiners / 10);
    int cooldown = activeMiners - reduction;
    return std::clamp(cooldown, MIN_COOLDOWN, MAX_COOLDOWN);
}

bool CCooldownTracker::IsInCooldown(const Address& addr, int height) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_lastWinHeight.find(addr);
    if (it == m_lastWinHeight.end())
        return false;

    RecalcActiveMiners(height);
    int cooldown = CalculateCooldown(m_cachedActiveMinersMut);
    return (height - it->second) < cooldown;
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

int CCooldownTracker::GetLastWinHeight(const Address& addr) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_lastWinHeight.find(addr);
    return (it != m_lastWinHeight.end()) ? it->second : -1;
}

void CCooldownTracker::OnBlockConnected(int height, const Address& winner)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_lastWinHeight[winner] = height;
    m_heightToWinner[height] = winner;

    // Evict entries outside the active window [height - ACTIVE_WINDOW + 1, height].
    int cutoff = height - ACTIVE_WINDOW + 1;
    auto it = m_heightToWinner.begin();
    while (it != m_heightToWinner.end() && it->first < cutoff) {
        // Only remove from m_lastWinHeight if this was their most recent win.
        auto lwh = m_lastWinHeight.find(it->second);
        if (lwh != m_lastWinHeight.end() && lwh->second == it->first) {
            m_lastWinHeight.erase(lwh);
        }
        it = m_heightToWinner.erase(it);
    }

    // Recalc active miners at this height.
    RecalcActiveMiners(height);
}

void CCooldownTracker::OnBlockDisconnected(int height)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_heightToWinner.find(height);
    if (it == m_heightToWinner.end())
        return;

    Address winner = it->second;
    m_heightToWinner.erase(it);

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
    } else {
        m_lastWinHeight.erase(winner);
    }

    // Invalidate cache so next query recalculates.
    m_cachedAtHeightMut = -1;
}

void CCooldownTracker::Clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lastWinHeight.clear();
    m_heightToWinner.clear();
    m_cachedActiveMinersMut = 0;
    m_cachedAtHeightMut = -1;
}

void CCooldownTracker::RecalcActiveMiners(int height) const
{
    // Caller must hold m_mutex.
    if (m_cachedAtHeightMut == height)
        return;

    int cutoff = height - ACTIVE_WINDOW + 1;
    std::set<Address> unique;
    for (auto it = m_heightToWinner.lower_bound(cutoff);
         it != m_heightToWinner.end() && it->first <= height; ++it) {
        unique.insert(it->second);
    }

    m_cachedActiveMinersMut = static_cast<int>(unique.size());
    m_cachedAtHeightMut = height;
}
