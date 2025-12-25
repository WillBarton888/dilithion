// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/chain_tips_tracker.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

// ============================================================================
// Public API
// ============================================================================

bool CChainTipsTracker::AddOrUpdateTip(const uint256& hash, int height,
                                        const uint256& chainWork, NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_tips);

    auto it = m_tips.find(hash);
    if (it != m_tips.end()) {
        // Update existing tip
        it->second.height = height;
        it->second.chainWork = chainWork;
        it->second.peer = peer;
        it->second.lastSeen = std::chrono::steady_clock::now();
    } else {
        // Add new tip
        m_tips[hash] = ChainTip(hash, height, chainWork, peer);

        // Log fork detection
        if (m_tips.size() > 1) {
            std::cout << "[ChainTipsTracker] FORK: Now tracking " << m_tips.size()
                      << " competing chains. New tip at height " << height << std::endl;
        }
    }

    // Check if this becomes the new best tip
    bool isNewBest = false;
    if (m_bestTip.IsNull() || ChainWorkGreaterThan(chainWork, m_bestWork)) {
        if (!m_bestTip.IsNull() && hash != m_bestTip) {
            std::cout << "[ChainTipsTracker] CHAIN SWITCH: Best tip changed from height "
                      << m_tips[m_bestTip].height << " to " << height << std::endl;
        }
        m_bestTip = hash;
        m_bestWork = chainWork;
        isNewBest = true;
    }

    return isNewBest;
}

void CChainTipsTracker::RemoveTip(const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_tips);

    auto it = m_tips.find(hash);
    if (it == m_tips.end()) {
        return;  // Not a tip, nothing to do
    }

    m_tips.erase(it);

    // If we removed the best tip, recalculate
    if (hash == m_bestTip) {
        RecalculateBest();
    }
}

uint256 CChainTipsTracker::GetBestTip() const
{
    std::lock_guard<std::mutex> lock(cs_tips);
    return m_bestTip;
}

uint256 CChainTipsTracker::GetBestChainWork() const
{
    std::lock_guard<std::mutex> lock(cs_tips);
    return m_bestWork;
}

std::vector<ChainTip> CChainTipsTracker::GetCompetingTips() const
{
    std::lock_guard<std::mutex> lock(cs_tips);

    std::vector<ChainTip> tips;
    tips.reserve(m_tips.size());

    for (const auto& pair : m_tips) {
        tips.push_back(pair.second);
    }

    // Sort by chain work (descending - best first)
    std::sort(tips.begin(), tips.end());

    return tips;
}

bool CChainTipsTracker::IsTip(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_tips);
    return m_tips.find(hash) != m_tips.end();
}

size_t CChainTipsTracker::TipCount() const
{
    std::lock_guard<std::mutex> lock(cs_tips);
    return m_tips.size();
}

bool CChainTipsTracker::HasCompetingForks() const
{
    std::lock_guard<std::mutex> lock(cs_tips);
    return m_tips.size() > 1;
}

std::vector<uint256> CChainTipsTracker::GetWeakTips(int threshold_percent) const
{
    std::lock_guard<std::mutex> lock(cs_tips);

    std::vector<uint256> weak;

    if (m_tips.empty() || m_bestWork.IsNull()) {
        return weak;
    }

    // For simplicity, we consider tips "weak" if they have less work than
    // the best tip. A more sophisticated version could use percentage thresholds.
    // Note: threshold_percent is ignored in this simplified implementation
    (void)threshold_percent;

    for (const auto& pair : m_tips) {
        // If this tip has less work than best, it's weak
        if (ChainWorkGreaterThan(m_bestWork, pair.second.chainWork)) {
            weak.push_back(pair.first);
        }
    }

    return weak;
}

std::vector<uint256> CChainTipsTracker::GetStaleTips(int max_age_seconds) const
{
    std::lock_guard<std::mutex> lock(cs_tips);

    std::vector<uint256> stale;
    auto now = std::chrono::steady_clock::now();

    for (const auto& pair : m_tips) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - pair.second.lastSeen).count();

        if (age > max_age_seconds) {
            stale.push_back(pair.first);
        }
    }

    return stale;
}

size_t CChainTipsTracker::PruneBelowWork(const uint256& minWork)
{
    std::lock_guard<std::mutex> lock(cs_tips);

    size_t removed = 0;
    auto it = m_tips.begin();

    while (it != m_tips.end()) {
        // Prune if minWork > tip.chainWork (tip has less work than minimum)
        if (ChainWorkGreaterThan(minWork, it->second.chainWork)) {
            std::cout << "[ChainTipsTracker] Pruning weak tip at height "
                      << it->second.height << " (below minimum work)" << std::endl;
            it = m_tips.erase(it);
            removed++;
        } else {
            ++it;
        }
    }

    // Recalculate best if we pruned anything
    if (removed > 0) {
        RecalculateBest();
    }

    return removed;
}

void CChainTipsTracker::Clear()
{
    std::lock_guard<std::mutex> lock(cs_tips);
    m_tips.clear();
    m_bestTip = uint256();
    m_bestWork = uint256();
}

std::string CChainTipsTracker::GetDebugInfo() const
{
    std::lock_guard<std::mutex> lock(cs_tips);

    std::ostringstream ss;
    ss << "Chain Tips (" << m_tips.size() << " total):\n";

    if (m_tips.empty()) {
        ss << "  (none)\n";
        return ss.str();
    }

    // Get sorted tips
    std::vector<ChainTip> tips;
    for (const auto& pair : m_tips) {
        tips.push_back(pair.second);
    }
    std::sort(tips.begin(), tips.end());

    for (size_t i = 0; i < tips.size(); i++) {
        const auto& tip = tips[i];
        ss << "  " << (i + 1) << ". Height " << tip.height
           << " | Hash: " << tip.hash.GetHex().substr(0, 16) << "..."
           << " | Work: " << tip.chainWork.GetHex().substr(0, 16) << "..."
           << " | Peer: " << tip.peer;

        if (tip.hash == m_bestTip) {
            ss << " [BEST]";
        }

        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - tip.lastSeen).count();
        ss << " | Age: " << age << "s\n";
    }

    return ss.str();
}

// ============================================================================
// Private Implementation
// ============================================================================

void CChainTipsTracker::RecalculateBest()
{
    // Already holding cs_tips

    m_bestTip = uint256();
    m_bestWork = uint256();

    for (const auto& pair : m_tips) {
        if (ChainWorkGreaterThan(pair.second.chainWork, m_bestWork)) {
            m_bestTip = pair.first;
            m_bestWork = pair.second.chainWork;
        }
    }
}
