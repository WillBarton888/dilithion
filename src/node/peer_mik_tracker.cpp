#include <node/peer_mik_tracker.h>
#include <iostream>

void CPeerMIKTracker::RecordMIKRelay(int peerId, const std::string& mikHex, const std::string& peerAddr) {
    if (peerId < 0 || mikHex.empty()) return;

    std::lock_guard<std::mutex> lock(m_mutex);

    auto now = std::chrono::steady_clock::now();
    auto& pw = m_peerWindows[peerId];

    // Reset window if expired
    if (pw.windowStart == std::chrono::steady_clock::time_point{} ||
        std::chrono::duration_cast<std::chrono::seconds>(now - pw.windowStart).count() >= WINDOW_SECONDS) {
        pw.windowStart = now;
        pw.miks.clear();
        pw.warnLogged = false;
    }

    if (!peerAddr.empty()) {
        pw.peerAddr = peerAddr;
    }

    pw.miks.insert(mikHex);
    int count = static_cast<int>(pw.miks.size());

    // Tiered logging (not hard ban -- multi-signal corroboration required)
    if (count == INFO_THRESHOLD + 1) {
        std::cout << "[SybilRelay] INFO: peer " << peerId
                  << " (" << pw.peerAddr << ") has relayed blocks from "
                  << count << " distinct MIKs in 24h window" << std::endl;
    } else if (count >= WARN_THRESHOLD && !pw.warnLogged) {
        pw.warnLogged = true;
        std::cout << "[SybilRelay] WARN: peer " << peerId
                  << " (" << pw.peerAddr << ") has relayed blocks from "
                  << count << " distinct MIKs in 24h window -- potential Sybil relay"
                  << std::endl;
    }
}

int CPeerMIKTracker::GetUniqueMIKCount(int peerId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_peerWindows.find(peerId);
    if (it == m_peerWindows.end()) return 0;

    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.windowStart).count() >= WINDOW_SECONDS) {
        return 0;  // Window expired
    }
    return static_cast<int>(it->second.miks.size());
}

std::map<int, CPeerMIKTracker::PeerRelayInfo> CPeerMIKTracker::GetAllRelayData() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::map<int, PeerRelayInfo> result;

    auto now = std::chrono::steady_clock::now();
    for (const auto& [peerId, pw] : m_peerWindows) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - pw.windowStart).count() >= WINDOW_SECONDS) {
            continue;  // Skip expired windows
        }
        if (pw.miks.empty()) continue;

        PeerRelayInfo info;
        info.uniqueMIKs = static_cast<int>(pw.miks.size());
        info.peerAddr = pw.peerAddr;
        info.miks = pw.miks;
        result[peerId] = info;
    }
    return result;
}

void CPeerMIKTracker::Cleanup() {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto now = std::chrono::steady_clock::now();
    for (auto it = m_peerWindows.begin(); it != m_peerWindows.end(); ) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.windowStart).count() >= WINDOW_SECONDS * 2) {
            it = m_peerWindows.erase(it);
        } else {
            ++it;
        }
    }
}
