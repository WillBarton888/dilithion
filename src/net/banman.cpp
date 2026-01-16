// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
// Bitcoin Core-style ban manager with persistence

#include <net/banman.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// CBanEntry implementation
std::string CBanEntry::ToString() const {
    std::ostringstream ss;
    ss << "BanEntry{created=" << nCreateTime
       << ", until=" << (nBanUntil == 0 ? "permanent" : std::to_string(nBanUntil))
       << ", reason=" << static_cast<int>(banReason)
       << ", type=" << MisbehaviorTypeToString(misbehaviorType)
       << ", score=" << nMisbehaviorScore;
    if (!strComment.empty()) {
        ss << ", comment=\"" << strComment << "\"";
    }
    ss << "}";
    return ss.str();
}

// CBanManager implementation
CBanManager::CBanManager(const std::string& datadir)
    : m_is_dirty(false) {
    if (!datadir.empty()) {
        m_ban_file_path = datadir + "/banlist.dat";
        LoadBanList();
    }
}

CBanManager::~CBanManager() {
    if (m_is_dirty && !m_ban_file_path.empty()) {
        SaveBanList();
    }
}

void CBanManager::Ban(const std::string& ip, const CBanEntry& entry) {
    std::lock_guard<std::mutex> lock(cs_banned);

    // Check if we're at the limit
    if (m_banned.size() >= MAX_BANNED_IPS && m_banned.find(ip) == m_banned.end()) {
        // Find oldest temporary ban to evict (LRU)
        int64_t oldest_time = std::numeric_limits<int64_t>::max();
        std::string oldest_ip;

        for (const auto& [banned_ip, ban_entry] : m_banned) {
            // Prefer evicting temporary bans over permanent ones
            if (!ban_entry.IsPermanent() && ban_entry.nCreateTime < oldest_time) {
                oldest_time = ban_entry.nCreateTime;
                oldest_ip = banned_ip;
            }
        }

        // If no temporary bans found, evict oldest permanent ban
        if (oldest_ip.empty()) {
            for (const auto& [banned_ip, ban_entry] : m_banned) {
                if (ban_entry.nCreateTime < oldest_time) {
                    oldest_time = ban_entry.nCreateTime;
                    oldest_ip = banned_ip;
                }
            }
        }

        if (!oldest_ip.empty()) {
            m_banned.erase(oldest_ip);
        }
    }

    m_banned[ip] = entry;
    m_is_dirty = true;

    std::cout << "[BanManager] Banned IP: " << ip
              << " (reason: " << MisbehaviorTypeToString(entry.misbehaviorType)
              << ", score: " << entry.nMisbehaviorScore << ")" << std::endl;
}

void CBanManager::Ban(const std::string& ip, int64_t duration_seconds,
                      BanReason reason, MisbehaviorType type, int score) {
    CBanEntry entry;
    entry.nCreateTime = time(nullptr);
    entry.nBanUntil = (duration_seconds == 0) ? 0 : entry.nCreateTime + duration_seconds;
    entry.banReason = reason;
    entry.misbehaviorType = type;
    entry.nMisbehaviorScore = score;

    Ban(ip, entry);
}

void CBanManager::Unban(const std::string& ip) {
    std::lock_guard<std::mutex> lock(cs_banned);
    auto it = m_banned.find(ip);
    if (it != m_banned.end()) {
        m_banned.erase(it);
        m_is_dirty = true;
        std::cout << "[BanManager] Unbanned IP: " << ip << std::endl;
    }
}

bool CBanManager::IsBanned(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(cs_banned);
    auto it = m_banned.find(ip);
    if (it == m_banned.end()) {
        return false;
    }
    return !it->second.IsExpired();
}

bool CBanManager::IsBanned(const std::string& ip, CBanEntry& entryOut) const {
    std::lock_guard<std::mutex> lock(cs_banned);
    auto it = m_banned.find(ip);
    if (it == m_banned.end()) {
        return false;
    }
    if (it->second.IsExpired()) {
        return false;
    }
    entryOut = it->second;
    return true;
}

void CBanManager::ClearBanned() {
    std::lock_guard<std::mutex> lock(cs_banned);
    if (!m_banned.empty()) {
        m_banned.clear();
        m_is_dirty = true;
        std::cout << "[BanManager] Cleared all bans" << std::endl;
    }
}

std::vector<std::pair<std::string, CBanEntry>> CBanManager::GetBanned() const {
    std::lock_guard<std::mutex> lock(cs_banned);
    std::vector<std::pair<std::string, CBanEntry>> result;
    result.reserve(m_banned.size());
    for (const auto& [ip, entry] : m_banned) {
        if (!entry.IsExpired()) {
            result.emplace_back(ip, entry);
        }
    }
    // MAINNET FIX: Return without std::move to allow RVO
    return result;
}

size_t CBanManager::GetBannedCount() const {
    std::lock_guard<std::mutex> lock(cs_banned);
    size_t count = 0;
    for (const auto& [ip, entry] : m_banned) {
        if (!entry.IsExpired()) {
            count++;
        }
    }
    return count;
}

size_t CBanManager::SweepExpiredBans() {
    std::lock_guard<std::mutex> lock(cs_banned);
    size_t removed = 0;

    for (auto it = m_banned.begin(); it != m_banned.end(); ) {
        if (it->second.IsExpired()) {
            it = m_banned.erase(it);
            removed++;
            m_is_dirty = true;
        } else {
            ++it;
        }
    }

    if (removed > 0) {
        std::cout << "[BanManager] Swept " << removed << " expired bans" << std::endl;
    }
    return removed;
}

CBanManager::Stats CBanManager::GetStats() const {
    std::lock_guard<std::mutex> lock(cs_banned);
    Stats stats{0, 0, 0, 0};

    for (const auto& [ip, entry] : m_banned) {
        if (entry.IsExpired()) {
            stats.expired_bans++;
        } else if (entry.IsPermanent()) {
            stats.permanent_bans++;
            stats.total_banned++;
        } else {
            stats.temporary_bans++;
            stats.total_banned++;
        }
    }

    return stats;
}

bool CBanManager::SaveBanList() {
    if (m_ban_file_path.empty()) {
        return false;
    }

    std::string temp_path = m_ban_file_path + ".new";

    try {
        std::ofstream file(temp_path, std::ios::binary);
        if (!file) {
            std::cerr << "[BanManager] Failed to open " << temp_path << " for writing" << std::endl;
            return false;
        }

        std::lock_guard<std::mutex> lock(cs_banned);

        // Write magic number
        uint32_t magic = BANLIST_MAGIC;
        file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));

        // Write version
        uint8_t version = BANLIST_VERSION;
        file.write(reinterpret_cast<const char*>(&version), sizeof(version));

        // Count non-expired entries
        size_t count = 0;
        for (const auto& [ip, entry] : m_banned) {
            if (!entry.IsExpired()) count++;
        }

        // Write entry count
        uint32_t entry_count = static_cast<uint32_t>(count);
        file.write(reinterpret_cast<const char*>(&entry_count), sizeof(entry_count));

        // Write entries
        for (const auto& [ip, entry] : m_banned) {
            if (entry.IsExpired()) continue;

            // Write IP length and string
            uint16_t ip_len = static_cast<uint16_t>(ip.size());
            file.write(reinterpret_cast<const char*>(&ip_len), sizeof(ip_len));
            file.write(ip.data(), ip_len);

            // Write ban entry fields
            file.write(reinterpret_cast<const char*>(&entry.nCreateTime), sizeof(entry.nCreateTime));
            file.write(reinterpret_cast<const char*>(&entry.nBanUntil), sizeof(entry.nBanUntil));

            uint8_t reason = static_cast<uint8_t>(entry.banReason);
            file.write(reinterpret_cast<const char*>(&reason), sizeof(reason));

            uint16_t type = static_cast<uint16_t>(entry.misbehaviorType);
            file.write(reinterpret_cast<const char*>(&type), sizeof(type));

            file.write(reinterpret_cast<const char*>(&entry.nMisbehaviorScore), sizeof(entry.nMisbehaviorScore));

            // Write comment length and string
            uint16_t comment_len = static_cast<uint16_t>(entry.strComment.size());
            file.write(reinterpret_cast<const char*>(&comment_len), sizeof(comment_len));
            if (comment_len > 0) {
                file.write(entry.strComment.data(), comment_len);
            }
        }

        file.close();

        // Atomic rename (remove old file first on Windows)
        // CID 1675200 FIX: Check return value of std::remove to ensure old file is removed
        // std::remove returns 0 on success, non-zero on error
        // On Windows, we need to remove the old file before rename (rename doesn't replace existing files)
        // If file doesn't exist, remove will fail but that's okay - we just want to ensure it's gone
#ifdef _WIN32
        if (std::remove(m_ban_file_path.c_str()) != 0) {
            // File might not exist (first save) - that's okay, but check for actual errors
            DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                // Actual error (not just "file doesn't exist") - log warning but continue
                // This is non-fatal - rename might still work
                std::cerr << "[BanManager] Warning: Failed to remove old ban file: " << m_ban_file_path
                          << " (error: " << error << ")" << std::endl;
            }
        }
#endif
        if (std::rename(temp_path.c_str(), m_ban_file_path.c_str()) != 0) {
            std::cerr << "[BanManager] Failed to rename " << temp_path << " to " << m_ban_file_path << std::endl;
            // CID 1675200 FIX: Best-effort cleanup - remove temp file (errors are non-critical here)
            (void)std::remove(temp_path.c_str());
            return false;
        }

        m_is_dirty = false;
        std::cout << "[BanManager] Saved " << entry_count << " bans to " << m_ban_file_path << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "[BanManager] Exception saving ban list: " << e.what() << std::endl;
        std::remove(temp_path.c_str());
        return false;
    }
}

bool CBanManager::LoadBanList() {
    if (m_ban_file_path.empty()) {
        return false;
    }

    std::ifstream file(m_ban_file_path, std::ios::binary);
    if (!file) {
        // File doesn't exist yet - that's okay for a new node
        return true;
    }

    try {
        // Read and verify magic
        uint32_t magic = 0;
        file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        if (magic != BANLIST_MAGIC) {
            std::cerr << "[BanManager] Invalid magic number in " << m_ban_file_path << std::endl;
            return false;
        }

        // Read and verify version
        uint8_t version = 0;
        file.read(reinterpret_cast<char*>(&version), sizeof(version));
        if (version != BANLIST_VERSION) {
            std::cerr << "[BanManager] Unsupported version " << (int)version << " in " << m_ban_file_path << std::endl;
            return false;
        }

        // Read entry count
        uint32_t entry_count = 0;
        file.read(reinterpret_cast<char*>(&entry_count), sizeof(entry_count));

        if (entry_count > MAX_BANNED_IPS) {
            std::cerr << "[BanManager] Too many entries (" << entry_count << ") in " << m_ban_file_path << std::endl;
            entry_count = MAX_BANNED_IPS;
        }

        std::lock_guard<std::mutex> lock(cs_banned);
        m_banned.clear();

        size_t loaded = 0;
        for (uint32_t i = 0; i < entry_count && file; i++) {
            // Read IP
            uint16_t ip_len = 0;
            file.read(reinterpret_cast<char*>(&ip_len), sizeof(ip_len));
            if (ip_len > 256) {
                std::cerr << "[BanManager] Invalid IP length at entry " << i << std::endl;
                break;
            }

            std::string ip(ip_len, '\0');
            file.read(&ip[0], ip_len);

            // Read ban entry
            CBanEntry entry;
            file.read(reinterpret_cast<char*>(&entry.nCreateTime), sizeof(entry.nCreateTime));
            file.read(reinterpret_cast<char*>(&entry.nBanUntil), sizeof(entry.nBanUntil));

            uint8_t reason = 0;
            file.read(reinterpret_cast<char*>(&reason), sizeof(reason));
            entry.banReason = static_cast<BanReason>(reason);

            uint16_t type = 0;
            file.read(reinterpret_cast<char*>(&type), sizeof(type));
            entry.misbehaviorType = static_cast<MisbehaviorType>(type);

            file.read(reinterpret_cast<char*>(&entry.nMisbehaviorScore), sizeof(entry.nMisbehaviorScore));

            // Read comment
            uint16_t comment_len = 0;
            file.read(reinterpret_cast<char*>(&comment_len), sizeof(comment_len));
            if (comment_len > 0 && comment_len < 1024) {
                entry.strComment.resize(comment_len);
                file.read(&entry.strComment[0], comment_len);
            }

            // Only add non-expired entries
            if (!entry.IsExpired()) {
                m_banned[ip] = entry;
                loaded++;
            }
        }

        std::cout << "[BanManager] Loaded " << loaded << " bans from " << m_ban_file_path << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "[BanManager] Exception loading ban list: " << e.what() << std::endl;
        return false;
    }
}

bool CBanManager::RecordGenesisFailure(const std::string& ip, const std::string& their_genesis) {
    std::lock_guard<std::mutex> lock(cs_genesis_failures);

    int64_t now = time(nullptr);
    auto& entry = m_genesis_failures[ip];

    // Reset window if expired
    if (entry.first_failure == 0 || (now - entry.first_failure > GENESIS_FAILURE_WINDOW)) {
        entry.first_failure = now;
        entry.failure_count = 0;
    }

    entry.failure_count++;
    entry.total_failures++;
    entry.last_genesis = their_genesis;

    // Alert on repeated probing (only once at threshold)
    if (entry.total_failures == GENESIS_ALERT_THRESHOLD) {
        std::cerr << "\n[SECURITY-ALERT] ================================================" << std::endl;
        std::cerr << "[SECURITY-ALERT] REPEATED GENESIS PROBING DETECTED" << std::endl;
        std::cerr << "[SECURITY-ALERT] IP: " << ip << std::endl;
        std::cerr << "[SECURITY-ALERT] Total failures: " << entry.total_failures << std::endl;
        std::cerr << "[SECURITY-ALERT] Their genesis: " << their_genesis << std::endl;
        std::cerr << "[SECURITY-ALERT] Possible network reconnaissance or outdated node" << std::endl;
        std::cerr << "[SECURITY-ALERT] ================================================\n" << std::endl;
    }

    // Check if should ban (exceeded threshold in current window)
    if (entry.failure_count >= GENESIS_FAILURE_BAN_THRESHOLD) {
        return true;  // Signal to ban this IP
    }

    return false;
}

void CBanManager::CleanupGenesisFailures() {
    std::lock_guard<std::mutex> lock(cs_genesis_failures);

    int64_t now = time(nullptr);
    int64_t cleanup_threshold = GENESIS_FAILURE_WINDOW * 2;  // Remove entries older than 2x window

    size_t removed = 0;
    for (auto it = m_genesis_failures.begin(); it != m_genesis_failures.end(); ) {
        if (now - it->second.first_failure > cleanup_threshold) {
            it = m_genesis_failures.erase(it);
            removed++;
        } else {
            ++it;
        }
    }

    if (removed > 0) {
        std::cout << "[BanManager] Cleaned up " << removed << " old genesis failure entries" << std::endl;
    }
}

size_t CBanManager::GetGenesisFailureCount() const {
    std::lock_guard<std::mutex> lock(cs_genesis_failures);
    return m_genesis_failures.size();
}
