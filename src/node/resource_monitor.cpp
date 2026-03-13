// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/resource_monitor.h>

#include <iostream>
#include <cstring>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <unistd.h>
#include <fstream>
#include <sstream>
#endif

// Global instance
CResourceMonitor* g_resource_monitor = nullptr;

// ============================================================================
// Constructor/Destructor
// ============================================================================

CResourceMonitor::CResourceMonitor() = default;

CResourceMonitor::~CResourceMonitor() {
    Stop();
}

// ============================================================================
// Thread Control
// ============================================================================

bool CResourceMonitor::Start() {
    if (m_running.load()) {
        return false;  // Already running
    }

    m_shutdown.store(false);
    m_running.store(true);
    m_thread = std::thread(&CResourceMonitor::MonitorThread, this);

    std::cout << "[ResourceMonitor] Started with "
              << (m_memory_limit / (1024 * 1024)) << "MB limit, "
              << "checking every " << CHECK_INTERVAL_MS << "ms" << std::endl;

    return true;
}

void CResourceMonitor::Stop() {
    if (!m_running.load()) {
        return;  // Already stopped
    }

    m_shutdown.store(true);
    m_running.store(false);

    if (m_thread.joinable()) {
        m_thread.join();
    }

    std::cout << "[ResourceMonitor] Stopped (triggered " << m_cleanup_count.load()
              << " cleanup(s) during session)" << std::endl;
}

void CResourceMonitor::SetCleanupCallback(CleanupCallback callback) {
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    m_cleanup_callback = std::move(callback);
}

// ============================================================================
// Memory Monitoring
// ============================================================================

size_t CResourceMonitor::GetProcessRSS() const {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    return 0;
#else
    // Linux: Read from /proc/self/statm
    std::ifstream statm("/proc/self/statm");
    if (statm.is_open()) {
        size_t size, resident, shared, text, lib, data, dt;
        statm >> size >> resident >> shared >> text >> lib >> data >> dt;
        // resident is in pages, convert to bytes
        long page_size = sysconf(_SC_PAGESIZE);
        return resident * page_size;
    }
    return 0;
#endif
}

size_t CResourceMonitor::GetCurrentMemoryUsage() const {
    return m_last_rss.load();
}

size_t CResourceMonitor::GetTotalSystemRAM() {
#ifdef _WIN32
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);
    if (GlobalMemoryStatusEx(&memInfo)) {
        return static_cast<size_t>(memInfo.ullTotalPhys);
    }
    return 0;
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages > 0 && page_size > 0) {
        return static_cast<size_t>(pages) * static_cast<size_t>(page_size);
    }
    return 0;
#endif
}

size_t CResourceMonitor::AutoDetectMemoryLimit(double fraction) {
    size_t total_ram = GetTotalSystemRAM();
    if (total_ram == 0) {
        // Fallback: 4GB default if detection fails
        m_memory_limit = 4ULL * 1024 * 1024 * 1024;
    } else {
        m_memory_limit = static_cast<size_t>(total_ram * fraction);
    }
    return m_memory_limit;
}

void CResourceMonitor::CheckMemoryPressure() {
    size_t rss = GetProcessRSS();
    m_last_rss.store(rss);

    if (m_memory_limit == 0) {
        m_current_level.store(0);
        return;
    }

    double usage_ratio = static_cast<double>(rss) / m_memory_limit;
    int new_level = 0;

    if (usage_ratio >= CRITICAL_THRESHOLD) {
        new_level = 2;  // Critical
    } else if (usage_ratio >= WARNING_THRESHOLD) {
        new_level = 1;  // Warning
    }

    int old_level = m_current_level.exchange(new_level);

    // Trigger cleanup if level increased or we're at critical
    if (new_level > 0 && (new_level > old_level || new_level == 2)) {

        // Cooldown: if previous cleanup didn't free meaningful memory (< 5%),
        // suppress repeated logs for COOLDOWN_SECONDS to avoid log spam.
        // The cleanup callback still runs — we just don't log it.
        auto now = std::chrono::steady_clock::now();
        bool should_log = true;

        if (new_level == 2 && m_rss_before_last_cleanup > 0) {
            // Check if last cleanup was futile (RSS didn't drop by at least 5%)
            double reduction = 1.0 - (static_cast<double>(rss) / m_rss_before_last_cleanup);
            if (reduction < 0.05) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - m_last_critical_log).count();
                if (elapsed < COOLDOWN_SECONDS) {
                    should_log = false;
                }
            }
        }

        m_cleanup_count.fetch_add(1);
        m_rss_before_last_cleanup = rss;

        if (should_log) {
            if (new_level == 2) {
                std::cerr << "[ResourceMonitor] CRITICAL: Memory usage at "
                          << (rss / (1024 * 1024)) << "MB ("
                          << static_cast<int>(usage_ratio * 100) << "% of "
                          << (m_memory_limit / (1024 * 1024)) << "MB limit)"
                          << " - triggering aggressive cleanup" << std::endl;
                m_last_critical_log = now;
            } else {
                std::cout << "[ResourceMonitor] WARNING: Memory usage at "
                          << (rss / (1024 * 1024)) << "MB ("
                          << static_cast<int>(usage_ratio * 100) << "% of "
                          << (m_memory_limit / (1024 * 1024)) << "MB limit)"
                          << " - triggering light cleanup" << std::endl;
            }
        }

        // Always run cleanup callback (even if log is suppressed)
        CleanupCallback callback;
        {
            std::lock_guard<std::mutex> lock(m_callback_mutex);
            callback = m_cleanup_callback;
        }

        if (callback) {
            try {
                callback(new_level);
            } catch (const std::exception& e) {
                std::cerr << "[ResourceMonitor] Cleanup callback exception: "
                          << e.what() << std::endl;
            }
        }
    }
}

void CResourceMonitor::MonitorThread() {
    while (!m_shutdown.load()) {
        // Sleep for check interval
        std::this_thread::sleep_for(std::chrono::milliseconds(CHECK_INTERVAL_MS));

        if (m_shutdown.load()) {
            break;
        }

        CheckMemoryPressure();
    }
}
