// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Performance Benchmarking Infrastructure
 * Phase: Performance Optimization
 * 
 * Simple timing utilities for performance measurement
 */

#ifndef DILITHION_UTIL_BENCH_H
#define DILITHION_UTIL_BENCH_H

#include <chrono>
#include <string>
#include <map>
#include <vector>
#include <mutex>

/**
 * Simple benchmark timer
 * Usage:
 *   BENCHMARK_START("operation_name");
 *   // ... code to measure ...
 *   BENCHMARK_END("operation_name");
 */
class CBenchmark {
private:
    std::map<std::string, std::chrono::high_resolution_clock::time_point> m_starts;
    std::map<std::string, std::vector<double>> m_times;  // Times in milliseconds
    std::mutex m_mutex;

public:
    static CBenchmark& GetInstance() {
        static CBenchmark instance;
        return instance;
    }

    void Start(const std::string& name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_starts[name] = std::chrono::high_resolution_clock::now();
    }

    double End(const std::string& name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_starts.find(name);
        if (it == m_starts.end()) {
            return -1.0;  // Start not found
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - it->second);
        double ms = duration.count() / 1000.0;
        
        m_times[name].push_back(ms);
        m_starts.erase(it);
        return ms;
    }

    void GetStats(const std::string& name, double& avg, double& min, double& max, size_t& count) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_times.find(name);
        if (it == m_times.end() || it->second.empty()) {
            avg = min = max = 0.0;
            count = 0;
            return;
        }

        const auto& times = it->second;
        count = times.size();
        min = *std::min_element(times.begin(), times.end());
        max = *std::max_element(times.begin(), times.end());
        double sum = 0.0;
        for (double t : times) {
            sum += t;
        }
        avg = sum / count;
    }

    void Reset(const std::string& name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_times.erase(name);
        m_starts.erase(name);
    }

    void ResetAll() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_times.clear();
        m_starts.clear();
    }
};

// Convenience macros
#define BENCHMARK_START(name) CBenchmark::GetInstance().Start(name)
#define BENCHMARK_END(name) CBenchmark::GetInstance().End(name)

#endif // DILITHION_UTIL_BENCH_H

