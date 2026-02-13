#ifndef DILITHION_BEHAVIORAL_PROFILE_H
#define DILITHION_BEHAVIORAL_PROFILE_H

/**
 * Behavioral Consistency Layer
 *
 * Tracks protocol participation patterns that emerge from honest node operation.
 * Each identity develops a consistent behavioral profile over time:
 * - Activity distribution across hours (timezone proxy)
 * - Block relay speed (position signal)
 * - Peer session stability (churn rate)
 * - Transaction relay patterns
 *
 * Batch-created Sybils show suspiciously uniform or artificially varied patterns.
 *
 * Minimum observation period: 7 days before profile is considered reliable.
 */

#include <array>
#include <vector>
#include <cstdint>
#include <string>
#include <mutex>

namespace digital_dna {

struct BehavioralProfile {
    // Activity distribution (24 hourly buckets, normalized to sum to 1.0)
    std::array<double, 24> hourly_activity{};

    // Relay performance
    double mean_relay_delay_ms = 0.0;
    double relay_consistency = 0.0;    // Stddev of relay delay (lower = more consistent)

    // Peer behavior
    double avg_peer_session_duration_sec = 0.0;
    double peer_diversity_score = 0.0; // Unique ASN ratio (0.0-1.0)

    // Transaction patterns (timing only, no personal data)
    double tx_relay_rate = 0.0;        // Transactions relayed per hour
    double tx_timing_entropy = 0.0;    // Shannon entropy of tx timing (higher = more random)

    // Observation metadata
    uint32_t observation_blocks = 0;
    uint64_t start_time = 0;
    uint64_t end_time = 0;

    // Minimum blocks before profile is considered reliable
    static constexpr uint32_t MIN_OBSERVATION_BLOCKS = 1008;  // ~7 days at 10min/block

    bool is_mature() const { return observation_blocks >= MIN_OBSERVATION_BLOCKS; }

    // Comparison
    static double similarity(const BehavioralProfile& a, const BehavioralProfile& b);

    // Serialization
    std::string to_json() const;
    std::vector<uint8_t> serialize() const;
    static BehavioralProfile deserialize(const std::vector<uint8_t>& data);
};

class BehavioralProfileCollector {
public:
    BehavioralProfileCollector();

    // Event handlers (called by net_processing hooks)
    void on_block_relayed(uint64_t timestamp_ms, double relay_delay_ms);
    void on_tx_relayed(uint64_t timestamp_ms);
    void on_peer_connected(uint64_t timestamp_ms);
    void on_peer_disconnected(uint64_t timestamp_ms, uint64_t session_duration_sec);
    void on_block_received(uint32_t block_height);

    // Get current profile snapshot
    BehavioralProfile get_profile() const;

    // Reset collection (e.g., after DNA submission)
    void reset();

private:
    mutable std::mutex mutex_;

    // Raw event counters per hour
    std::array<uint32_t, 24> hourly_block_relays_{};
    uint32_t total_block_relays_ = 0;

    // Relay delay samples (keep last N for rolling stats)
    std::vector<double> relay_delays_;
    static constexpr size_t MAX_RELAY_SAMPLES = 10000;

    // Peer session durations (rolling)
    std::vector<double> peer_sessions_;
    static constexpr size_t MAX_SESSION_SAMPLES = 5000;

    // Transaction timestamps (for entropy calculation)
    std::vector<uint64_t> tx_timestamps_;
    static constexpr size_t MAX_TX_TIMESTAMPS = 50000;

    // Observation window
    uint64_t start_time_ = 0;
    uint32_t blocks_observed_ = 0;

    // Internal helpers
    void normalize_hourly(std::array<double, 24>& out) const;
    double compute_tx_entropy() const;

public:
    // Stateless similarity utilities (used by BehavioralProfile::similarity)
    static double cosine_similarity(const std::array<double, 24>& a, const std::array<double, 24>& b);
    static double metric_similarity(double a, double b);
};

} // namespace digital_dna

#endif // DILITHION_BEHAVIORAL_PROFILE_H
