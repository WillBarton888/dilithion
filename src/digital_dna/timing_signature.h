#ifndef DILITHION_TIMING_SIGNATURE_H
#define DILITHION_TIMING_SIGNATURE_H

#include <vector>
#include <array>
#include <chrono>
#include <cstdint>
#include <string>

namespace digital_dna {

// Timing checkpoint during VDF computation
struct TimingCheckpoint {
    uint64_t iteration;
    uint64_t elapsed_us;  // Microseconds since start
};

// VDF timing signature
struct TimingSignature {
    std::vector<TimingCheckpoint> checkpoints;
    uint64_t total_iterations;
    uint64_t total_time_us;
    double iterations_per_second;

    // Derived metrics
    std::vector<double> checkpoint_intervals_us;  // Time between checkpoints
    double mean_interval_us;
    double stddev_interval_us;

    // Serialization
    std::string to_json() const;

    // Comparison
    static double correlation(const TimingSignature& a, const TimingSignature& b);
    static double progress_rate_similarity(const TimingSignature& a, const TimingSignature& b);
};

// Configuration for timing measurement
struct TimingConfig {
    uint64_t total_iterations = 1000000;    // 1M iterations (~5-10 seconds)
    uint64_t checkpoint_interval = 10000;   // Checkpoint every 10K iterations
    uint32_t warmup_iterations = 10000;     // Warmup to stabilize CPU state
};

// Timing signature collector
class TimingSignatureCollector {
public:
    TimingSignatureCollector(const TimingConfig& config = TimingConfig());

    // Collect timing signature using repeated hash as delay function
    // Note: This is NOT a true VDF (it's parallelizable), but works for
    // timing measurement prototyping
    TimingSignature collect(const std::array<uint8_t, 32>& challenge);

    // Get progress during collection (0.0 to 1.0)
    double get_progress() const { return progress_; }

    // Check if collection is in progress
    bool is_collecting() const { return collecting_; }

private:
    TimingConfig config_;
    double progress_ = 0.0;
    bool collecting_ = false;

    // Simple hash function for delay (SHA256-like)
    void hash_iteration(std::array<uint8_t, 32>& state);
};

// Utility functions
double compute_correlation(const std::vector<double>& a, const std::vector<double>& b);

} // namespace digital_dna

#endif // DILITHION_TIMING_SIGNATURE_H
