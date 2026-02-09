#include "timing_signature.h"

#include <algorithm>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <numeric>

namespace digital_dna {

TimingSignatureCollector::TimingSignatureCollector(const TimingConfig& config)
    : config_(config) {}

// Simple hash iteration using a lightweight mixing function
// (Not cryptographically secure, but sufficient for timing measurement)
void TimingSignatureCollector::hash_iteration(std::array<uint8_t, 32>& state) {
    // Based on SipHash-like mixing
    uint64_t* s = reinterpret_cast<uint64_t*>(state.data());

    // Mix the state
    s[0] += s[1];
    s[1] = (s[1] << 13) | (s[1] >> 51);
    s[1] ^= s[0];
    s[0] = (s[0] << 32) | (s[0] >> 32);

    s[2] += s[3];
    s[3] = (s[3] << 16) | (s[3] >> 48);
    s[3] ^= s[2];

    s[0] += s[3];
    s[3] = (s[3] << 21) | (s[3] >> 43);
    s[3] ^= s[0];

    s[2] += s[1];
    s[1] = (s[1] << 17) | (s[1] >> 47);
    s[1] ^= s[2];
    s[2] = (s[2] << 32) | (s[2] >> 32);
}

TimingSignature TimingSignatureCollector::collect(const std::array<uint8_t, 32>& challenge) {
    collecting_ = true;
    progress_ = 0.0;

    TimingSignature sig;
    sig.total_iterations = config_.total_iterations;

    // Initialize state from challenge
    std::array<uint8_t, 32> state = challenge;

    // Warmup phase (stabilize CPU state, caches, etc.)
    for (uint32_t i = 0; i < config_.warmup_iterations; i++) {
        hash_iteration(state);
    }

    // Reset state for actual measurement
    state = challenge;

    // Start timing
    auto start = std::chrono::high_resolution_clock::now();

    uint64_t checkpoint_count = config_.total_iterations / config_.checkpoint_interval;
    sig.checkpoints.reserve(checkpoint_count);

    // Main computation loop with checkpoints
    for (uint64_t i = 0; i < config_.total_iterations; i++) {
        hash_iteration(state);

        // Record checkpoint
        if ((i + 1) % config_.checkpoint_interval == 0) {
            auto now = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - start);

            TimingCheckpoint cp;
            cp.iteration = i + 1;
            cp.elapsed_us = elapsed.count();
            sig.checkpoints.push_back(cp);

            progress_ = static_cast<double>(i + 1) / config_.total_iterations;
        }
    }

    // Final timing
    auto end = std::chrono::high_resolution_clock::now();
    sig.total_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    sig.iterations_per_second = static_cast<double>(config_.total_iterations) / (sig.total_time_us / 1000000.0);

    // Compute checkpoint intervals
    sig.checkpoint_intervals_us.reserve(sig.checkpoints.size());
    for (size_t i = 0; i < sig.checkpoints.size(); i++) {
        uint64_t prev_time = (i == 0) ? 0 : sig.checkpoints[i-1].elapsed_us;
        uint64_t interval = sig.checkpoints[i].elapsed_us - prev_time;
        sig.checkpoint_intervals_us.push_back(static_cast<double>(interval));
    }

    // Compute statistics
    if (!sig.checkpoint_intervals_us.empty()) {
        double sum = std::accumulate(sig.checkpoint_intervals_us.begin(),
                                    sig.checkpoint_intervals_us.end(), 0.0);
        sig.mean_interval_us = sum / sig.checkpoint_intervals_us.size();

        double sq_sum = 0.0;
        for (double v : sig.checkpoint_intervals_us) {
            double diff = v - sig.mean_interval_us;
            sq_sum += diff * diff;
        }
        sig.stddev_interval_us = std::sqrt(sq_sum / sig.checkpoint_intervals_us.size());
    }

    collecting_ = false;
    progress_ = 1.0;

    return sig;
}

double compute_correlation(const std::vector<double>& a, const std::vector<double>& b) {
    if (a.size() != b.size() || a.empty()) return 0.0;

    size_t n = a.size();

    // Compute means
    double mean_a = std::accumulate(a.begin(), a.end(), 0.0) / n;
    double mean_b = std::accumulate(b.begin(), b.end(), 0.0) / n;

    // Compute correlation
    double numerator = 0.0;
    double sum_sq_a = 0.0;
    double sum_sq_b = 0.0;

    for (size_t i = 0; i < n; i++) {
        double da = a[i] - mean_a;
        double db = b[i] - mean_b;
        numerator += da * db;
        sum_sq_a += da * da;
        sum_sq_b += db * db;
    }

    double denominator = std::sqrt(sum_sq_a * sum_sq_b);
    if (denominator < 1e-10) return 0.0;

    return numerator / denominator;
}

double TimingSignature::correlation(const TimingSignature& a, const TimingSignature& b) {
    return compute_correlation(a.checkpoint_intervals_us, b.checkpoint_intervals_us);
}

double TimingSignature::progress_rate_similarity(const TimingSignature& a, const TimingSignature& b) {
    double rate_a = a.iterations_per_second;
    double rate_b = b.iterations_per_second;

    if (rate_a < 1e-10 || rate_b < 1e-10) return 0.0;

    // Similarity = 1 - relative_difference
    double diff = std::abs(rate_a - rate_b) / std::max(rate_a, rate_b);
    return 1.0 - diff;
}

std::string TimingSignature::to_json() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    oss << "{\n";
    oss << "  \"total_iterations\": " << total_iterations << ",\n";
    oss << "  \"total_time_us\": " << total_time_us << ",\n";
    oss << "  \"iterations_per_second\": " << iterations_per_second << ",\n";
    oss << "  \"mean_interval_us\": " << mean_interval_us << ",\n";
    oss << "  \"stddev_interval_us\": " << stddev_interval_us << ",\n";
    oss << "  \"num_checkpoints\": " << checkpoints.size() << ",\n";

    // Include first/last few intervals for analysis
    oss << "  \"sample_intervals_us\": [";
    size_t samples = std::min(checkpoint_intervals_us.size(), size_t(10));
    for (size_t i = 0; i < samples; i++) {
        oss << checkpoint_intervals_us[i];
        if (i < samples - 1) oss << ", ";
    }
    oss << "],\n";

    // Include interval variance signature (normalized deviations)
    oss << "  \"variance_signature\": [";
    samples = std::min(checkpoint_intervals_us.size(), size_t(20));
    for (size_t i = 0; i < samples; i++) {
        double deviation = (checkpoint_intervals_us[i] - mean_interval_us) / (stddev_interval_us + 1e-10);
        oss << std::setprecision(4) << deviation;
        if (i < samples - 1) oss << ", ";
    }
    oss << "]\n";

    oss << "}\n";

    return oss.str();
}

} // namespace digital_dna
