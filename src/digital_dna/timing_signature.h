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

    // VDF output and proof (from real VDF computation)
    std::array<uint8_t, 32> vdf_output;     // VDF result (verifiable)
    std::vector<uint8_t> vdf_proof;         // Wesolowski proof

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

    // Collect timing signature using real chiavdf VDF computation.
    // Records timing checkpoints via VDF progress callback.
    TimingSignature collect(const std::array<uint8_t, 32>& challenge);

    // Get progress during collection (0.0 to 1.0)
    double get_progress() const { return progress_; }

    // Check if collection is in progress
    bool is_collecting() const { return collecting_; }

private:
    TimingConfig config_;
    double progress_ = 0.0;
    bool collecting_ = false;

    // Compute derived metrics from checkpoints
    void compute_derived_metrics(TimingSignature& sig);
};

// Thermal throttling profile (derived from VDF timing checkpoints)
// CPUs heat up during VDF computation and throttle at rates depending on
// cooling solution, TDP, and form factor. This creates a "cooling curve"
// that distinguishes laptops from desktops from servers — at zero extra cost.
struct ThermalProfile {
    // VDF speed at each measurement interval (iterations/sec per bucket)
    std::vector<double> speed_curve;
    uint32_t measurement_interval_sec = 60;  // Bucket width (default: 1 minute)

    // Derived metrics
    double initial_speed = 0.0;           // Speed in first bucket (before thermal effects)
    double sustained_speed = 0.0;         // Average speed in last 3 buckets (steady state)
    double throttle_ratio = 1.0;          // sustained/initial (1.0 = no throttle)
    double time_to_steady_state_sec = 0.0;// Time until speed stabilizes (within 5% of sustained)
    double thermal_jitter = 0.0;          // Stddev of speed in steady state

    // Comparison
    static double similarity(const ThermalProfile& a, const ThermalProfile& b);
};

// Derive thermal profile from existing VDF timing checkpoints.
// No additional computation — extracts data we already collect.
ThermalProfile derive_thermal_profile(const TimingSignature& sig,
                                       uint32_t bucket_sec = 60);

// Utility functions
double compute_correlation(const std::vector<double>& a, const std::vector<double>& b);

} // namespace digital_dna

#endif // DILITHION_TIMING_SIGNATURE_H
