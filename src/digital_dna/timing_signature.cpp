#include "timing_signature.h"
#include "vdf/vdf.h"

#include <algorithm>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <numeric>

namespace digital_dna {

TimingSignatureCollector::TimingSignatureCollector(const TimingConfig& config)
    : config_(config) {}

TimingSignature TimingSignatureCollector::collect(const std::array<uint8_t, 32>& challenge) {
    collecting_ = true;
    progress_ = 0.0;

    TimingSignature sig;
    sig.total_iterations = config_.total_iterations;

    // Reserve space for checkpoints
    uint64_t checkpoint_count = config_.total_iterations / config_.checkpoint_interval;
    sig.checkpoints.reserve(checkpoint_count);

    // Start timing
    auto start = std::chrono::high_resolution_clock::now();

    // Configure VDF to report progress at our checkpoint interval
    vdf::VDFConfig vdf_cfg;
    vdf_cfg.target_iterations = config_.total_iterations;
    vdf_cfg.progress_interval = config_.checkpoint_interval;

    // Progress callback records timing checkpoints
    auto progress_cb = [&](uint64_t current, uint64_t total) {
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - start);

        TimingCheckpoint cp;
        cp.iteration = current;
        cp.elapsed_us = elapsed.count();
        sig.checkpoints.push_back(cp);

        progress_ = static_cast<double>(current) / total;
    };

    // Run real VDF computation (sequential, non-parallelizable)
    vdf::VDFResult result = vdf::compute(challenge, config_.total_iterations, vdf_cfg, progress_cb);

    // Store VDF output and proof (witnesses can verify this)
    sig.vdf_output = result.output;
    sig.vdf_proof = result.proof;

    // Final timing
    auto end = std::chrono::high_resolution_clock::now();
    sig.total_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    sig.iterations_per_second = static_cast<double>(config_.total_iterations) / (sig.total_time_us / 1000000.0);

    // Compute derived metrics
    compute_derived_metrics(sig);

    collecting_ = false;
    progress_ = 1.0;

    return sig;
}

void TimingSignatureCollector::compute_derived_metrics(TimingSignature& sig) {
    sig.checkpoint_intervals_us.reserve(sig.checkpoints.size());
    for (size_t i = 0; i < sig.checkpoints.size(); i++) {
        uint64_t prev_time = (i == 0) ? 0 : sig.checkpoints[i-1].elapsed_us;
        uint64_t interval = sig.checkpoints[i].elapsed_us - prev_time;
        sig.checkpoint_intervals_us.push_back(static_cast<double>(interval));
    }

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
    oss << "  \"has_vdf_proof\": " << (vdf_proof.empty() ? "false" : "true") << ",\n";

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

ThermalProfile derive_thermal_profile(const TimingSignature& sig, uint32_t bucket_sec) {
    ThermalProfile profile;
    profile.measurement_interval_sec = bucket_sec;

    if (sig.checkpoints.size() < 2) return profile;

    uint64_t bucket_us = static_cast<uint64_t>(bucket_sec) * 1000000ULL;

    // Group checkpoints into time buckets and compute iterations/sec per bucket
    uint64_t bucket_start = 0;
    uint64_t bucket_iters_start = 0;

    for (size_t i = 0; i < sig.checkpoints.size(); i++) {
        uint64_t elapsed = sig.checkpoints[i].elapsed_us;
        uint64_t iters = sig.checkpoints[i].iteration;

        // Check if we've crossed a bucket boundary
        while (elapsed >= bucket_start + bucket_us && bucket_start + bucket_us <= sig.total_time_us) {
            // Find how many iterations completed in this bucket
            uint64_t bucket_end_us = bucket_start + bucket_us;

            // Interpolate iterations at bucket boundary
            uint64_t prev_elapsed = (i > 0) ? sig.checkpoints[i-1].elapsed_us : 0;
            uint64_t prev_iters = (i > 0) ? sig.checkpoints[i-1].iteration : 0;

            double frac = 0.0;
            if (elapsed > prev_elapsed) {
                frac = static_cast<double>(bucket_end_us - prev_elapsed) /
                       static_cast<double>(elapsed - prev_elapsed);
            }
            uint64_t interp_iters = prev_iters + static_cast<uint64_t>(frac * (iters - prev_iters));
            uint64_t bucket_iters = interp_iters - bucket_iters_start;

            double speed = static_cast<double>(bucket_iters) / bucket_sec;
            profile.speed_curve.push_back(speed);

            bucket_iters_start = interp_iters;
            bucket_start += bucket_us;
        }
    }

    // Handle remaining time in the last partial bucket
    if (sig.total_time_us > bucket_start) {
        uint64_t remaining_us = sig.total_time_us - bucket_start;
        uint64_t remaining_iters = sig.total_iterations - bucket_iters_start;
        if (remaining_us > 0) {
            double speed = static_cast<double>(remaining_iters) / (remaining_us / 1000000.0);
            profile.speed_curve.push_back(speed);
        }
    }

    if (profile.speed_curve.empty()) return profile;

    // Derive metrics
    profile.initial_speed = profile.speed_curve.front();

    // Sustained speed = average of last 3 buckets (or all if fewer)
    size_t tail_count = std::min(profile.speed_curve.size(), size_t(3));
    double tail_sum = 0.0;
    for (size_t i = profile.speed_curve.size() - tail_count; i < profile.speed_curve.size(); i++) {
        tail_sum += profile.speed_curve[i];
    }
    profile.sustained_speed = tail_sum / tail_count;

    // Throttle ratio
    if (profile.initial_speed > 1e-6) {
        profile.throttle_ratio = profile.sustained_speed / profile.initial_speed;
    }

    // Time to steady state: first bucket within 5% of sustained speed
    profile.time_to_steady_state_sec = profile.speed_curve.size() * bucket_sec;  // Default: never
    for (size_t i = 0; i < profile.speed_curve.size(); i++) {
        double rel_diff = std::abs(profile.speed_curve[i] - profile.sustained_speed) / (profile.sustained_speed + 1e-6);
        if (rel_diff < 0.05) {
            profile.time_to_steady_state_sec = (i + 1) * bucket_sec;
            break;
        }
    }

    // Thermal jitter: stddev of speed in steady-state buckets
    if (tail_count >= 2) {
        double mean = profile.sustained_speed;
        double sq_sum = 0.0;
        for (size_t i = profile.speed_curve.size() - tail_count; i < profile.speed_curve.size(); i++) {
            double diff = profile.speed_curve[i] - mean;
            sq_sum += diff * diff;
        }
        profile.thermal_jitter = std::sqrt(sq_sum / tail_count);
    }

    return profile;
}

double ThermalProfile::similarity(const ThermalProfile& a, const ThermalProfile& b) {
    if (a.speed_curve.empty() || b.speed_curve.empty()) return 0.0;

    // 1. Throttle ratio similarity (most distinctive metric)
    double throttle_sim = 1.0 - std::abs(a.throttle_ratio - b.throttle_ratio);
    throttle_sim = std::max(0.0, throttle_sim);

    // 2. Time-to-steady-state similarity
    double max_ttss = std::max(a.time_to_steady_state_sec, b.time_to_steady_state_sec);
    double ttss_sim = (max_ttss > 1e-6) ?
        1.0 - std::abs(a.time_to_steady_state_sec - b.time_to_steady_state_sec) / max_ttss :
        1.0;
    ttss_sim = std::max(0.0, ttss_sim);

    // 3. Speed curve correlation (shape similarity)
    double curve_sim = 0.0;
    if (a.speed_curve.size() >= 2 && b.speed_curve.size() >= 2) {
        // Resample both curves to same length for correlation
        size_t target_len = std::min(a.speed_curve.size(), b.speed_curve.size());
        std::vector<double> sa(target_len), sb(target_len);

        for (size_t i = 0; i < target_len; i++) {
            double t = static_cast<double>(i) / (target_len - 1);
            size_t idx_a = static_cast<size_t>(t * (a.speed_curve.size() - 1));
            size_t idx_b = static_cast<size_t>(t * (b.speed_curve.size() - 1));
            sa[i] = a.speed_curve[std::min(idx_a, a.speed_curve.size() - 1)];
            sb[i] = b.speed_curve[std::min(idx_b, b.speed_curve.size() - 1)];
        }

        curve_sim = compute_correlation(sa, sb);
        curve_sim = (curve_sim + 1.0) / 2.0;  // Normalize from [-1,1] to [0,1]
    }

    // 4. Jitter similarity
    double max_jitter = std::max(a.thermal_jitter, b.thermal_jitter);
    double jitter_sim = (max_jitter > 1e-6) ?
        1.0 - std::abs(a.thermal_jitter - b.thermal_jitter) / max_jitter :
        1.0;
    jitter_sim = std::max(0.0, jitter_sim);

    // Weighted combination
    return 0.35 * throttle_sim +
           0.25 * curve_sim +
           0.25 * ttss_sim +
           0.15 * jitter_sim;
}

} // namespace digital_dna
