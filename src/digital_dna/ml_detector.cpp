#include "ml_detector.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <sstream>
#include <iomanip>

namespace digital_dna {

// --- PairFeatures ---

const char* PairFeatures::feature_name(size_t index) {
    static const char* names[] = {
        "latency_euclidean",
        "latency_wasserstein",
        "vdf_speed_ratio",
        "vdf_checkpoint_corr",
        "memory_dtw_dist",
        "clock_drift_diff_ppm",
        "peer_jaccard_sim",
        "hourly_cosine_sim",
        "bw_asymmetry_diff",
        "thermal_throttle_diff",
        "trust_score_diff",
        "reg_gap_blocks",
        "same_region"
    };
    if (index < NUM_FEATURES) return names[index];
    return "unknown";
}

// --- IsolationTree ---

double IsolationTree::c_factor(size_t n) {
    if (n <= 1) return 0.0;
    if (n == 2) return 1.0;
    // Average path length of unsuccessful search in BST:
    // c(n) = 2*H(n-1) - 2*(n-1)/n, where H(i) = ln(i) + euler_gamma
    double euler = 0.5772156649;
    double h = std::log(static_cast<double>(n - 1)) + euler;
    return 2.0 * h - 2.0 * (n - 1.0) / n;
}

void IsolationTree::build(const std::vector<PairFeatures>& data,
                           const std::vector<size_t>& indices,
                           size_t max_depth,
                           std::mt19937& rng) {
    nodes_.clear();
    std::vector<size_t> idx_copy = indices;
    build_recursive(data, idx_copy, 0, max_depth, rng);
}

int IsolationTree::build_recursive(const std::vector<PairFeatures>& data,
                                    std::vector<size_t>& indices,
                                    size_t depth,
                                    size_t max_depth,
                                    std::mt19937& rng) {
    int node_idx = static_cast<int>(nodes_.size());
    nodes_.push_back(IsolationNode{});

    // Base case: leaf
    if (indices.size() <= 1 || depth >= max_depth) {
        nodes_[node_idx].size = indices.size();
        return node_idx;
    }

    // Pick random feature
    std::uniform_int_distribution<size_t> feat_dist(0, PairFeatures::NUM_FEATURES - 1);
    size_t feature = feat_dist(rng);

    // Find min/max of feature in this subset
    double min_val = data[indices[0]].values[feature];
    double max_val = min_val;
    for (size_t idx : indices) {
        double v = data[idx].values[feature];
        if (v < min_val) min_val = v;
        if (v > max_val) max_val = v;
    }

    // If all values are the same, make a leaf
    if (std::abs(max_val - min_val) < 1e-10) {
        nodes_[node_idx].size = indices.size();
        return node_idx;
    }

    // Random split point between min and max
    std::uniform_real_distribution<double> split_dist(min_val, max_val);
    double split_val = split_dist(rng);

    nodes_[node_idx].split_feature = feature;
    nodes_[node_idx].split_value = split_val;

    // Partition
    std::vector<size_t> left_idx, right_idx;
    for (size_t idx : indices) {
        if (data[idx].values[feature] < split_val) {
            left_idx.push_back(idx);
        } else {
            right_idx.push_back(idx);
        }
    }

    // Handle edge case: all went to one side
    if (left_idx.empty() || right_idx.empty()) {
        nodes_[node_idx].size = indices.size();
        return node_idx;
    }

    nodes_[node_idx].left = build_recursive(data, left_idx, depth + 1, max_depth, rng);
    nodes_[node_idx].right = build_recursive(data, right_idx, depth + 1, max_depth, rng);

    return node_idx;
}

double IsolationTree::path_length(const PairFeatures& sample) const {
    if (nodes_.empty()) return 0.0;
    return path_length_recursive(sample, 0, 0);
}

double IsolationTree::path_length_recursive(const PairFeatures& sample, int node_idx, size_t depth) const {
    if (node_idx < 0 || node_idx >= static_cast<int>(nodes_.size())) return depth;

    const auto& node = nodes_[node_idx];

    // Leaf node
    if (node.left == -1 && node.right == -1) {
        return depth + c_factor(node.size);
    }

    if (sample.values[node.split_feature] < node.split_value) {
        return path_length_recursive(sample, node.left, depth + 1);
    } else {
        return path_length_recursive(sample, node.right, depth + 1);
    }
}

// --- IsolationForest ---

IsolationForest::IsolationForest() = default;

IsolationForest::IsolationForest(const Config& config)
    : config_(config) {}

void IsolationForest::fit(const std::vector<PairFeatures>& data) {
    if (data.empty()) return;

    training_samples_ = data.size();
    trees_.clear();
    trees_.resize(config_.num_trees);

    std::mt19937 rng(config_.random_seed);
    size_t max_depth = static_cast<size_t>(std::ceil(std::log2(config_.subsample_size)));

    for (size_t t = 0; t < config_.num_trees; t++) {
        // Subsample
        std::vector<size_t> indices(data.size());
        std::iota(indices.begin(), indices.end(), 0);

        // Shuffle and take subsample
        for (size_t i = indices.size() - 1; i > 0; i--) {
            std::uniform_int_distribution<size_t> dist(0, i);
            std::swap(indices[i], indices[dist(rng)]);
        }
        size_t subsample = std::min(config_.subsample_size, data.size());
        indices.resize(subsample);

        trees_[t].build(data, indices, max_depth, rng);
    }

    // Compute threshold from contamination
    // Score all training data and find the percentile corresponding to contamination
    std::vector<double> scores;
    scores.reserve(data.size());
    for (const auto& d : data) {
        scores.push_back(anomaly_score(d));
    }
    std::sort(scores.begin(), scores.end());

    size_t threshold_idx = static_cast<size_t>((1.0 - config_.contamination) * scores.size());
    threshold_idx = std::min(threshold_idx, scores.size() - 1);
    threshold_ = scores[threshold_idx];
}

double IsolationForest::anomaly_score(const PairFeatures& sample) const {
    if (trees_.empty() || training_samples_ == 0) return 0.5;

    double avg_path = 0.0;
    for (const auto& tree : trees_) {
        avg_path += tree.path_length(sample);
    }
    avg_path /= trees_.size();

    double c = IsolationTree::c_factor(training_samples_);
    if (c < 1e-10) return 0.5;

    // Anomaly score: s = 2^(-avg_path / c)
    // Higher score = more anomalous
    return std::pow(2.0, -avg_path / c);
}

bool IsolationForest::predict(const PairFeatures& sample) const {
    return anomaly_score(sample) >= threshold_;
}

// --- MLSybilDetector ---

MLSybilDetector::MLSybilDetector(Mode mode) : mode_(mode) {}

PairFeatures MLSybilDetector::extract_features(
    double latency_distance,
    double latency_wasserstein,
    double vdf_speed_ratio,
    double vdf_correlation,
    double memory_dtw_distance,
    double clock_drift_diff_ppm,
    double peer_jaccard,
    double hourly_cosine,
    double bandwidth_asymmetry_diff,
    double thermal_throttle_diff,
    double trust_score_diff,
    double registration_gap_blocks,
    bool same_region)
{
    PairFeatures f;
    f.values[0] = latency_distance;
    f.values[1] = latency_wasserstein;
    f.values[2] = vdf_speed_ratio;
    f.values[3] = vdf_correlation;
    f.values[4] = memory_dtw_distance;
    f.values[5] = clock_drift_diff_ppm;
    f.values[6] = peer_jaccard;
    f.values[7] = hourly_cosine;
    f.values[8] = bandwidth_asymmetry_diff;
    f.values[9] = thermal_throttle_diff;
    f.values[10] = trust_score_diff;
    f.values[11] = registration_gap_blocks;
    f.values[12] = same_region ? 1.0 : 0.0;
    return f;
}

void MLSybilDetector::retrain(const std::vector<PairFeatures>& pair_data) {
    if (pair_data.size() < MIN_TRAINING_SAMPLES) return;

    std::lock_guard<std::mutex> lock(mutex_);
    forest_.fit(pair_data);
}

double MLSybilDetector::score_pair(const PairFeatures& features) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!forest_.is_trained()) return 0.5;
    return forest_.anomaly_score(features);
}

bool MLSybilDetector::is_anomalous(const PairFeatures& features) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!forest_.is_trained()) return false;
    return forest_.predict(features);
}

std::string MLSybilDetector::status_json() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(4);

    oss << "{\n";
    oss << "  \"mode\": \"" << (mode_ == Mode::DISABLED ? "disabled" :
                                 mode_ == Mode::ADVISORY ? "advisory" : "supplementary") << "\",\n";
    oss << "  \"is_trained\": " << (forest_.is_trained() ? "true" : "false") << ",\n";
    oss << "  \"num_trees\": " << forest_.num_trees() << ",\n";
    oss << "  \"training_samples\": " << forest_.training_samples() << ",\n";
    oss << "  \"threshold\": " << forest_.threshold() << ",\n";
    oss << "  \"total_scored\": " << total_scored_ << ",\n";
    oss << "  \"total_flagged\": " << total_flagged_ << ",\n";
    oss << "  \"readiness\": {\n";
    oss << "    \"total_scored_pairs\": " << stats_.total_scored_pairs << ",\n";
    oss << "    \"full_dim_pairs\": " << stats_.full_dim_pairs << ",\n";
    oss << "    \"labeled_outcomes\": " << stats_.labeled_outcomes << ",\n";
    oss << "    \"fpr\": " << stats_.false_positive_rate() << ",\n";
    oss << "    \"fnr\": " << stats_.false_negative_rate() << ",\n";
    oss << "    \"precision\": " << stats_.suspicious_band_precision() << ",\n";
    oss << "    \"hw_clusters\": " << stats_.hardware_clusters << ",\n";
    oss << "    \"geo_regions\": " << stats_.geo_regions << ",\n";
    oss << "    \"distributions_stable\": " << (stats_.distributions_stable ? "true" : "false") << ",\n";
    oss << "    \"ready_for_promotion\": " << (stats_.ready_for_supplementary() ? "true" : "false") << "\n";
    oss << "  }\n";
    oss << "}\n";

    return oss.str();
}

// --- Readiness Tracking ---

void MLSybilDetector::record_scored(bool full_dimensions) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_scored_pairs++;
    if (full_dimensions) {
        stats_.full_dim_pairs++;
    } else {
        stats_.partial_dim_pairs++;
    }
}

void MLSybilDetector::record_challenge_outcome(bool ml_flagged, bool confirmed_sybil) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.labeled_outcomes++;
    if (ml_flagged && confirmed_sybil)   stats_.true_positives++;
    if (ml_flagged && !confirmed_sybil)  stats_.false_positives++;
    if (!ml_flagged && !confirmed_sybil) stats_.true_negatives++;
    if (!ml_flagged && confirmed_sybil)  stats_.false_negatives++;
}

void MLSybilDetector::record_challenge_error() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.challenge_errors++;
}

void MLSybilDetector::update_diversity(uint32_t hw_clusters, uint32_t regions) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.hardware_clusters = hw_clusters;
    stats_.geo_regions = regions;
}

void MLSybilDetector::update_stability(bool stable) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.distributions_stable = stable;
}

} // namespace digital_dna
