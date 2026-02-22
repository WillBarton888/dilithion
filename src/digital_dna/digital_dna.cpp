/**
 * Digital DNA Implementation
 */

#include "digital_dna.h"

#include <crypto/sha3.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>
#include <fstream>
#include <iomanip>

namespace digital_dna {

// ============ DigitalDNA ============

std::string DigitalDNA::to_json() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    oss << "{\n";

    // Address
    oss << "  \"address\": \"";
    for (int i = 0; i < 8; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)address[i];
    }
    oss << std::dec << "...\",\n";

    // Registration
    oss << "  \"registration_height\": " << registration_height << ",\n";
    oss << "  \"registration_time\": " << registration_time << ",\n";
    oss << "  \"is_valid\": " << (is_valid ? "true" : "false") << ",\n";

    // Latency fingerprint
    oss << "  \"latency\": {\n";
    oss << "    \"seeds\": [";
    for (size_t i = 0; i < latency.seed_stats.size(); i++) {
        oss << "{\"name\": \"" << latency.seed_stats[i].seed_name << "\", ";
        oss << "\"median_ms\": " << latency.seed_stats[i].median_ms << "}";
        if (i < latency.seed_stats.size() - 1) oss << ", ";
    }
    oss << "]\n";
    oss << "  },\n";

    // Timing signature
    oss << "  \"timing\": {\n";
    oss << "    \"iterations\": " << timing.total_iterations << ",\n";
    oss << "    \"iterations_per_second\": " << timing.iterations_per_second << ",\n";
    oss << "    \"mean_interval_us\": " << timing.mean_interval_us << "\n";
    oss << "  },\n";

    // Perspective
    oss << "  \"perspective\": {\n";
    oss << "    \"total_unique_peers\": " << perspective.total_unique_peers() << ",\n";
    oss << "    \"peer_turnover_rate\": " << perspective.peer_turnover_rate() << ",\n";
    oss << "    \"witness_coverage\": " << perspective.witness_coverage() << "\n";
    oss << "  }\n";

    oss << "}";

    return oss.str();
}

std::vector<uint8_t> DigitalDNA::serialize() const {
    std::vector<uint8_t> data;

    // Address (20 bytes)
    data.insert(data.end(), address.begin(), address.end());

    // Registration height (4 bytes)
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(registration_height >> (i * 8)));

    // Registration time (8 bytes)
    for (int i = 0; i < 8; i++)
        data.push_back(static_cast<uint8_t>(registration_time >> (i * 8)));

    // Latency - seed count (4 bytes) + median values (N seeds * 8 bytes)
    uint32_t seed_count = static_cast<uint32_t>(latency.seed_stats.size());
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(seed_count >> (i * 8)));

    for (const auto& s : latency.seed_stats) {
        uint64_t median_bits;
        std::memcpy(&median_bits, &s.median_ms, sizeof(double));
        for (int i = 0; i < 8; i++)
            data.push_back(static_cast<uint8_t>(median_bits >> (i * 8)));
    }

    // Timing - iterations per second (8 bytes)
    uint64_t ips_bits;
    std::memcpy(&ips_bits, &timing.iterations_per_second, sizeof(double));
    for (int i = 0; i < 8; i++)
        data.push_back(static_cast<uint8_t>(ips_bits >> (i * 8)));

    // Perspective - unique peer count and turnover rate (12 bytes)
    uint32_t peer_count = static_cast<uint32_t>(perspective.total_unique_peers());
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(peer_count >> (i * 8)));

    uint64_t turnover_bits;
    double turnover = perspective.peer_turnover_rate();
    std::memcpy(&turnover_bits, &turnover, sizeof(double));
    for (int i = 0; i < 8; i++)
        data.push_back(static_cast<uint8_t>(turnover_bits >> (i * 8)));

    return data;
}

std::optional<DigitalDNA> DigitalDNA::deserialize(const std::vector<uint8_t>& data) {
    // Minimum size: 20 (addr) + 4 (height) + 8 (time) + 4 (seed_count) + 8 (timing) + 12 (persp) = 56 bytes
    if (data.size() < 56) return std::nullopt;

    DigitalDNA dna;
    size_t offset = 0;

    // Address
    std::copy(data.begin(), data.begin() + 20, dna.address.begin());
    offset += 20;

    // Registration height
    dna.registration_height = 0;
    for (int i = 0; i < 4; i++)
        dna.registration_height |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
    offset += 4;

    // Registration time
    dna.registration_time = 0;
    for (int i = 0; i < 8; i++)
        dna.registration_time |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
    offset += 8;

    // Latency - seed count + median values
    uint32_t seed_count = 0;
    for (int i = 0; i < 4; i++)
        seed_count |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
    offset += 4;

    if (data.size() < offset + seed_count * 8 + 8 + 12) return std::nullopt;

    dna.latency.seed_stats.resize(seed_count);
    for (uint32_t s = 0; s < seed_count; s++) {
        uint64_t median_bits = 0;
        for (int i = 0; i < 8; i++)
            median_bits |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
        std::memcpy(&dna.latency.seed_stats[s].median_ms, &median_bits, sizeof(double));
        offset += 8;
    }

    // Timing - iterations per second
    uint64_t ips_bits = 0;
    for (int i = 0; i < 8; i++)
        ips_bits |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
    std::memcpy(&dna.timing.iterations_per_second, &ips_bits, sizeof(double));
    offset += 8;

    // Perspective - peer count (simplified - full deserialization would need more data)
    offset += 12;

    dna.is_valid = true;
    return dna;
}

std::array<uint8_t, 32> DigitalDNA::hash() const {
    auto data = serialize();
    std::array<uint8_t, 32> result;
    SHA3_256(data.data(), data.size(), result.data());
    return result;
}

// ============ SimilarityScore ============

std::string SimilarityScore::verdict() const {
    if (is_same_identity()) {
        return "SAME_IDENTITY";
    } else if (is_suspicious()) {
        return "SUSPICIOUS";
    } else {
        return "DIFFERENT";
    }
}

// ============ DigitalDNACollector ============

DigitalDNACollector::DigitalDNACollector(const std::array<uint8_t, 20>& address, const Config& config)
    : address_(address)
    , config_(config)
    , latency_collector_()
    , timing_collector_(TimingConfig{config.timing_iterations, config.timing_checkpoint_interval, 10000})
    , perspective_collector_(address, PerspectiveConfig{60, config.perspective_duration_sec, 3, false})
{
    latency_collector_.set_samples_per_seed(config.latency_samples);
    latency_collector_.set_timeout_ms(config.latency_timeout_ms);
}

DigitalDNACollector::~DigitalDNACollector() {
    collecting_ = false;
    if (collection_thread_.joinable()) {
        collection_thread_.join();
    }
}

void DigitalDNACollector::start_collection() {
    collecting_ = true;

    // Run collection in background thread to avoid blocking node startup
    collection_thread_ = std::thread([this]() {
        // Collect latency fingerprint (quick - ~30 seconds)
        LatencyFingerprint latency;
        latency.measurement_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        latency.seed_stats.reserve(MAINNET_SEEDS.size());
        for (size_t i = 0; i < MAINNET_SEEDS.size(); i++) {
            latency.seed_stats.push_back(latency_collector_.measure_seed(MAINNET_SEEDS[i]));
        }
        latency_result_ = latency;

        // Collect timing signature (depends on config - typically seconds to minutes)
        std::array<uint8_t, 32> challenge = {};
        for (int i = 0; i < 20; i++) {
            challenge[i] = address_[i];
        }
        timing_result_ = timing_collector_.collect(challenge);

        // Perspective collection is ongoing - call on_peer_* methods
        // For now, we just take a snapshot
    });
}

void DigitalDNACollector::stop_collection() {
    collecting_ = false;

    // Wait for background collection thread to finish
    if (collection_thread_.joinable()) {
        collection_thread_.join();
    }

    // Finalize perspective
    perspective_result_ = perspective_collector_.get_proof();
}

double DigitalDNACollector::get_progress() const {
    if (!collecting_) {
        return latency_result_ && timing_result_ && perspective_result_ ? 1.0 : 0.0;
    }

    double latency_progress = latency_result_ ? 1.0 : 0.0;
    double timing_progress = timing_collector_.get_progress();
    double perspective_progress = perspective_collector_.get_progress();

    // Weighted: latency 20%, timing 30%, perspective 50%
    return 0.2 * latency_progress + 0.3 * timing_progress + 0.5 * perspective_progress;
}

std::optional<DigitalDNA> DigitalDNACollector::get_dna() const {
    if (!latency_result_ || !timing_result_) {
        return std::nullopt;
    }

    DigitalDNA dna;
    dna.address = address_;
    dna.latency = *latency_result_;
    dna.timing = *timing_result_;
    dna.perspective = perspective_result_.value_or(perspective_collector_.get_proof());
    dna.registration_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    dna.is_valid = true;

    return dna;
}

void DigitalDNACollector::on_peer_connected(const std::array<uint8_t, 20>& peer_id) {
    perspective_collector_.on_peer_connected(peer_id);
}

void DigitalDNACollector::on_peer_disconnected(const std::array<uint8_t, 20>& peer_id) {
    perspective_collector_.on_peer_disconnected(peer_id);
}

// ============ DigitalDNARegistry ============

DigitalDNARegistry::DigitalDNARegistry() {}

DigitalDNARegistry::RegisterResult DigitalDNARegistry::register_identity(const DigitalDNA& dna) {
    if (!dna.is_valid) {
        return RegisterResult::INVALID_DNA;
    }

    // Check if already registered
    if (is_registered(dna.address)) {
        return RegisterResult::ALREADY_REGISTERED;
    }

    // Check for Sybils
    auto similar = find_similar(dna, SimilarityScore::SAME_IDENTITY_THRESHOLD);
    if (!similar.empty()) {
        return RegisterResult::SYBIL_DETECTED;
    }

    identities_.push_back(dna);
    return RegisterResult::SUCCESS;
}

bool DigitalDNARegistry::is_registered(const std::array<uint8_t, 20>& address) const {
    return std::any_of(identities_.begin(), identities_.end(),
        [&](const DigitalDNA& d) { return d.address == address; });
}

std::optional<DigitalDNA> DigitalDNARegistry::get_identity(const std::array<uint8_t, 20>& address) const {
    auto it = std::find_if(identities_.begin(), identities_.end(),
        [&](const DigitalDNA& d) { return d.address == address; });
    if (it != identities_.end()) {
        return *it;
    }
    return std::nullopt;
}

std::vector<std::pair<DigitalDNA, SimilarityScore>> DigitalDNARegistry::find_similar(
    const DigitalDNA& dna,
    double threshold
) const {
    std::vector<std::pair<DigitalDNA, SimilarityScore>> results;

    for (const auto& other : identities_) {
        if (other.address == dna.address) continue;

        auto score = compare(dna, other);
        if (score.combined_score >= threshold) {
            results.push_back({other, score});
        }
    }

    // Sort by similarity (highest first)
    std::sort(results.begin(), results.end(),
        [](const auto& a, const auto& b) {
            return a.second.combined_score > b.second.combined_score;
        });

    return results;
}

SimilarityScore DigitalDNARegistry::compare(const DigitalDNA& a, const DigitalDNA& b) const {
    SimilarityScore score;

    // Core v2.0 dimensions (always available)
    score.latency_similarity = calculate_latency_similarity(a.latency, b.latency);
    score.timing_similarity = calculate_timing_similarity(a.timing, b.timing);
    score.perspective_similarity = calculate_perspective_similarity(a.perspective, b.perspective);

    // v3.0 extended dimensions (scored only when both identities have data)
    if (a.memory && b.memory) {
        score.memory_similarity = MemoryFingerprint::similarity(*a.memory, *b.memory);
        score.has_memory = true;
    }
    if (a.clock_drift && b.clock_drift) {
        score.clock_drift_similarity = ClockDriftFingerprint::similarity(*a.clock_drift, *b.clock_drift);
        score.has_clock_drift = true;
    }
    if (a.bandwidth && b.bandwidth) {
        score.bandwidth_similarity = BandwidthFingerprint::similarity(*a.bandwidth, *b.bandwidth);
        score.has_bandwidth = true;
    }
    if (a.thermal && b.thermal) {
        score.thermal_similarity = ThermalProfile::similarity(*a.thermal, *b.thermal);
        score.has_thermal = true;
    }
    if (a.behavioral && b.behavioral) {
        score.behavioral_similarity = BehavioralProfile::similarity(*a.behavioral, *b.behavioral);
        score.has_behavioral = true;
    }

    return compute_combined_score(score);
}

SimilarityScore DigitalDNARegistry::compute_combined_score(SimilarityScore score) {
    // Equal-weight average across all available dimensions.
    // During bootstrap (few v3.0 identities), this degrades gracefully
    // to the 3 core dimensions. As the network matures, all 8 contribute.
    //
    // Correlation-aware damping: V (Timing), M (Memory), T (Thermal) are
    // correlated by hardware SKU. When all three are high and close to each
    // other, they likely indicate "same model" not "same machine." We dampen
    // their combined contribution so they don't inflate the score.

    double sum = 0.0;
    double weight_sum = 0.0;

    // Helper: add a dimension with given weight
    auto add = [&](double similarity, double weight) {
        sum += similarity * weight;
        weight_sum += weight;
    };

    // Independent dimensions: full weight (1.0 each)
    add(score.latency_similarity, 1.0);         // L: geographic
    add(score.perspective_similarity, 1.0);       // P: network topology

    // V/M/T correlation cluster: check if they move together
    double vmt_weight = 1.0;  // default: full weight each
    bool has_vmt_cluster = score.has_memory && score.has_thermal;
    if (has_vmt_cluster) {
        double v = score.timing_similarity;
        double m = score.memory_similarity;
        double t = score.thermal_similarity;
        double vmt_max = std::max({v, m, t});
        double vmt_min = std::min({v, m, t});
        double vmt_spread = vmt_max - vmt_min;

        // If all three are high (>0.80) and tightly clustered (spread <0.15),
        // they're likely correlated by hardware SKU. Dampen to 0.5 weight each
        // so the cluster contributes ~1.5 dimensions instead of 3.
        if (vmt_min > 0.80 && vmt_spread < 0.15) {
            vmt_weight = 0.5;
        }
    }

    add(score.timing_similarity, vmt_weight);     // V: VDF speed
    if (score.has_memory)
        add(score.memory_similarity, vmt_weight);  // M: cache hierarchy
    if (score.has_thermal)
        add(score.thermal_similarity, vmt_weight); // T: cooling curve

    // Independent extended dimensions: full weight
    if (score.has_clock_drift)
        add(score.clock_drift_similarity, 1.0);   // D: oscillator (unique per machine)
    if (score.has_bandwidth)
        add(score.bandwidth_similarity, 1.0);      // B: throughput
    if (score.has_behavioral)
        add(score.behavioral_similarity, 1.0);     // BP: activity patterns

    score.dimensions_scored = static_cast<uint32_t>(
        3 + (score.has_memory ? 1 : 0) + (score.has_clock_drift ? 1 : 0) +
        (score.has_bandwidth ? 1 : 0) + (score.has_thermal ? 1 : 0) +
        (score.has_behavioral ? 1 : 0));
    score.combined_score = (weight_sum > 0.0) ? sum / weight_sum : 0.0;

    return score;
}

std::vector<DigitalDNA> DigitalDNARegistry::get_all() const {
    return identities_;
}

bool DigitalDNARegistry::save(const std::string& path) const {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;

    uint32_t count = static_cast<uint32_t>(identities_.size());
    ofs.write(reinterpret_cast<const char*>(&count), 4);

    for (const auto& dna : identities_) {
        auto data = dna.serialize();
        uint32_t size = static_cast<uint32_t>(data.size());
        ofs.write(reinterpret_cast<const char*>(&size), 4);
        ofs.write(reinterpret_cast<const char*>(data.data()), size);
    }

    return true;
}

bool DigitalDNARegistry::load(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;

    uint32_t count;
    ifs.read(reinterpret_cast<char*>(&count), 4);

    identities_.clear();
    for (uint32_t i = 0; i < count; i++) {
        uint32_t size;
        ifs.read(reinterpret_cast<char*>(&size), 4);

        std::vector<uint8_t> data(size);
        ifs.read(reinterpret_cast<char*>(data.data()), size);

        auto dna = DigitalDNA::deserialize(data);
        if (dna) {
            identities_.push_back(*dna);
        }
    }

    return true;
}

double DigitalDNARegistry::calculate_latency_similarity(
    const LatencyFingerprint& a, const LatencyFingerprint& b
) const {
    return latency_similarity(a, b);
}

double DigitalDNARegistry::calculate_timing_similarity(
    const TimingSignature& a, const TimingSignature& b
) const {
    return timing_similarity(a, b);
}

double DigitalDNARegistry::calculate_perspective_similarity(
    const PerspectiveProof& a, const PerspectiveProof& b
) const {
    return perspective_similarity(a, b);
}

// ============ Utility Functions ============

double latency_similarity(const LatencyFingerprint& a, const LatencyFingerprint& b) {
    // Use Euclidean distance, convert to similarity
    double distance = LatencyFingerprint::distance(a, b);

    // Convert distance to similarity (0-1)
    // At 0ms distance -> 1.0 similarity
    // At 100ms distance -> ~0.37 similarity
    // At 300ms distance -> ~0.05 similarity
    return std::exp(-distance / 100.0);
}

double timing_similarity(const TimingSignature& a, const TimingSignature& b) {
    // Use progress rate similarity (more stable than checkpoint correlation)
    return TimingSignature::progress_rate_similarity(a, b);
}

double perspective_similarity(const PerspectiveProof& a, const PerspectiveProof& b) {
    return PerspectiveProof::similarity(a, b);
}

const std::array<SeedNode, 4>& get_mainnet_seeds() {
    return MAINNET_SEEDS;
}

const std::array<SeedNode, 3>& get_testnet_seeds() {
    return TESTNET_SEEDS;
}

} // namespace digital_dna
