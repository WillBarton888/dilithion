/**
 * Digital DNA Implementation
 */

#include "digital_dna.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>
#include <fstream>
#include <iomanip>

namespace digital_dna {

// Simple hash function for identity (would use SHA3 in production)
static void compute_hash(const uint8_t* data, size_t len, uint8_t* out) {
    // SipHash-like mixing for simplicity
    uint64_t h[4] = {0x736f6d6570736575ULL, 0x646f72616e646f6dULL,
                     0x6c7967656e657261ULL, 0x7465646279746573ULL};

    for (size_t i = 0; i < len; i++) {
        h[i % 4] ^= static_cast<uint64_t>(data[i]) << ((i % 8) * 8);
        h[0] += h[1]; h[1] = (h[1] << 13) | (h[1] >> 51); h[1] ^= h[0];
        h[2] += h[3]; h[3] = (h[3] << 16) | (h[3] >> 48); h[3] ^= h[2];
    }

    // Final mixing
    for (int round = 0; round < 4; round++) {
        h[0] += h[1]; h[1] = (h[1] << 13) | (h[1] >> 51); h[1] ^= h[0];
        h[2] += h[3]; h[3] = (h[3] << 16) | (h[3] >> 48); h[3] ^= h[2];
        h[0] += h[3]; h[2] += h[1];
    }

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = static_cast<uint8_t>(h[i] >> (j * 8));
        }
    }
}

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

    // Latency - just median values for each seed (4 seeds * 8 bytes = 32 bytes)
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
    // Minimum size: 20 + 4 + 8 + 32 + 8 + 12 = 84 bytes
    if (data.size() < 84) return std::nullopt;

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

    // Latency - median values
    for (int s = 0; s < 4; s++) {
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

    // Perspective - peer count (we don't fully reconstruct, just store key metrics)
    // This is simplified - full deserialization would need more data
    offset += 12;

    dna.is_valid = true;
    return dna;
}

std::array<uint8_t, 32> DigitalDNA::hash() const {
    auto data = serialize();
    std::array<uint8_t, 32> result;
    compute_hash(data.data(), data.size(), result.data());
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

void DigitalDNACollector::start_collection() {
    collecting_ = true;

    // Collect latency fingerprint (quick - ~30 seconds)
    LatencyFingerprint latency;
    latency.measurement_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    for (size_t i = 0; i < MAINNET_SEEDS.size(); i++) {
        latency.seed_stats[i] = latency_collector_.measure_seed(MAINNET_SEEDS[i]);
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
}

void DigitalDNACollector::stop_collection() {
    collecting_ = false;

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

    score.latency_similarity = calculate_latency_similarity(a.latency, b.latency);
    score.timing_similarity = calculate_timing_similarity(a.timing, b.timing);
    score.perspective_similarity = calculate_perspective_similarity(a.perspective, b.perspective);

    // Weighted combination: latency 40%, timing 30%, perspective 30%
    score.combined_score = 0.4 * score.latency_similarity +
                          0.3 * score.timing_similarity +
                          0.3 * score.perspective_similarity;

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
