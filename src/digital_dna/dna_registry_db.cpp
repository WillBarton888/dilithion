#include "dna_registry_db.h"

#include <leveldb/write_batch.h>

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <sstream>

namespace digital_dna {

const std::string DNARegistryDB::KEY_PREFIX = "dna:";

DNARegistryDB::DNARegistryDB() {}

DNARegistryDB::~DNARegistryDB() {
    Close();
}

bool DNARegistryDB::Open(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (db_) return true;  // Already open

    path_ = path;

    leveldb::Options options;
    options.create_if_missing = true;

    leveldb::DB* raw_db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, path, &raw_db);
    if (!status.ok()) {
        return false;
    }

    db_.reset(raw_db);

    // Load all identities into cache
    load_cache();

    return true;
}

void DNARegistryDB::Close() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
    db_.reset();
}

bool DNARegistryDB::IsOpen() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_ != nullptr;
}

DNARegistryDB::RegisterResult DNARegistryDB::register_identity(const DigitalDNA& dna) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!db_) return RegisterResult::DB_ERROR;
    if (!dna.is_valid) return RegisterResult::INVALID_DNA;

    // Check if already registered
    std::string key = make_key(dna.address);
    std::string existing;
    leveldb::Status status = db_->Get(leveldb::ReadOptions(), key, &existing);
    if (status.ok()) {
        return RegisterResult::ALREADY_REGISTERED;
    }

    // Check for Sybils against all cached identities (v3.0: 8-dimension scoring)
    bool ml_flagged = false;
    for (const auto& [addr, other] : cache_) {
        if (addr == dna.address) continue;

        auto score = compare(dna, other);

        // Primary gate: threshold-based rejection
        if (score.is_same_identity()) {
            return RegisterResult::SYBIL_DETECTED;
        }

        // ML supplementary gate: if suspicious and ML is active + trained
        if (score.is_suspicious() && ml_detector_ &&
            ml_detector_->get_mode() != MLSybilDetector::Mode::DISABLED) {

            // Build raw feature vector from the pair
            double lat_dist = LatencyFingerprint::distance(dna.latency, other.latency);
            double vdf_ratio = (other.timing.iterations_per_second > 0)
                ? dna.timing.iterations_per_second / other.timing.iterations_per_second : 1.0;
            double mem_dtw = (dna.memory && other.memory)
                ? (1.0 - score.memory_similarity) * 100.0 : 0.0;
            double drift_diff = (dna.clock_drift && other.clock_drift)
                ? std::abs(dna.clock_drift->drift_rate_ppm - other.clock_drift->drift_rate_ppm) : 0.0;
            double bw_asym_diff = (dna.bandwidth && other.bandwidth)
                ? std::abs(dna.bandwidth->median_asymmetry - other.bandwidth->median_asymmetry) : 0.0;
            double therm_diff = (dna.thermal && other.thermal)
                ? std::abs(dna.thermal->throttle_ratio - other.thermal->throttle_ratio) : 0.0;
            double reg_gap = std::abs(
                static_cast<double>(dna.registration_height) - static_cast<double>(other.registration_height));

            auto features = ml_detector_->extract_features(
                lat_dist,                       // 1. Latency Euclidean distance
                0.0,                            // 2. Latency Wasserstein (not yet computed)
                vdf_ratio,                      // 3. VDF speed ratio
                score.timing_similarity,        // 4. VDF checkpoint correlation proxy
                mem_dtw,                        // 5. Memory curve DTW distance
                drift_diff,                     // 6. Clock drift rate difference (ppm)
                score.perspective_similarity,   // 7. Peer set Jaccard
                score.behavioral_similarity,    // 8. Hourly activity cosine
                bw_asym_diff,                   // 9. Bandwidth asymmetry difference
                therm_diff,                     // 10. Thermal throttle ratio difference
                0.0,                            // 11. Trust score difference (not in DigitalDNA yet)
                reg_gap,                        // 12. Registration time gap (blocks)
                false);                         // 13. Same region (not yet computed)

            // Track readiness stats
            bool full_dims = score.dimensions_scored >= 8;
            ml_detector_->record_scored(full_dims);

            if (ml_detector_->is_anomalous(features)) {
                if (ml_detector_->get_mode() == MLSybilDetector::Mode::SUPPLEMENTARY) {
                    ml_flagged = true;
                }
                // ADVISORY mode: logged inside is_anomalous(), no action
            }
        }
    }

    // ML supplementary rejection: suspicious pair + ML anomaly = reject
    if (ml_flagged) {
        return RegisterResult::SYBIL_DETECTED;
    }

    // Serialize and store
    auto data = dna.serialize();
    std::string value(data.begin(), data.end());

    status = db_->Put(leveldb::WriteOptions(), key, value);
    if (!status.ok()) {
        return RegisterResult::DB_ERROR;
    }

    // Update cache
    cache_[dna.address] = dna;

    return RegisterResult::SUCCESS;
}

bool DNARegistryDB::is_registered(const std::array<uint8_t, 20>& address) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check cache first
    if (cache_.find(address) != cache_.end()) return true;

    // Check DB
    if (!db_) return false;
    std::string key = make_key(address);
    std::string value;
    return db_->Get(leveldb::ReadOptions(), key, &value).ok();
}

std::optional<DigitalDNA> DNARegistryDB::get_identity(const std::array<uint8_t, 20>& address) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check cache first
    auto it = cache_.find(address);
    if (it != cache_.end()) return it->second;

    // Check DB
    if (!db_) return std::nullopt;
    std::string key = make_key(address);
    std::string value;
    leveldb::Status status = db_->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok()) return std::nullopt;

    std::vector<uint8_t> data(value.begin(), value.end());
    return DigitalDNA::deserialize(data);
}

std::vector<std::pair<DigitalDNA, SimilarityScore>> DNARegistryDB::find_similar(
    const DigitalDNA& dna,
    double threshold
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::pair<DigitalDNA, SimilarityScore>> results;

    for (const auto& [addr, other] : cache_) {
        if (addr == dna.address) continue;

        auto score = compare(dna, other);
        if (score.combined_score >= threshold) {
            results.push_back({other, score});
        }
    }

    std::sort(results.begin(), results.end(),
        [](const auto& a, const auto& b) {
            return a.second.combined_score > b.second.combined_score;
        });

    return results;
}

SimilarityScore DNARegistryDB::compare(const DigitalDNA& a, const DigitalDNA& b) const {
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

    return DigitalDNARegistry::compute_combined_score(score);
}

std::vector<DigitalDNA> DNARegistryDB::get_all() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DigitalDNA> result;
    result.reserve(cache_.size());
    for (const auto& [addr, dna] : cache_) {
        result.push_back(dna);
    }
    return result;
}

size_t DNARegistryDB::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.size();
}

bool DNARegistryDB::remove_identity(const std::array<uint8_t, 20>& address) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!db_) return false;

    std::string key = make_key(address);
    leveldb::Status status = db_->Delete(leveldb::WriteOptions(), key);

    cache_.erase(address);

    return status.ok();
}

void DNARegistryDB::clear() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!db_) return;

    // Delete all entries with our prefix
    leveldb::WriteBatch batch;
    std::unique_ptr<leveldb::Iterator> it(db_->NewIterator(leveldb::ReadOptions()));
    for (it->Seek(KEY_PREFIX); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.substr(0, KEY_PREFIX.size()) != KEY_PREFIX) break;
        batch.Delete(key);
    }
    db_->Write(leveldb::WriteOptions(), &batch);

    cache_.clear();
}

// --- Private helpers ---

std::string DNARegistryDB::make_key(const std::array<uint8_t, 20>& address) const {
    return KEY_PREFIX + address_to_hex(address);
}

std::string DNARegistryDB::address_to_hex(const std::array<uint8_t, 20>& addr) {
    std::ostringstream oss;
    for (auto b : addr) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

void DNARegistryDB::load_cache() const {
    if (!db_) return;

    cache_.clear();

    std::unique_ptr<leveldb::Iterator> it(db_->NewIterator(leveldb::ReadOptions()));
    for (it->Seek(KEY_PREFIX); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.substr(0, KEY_PREFIX.size()) != KEY_PREFIX) break;

        std::string value = it->value().ToString();
        std::vector<uint8_t> data(value.begin(), value.end());
        auto dna = DigitalDNA::deserialize(data);
        if (dna) {
            cache_[dna->address] = *dna;
        }

        if (cache_.size() >= MAX_CACHE_SIZE) break;
    }
}

double DNARegistryDB::calculate_latency_similarity(
    const LatencyFingerprint& a, const LatencyFingerprint& b
) const {
    return latency_similarity(a, b);
}

double DNARegistryDB::calculate_timing_similarity(
    const TimingSignature& a, const TimingSignature& b
) const {
    return timing_similarity(a, b);
}

double DNARegistryDB::calculate_perspective_similarity(
    const PerspectiveProof& a, const PerspectiveProof& b
) const {
    return perspective_similarity(a, b);
}

// --- ML Detector Integration ---

void DNARegistryDB::set_ml_detector(std::shared_ptr<MLSybilDetector> detector) {
    std::lock_guard<std::mutex> lock(mutex_);
    ml_detector_ = std::move(detector);
}

std::string DNARegistryDB::ml_status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ml_detector_) return "{\"status\": \"not_configured\"}";
    return ml_detector_->status_json();
}

} // namespace digital_dna
