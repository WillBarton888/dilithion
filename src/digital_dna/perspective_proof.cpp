#include "perspective_proof.h"

#include <crypto/sha3.h>

#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <numeric>

// Dilithium verification (defined in wallet.cpp, linked at build time)
extern "C" int pqcrystals_dilithium3_ref_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t *pk);

namespace digital_dna {

// Get current timestamp in milliseconds
static uint64_t current_time_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::array<uint8_t, 32> WitnessedObservation::signed_message() const {
    // Build message: peer_id || observer_id || timestamp || block_height
    std::vector<uint8_t> msg;
    msg.reserve(20 + 20 + 8 + 4);

    msg.insert(msg.end(), peer_id.begin(), peer_id.end());
    msg.insert(msg.end(), observer_id.begin(), observer_id.end());

    for (int i = 0; i < 8; i++)
        msg.push_back(static_cast<uint8_t>(timestamp >> (i * 8)));
    for (int i = 0; i < 4; i++)
        msg.push_back(static_cast<uint8_t>(block_height >> (i * 8)));

    std::array<uint8_t, 32> hash;
    SHA3_256(msg.data(), msg.size(), hash.data());
    return hash;
}

bool WitnessedObservation::verify() const {
    // Validate sizes
    if (peer_pubkey.size() != DNA_PUBKEY_SIZE) return false;
    if (peer_signature.empty()) return false;

    // Compute the message hash that was signed
    auto msg = signed_message();

    // Verify Dilithium-3 signature
    int result = pqcrystals_dilithium3_ref_verify(
        peer_signature.data(), peer_signature.size(),
        msg.data(), msg.size(),
        nullptr, 0,  // No context
        peer_pubkey.data()
    );

    return result == 0;
}

size_t PerspectiveProof::total_unique_peers() const {
    std::set<std::array<uint8_t, 20>> all_peers;
    for (const auto& snap : snapshots) {
        for (const auto& peer : snap.active_peers) {
            all_peers.insert(peer);
        }
    }
    return all_peers.size();
}

double PerspectiveProof::peer_turnover_rate() const {
    if (snapshots.size() < 2) return 0.0;

    size_t total_changes = 0;
    for (size_t i = 1; i < snapshots.size(); i++) {
        std::set<std::array<uint8_t, 20>> prev(snapshots[i-1].active_peers.begin(),
                                                snapshots[i-1].active_peers.end());
        std::set<std::array<uint8_t, 20>> curr(snapshots[i].active_peers.begin(),
                                                snapshots[i].active_peers.end());

        for (const auto& p : curr) {
            if (prev.find(p) == prev.end()) total_changes++;
        }
        for (const auto& p : prev) {
            if (curr.find(p) == curr.end()) total_changes++;
        }
    }

    return static_cast<double>(total_changes) / (snapshots.size() - 1);
}

double PerspectiveProof::witness_coverage() const {
    if (snapshots.empty()) return 0.0;

    size_t total_observations = 0;
    size_t witnessed_observations = 0;

    for (const auto& snap : snapshots) {
        total_observations += snap.active_peers.size();
        witnessed_observations += snap.witnessed.size();
    }

    if (total_observations == 0) return 0.0;
    return static_cast<double>(witnessed_observations) / total_observations;
}

size_t PerspectiveProof::verified_witness_count() const {
    size_t count = 0;
    for (const auto& snap : snapshots) {
        for (const auto& w : snap.witnessed) {
            if (w.verify()) count++;
        }
    }
    return count;
}

std::string PerspectiveProof::to_json() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(4);

    oss << "{\n";
    oss << "  \"node_id\": \"";
    for (int i = 0; i < 8; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)node_id[i];
    }
    oss << "...\",\n";

    oss << std::dec;
    oss << "  \"start_time\": " << start_time << ",\n";
    oss << "  \"end_time\": " << end_time << ",\n";
    oss << "  \"duration_sec\": " << (end_time - start_time) / 1000 << ",\n";
    oss << "  \"num_snapshots\": " << snapshots.size() << ",\n";
    oss << "  \"total_unique_peers\": " << total_unique_peers() << ",\n";
    oss << "  \"peer_turnover_rate\": " << peer_turnover_rate() << ",\n";
    oss << "  \"witness_coverage\": " << witness_coverage() << ",\n";

    // Sample of peer counts per snapshot
    oss << "  \"peer_counts\": [";
    size_t show = std::min(snapshots.size(), size_t(10));
    for (size_t i = 0; i < show; i++) {
        oss << snapshots[i].active_peers.size();
        if (i < show - 1) oss << ", ";
    }
    if (snapshots.size() > show) oss << ", ...";
    oss << "]\n";

    oss << "}";

    return oss.str();
}

double PerspectiveProof::similarity(const PerspectiveProof& a, const PerspectiveProof& b) {
    std::set<std::array<uint8_t, 20>> peers_a, peers_b;

    for (const auto& snap : a.snapshots) {
        for (const auto& peer : snap.active_peers) {
            peers_a.insert(peer);
        }
    }

    for (const auto& snap : b.snapshots) {
        for (const auto& peer : snap.active_peers) {
            peers_b.insert(peer);
        }
    }

    return jaccard_similarity(peers_a, peers_b);
}

PerspectiveCollector::PerspectiveCollector(const std::array<uint8_t, 20>& node_id,
                                           const PerspectiveConfig& config)
    : node_id_(node_id), config_(config), start_time_(current_time_ms()) {}

void PerspectiveCollector::on_peer_connected(const std::array<uint8_t, 20>& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    active_peers_.insert(peer_id);
}

void PerspectiveCollector::on_peer_disconnected(const std::array<uint8_t, 20>& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    active_peers_.erase(peer_id);
}

void PerspectiveCollector::add_witness(const WitnessedObservation& obs) {
    std::lock_guard<std::mutex> lock(mutex_);

    // If signatures are required, verify before accepting
    if (config_.require_signatures && !obs.verify()) {
        return;  // Reject unverified witness
    }

    witnesses_.push_back(obs);
}

PerspectiveSnapshot PerspectiveCollector::take_snapshot(uint32_t block_height) {
    std::lock_guard<std::mutex> lock(mutex_);

    PerspectiveSnapshot snap;
    snap.timestamp = current_time_ms();
    snap.block_height = block_height;

    snap.active_peers.assign(active_peers_.begin(), active_peers_.end());

    uint64_t last_snap_time = snapshots_.empty() ? start_time_ : snapshots_.back().timestamp;
    for (const auto& w : witnesses_) {
        if (w.timestamp > last_snap_time && w.timestamp <= snap.timestamp) {
            snap.witnessed.push_back(w);
        }
    }

    snapshots_.push_back(snap);
    return snap;
}

PerspectiveProof PerspectiveCollector::get_proof() const {
    std::lock_guard<std::mutex> lock(mutex_);

    PerspectiveProof proof;
    proof.node_id = node_id_;
    proof.snapshots = snapshots_;
    proof.start_time = start_time_;
    proof.end_time = current_time_ms();

    return proof;
}

void PerspectiveCollector::simulate_peer_activity(int num_peers, int churn_events) {
    std::random_device rd;
    std::mt19937 gen(rd());

    std::vector<std::array<uint8_t, 20>> all_peers;
    for (int i = 0; i < num_peers * 2; i++) {
        all_peers.push_back(generate_random_peer_id());
    }

    for (int i = 0; i < num_peers; i++) {
        on_peer_connected(all_peers[i]);
    }

    // Temporarily disable signature requirement for simulation
    bool orig_require_sigs = config_.require_signatures;
    config_.require_signatures = false;

    std::uniform_int_distribution<> peer_dist(0, static_cast<int>(all_peers.size()) - 1);
    std::uniform_int_distribution<> action_dist(0, 1);

    for (int i = 0; i < churn_events; i++) {
        int idx = peer_dist(gen);
        if (action_dist(gen) == 0) {
            on_peer_connected(all_peers[idx]);
        } else {
            on_peer_disconnected(all_peers[idx]);
        }

        // Occasionally create a simulated witness (no real signature in test mode)
        if (i % 3 == 0) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!active_peers_.empty()) {
                auto it = active_peers_.begin();
                std::advance(it, gen() % active_peers_.size());

                WitnessedObservation obs;
                obs.peer_id = *it;
                obs.observer_id = node_id_;
                obs.timestamp = current_time_ms();
                obs.block_height = static_cast<uint32_t>(i);
                // No real signature in simulation mode

                witnesses_.push_back(obs);
            }
        }
    }

    config_.require_signatures = orig_require_sigs;
}

bool PerspectiveCollector::is_complete() const {
    uint64_t elapsed = current_time_ms() - start_time_;
    return elapsed >= config_.collection_duration_sec * 1000ULL;
}

double PerspectiveCollector::get_progress() const {
    uint64_t elapsed = current_time_ms() - start_time_;
    uint64_t total = config_.collection_duration_sec * 1000ULL;
    return std::min(1.0, static_cast<double>(elapsed) / total);
}

std::array<uint8_t, 20> generate_random_peer_id() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());

    std::array<uint8_t, 20> id;
    for (int i = 0; i < 20; i += 8) {
        uint64_t r = gen();
        for (int j = 0; j < 8 && i + j < 20; j++) {
            id[i + j] = static_cast<uint8_t>(r >> (j * 8));
        }
    }
    return id;
}

double jaccard_similarity(const std::set<std::array<uint8_t, 20>>& a,
                          const std::set<std::array<uint8_t, 20>>& b) {
    if (a.empty() && b.empty()) return 1.0;
    if (a.empty() || b.empty()) return 0.0;

    size_t intersection = 0;
    for (const auto& x : a) {
        if (b.find(x) != b.end()) {
            intersection++;
        }
    }

    size_t union_size = a.size() + b.size() - intersection;
    return static_cast<double>(intersection) / union_size;
}

} // namespace digital_dna
