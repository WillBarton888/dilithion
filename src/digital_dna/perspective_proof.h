#ifndef DILITHION_PERSPECTIVE_PROOF_H
#define DILITHION_PERSPECTIVE_PROOF_H

#include <vector>
#include <array>
#include <map>
#include <set>
#include <chrono>
#include <cstdint>
#include <string>
#include <mutex>

namespace digital_dna {

// Dilithium-3 signature constants (matching wallet.h)
static constexpr size_t DNA_PUBKEY_SIZE = 1952;
static constexpr size_t DNA_SIGNATURE_SIZE = 3309;

// A witnessed peer observation (peer-signed receipt using Dilithium)
struct WitnessedObservation {
    std::array<uint8_t, 20> peer_id;        // Hash of peer's public key
    std::array<uint8_t, 20> observer_id;    // Our identity
    uint64_t timestamp;                      // When observation occurred
    uint32_t block_height;                   // Block height at observation

    // Dilithium signature from the peer attesting to this observation
    std::vector<uint8_t> peer_pubkey;       // Peer's full public key (1952 bytes)
    std::vector<uint8_t> peer_signature;    // Dilithium signature (~3309 bytes)

    // Verify the peer's Dilithium signature on this observation
    bool verify() const;

    // Compute the message that is signed: SHA3-256(peer_id || observer_id || timestamp || height)
    std::array<uint8_t, 32> signed_message() const;
};

// Perspective snapshot at a point in time
struct PerspectiveSnapshot {
    uint64_t timestamp;
    uint32_t block_height;
    std::vector<std::array<uint8_t, 20>> active_peers;  // Peers we're connected to
    std::vector<WitnessedObservation> witnessed;        // Peer-signed receipts

    // Metrics
    size_t unique_peer_count() const { return active_peers.size(); }
};

// Full perspective proof over a time window
struct PerspectiveProof {
    std::array<uint8_t, 20> node_id;
    std::vector<PerspectiveSnapshot> snapshots;
    uint64_t start_time = 0;
    uint64_t end_time = 0;

    // Cached summary from serialization (used when snapshots are not available)
    uint32_t cached_peer_count = 0;
    double cached_turnover_rate = 0.0;

    // Derived metrics
    size_t total_unique_peers() const;
    double peer_turnover_rate() const;          // How often peers change
    double witness_coverage() const;            // % of observations with witnesses
    size_t verified_witness_count() const;      // Count of cryptographically verified witnesses

    // Serialization
    std::string to_json() const;

    // Comparison - Jaccard similarity of peer sets
    static double similarity(const PerspectiveProof& a, const PerspectiveProof& b);
};

// Configuration for perspective collection
struct PerspectiveConfig {
    uint32_t snapshot_interval_sec = 60;        // Take snapshot every 60 seconds
    uint32_t collection_duration_sec = 3600;    // Collect for 1 hour
    uint32_t min_witnesses_required = 3;        // Minimum peer witnesses needed
    bool require_signatures = true;             // Require real Dilithium signatures
};

// Perspective collector (would integrate with node's peer manager)
class PerspectiveCollector {
public:
    PerspectiveCollector(const std::array<uint8_t, 20>& node_id,
                         const PerspectiveConfig& config = PerspectiveConfig());

    // Record a peer connection/disconnection
    void on_peer_connected(const std::array<uint8_t, 20>& peer_id);
    void on_peer_disconnected(const std::array<uint8_t, 20>& peer_id);

    // Record a witnessed observation (peer signed our presence)
    void add_witness(const WitnessedObservation& obs);

    // Take a snapshot of current state
    PerspectiveSnapshot take_snapshot(uint32_t block_height);

    // Get collected proof
    PerspectiveProof get_proof() const;

    // Simulate peer activity for testing
    void simulate_peer_activity(int num_peers, int churn_events);

    // Check if collection is complete
    bool is_complete() const;

    // Get progress (0.0 to 1.0)
    double get_progress() const;

private:
    std::array<uint8_t, 20> node_id_;
    PerspectiveConfig config_;

    // Current state
    std::set<std::array<uint8_t, 20>> active_peers_;
    std::vector<WitnessedObservation> witnesses_;
    std::vector<PerspectiveSnapshot> snapshots_;

    uint64_t start_time_;
    mutable std::mutex mutex_;
};

// Utility: Generate a random peer ID for simulation
std::array<uint8_t, 20> generate_random_peer_id();

// Utility: Compute Jaccard similarity between two peer sets
double jaccard_similarity(const std::set<std::array<uint8_t, 20>>& a,
                          const std::set<std::array<uint8_t, 20>>& b);

} // namespace digital_dna

#endif // DILITHION_PERSPECTIVE_PROOF_H
