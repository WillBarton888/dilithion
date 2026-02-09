/**
 * Digital DNA - Anonymous Sybil-Resistant Identity System
 *
 * Combines three unforgeable identity factors:
 *   L - Latency Fingerprint (geographic location via RTT)
 *   V - VDF Timing Signature (hardware fingerprint via computation speed)
 *   P - Perspective Proof (network vantage point via peer observations)
 *
 * Key properties:
 *   - Anonymous: No KYC, no trusted hardware, no personal data
 *   - Unforgeable: Based on physics (speed of light, computation time)
 *   - Verifiable: Third parties can validate claims
 *   - Sybil-resistant: Similar identities flagged for additional verification
 */

#ifndef DILITHION_DIGITAL_DNA_H
#define DILITHION_DIGITAL_DNA_H

#include "latency_fingerprint.h"
#include "timing_signature.h"
#include "perspective_proof.h"

#include <array>
#include <string>
#include <vector>
#include <chrono>
#include <optional>
#include <functional>

namespace digital_dna {

// Forward declarations
class CConnman;  // Peer manager (from net.h)

/**
 * Complete Digital DNA identity.
 *
 * This is the unforgeable identity that proves a miner is unique.
 */
struct DigitalDNA {
    // Identity components
    LatencyFingerprint latency;         // L: Geographic fingerprint
    TimingSignature timing;             // V: Hardware fingerprint
    PerspectiveProof perspective;       // P: Network vantage point

    // Metadata
    std::array<uint8_t, 20> address;    // Coinbase address (identity anchor)
    uint32_t registration_height;       // Block height when registered
    uint64_t registration_time;         // Unix timestamp

    // Validation state
    bool is_valid = false;
    std::string validation_error;

    // Serialization
    std::string to_json() const;
    std::vector<uint8_t> serialize() const;
    static std::optional<DigitalDNA> deserialize(const std::vector<uint8_t>& data);

    // Compute 32-byte identity hash
    std::array<uint8_t, 32> hash() const;
};

/**
 * Similarity score between two Digital DNA identities.
 */
struct SimilarityScore {
    double latency_similarity;      // 0.0 (different) to 1.0 (identical)
    double timing_similarity;       // Based on progress rate
    double perspective_similarity;  // Jaccard similarity of peer sets
    double combined_score;          // Weighted combination

    // Thresholds
    static constexpr double SAME_IDENTITY_THRESHOLD = 0.85;
    static constexpr double SUSPICIOUS_THRESHOLD = 0.70;

    bool is_same_identity() const { return combined_score >= SAME_IDENTITY_THRESHOLD; }
    bool is_suspicious() const { return combined_score >= SUSPICIOUS_THRESHOLD; }

    std::string verdict() const;
};

/**
 * Digital DNA collector.
 *
 * Collects all identity components and creates a DigitalDNA proof.
 */
class DigitalDNACollector {
public:
    struct Config {
        // Latency config
        uint32_t latency_samples;
        uint32_t latency_timeout_ms;

        // Timing config
        uint64_t timing_iterations;
        uint64_t timing_checkpoint_interval;

        // Perspective config
        uint32_t perspective_duration_sec;
        uint32_t perspective_min_peers;

        Config()
            : latency_samples(20)
            , latency_timeout_ms(5000)
            , timing_iterations(1'000'000)
            , timing_checkpoint_interval(10'000)
            , perspective_duration_sec(3600)
            , perspective_min_peers(4)
        {}
    };

    explicit DigitalDNACollector(const std::array<uint8_t, 20>& address, const Config& config = Config());

    // Start/stop collection
    void start_collection();
    void stop_collection();
    bool is_collecting() const { return collecting_; }

    // Progress (0.0 to 1.0)
    double get_progress() const;

    // Get collected DNA (only valid after collection complete)
    std::optional<DigitalDNA> get_dna() const;

    // Peer hooks (call from peer manager)
    void on_peer_connected(const std::array<uint8_t, 20>& peer_id);
    void on_peer_disconnected(const std::array<uint8_t, 20>& peer_id);

private:
    std::array<uint8_t, 20> address_;
    Config config_;
    bool collecting_ = false;

    // Collectors
    LatencyFingerprintCollector latency_collector_;
    TimingSignatureCollector timing_collector_;
    PerspectiveCollector perspective_collector_;

    // Results
    std::optional<LatencyFingerprint> latency_result_;
    std::optional<TimingSignature> timing_result_;
    std::optional<PerspectiveProof> perspective_result_;
};

/**
 * Digital DNA registry.
 *
 * Stores known identities and checks for Sybils.
 */
class DigitalDNARegistry {
public:
    DigitalDNARegistry();

    // Register a new identity
    enum class RegisterResult {
        SUCCESS,
        ALREADY_REGISTERED,
        SYBIL_DETECTED,
        INVALID_DNA,
        COOLDOWN_ACTIVE
    };

    RegisterResult register_identity(const DigitalDNA& dna);

    // Check if address is registered
    bool is_registered(const std::array<uint8_t, 20>& address) const;

    // Get identity by address
    std::optional<DigitalDNA> get_identity(const std::array<uint8_t, 20>& address) const;

    // Find similar identities (potential Sybils)
    std::vector<std::pair<DigitalDNA, SimilarityScore>> find_similar(
        const DigitalDNA& dna,
        double threshold = SimilarityScore::SUSPICIOUS_THRESHOLD
    ) const;

    // Check if two identities are likely the same person
    SimilarityScore compare(const DigitalDNA& a, const DigitalDNA& b) const;

    // Get all registered identities
    std::vector<DigitalDNA> get_all() const;

    // Persistence
    bool save(const std::string& path) const;
    bool load(const std::string& path);

    // Statistics
    size_t count() const { return identities_.size(); }

private:
    std::vector<DigitalDNA> identities_;

    // Similarity calculation
    double calculate_latency_similarity(const LatencyFingerprint& a, const LatencyFingerprint& b) const;
    double calculate_timing_similarity(const TimingSignature& a, const TimingSignature& b) const;
    double calculate_perspective_similarity(const PerspectiveProof& a, const PerspectiveProof& b) const;
};

/**
 * Utility functions
 */

// Compute similarity between two latency fingerprints
// Returns 1.0 if identical, 0.0 if completely different
double latency_similarity(const LatencyFingerprint& a, const LatencyFingerprint& b);

// Compute similarity between two timing signatures
// Based on progress rate comparison
double timing_similarity(const TimingSignature& a, const TimingSignature& b);

// Compute similarity between two perspective proofs
// Uses Jaccard similarity of peer sets
double perspective_similarity(const PerspectiveProof& a, const PerspectiveProof& b);

// Get mainnet seed nodes
const std::array<SeedNode, 4>& get_mainnet_seeds();

// Get testnet seed nodes
const std::array<SeedNode, 3>& get_testnet_seeds();

} // namespace digital_dna

#endif // DILITHION_DIGITAL_DNA_H
