#ifndef DILITHION_BANDWIDTH_PROOF_H
#define DILITHION_BANDWIDTH_PROOF_H

/**
 * Proof of Bandwidth (6th Dimension)
 *
 * Network bandwidth is a physical constraint that varies dramatically
 * between connection types (home broadband, datacenter, mobile).
 * Measuring relay throughput adds an orthogonal dimension and helps
 * detect co-located VMs that share bandwidth (contention detection).
 *
 * Key metrics:
 * - Upload/download throughput (Mbps)
 * - Asymmetry ratio: home ~0.1, datacenter ~1.0
 * - Bandwidth stability: cloud = stable, home = variable
 */

#include <array>
#include <vector>
#include <cstdint>
#include <string>
#include <mutex>

namespace digital_dna {

struct BandwidthMeasurement {
    std::array<uint8_t, 20> peer_id;
    double upload_mbps = 0.0;
    double download_mbps = 0.0;
    double asymmetry_ratio = 0.0;       // upload/download
    uint64_t timestamp = 0;
    std::vector<uint8_t> peer_signature; // Peer attests to measurement
};

struct BandwidthFingerprint {
    std::vector<BandwidthMeasurement> measurements;

    // Derived metrics (computed from measurements)
    double median_upload_mbps = 0.0;
    double median_download_mbps = 0.0;
    double median_asymmetry = 0.0;
    double bandwidth_stability = 0.0;     // Stddev of measurements (lower = more stable)

    // Minimum measurements before fingerprint is reliable
    static constexpr uint32_t MIN_MEASUREMENTS = 3;

    bool is_reliable() const { return measurements.size() >= MIN_MEASUREMENTS; }

    // Compute derived metrics from measurements
    void compute_derived();

    // Comparison
    static double similarity(const BandwidthFingerprint& a, const BandwidthFingerprint& b);

    // Serialization
    std::string to_json() const;
    std::vector<uint8_t> serialize() const;
    static BandwidthFingerprint deserialize(const std::vector<uint8_t>& data);
};

// Bandwidth test configuration
struct BandwidthTestConfig {
    uint32_t payload_size = 1024 * 1024;  // 1 MB test payload
    uint32_t timeout_ms = 30000;           // 30 second timeout
    uint32_t min_peers = 3;                // Minimum peers to test
    uint32_t max_peers = 8;                // Maximum peers to test
};

class BandwidthProofCollector {
public:
    BandwidthProofCollector(const BandwidthTestConfig& config = BandwidthTestConfig());

    // Record a bandwidth measurement result from a peer exchange
    void record_measurement(const BandwidthMeasurement& measurement);

    // Compute transfer throughput from payload size and elapsed time
    static double compute_throughput_mbps(uint32_t payload_bytes, uint64_t elapsed_ms);

    // Get current fingerprint
    BandwidthFingerprint get_fingerprint() const;

    // Check readiness
    bool is_ready() const;

    // Reset
    void reset();

private:
    mutable std::mutex mutex_;
    BandwidthTestConfig config_;
    std::vector<BandwidthMeasurement> measurements_;
    static constexpr size_t MAX_MEASUREMENTS = 1000;
};

} // namespace digital_dna

#endif // DILITHION_BANDWIDTH_PROOF_H
