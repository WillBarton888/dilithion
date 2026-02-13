#ifndef DILITHION_MEMORY_FINGERPRINT_H
#define DILITHION_MEMORY_FINGERPRINT_H

/**
 * Memory Subsystem Fingerprinting
 *
 * Creates a hardware fingerprint by probing memory access patterns at
 * different working set sizes. Sharp jumps in access time reveal cache
 * boundaries (L1/L2/L3/DRAM), creating a unique "memory curve" per machine.
 *
 * Key properties:
 * - Different hardware classes (laptop/desktop/server) produce distinct curves
 * - Co-located VMs on same host produce identical curves (shared memory hierarchy)
 * - Cannot be faked (hardware physical constraints)
 * - Probing completes in ~5-10 seconds
 */

#include <vector>
#include <array>
#include <cstdint>
#include <string>

namespace digital_dna {

struct MemoryProbeResult {
    uint32_t working_set_kb;        // Size of working set for this probe
    double access_time_ns;          // Average random access time at this size
    double bandwidth_mbps;          // Sequential throughput at this size
};

struct MemoryFingerprint {
    // Access time curve at different working set sizes
    std::vector<MemoryProbeResult> access_curve;

    // Derived features (detected cache boundaries)
    double estimated_l1_kb = 0;
    double estimated_l2_kb = 0;
    double estimated_l3_kb = 0;
    double dram_latency_ns = 0;
    double peak_bandwidth_mbps = 0;

    // Comparison using Dynamic Time Warping on access curves
    static double similarity(const MemoryFingerprint& a, const MemoryFingerprint& b);

    // Serialization
    std::string to_json() const;
    std::vector<uint8_t> serialize() const;
    static MemoryFingerprint deserialize(const std::vector<uint8_t>& data);
};

class MemoryFingerprintCollector {
public:
    // Collect memory fingerprint (~5-10 seconds)
    MemoryFingerprint collect();

private:
    // Probe at specific working set size using pointer-chase pattern
    MemoryProbeResult probe_random_access(uint32_t working_set_kb, uint32_t iterations);

    // Probe sequential bandwidth at specific working set size
    double probe_bandwidth(uint32_t working_set_kb);

    // Detect cache boundaries from access curve inflection points
    void detect_cache_boundaries(MemoryFingerprint& fp);

    // Working set sizes to probe (KB)
    static const std::vector<uint32_t> PROBE_SIZES;

    // Number of random accesses per probe
    static constexpr uint32_t ACCESSES_PER_PROBE = 1000000;
};

} // namespace digital_dna

#endif // DILITHION_MEMORY_FINGERPRINT_H
