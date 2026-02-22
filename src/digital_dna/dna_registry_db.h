#ifndef DILITHION_DNA_REGISTRY_DB_H
#define DILITHION_DNA_REGISTRY_DB_H

/**
 * Digital DNA Registry - LevelDB Persistent Storage
 *
 * Stores registered Digital DNA identities on disk for durability
 * across node restarts. Provides Sybil detection via similarity
 * comparison against all registered identities.
 *
 * Key format:
 *   "dna:" + address_hex (20 bytes hex = 40 chars) → serialized DigitalDNA
 *
 * Thread-safe: Protected by internal mutex with in-memory cache.
 */

#include "digital_dna.h"
#include "dna_registry_interface.h"
#include "ml_detector.h"

#include <leveldb/db.h>

#include <memory>
#include <mutex>
#include <map>
#include <string>

namespace digital_dna {

class DNARegistryDB : public IDNARegistry {
public:
    DNARegistryDB();
    ~DNARegistryDB();

    // Prevent copying
    DNARegistryDB(const DNARegistryDB&) = delete;
    DNARegistryDB& operator=(const DNARegistryDB&) = delete;

    /**
     * Open the DNA registry database
     * @param path Directory path for database files (e.g., datadir/dna_registry)
     * @return true if opened successfully
     */
    bool Open(const std::string& path);

    /** Close the database */
    void Close();

    /** Check if database is open */
    bool IsOpen() const;

    // --- IDNARegistry implementation ---

    RegisterResult register_identity(const DigitalDNA& dna) override;
    RegisterResult update_identity(const DigitalDNA& dna) override;
    bool is_registered(const std::array<uint8_t, 20>& address) const override;
    std::optional<DigitalDNA> get_identity(const std::array<uint8_t, 20>& address) const override;
    std::vector<std::pair<DigitalDNA, SimilarityScore>> find_similar(
        const DigitalDNA& dna,
        double threshold = SimilarityScore::SUSPICIOUS_THRESHOLD
    ) const override;
    SimilarityScore compare(const DigitalDNA& a, const DigitalDNA& b) const override;
    std::vector<DigitalDNA> get_all() const override;
    size_t count() const override;

    // --- Additional methods (not in interface) ---

    /** Remove an identity (for Sybil slashing or reorg undo) */
    bool remove_identity(const std::array<uint8_t, 20>& address);

    /** Clear all data (for testing) */
    void clear();

    /** Set ML detector (ADVISORY or SUPPLEMENTARY mode) */
    void set_ml_detector(std::shared_ptr<MLSybilDetector> detector);

    /** Get ML detector status */
    std::string ml_status() const;

private:
    std::shared_ptr<MLSybilDetector> ml_detector_;

    std::unique_ptr<leveldb::DB> db_;
    mutable std::mutex mutex_;
    std::string path_;

    // In-memory cache for fast similarity lookups
    mutable std::map<std::array<uint8_t, 20>, DigitalDNA> cache_;
    static constexpr size_t MAX_CACHE_SIZE = 10000;

    static const std::string KEY_PREFIX;  // "dna:"

    // Key helpers
    std::string make_key(const std::array<uint8_t, 20>& address) const;
    static std::string address_to_hex(const std::array<uint8_t, 20>& addr);

    // Load all identities into cache on startup
    void load_cache() const;

    // Similarity calculation (delegated to same logic as DigitalDNARegistry)
    double calculate_latency_similarity(const LatencyFingerprint& a, const LatencyFingerprint& b) const;
    double calculate_timing_similarity(const TimingSignature& a, const TimingSignature& b) const;
    double calculate_perspective_similarity(const PerspectiveProof& a, const PerspectiveProof& b) const;
};

} // namespace digital_dna

#endif // DILITHION_DNA_REGISTRY_DB_H
