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
#include "dna_verification.h"
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
    RegisterResult append_sample(const DigitalDNA& dna) override;
    bool is_registered(const std::array<uint8_t, 20>& address) const override;
    std::optional<DigitalDNA> get_identity(const std::array<uint8_t, 20>& address) const override;
    std::optional<DigitalDNA> get_identity_by_mik(const std::array<uint8_t, 20>& mik) const override;
    std::vector<std::pair<DigitalDNA, SimilarityScore>> find_similar(
        const DigitalDNA& dna,
        double threshold = SimilarityScore::SUSPICIOUS_THRESHOLD
    ) const override;
    SimilarityScore compare(const DigitalDNA& a, const DigitalDNA& b) const override;
    std::vector<DigitalDNA> get_all() const override;
    size_t count() const override;
    std::vector<std::pair<uint64_t, DigitalDNA>> get_dna_history(
        const std::array<uint8_t, 20>& mik, size_t max_entries = 100) const override;

    // --- Additional methods (not in interface) ---

    /** Remove an identity (for Sybil slashing or reorg undo) */
    bool remove_identity(const std::array<uint8_t, 20>& address);

    /** Clear all data (for testing) */
    void clear();

    /** Enable/disable DNA deduplication enforcement (Sybil defense Phase 2A).
     *  When enabled, register_identity() rejects (does not store) identities
     *  that match an existing identity at the SAME_IDENTITY threshold (>=0.92).
     *  Default: false (advisory mode — store and flag). */
    void SetEnforceDNADedup(bool enforce) { m_enforceDNADedup = enforce; }
    bool GetEnforceDNADedup() const { return m_enforceDNADedup; }

    /** Set ML detector (ADVISORY or SUPPLEMENTARY mode) */
    void set_ml_detector(std::shared_ptr<MLSybilDetector> detector);

    /** Get ML detector status */
    std::string ml_status() const;

    // --- Attestation storage (Phase 2: Verification) ---

    /** Store a verified attestation */
    bool store_attestation(const verification::DNAAttestation& attestation);

    /** Get all attestations for a target MIK */
    std::vector<verification::DNAAttestation> get_attestations(
        const std::array<uint8_t, 20>& target_mik) const;

    /** Count PASS attestations for a target MIK */
    size_t count_pass_attestations(const std::array<uint8_t, 20>& target_mik) const;

    /** Get verification status for a MIK (computed from attestation count) */
    verification::VerificationStatus get_verification_status(
        const std::array<uint8_t, 20>& mik) const;

    /** Get all registered MIK identities (for verifier selection and Phase 1.2 discovery) */
    std::vector<std::array<uint8_t, 20>> get_all_miks() const override;

private:
    std::shared_ptr<MLSybilDetector> ml_detector_;
    bool m_enforceDNADedup{false};  // Phase 2A: reject same-identity DNA (default: advisory)

    std::unique_ptr<leveldb::DB> db_;
    mutable std::mutex mutex_;
    std::string path_;

    // In-memory cache for fast similarity lookups (keyed by address)
    mutable std::map<std::array<uint8_t, 20>, DigitalDNA> cache_;
    // MIK-to-address index for fast MIK lookups
    mutable std::map<std::array<uint8_t, 20>, std::array<uint8_t, 20>> mik_to_address_;
    static constexpr size_t MAX_CACHE_SIZE = 10000;

    static const std::string KEY_PREFIX;      // "dna:"
    static const std::string MIK_KEY_PREFIX;  // "dna_mik:"
    static const std::string HIST_KEY_PREFIX; // "dna_hist:"
    static const std::string ATT_KEY_PREFIX;  // "dna_att:"

    // Key helpers
    std::string make_key(const std::array<uint8_t, 20>& address) const;
    std::string make_mik_key(const std::array<uint8_t, 20>& mik) const;
    std::string make_hist_key(const std::array<uint8_t, 20>& mik, uint64_t timestamp) const;
    std::string make_att_key(const std::array<uint8_t, 20>& target_mik,
                             const std::array<uint8_t, 20>& verifier_mik,
                             uint32_t height) const;
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
