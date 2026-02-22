#ifndef DILITHION_TRUST_SCORE_H
#define DILITHION_TRUST_SCORE_H

/**
 * Digital DNA Progressive Trust Scoring
 *
 * Creates a time-weighted reputation score that makes Sybil attacks
 * fundamentally more expensive. New identities start at 0; trust builds
 * through consistent honest participation over time.
 *
 * Trust tiers:
 *   UNTRUSTED  (0-10)   Basic participation only
 *   NEW        (10-30)  Can participate in witness committees (low weight)
 *   ESTABLISHED(30-60)  Full witness committee participation
 *   TRUSTED    (60-90)  Priority in tie-breaking, higher witness weight
 *   VETERAN    (90-100) Can serve as latency measurement reference node
 *
 * Key property: Time cannot be purchased. 100 new Sybils = 100 untrusted
 * identities vs a single 6-month veteran with high trust.
 */

#include <array>
#include <vector>
#include <map>
#include <cstdint>
#include <cmath>
#include <string>
#include <mutex>

namespace digital_dna {

struct TrustEvent {
    enum Type {
        HEARTBEAT_SUCCESS,          // +1.0 per successful heartbeat
        HEARTBEAT_MISSED,           // -5.0 per missed heartbeat
        BLOCK_RELAYED_HONEST,       // +0.1 per honestly relayed block
        SYBIL_CHALLENGE_RECEIVED,   // -10.0 (hold until resolved)
        SYBIL_CHALLENGE_CLEARED,    // +2.0 (vindicated after challenge)
        SYBIL_CHALLENGE_UPHELD,     // Score zeroed (identity is Sybil)
        REGISTRATION_COMPLETE,      // +0.0 (start at zero)
    };

    Type type;
    uint32_t block_height;
    uint64_t timestamp;
    double score_delta;
};

struct TrustScore {
    double current_score = 0.0;         // Current trust (0.0 to 100.0)
    double lifetime_earned = 0.0;       // Sum of all positive contributions
    uint32_t registration_height = 0;
    uint32_t last_heartbeat_height = 0;
    uint32_t consecutive_heartbeats = 0;
    uint32_t total_heartbeats = 0;
    uint32_t missed_heartbeats = 0;
    uint32_t blocks_relayed = 0;
    bool challenge_pending = false;

    // Recent events (last 50 for diagnostics)
    std::vector<TrustEvent> recent_events;
    static constexpr size_t MAX_RECENT_EVENTS = 50;

    // Trust tier thresholds
    static constexpr double TIER_UNTRUSTED = 0.0;
    static constexpr double TIER_NEW = 10.0;
    static constexpr double TIER_ESTABLISHED = 30.0;
    static constexpr double TIER_TRUSTED = 60.0;
    static constexpr double TIER_VETERAN = 90.0;
    static constexpr double MAX_SCORE = 100.0;

    // Decay: trust decays by 0.1% per 2000 blocks (~5.5 days) of inactivity
    static constexpr double DECAY_RATE = 0.001;
    static constexpr uint32_t DECAY_INTERVAL = 2000;

    enum Tier { UNTRUSTED, NEW, ESTABLISHED, TRUSTED, VETERAN };

    Tier get_tier() const {
        if (current_score >= TIER_VETERAN) return VETERAN;
        if (current_score >= TIER_TRUSTED) return TRUSTED;
        if (current_score >= TIER_ESTABLISHED) return ESTABLISHED;
        if (current_score >= TIER_NEW) return NEW;
        return UNTRUSTED;
    }

    const char* tier_name() const {
        switch (get_tier()) {
            case VETERAN: return "VETERAN";
            case TRUSTED: return "TRUSTED";
            case ESTABLISHED: return "ESTABLISHED";
            case NEW: return "NEW";
            default: return "UNTRUSTED";
        }
    }

    // Time-weighted score: score * log2(age_in_blocks / 1000 + 1)
    double time_weighted_score(uint32_t current_height) const {
        if (current_height <= registration_height) return current_score;
        uint32_t age = current_height - registration_height;
        double time_multiplier = std::log2(static_cast<double>(age) / 1000.0 + 1.0);
        return current_score * std::max(1.0, time_multiplier);
    }

    // Serialization for LevelDB storage
    std::vector<uint8_t> serialize() const;
    static TrustScore deserialize(const std::vector<uint8_t>& data);
};

class TrustScoreManager {
public:
    TrustScoreManager();

    // --- Event Handlers ---

    void on_registration(const std::array<uint8_t, 20>& address, uint32_t height);
    void on_heartbeat_success(const std::array<uint8_t, 20>& address, uint32_t height);
    void on_heartbeat_missed(const std::array<uint8_t, 20>& address, uint32_t height);
    void on_block_relayed(const std::array<uint8_t, 20>& address, uint32_t height);
    void on_sybil_challenge(const std::array<uint8_t, 20>& address, uint32_t height);
    void on_sybil_challenge_cleared(const std::array<uint8_t, 20>& address, uint32_t height);
    void on_sybil_challenge_upheld(const std::array<uint8_t, 20>& address, uint32_t height);

    // --- Queries ---

    TrustScore get_score(const std::array<uint8_t, 20>& address) const;
    TrustScore::Tier get_tier(const std::array<uint8_t, 20>& address) const;
    bool has_score(const std::array<uint8_t, 20>& address) const;

    // Get all identities at or above a trust tier
    std::vector<std::array<uint8_t, 20>> get_addresses_at_tier(TrustScore::Tier min_tier) const;

    // Get count of tracked identities
    size_t count() const;

    // --- Persistence ---

    bool save(const std::string& db_path) const;
    bool load(const std::string& db_path);

private:
    mutable std::mutex mutex_;
    std::map<std::array<uint8_t, 20>, TrustScore> scores_;

    void apply_event(TrustScore& score, const TrustEvent& event, uint32_t height);
    void apply_decay(TrustScore& score, uint32_t current_height);
    void clamp_score(TrustScore& score);
    void record_event(TrustScore& score, const TrustEvent& event);
};

} // namespace digital_dna

#endif // DILITHION_TRUST_SCORE_H
