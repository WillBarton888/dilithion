#include "trust_score.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>

namespace digital_dna {

// ============ TrustScore Serialization ============

std::vector<uint8_t> TrustScore::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(64);

    // current_score (8 bytes)
    uint64_t score_bits;
    std::memcpy(&score_bits, &current_score, sizeof(double));
    for (int i = 0; i < 8; i++)
        data.push_back(static_cast<uint8_t>(score_bits >> (i * 8)));

    // lifetime_earned (8 bytes)
    uint64_t lifetime_bits;
    std::memcpy(&lifetime_bits, &lifetime_earned, sizeof(double));
    for (int i = 0; i < 8; i++)
        data.push_back(static_cast<uint8_t>(lifetime_bits >> (i * 8)));

    // registration_height (4 bytes)
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(registration_height >> (i * 8)));

    // last_heartbeat_height (4 bytes)
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(last_heartbeat_height >> (i * 8)));

    // consecutive_heartbeats (4 bytes)
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(consecutive_heartbeats >> (i * 8)));

    // total_heartbeats (4 bytes)
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(total_heartbeats >> (i * 8)));

    // missed_heartbeats (4 bytes)
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(missed_heartbeats >> (i * 8)));

    // blocks_relayed (4 bytes)
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(blocks_relayed >> (i * 8)));

    // challenge_pending (1 byte)
    data.push_back(challenge_pending ? 1 : 0);

    // Phase 5: Rotation tracking (12 bytes)
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(last_dna_change_height >> (i * 8)));
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(dna_change_count >> (i * 8)));
    for (int i = 0; i < 4; i++)
        data.push_back(static_cast<uint8_t>(dna_changes_recent >> (i * 8)));

    return data;  // 53 bytes total (41 + 4+4+4)
}

TrustScore TrustScore::deserialize(const std::vector<uint8_t>& data) {
    TrustScore ts;
    if (data.size() < 41) return ts;

    size_t offset = 0;

    // current_score
    uint64_t score_bits = 0;
    for (int i = 0; i < 8; i++)
        score_bits |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
    std::memcpy(&ts.current_score, &score_bits, sizeof(double));
    offset += 8;

    // lifetime_earned
    uint64_t lifetime_bits = 0;
    for (int i = 0; i < 8; i++)
        lifetime_bits |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
    std::memcpy(&ts.lifetime_earned, &lifetime_bits, sizeof(double));
    offset += 8;

    // registration_height
    for (int i = 0; i < 4; i++)
        ts.registration_height |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
    offset += 4;

    // last_heartbeat_height
    for (int i = 0; i < 4; i++)
        ts.last_heartbeat_height |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
    offset += 4;

    // consecutive_heartbeats
    for (int i = 0; i < 4; i++)
        ts.consecutive_heartbeats |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
    offset += 4;

    // total_heartbeats
    for (int i = 0; i < 4; i++)
        ts.total_heartbeats |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
    offset += 4;

    // missed_heartbeats
    for (int i = 0; i < 4; i++)
        ts.missed_heartbeats |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
    offset += 4;

    // blocks_relayed
    for (int i = 0; i < 4; i++)
        ts.blocks_relayed |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
    offset += 4;

    // challenge_pending
    ts.challenge_pending = data[offset] != 0;

    // Phase 5 fields (backward compatible — old 41-byte data leaves these at 0)
    if (data.size() >= 53) {
        offset = 41;
        for (int i = 0; i < 4; i++)
            ts.last_dna_change_height |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
        offset += 4;
        for (int i = 0; i < 4; i++)
            ts.dna_change_count |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
        offset += 4;
        for (int i = 0; i < 4; i++)
            ts.dna_changes_recent |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
    }

    return ts;
}

// ============ TrustScoreManager ============

TrustScoreManager::TrustScoreManager() {}

void TrustScoreManager::on_registration(const std::array<uint8_t, 20>& address, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    TrustScore& score = scores_[address];
    score.registration_height = height;
    score.current_score = 0.0;

    TrustEvent event;
    event.type = TrustEvent::REGISTRATION_COMPLETE;
    event.block_height = height;
    event.score_delta = 0.0;
    record_event(score, event);
}

void TrustScoreManager::on_heartbeat_success(const std::array<uint8_t, 20>& address, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scores_.find(address);
    if (it == scores_.end()) return;

    TrustScore& score = it->second;

    // Apply decay before adding new score
    apply_decay(score, height);

    TrustEvent event;
    event.type = TrustEvent::HEARTBEAT_SUCCESS;
    event.block_height = height;
    event.score_delta = 1.0;

    // Bonus for consecutive heartbeats (up to +0.5 extra)
    double consecutive_bonus = std::min(0.5, score.consecutive_heartbeats * 0.05);
    event.score_delta += consecutive_bonus;

    apply_event(score, event, height);

    score.last_heartbeat_height = height;
    score.consecutive_heartbeats++;
    score.total_heartbeats++;
}

void TrustScoreManager::on_heartbeat_missed(const std::array<uint8_t, 20>& address, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scores_.find(address);
    if (it == scores_.end()) return;

    TrustScore& score = it->second;

    TrustEvent event;
    event.type = TrustEvent::HEARTBEAT_MISSED;
    event.block_height = height;
    event.score_delta = -5.0;

    apply_event(score, event, height);

    score.consecutive_heartbeats = 0;
    score.missed_heartbeats++;
}

void TrustScoreManager::on_block_relayed(const std::array<uint8_t, 20>& address, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scores_.find(address);
    if (it == scores_.end()) return;

    TrustScore& score = it->second;

    TrustEvent event;
    event.type = TrustEvent::BLOCK_RELAYED_HONEST;
    event.block_height = height;
    event.score_delta = 0.1;

    apply_event(score, event, height);
    score.blocks_relayed++;
}

void TrustScoreManager::on_sybil_challenge(const std::array<uint8_t, 20>& address, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scores_.find(address);
    if (it == scores_.end()) return;

    TrustScore& score = it->second;

    TrustEvent event;
    event.type = TrustEvent::SYBIL_CHALLENGE_RECEIVED;
    event.block_height = height;
    event.score_delta = -10.0;

    apply_event(score, event, height);
    score.challenge_pending = true;
}

void TrustScoreManager::on_sybil_challenge_cleared(const std::array<uint8_t, 20>& address, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scores_.find(address);
    if (it == scores_.end()) return;

    TrustScore& score = it->second;

    TrustEvent event;
    event.type = TrustEvent::SYBIL_CHALLENGE_CLEARED;
    event.block_height = height;
    event.score_delta = 2.0;  // Small reward for surviving challenge

    apply_event(score, event, height);
    score.challenge_pending = false;
}

void TrustScoreManager::on_sybil_challenge_upheld(const std::array<uint8_t, 20>& address, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scores_.find(address);
    if (it == scores_.end()) return;

    TrustScore& score = it->second;

    TrustEvent event;
    event.type = TrustEvent::SYBIL_CHALLENGE_UPHELD;
    event.block_height = height;
    event.score_delta = -score.current_score;  // Zero out completely

    apply_event(score, event, height);
    score.challenge_pending = false;
}

// Phase 5: Rotation & History
void TrustScoreManager::on_dna_changed(const std::array<uint8_t, 20>& address, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scores_.find(address);
    if (it == scores_.end()) return;

    TrustScore& score = it->second;

    TrustEvent event;
    event.type = TrustEvent::DNA_CHANGED;
    event.block_height = height;
    event.score_delta = -10.0;

    apply_event(score, event, height);
    score.last_dna_change_height = height;
    score.dna_change_count++;
    score.dna_changes_recent++;

    // Check for rapid rotation
    if (score.dna_changes_recent >= TrustScore::RAPID_ROTATION_THRESHOLD) {
        on_rapid_rotation(address, height);
    }
}

void TrustScoreManager::on_rapid_rotation(const std::array<uint8_t, 20>& address, uint32_t height) {
    // Note: mutex already held by caller (on_dna_changed)
    auto it = scores_.find(address);
    if (it == scores_.end()) return;

    TrustScore& score = it->second;

    TrustEvent event;
    event.type = TrustEvent::RAPID_ROTATION_FLAGGED;
    event.block_height = height;
    event.score_delta = -20.0;

    apply_event(score, event, height);
}

void TrustScoreManager::on_verification_pass(const std::array<uint8_t, 20>& address, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scores_.find(address);
    if (it == scores_.end()) return;

    TrustEvent event;
    event.type = TrustEvent::VERIFICATION_PASSED;
    event.block_height = height;
    event.score_delta = 2.0;

    apply_event(it->second, event, height);
}

void TrustScoreManager::on_verification_fail(const std::array<uint8_t, 20>& address, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scores_.find(address);
    if (it == scores_.end()) return;

    TrustEvent event;
    event.type = TrustEvent::VERIFICATION_FAILED;
    event.block_height = height;
    event.score_delta = -10.0;

    apply_event(it->second, event, height);
}

TrustScore TrustScoreManager::get_score(const std::array<uint8_t, 20>& address) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scores_.find(address);
    if (it == scores_.end()) return TrustScore{};
    return it->second;
}

TrustScore::Tier TrustScoreManager::get_tier(const std::array<uint8_t, 20>& address) const {
    return get_score(address).get_tier();
}

bool TrustScoreManager::has_score(const std::array<uint8_t, 20>& address) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return scores_.find(address) != scores_.end();
}

std::vector<std::array<uint8_t, 20>> TrustScoreManager::get_addresses_at_tier(
    TrustScore::Tier min_tier
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::array<uint8_t, 20>> result;
    for (const auto& [addr, score] : scores_) {
        if (score.get_tier() >= min_tier) {
            result.push_back(addr);
        }
    }
    return result;
}

size_t TrustScoreManager::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return scores_.size();
}

bool TrustScoreManager::save(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;

    uint32_t count = static_cast<uint32_t>(scores_.size());
    ofs.write(reinterpret_cast<const char*>(&count), 4);

    for (const auto& [addr, score] : scores_) {
        // Write address (20 bytes)
        ofs.write(reinterpret_cast<const char*>(addr.data()), 20);

        // Write serialized score
        auto data = score.serialize();
        uint32_t size = static_cast<uint32_t>(data.size());
        ofs.write(reinterpret_cast<const char*>(&size), 4);
        ofs.write(reinterpret_cast<const char*>(data.data()), size);
    }

    return true;
}

bool TrustScoreManager::load(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;

    uint32_t count;
    ifs.read(reinterpret_cast<char*>(&count), 4);

    scores_.clear();
    for (uint32_t i = 0; i < count; i++) {
        std::array<uint8_t, 20> addr;
        ifs.read(reinterpret_cast<char*>(addr.data()), 20);

        uint32_t size;
        ifs.read(reinterpret_cast<char*>(&size), 4);

        std::vector<uint8_t> data(size);
        ifs.read(reinterpret_cast<char*>(data.data()), size);

        scores_[addr] = TrustScore::deserialize(data);
    }

    return true;
}

// --- Private helpers ---

void TrustScoreManager::apply_event(TrustScore& score, const TrustEvent& event, uint32_t height) {
    // Phase 5: Block positive trust changes during stabilization period
    // (DNA recently changed — trust must re-earn from current level)
    if (event.score_delta > 0 && score.is_stabilizing(height)) {
        record_event(score, event);  // Record but don't apply
        return;
    }

    // Decay recent rotation counter if window has passed
    if (score.dna_changes_recent > 0 && score.last_dna_change_height > 0 &&
        height > score.last_dna_change_height + TrustScore::RAPID_ROTATION_WINDOW) {
        score.dna_changes_recent = 0;
    }

    score.current_score += event.score_delta;
    if (event.score_delta > 0) {
        score.lifetime_earned += event.score_delta;
    }
    clamp_score(score);
    record_event(score, event);
}

void TrustScoreManager::apply_decay(TrustScore& score, uint32_t current_height) {
    if (score.last_heartbeat_height == 0) return;
    if (current_height <= score.last_heartbeat_height) return;

    uint32_t blocks_since = current_height - score.last_heartbeat_height;
    uint32_t decay_periods = blocks_since / TrustScore::DECAY_INTERVAL;

    if (decay_periods > 0) {
        // Exponential decay: score *= (1 - DECAY_RATE)^periods
        double decay_factor = std::pow(1.0 - TrustScore::DECAY_RATE, decay_periods);
        score.current_score *= decay_factor;
        clamp_score(score);
    }
}

void TrustScoreManager::clamp_score(TrustScore& score) {
    score.current_score = std::max(0.0, std::min(TrustScore::MAX_SCORE, score.current_score));
}

void TrustScoreManager::record_event(TrustScore& score, const TrustEvent& event) {
    score.recent_events.push_back(event);
    if (score.recent_events.size() > TrustScore::MAX_RECENT_EVENTS) {
        score.recent_events.erase(score.recent_events.begin());
    }
}

} // namespace digital_dna
