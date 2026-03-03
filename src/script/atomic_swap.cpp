// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <script/atomic_swap.h>
#include <3rdparty/json.hpp>
#include <fstream>
#include <sstream>
#include <chrono>
#include <stdexcept>

using json = nlohmann::json;

// ============================================================================
// String helpers
// ============================================================================

const char* SwapRoleStr(SwapRole role) {
    switch (role) {
        case SwapRole::INITIATOR: return "initiator";
        case SwapRole::RESPONDER: return "responder";
    }
    return "unknown";
}

const char* SwapStateStr(SwapState state) {
    switch (state) {
        case SwapState::CREATED:             return "created";
        case SwapState::HTLC_FUNDED:         return "htlc_funded";
        case SwapState::COUNTERPARTY_FUNDED: return "counterparty_funded";
        case SwapState::CLAIMED:             return "claimed";
        case SwapState::COMPLETED:           return "completed";
        case SwapState::REFUNDED:            return "refunded";
        case SwapState::EXPIRED:             return "expired";
    }
    return "unknown";
}

SwapState ParseSwapState(const std::string& s) {
    if (s == "htlc_funded")         return SwapState::HTLC_FUNDED;
    if (s == "counterparty_funded") return SwapState::COUNTERPARTY_FUNDED;
    if (s == "claimed")             return SwapState::CLAIMED;
    if (s == "completed")           return SwapState::COMPLETED;
    if (s == "refunded")            return SwapState::REFUNDED;
    if (s == "expired")             return SwapState::EXPIRED;
    return SwapState::CREATED;
}

// ============================================================================
// JSON serialization for SwapInfo
// ============================================================================

static std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out += hex[b >> 4];
        out += hex[b & 0xf];
    }
    return out;
}

static std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0) return out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        out.push_back((nibble(hex[i]) << 4) | nibble(hex[i+1]));
    }
    return out;
}

static json SwapToJson(const SwapInfo& s) {
    json j;
    j["swap_id"]             = s.swap_id;
    j["role"]                = static_cast<int>(s.role);
    j["state"]               = static_cast<int>(s.state);
    j["our_chain"]           = s.our_chain;
    j["our_amount"]          = static_cast<int64_t>(s.our_amount);
    j["our_htlc_txid"]       = s.our_htlc_txid;
    j["our_timeout"]         = s.our_timeout;
    j["their_chain"]         = s.their_chain;
    j["their_amount"]        = static_cast<int64_t>(s.their_amount);
    j["their_htlc_txid"]     = s.their_htlc_txid;
    j["their_htlc_vout"]     = s.their_htlc_vout;
    j["their_timeout"]       = s.their_timeout;
    j["preimage"]            = BytesToHex(s.preimage);
    j["hash_lock"]           = BytesToHex(s.hash_lock);
    j["our_refund_address"]  = s.our_refund_address;
    j["our_claim_address"]   = s.our_claim_address;
    j["their_claim_address"] = s.their_claim_address;
    j["created_at"]          = s.created_at;
    return j;
}

static SwapInfo SwapFromJson(const json& j) {
    SwapInfo s;
    s.swap_id             = j.at("swap_id").get<std::string>();
    s.role                = static_cast<SwapRole>(j.at("role").get<int>());
    s.state               = static_cast<SwapState>(j.at("state").get<int>());
    s.our_chain           = j.at("our_chain").get<std::string>();
    s.our_amount          = static_cast<CAmount>(j.at("our_amount").get<int64_t>());
    s.our_htlc_txid       = j.at("our_htlc_txid").get<std::string>();
    s.our_timeout         = j.at("our_timeout").get<uint32_t>();
    s.their_chain         = j.at("their_chain").get<std::string>();
    s.their_amount        = static_cast<CAmount>(j.at("their_amount").get<int64_t>());
    s.their_htlc_txid     = j.value("their_htlc_txid", "");
    s.their_htlc_vout     = j.value("their_htlc_vout", 0u);
    s.their_timeout       = j.value("their_timeout", 0u);
    s.preimage            = HexToBytes(j.at("preimage").get<std::string>());
    s.hash_lock           = HexToBytes(j.at("hash_lock").get<std::string>());
    s.our_refund_address  = j.value("our_refund_address", "");
    s.our_claim_address   = j.value("our_claim_address", "");
    s.their_claim_address = j.value("their_claim_address", "");
    s.created_at          = j.value("created_at", (int64_t)0);
    return s;
}

// ============================================================================
// SwapStore implementation
// ============================================================================

void SwapStore::SetPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_path = path;
}

void SwapStore::Load() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_path.empty()) return;

    std::ifstream f(m_path);
    if (!f.is_open()) return;  // File doesn't exist yet — start fresh

    try {
        json root = json::parse(f);
        if (root.contains("swaps") && root["swaps"].is_array()) {
            for (const auto& item : root["swaps"]) {
                SwapInfo s = SwapFromJson(item);
                m_swaps[s.swap_id] = std::move(s);
            }
        }
    } catch (const std::exception&) {
        // Corrupt file — start fresh (don't crash the node)
    }
}

void SwapStore::Save() const {
    // Caller must hold m_mutex or this is called internally
    if (m_path.empty()) return;

    json root;
    root["swaps"] = json::array();
    for (const auto& kv : m_swaps) {
        root["swaps"].push_back(SwapToJson(kv.second));
    }

    std::ofstream f(m_path);
    if (f.is_open()) {
        f << root.dump(2);
    }
}

std::string SwapStore::AddSwap(const SwapInfo& info) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_swaps[info.swap_id] = info;
    Save();
    return info.swap_id;
}

bool SwapStore::GetSwap(const std::string& swap_id, SwapInfo& out) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_swaps.find(swap_id);
    if (it == m_swaps.end()) return false;
    out = it->second;
    return true;
}

bool SwapStore::UpdateSwap(const std::string& swap_id, const SwapInfo& info) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_swaps.find(swap_id);
    if (it == m_swaps.end()) return false;
    it->second = info;
    Save();
    return true;
}

std::vector<SwapInfo> SwapStore::ListSwaps(int state_filter) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<SwapInfo> result;
    for (const auto& kv : m_swaps) {
        if (state_filter == -1 || static_cast<int>(kv.second.state) == state_filter) {
            result.push_back(kv.second);
        }
    }
    return result;
}

size_t SwapStore::Size() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_swaps.size();
}
