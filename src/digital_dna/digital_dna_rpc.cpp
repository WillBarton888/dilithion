/**
 * Digital DNA RPC Implementation
 */

#include "digital_dna_rpc.h"
#include <core/node_context.h>

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <memory>

// Forward-declared in node_context.h
extern NodeContext g_node_context;

namespace digital_dna {

static std::array<uint8_t, 20> g_my_address = {};

DigitalDNARpc::DigitalDNARpc(IDNARegistry& registry)
    : registry_(registry) {}

void DigitalDNARpc::register_commands() {
    handlers_["getmydigitaldna"] = [this](const JsonObject& p) { return cmd_getmydigitaldna(p); };
    handlers_["registerdigitaldna"] = [this](const JsonObject& p) { return cmd_registerdigitaldna(p); };
    handlers_["getdigitaldna"] = [this](const JsonObject& p) { return cmd_getdigitaldna(p); };
    handlers_["comparedigitaldna"] = [this](const JsonObject& p) { return cmd_comparedigitaldna(p); };
    handlers_["findsimilaridentities"] = [this](const JsonObject& p) { return cmd_findsimilaridentities(p); };
    handlers_["listdigitaldna"] = [this](const JsonObject& p) { return cmd_listdigitaldna(p); };
    handlers_["getdigitaldnastats"] = [this](const JsonObject& p) { return cmd_getdigitaldnastats(p); };
    handlers_["collectdigitaldna"] = [this](const JsonObject& p) { return cmd_collectdigitaldna(p); };
    handlers_["validatedigitaldna"] = [this](const JsonObject& p) { return cmd_validatedigitaldna(p); };
    handlers_["getlatencyfingerprint"] = [this](const JsonObject& p) { return cmd_getlatencyfingerprint(p); };
    handlers_["gettimingsignature"] = [this](const JsonObject& p) { return cmd_gettimingsignature(p); };
    handlers_["getperspectiveproof"] = [this](const JsonObject& p) { return cmd_getperspectiveproof(p); };
}

RpcHandler DigitalDNARpc::get_handler(const std::string& method) const {
    auto it = handlers_.find(method);
    if (it != handlers_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::string> DigitalDNARpc::list_commands() const {
    std::vector<std::string> cmds;
    for (const auto& [name, _] : handlers_) {
        cmds.push_back(name);
    }
    std::sort(cmds.begin(), cmds.end());
    return cmds;
}

JsonObject DigitalDNARpc::execute(const std::string& method, const JsonObject& params) {
    auto handler = get_handler(method);
    if (!handler) {
        return error(-32601, "Method not found: " + method);
    }
    return handler(params);
}

void DigitalDNARpc::set_my_address(const std::array<uint8_t, 20>& address) {
    g_my_address = address;
}

std::shared_ptr<DigitalDNACollector> DigitalDNARpc::get_collector() {
    return g_node_context.GetDNACollector();
}

void DigitalDNARpc::set_collector(std::shared_ptr<DigitalDNACollector> collector) {
    g_node_context.SetDNACollector(std::move(collector));
}

// ============ Command Implementations ============

JsonObject DigitalDNARpc::cmd_getmydigitaldna(const JsonObject& params) {
    // Get this node's collected Digital DNA
    auto collector = g_node_context.GetDNACollector();
    if (!collector) {
        return error(-1, "Digital DNA not collected yet. Run 'collectdigitaldna start' first.");
    }

    auto dna = collector->get_dna();
    if (!dna) {
        JsonObject result;
        result["status"] = "collecting";
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << (collector->get_progress() * 100);
        result["progress"] = oss.str() + "%";
        return result;
    }

    return dna_to_json(*dna);
}

JsonObject DigitalDNARpc::cmd_registerdigitaldna(const JsonObject& params) {
    // Register this node's Digital DNA on-chain
    auto collector = g_node_context.GetDNACollector();
    if (!collector) {
        return error(-1, "Digital DNA not collected yet");
    }

    auto dna = collector->get_dna();
    if (!dna) {
        return error(-1, "DNA collection incomplete");
    }

    auto result = registry_.register_identity(*dna);

    JsonObject response;
    switch (result) {
        case IDNARegistry::RegisterResult::SUCCESS:
            response["status"] = "success";
            response["address"] = address_to_hex(dna->address);
            response["message"] = "Identity registered successfully";
            break;
        case IDNARegistry::RegisterResult::ALREADY_REGISTERED:
            response["status"] = "error";
            response["error"] = "already_registered";
            response["message"] = "This address is already registered";
            break;
        case IDNARegistry::RegisterResult::SYBIL_FLAGGED:
            response["status"] = "success";
            response["address"] = address_to_hex(dna->address);
            response["message"] = "Identity registered (advisory: similar identity exists)";
            response["sybil_flagged"] = "true";
            break;
        case IDNARegistry::RegisterResult::INVALID_DNA:
            response["status"] = "error";
            response["error"] = "invalid_dna";
            response["message"] = "Digital DNA proof is invalid";
            break;
        case IDNARegistry::RegisterResult::UPDATED:
            response["status"] = "success";
            response["address"] = address_to_hex(dna->address);
            response["message"] = "Identity updated with enriched dimensions";
            break;
        case IDNARegistry::RegisterResult::DB_ERROR:
            response["status"] = "error";
            response["error"] = "db_error";
            response["message"] = "Database write failed";
            break;
    }

    return response;
}

JsonObject DigitalDNARpc::cmd_getdigitaldna(const JsonObject& params) {
    // Get Digital DNA for a specific address
    auto it = params.find("address");
    if (it == params.end()) {
        return error(-1, "Missing required parameter: address");
    }

    auto address = hex_to_address(it->second);
    auto dna = registry_.get_identity(address);

    if (!dna) {
        return error(-1, "Address not registered: " + it->second);
    }

    return dna_to_json(*dna);
}

JsonObject DigitalDNARpc::cmd_comparedigitaldna(const JsonObject& params) {
    // Compare two identities for similarity
    auto it1 = params.find("address1");
    auto it2 = params.find("address2");

    if (it1 == params.end() || it2 == params.end()) {
        return error(-1, "Missing required parameters: address1, address2");
    }

    auto addr1 = hex_to_address(it1->second);
    auto addr2 = hex_to_address(it2->second);

    auto dna1 = registry_.get_identity(addr1);
    auto dna2 = registry_.get_identity(addr2);

    if (!dna1) return error(-1, "Address not registered: " + it1->second);
    if (!dna2) return error(-1, "Address not registered: " + it2->second);

    auto score = registry_.compare(*dna1, *dna2);

    JsonObject result;
    result["address1"] = it1->second;
    result["address2"] = it2->second;
    result["latency_similarity"] = std::to_string(score.latency_similarity);
    result["timing_similarity"] = std::to_string(score.timing_similarity);
    result["perspective_similarity"] = std::to_string(score.perspective_similarity);
    result["combined_score"] = std::to_string(score.combined_score);
    result["verdict"] = score.verdict();
    result["is_same_identity"] = score.is_same_identity() ? "true" : "false";
    result["is_suspicious"] = score.is_suspicious() ? "true" : "false";

    return result;
}

JsonObject DigitalDNARpc::cmd_findsimilaridentities(const JsonObject& params) {
    // Find identities similar to a given address
    auto it = params.find("address");
    if (it == params.end()) {
        return error(-1, "Missing required parameter: address");
    }

    double threshold = SimilarityScore::SUSPICIOUS_THRESHOLD;
    auto th_it = params.find("threshold");
    if (th_it != params.end()) {
        threshold = std::stod(th_it->second);
    }

    auto address = hex_to_address(it->second);
    auto dna = registry_.get_identity(address);

    if (!dna) return error(-1, "Address not registered: " + it->second);

    auto similar = registry_.find_similar(*dna, threshold);

    JsonObject result;
    result["address"] = it->second;
    result["threshold"] = std::to_string(threshold);
    result["count"] = std::to_string(similar.size());

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < similar.size(); i++) {
        oss << "{";
        oss << "\"address\": \"" << address_to_hex(similar[i].first.address) << "\", ";
        oss << "\"similarity\": " << std::fixed << std::setprecision(4) << similar[i].second.combined_score << ", ";
        oss << "\"verdict\": \"" << similar[i].second.verdict() << "\"";
        oss << "}";
        if (i < similar.size() - 1) oss << ", ";
    }
    oss << "]";
    result["similar"] = oss.str();

    return result;
}

JsonObject DigitalDNARpc::cmd_listdigitaldna(const JsonObject& params) {
    // List all registered identities
    int limit = 100;
    auto it = params.find("limit");
    if (it != params.end()) {
        limit = std::stoi(it->second);
    }

    int offset = 0;
    auto off_it = params.find("offset");
    if (off_it != params.end()) {
        offset = std::stoi(off_it->second);
    }

    auto all = registry_.get_all();

    JsonObject result;
    result["total"] = std::to_string(all.size());
    result["limit"] = std::to_string(limit);
    result["offset"] = std::to_string(offset);

    std::ostringstream oss;
    oss << "[";
    int count = 0;
    for (size_t i = offset; i < all.size() && count < limit; i++, count++) {
        oss << "{";
        oss << "\"address\": \"" << address_to_hex(all[i].address) << "\", ";
        oss << "\"registration_height\": " << all[i].registration_height << ", ";
        oss << "\"iterations_per_sec\": " << std::fixed << std::setprecision(0)
            << all[i].timing.iterations_per_second;
        oss << "}";
        if (i < all.size() - 1 && count < limit - 1) oss << ", ";
    }
    oss << "]";
    result["identities"] = oss.str();

    return result;
}

JsonObject DigitalDNARpc::cmd_getdigitaldnastats(const JsonObject& params) {
    // Get network-wide identity statistics
    auto all = registry_.get_all();

    double total_ips = 0;
    double min_ips = std::numeric_limits<double>::max();
    double max_ips = 0;

    std::map<std::string, int> region_counts;

    for (const auto& dna : all) {
        total_ips += dna.timing.iterations_per_second;
        min_ips = std::min(min_ips, dna.timing.iterations_per_second);
        max_ips = std::max(max_ips, dna.timing.iterations_per_second);

        // Determine region from latency (lowest RTT = closest seed)
        double min_rtt = std::numeric_limits<double>::max();
        std::string region = "unknown";
        for (const auto& s : dna.latency.seed_stats) {
            if (s.median_ms < min_rtt && s.median_ms > 0) {
                min_rtt = s.median_ms;
                region = s.seed_name;
            }
        }
        region_counts[region]++;
    }

    JsonObject result;
    result["total_identities"] = std::to_string(all.size());

    if (!all.empty()) {
        result["avg_iterations_per_sec"] = std::to_string(total_ips / all.size());
        result["min_iterations_per_sec"] = std::to_string(min_ips);
        result["max_iterations_per_sec"] = std::to_string(max_ips);
    }

    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (const auto& [region, count] : region_counts) {
        if (!first) oss << ", ";
        oss << "\"" << region << "\": " << count;
        first = false;
    }
    oss << "}";
    result["region_distribution"] = oss.str();

    // Sybil detection summary
    int suspicious_pairs = 0;
    int same_identity_pairs = 0;
    for (size_t i = 0; i < all.size(); i++) {
        for (size_t j = i + 1; j < all.size(); j++) {
            auto score = registry_.compare(all[i], all[j]);
            if (score.is_same_identity()) same_identity_pairs++;
            else if (score.is_suspicious()) suspicious_pairs++;
        }
    }
    result["suspicious_pairs"] = std::to_string(suspicious_pairs);
    result["same_identity_pairs"] = std::to_string(same_identity_pairs);

    return result;
}

JsonObject DigitalDNARpc::cmd_collectdigitaldna(const JsonObject& params) {
    // Start or check DNA collection process
    auto it = params.find("action");
    std::string action = it != params.end() ? it->second : "status";

    if (action == "start") {
        auto cur = g_node_context.GetDNACollector();
        if (cur && cur->is_collecting()) {
            return error(-1, "Collection already in progress");
        }

        // Create new collector — shared_ptr for safe cross-thread replacement
        auto new_collector = std::make_shared<DigitalDNACollector>(g_my_address);
        new_collector->start_collection();
        set_collector(std::move(new_collector));

        JsonObject result;
        result["status"] = "started";
        result["message"] = "Digital DNA collection started";
        return result;

    } else if (action == "stop") {
        auto collector = g_node_context.GetDNACollector();
        if (!collector) {
            return error(-1, "No collection in progress");
        }

        collector->stop_collection();

        JsonObject result;
        result["status"] = "stopped";
        return result;

    } else {  // status
        auto collector = g_node_context.GetDNACollector();
        if (!collector) {
            JsonObject result;
            result["status"] = "not_started";
            result["message"] = "Run 'collectdigitaldna start' to begin";
            return result;
        }

        JsonObject result;
        if (collector->is_collecting()) {
            result["status"] = "collecting";
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(1) << (collector->get_progress() * 100);
            result["progress"] = oss.str() + "%";
        } else {
            auto dna = collector->get_dna();
            if (dna) {
                result["status"] = "complete";
                result["is_valid"] = dna->is_valid ? "true" : "false";
            } else {
                result["status"] = "incomplete";
            }
        }
        return result;
    }
}

JsonObject DigitalDNARpc::cmd_validatedigitaldna(const JsonObject& params) {
    // Validate a Digital DNA proof
    auto it = params.find("address");
    if (it == params.end()) {
        return error(-1, "Missing required parameter: address");
    }

    auto address = hex_to_address(it->second);
    auto dna = registry_.get_identity(address);

    if (!dna) return error(-1, "Address not registered");

    JsonObject result;
    result["address"] = it->second;
    result["is_valid"] = dna->is_valid ? "true" : "false";

    // Check for Sybils
    auto similar = registry_.find_similar(*dna, SimilarityScore::SUSPICIOUS_THRESHOLD);
    result["has_similar_identities"] = similar.empty() ? "false" : "true";
    result["similar_count"] = std::to_string(similar.size());

    // Validate components
    bool latency_valid = dna->latency.seed_stats[0].samples > 0;
    bool timing_valid = dna->timing.iterations_per_second > 0;
    bool perspective_valid = dna->perspective.total_unique_peers() > 0;

    result["latency_valid"] = latency_valid ? "true" : "false";
    result["timing_valid"] = timing_valid ? "true" : "false";
    result["perspective_valid"] = perspective_valid ? "true" : "false";

    return result;
}

JsonObject DigitalDNARpc::cmd_getlatencyfingerprint(const JsonObject& params) {
    // Get just the latency component
    auto it = params.find("address");

    if (it != params.end()) {
        // Get for specific address
        auto address = hex_to_address(it->second);
        auto dna = registry_.get_identity(address);
        if (!dna) return error(-1, "Address not registered");

        JsonObject result;
        result["address"] = it->second;

        std::ostringstream oss;
        oss << "[";
        for (size_t i = 0; i < dna->latency.seed_stats.size(); i++) {
            const auto& s = dna->latency.seed_stats[i];
            oss << "{";
            oss << "\"seed\": \"" << s.seed_name << "\", ";
            oss << "\"median_ms\": " << std::fixed << std::setprecision(2) << s.median_ms << ", ";
            oss << "\"stddev_ms\": " << s.stddev_ms << ", ";
            oss << "\"samples\": " << s.samples;
            oss << "}";
            if (i < dna->latency.seed_stats.size() - 1) oss << ", ";
        }
        oss << "]";
        result["seeds"] = oss.str();

        return result;
    }

    // Get live measurement for this node
    LatencyFingerprintCollector collector;
    collector.set_samples_per_seed(10);
    collector.set_timeout_ms(5000);

    LatencyFingerprint fp;
    for (size_t i = 0; i < MAINNET_SEEDS.size(); i++) {
        fp.seed_stats[i] = collector.measure_seed(MAINNET_SEEDS[i]);
    }

    JsonObject result;
    result["type"] = "live_measurement";

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < fp.seed_stats.size(); i++) {
        const auto& s = fp.seed_stats[i];
        oss << "{";
        oss << "\"seed\": \"" << s.seed_name << "\", ";
        oss << "\"median_ms\": " << std::fixed << std::setprecision(2) << s.median_ms << ", ";
        oss << "\"samples\": " << s.samples;
        oss << "}";
        if (i < fp.seed_stats.size() - 1) oss << ", ";
    }
    oss << "]";
    result["seeds"] = oss.str();

    return result;
}

JsonObject DigitalDNARpc::cmd_gettimingsignature(const JsonObject& params) {
    // Get just the timing component
    auto it = params.find("address");

    if (it != params.end()) {
        // Get for specific address
        auto address = hex_to_address(it->second);
        auto dna = registry_.get_identity(address);
        if (!dna) return error(-1, "Address not registered");

        JsonObject result;
        result["address"] = it->second;
        result["iterations"] = std::to_string(dna->timing.total_iterations);
        result["iterations_per_second"] = std::to_string(dna->timing.iterations_per_second);
        result["mean_interval_us"] = std::to_string(dna->timing.mean_interval_us);
        result["stddev_interval_us"] = std::to_string(dna->timing.stddev_interval_us);

        return result;
    }

    // Run live benchmark
    uint64_t iterations = 1'000'000;
    auto bench_it = params.find("iterations");
    if (bench_it != params.end()) {
        iterations = std::stoull(bench_it->second);
    }

    TimingConfig config;
    config.total_iterations = iterations;
    config.checkpoint_interval = 10000;
    config.warmup_iterations = 10000;

    TimingSignatureCollector collector(config);

    std::array<uint8_t, 32> challenge = {};
    auto timing = collector.collect(challenge);

    JsonObject result;
    result["type"] = "live_measurement";
    result["iterations"] = std::to_string(timing.total_iterations);
    result["total_time_ms"] = std::to_string(timing.total_time_us / 1000.0);
    result["iterations_per_second"] = std::to_string(timing.iterations_per_second);
    result["mean_interval_us"] = std::to_string(timing.mean_interval_us);
    result["stddev_interval_us"] = std::to_string(timing.stddev_interval_us);

    return result;
}

JsonObject DigitalDNARpc::cmd_getperspectiveproof(const JsonObject& params) {
    // Get just the perspective component
    auto it = params.find("address");

    if (it != params.end()) {
        // Get for specific address
        auto address = hex_to_address(it->second);
        auto dna = registry_.get_identity(address);
        if (!dna) return error(-1, "Address not registered");

        JsonObject result;
        result["address"] = it->second;
        result["total_unique_peers"] = std::to_string(dna->perspective.total_unique_peers());
        result["peer_turnover_rate"] = std::to_string(dna->perspective.peer_turnover_rate());
        result["witness_coverage"] = std::to_string(dna->perspective.witness_coverage());
        result["num_snapshots"] = std::to_string(dna->perspective.snapshots.size());

        return result;
    }

    // Get current node's perspective (would need peer manager integration)
    JsonObject result;
    result["type"] = "current_node";
    result["message"] = "Perspective requires peer manager integration";
    result["status"] = "not_available";

    return result;
}

// ============ Helpers ============

std::string DigitalDNARpc::address_to_hex(const std::array<uint8_t, 20>& addr) const {
    std::ostringstream oss;
    for (auto b : addr) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

std::array<uint8_t, 20> DigitalDNARpc::hex_to_address(const std::string& hex) const {
    std::array<uint8_t, 20> addr = {};
    for (size_t i = 0; i < 20 && i * 2 + 1 < hex.size(); i++) {
        addr[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
    }
    return addr;
}

JsonObject DigitalDNARpc::dna_to_json(const DigitalDNA& dna) const {
    JsonObject result;

    result["address"] = address_to_hex(dna.address);
    result["registration_height"] = std::to_string(dna.registration_height);
    result["registration_time"] = std::to_string(dna.registration_time);
    result["is_valid"] = dna.is_valid ? "true" : "false";

    // Latency
    std::ostringstream lat_oss;
    lat_oss << "[";
    for (size_t i = 0; i < dna.latency.seed_stats.size(); i++) {
        const auto& s = dna.latency.seed_stats[i];
        lat_oss << std::fixed << std::setprecision(1) << s.median_ms;
        if (i < dna.latency.seed_stats.size() - 1) lat_oss << ", ";
    }
    lat_oss << "]";
    result["latency_fingerprint_ms"] = lat_oss.str();

    // Timing
    result["iterations_per_second"] = std::to_string(dna.timing.iterations_per_second);

    // Perspective
    result["unique_peers"] = std::to_string(dna.perspective.total_unique_peers());
    result["peer_turnover"] = std::to_string(dna.perspective.peer_turnover_rate());

    // Hash
    auto hash = dna.hash();
    std::ostringstream hash_oss;
    for (int i = 0; i < 8; i++) {
        hash_oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    hash_oss << "...";
    result["identity_hash"] = hash_oss.str();

    return result;
}

JsonObject DigitalDNARpc::score_to_json(const SimilarityScore& score) const {
    JsonObject result;
    result["latency_similarity"] = std::to_string(score.latency_similarity);
    result["timing_similarity"] = std::to_string(score.timing_similarity);
    result["perspective_similarity"] = std::to_string(score.perspective_similarity);
    result["combined_score"] = std::to_string(score.combined_score);
    result["verdict"] = score.verdict();
    return result;
}

JsonObject DigitalDNARpc::error(int code, const std::string& message) const {
    JsonObject result;
    result["error"] = "true";
    result["code"] = std::to_string(code);
    result["message"] = message;
    return result;
}

// ============ Help Documentation ============

std::vector<RpcCommandInfo> get_rpc_help() {
    return {
        {
            "getmydigitaldna",
            "Get this node's Digital DNA identity",
            "None",
            "Object with address, latency fingerprint, timing signature, perspective proof",
            "getmydigitaldna"
        },
        {
            "registerdigitaldna",
            "Register this node's identity on-chain (requires collected DNA)",
            "None",
            "Object with status (success/error) and message",
            "registerdigitaldna"
        },
        {
            "getdigitaldna",
            "Get Digital DNA for any registered address",
            "address (string) - 40-character hex address",
            "Object with full Digital DNA details",
            "getdigitaldna {\"address\": \"0123456789abcdef0123456789abcdef01234567\"}"
        },
        {
            "comparedigitaldna",
            "Compare two identities for similarity (Sybil detection)",
            "address1 (string), address2 (string) - two addresses to compare",
            "Object with similarity scores and verdict (SAME_IDENTITY/SUSPICIOUS/DIFFERENT)",
            "comparedigitaldna {\"address1\": \"...\", \"address2\": \"...\"}"
        },
        {
            "findsimilaridentities",
            "Find identities similar to a given address",
            "address (string), threshold (optional, default 0.70)",
            "Array of similar identities with similarity scores",
            "findsimilaridentities {\"address\": \"...\", \"threshold\": 0.8}"
        },
        {
            "listdigitaldna",
            "List all registered identities",
            "limit (optional, default 100), offset (optional, default 0)",
            "Array of registered identities",
            "listdigitaldna {\"limit\": 50, \"offset\": 0}"
        },
        {
            "getdigitaldnastats",
            "Get network-wide identity statistics",
            "None",
            "Object with total identities, region distribution, Sybil detection summary",
            "getdigitaldnastats"
        },
        {
            "collectdigitaldna",
            "Start/check DNA collection process",
            "action (string) - 'start', 'stop', or 'status' (default)",
            "Collection status and progress",
            "collectdigitaldna {\"action\": \"start\"}"
        },
        {
            "validatedigitaldna",
            "Validate a Digital DNA proof",
            "address (string) - address to validate",
            "Validation results and Sybil check",
            "validatedigitaldna {\"address\": \"...\"}"
        },
        {
            "getlatencyfingerprint",
            "Get latency fingerprint (live measurement or for address)",
            "address (optional) - if provided, get stored fingerprint",
            "RTT measurements to all seed nodes",
            "getlatencyfingerprint  OR  getlatencyfingerprint {\"address\": \"...\"}"
        },
        {
            "gettimingsignature",
            "Get timing signature (live benchmark or for address)",
            "address (optional), iterations (optional, default 1M)",
            "VDF timing metrics",
            "gettimingsignature  OR  gettimingsignature {\"iterations\": 5000000}"
        },
        {
            "getperspectiveproof",
            "Get perspective proof for an address",
            "address (string) - address to query",
            "Peer observation statistics",
            "getperspectiveproof {\"address\": \"...\"}"
        }
    };
}

} // namespace digital_dna
