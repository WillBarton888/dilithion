// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <x402/x402_types.h>
#include <sstream>
#include <algorithm>

namespace x402 {

// Helper: escape a string for JSON
static std::string EscapeJSON(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 10);
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c; break;
        }
    }
    return result;
}

// Helper: extract a string value from JSON by key (simple parser, no nesting)
static bool ExtractString(const std::string& json, const std::string& key, std::string& value) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return false;

    size_t colon = json.find(':', pos + search.size());
    if (colon == std::string::npos) return false;

    size_t q1 = json.find('"', colon);
    if (q1 == std::string::npos) return false;

    size_t q2 = json.find('"', q1 + 1);
    if (q2 == std::string::npos) return false;

    value = json.substr(q1 + 1, q2 - q1 - 1);
    return true;
}

// Helper: extract an integer value from JSON by key
static bool ExtractInt(const std::string& json, const std::string& key, int64_t& value) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return false;

    size_t colon = json.find(':', pos + search.size());
    if (colon == std::string::npos) return false;

    // Skip whitespace
    size_t numStart = json.find_first_not_of(" \t\n\r", colon + 1);
    if (numStart == std::string::npos) return false;

    try {
        value = std::stoll(json.substr(numStart));
        return true;
    } catch (...) {
        return false;
    }
}

// --- PaymentRequired ---

std::string PaymentRequired::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"version\":" << version << ",";
    oss << "\"error\":\"" << EscapeJSON(error) << "\",";
    oss << "\"resource\":{";
    oss << "\"url\":\"" << EscapeJSON(resource.url) << "\",";
    oss << "\"description\":\"" << EscapeJSON(resource.description) << "\",";
    oss << "\"mimeType\":\"" << EscapeJSON(resource.mimeType) << "\"";
    oss << "},";
    oss << "\"accepts\":[";
    for (size_t i = 0; i < accepts.size(); i++) {
        if (i > 0) oss << ",";
        const auto& a = accepts[i];
        oss << "{";
        oss << "\"scheme\":\"" << EscapeJSON(a.scheme) << "\",";
        oss << "\"network\":\"" << EscapeJSON(a.network) << "\",";
        oss << "\"asset\":\"" << EscapeJSON(a.asset) << "\",";
        oss << "\"amount\":" << a.amount << ",";
        oss << "\"recipient\":\"" << EscapeJSON(a.recipient) << "\",";
        oss << "\"timeout\":" << a.timeout;
        oss << "}";
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

bool PaymentRequired::FromJSON(const std::string& json, PaymentRequired& out, std::string& error) {
    int64_t ver;
    if (!ExtractInt(json, "version", ver)) {
        error = "Missing version field";
        return false;
    }
    out.version = static_cast<int>(ver);
    ExtractString(json, "error", out.error);

    // Parse resource (simplified: just extract top-level fields)
    ExtractString(json, "url", out.resource.url);
    ExtractString(json, "description", out.resource.description);
    ExtractString(json, "mimeType", out.resource.mimeType);

    // Parse accepts array (simplified: extract first entry)
    out.accepts.clear();
    PaymentOption opt;
    if (ExtractString(json, "scheme", opt.scheme) &&
        ExtractString(json, "network", opt.network)) {
        ExtractString(json, "asset", opt.asset);
        ExtractInt(json, "amount", opt.amount);
        ExtractString(json, "recipient", opt.recipient);
        ExtractInt(json, "timeout", opt.timeout);
        out.accepts.push_back(opt);
    }

    return true;
}

// --- PaymentPayload ---

std::string PaymentPayload::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"version\":" << version << ",";
    oss << "\"scheme\":\"" << EscapeJSON(scheme) << "\",";
    oss << "\"network\":\"" << EscapeJSON(network) << "\",";
    oss << "\"resource\":\"" << EscapeJSON(resource) << "\",";
    oss << "\"rawTransaction\":\"" << EscapeJSON(rawTransaction) << "\",";
    oss << "\"payerAddress\":\"" << EscapeJSON(payerAddress) << "\"";
    oss << "}";
    return oss.str();
}

bool PaymentPayload::FromJSON(const std::string& json, PaymentPayload& out, std::string& error) {
    int64_t ver;
    if (!ExtractInt(json, "version", ver)) {
        error = "Missing version field";
        return false;
    }
    out.version = static_cast<int>(ver);

    if (!ExtractString(json, "rawTransaction", out.rawTransaction)) {
        error = "Missing rawTransaction field";
        return false;
    }

    ExtractString(json, "scheme", out.scheme);
    ExtractString(json, "network", out.network);
    ExtractString(json, "resource", out.resource);
    ExtractString(json, "payerAddress", out.payerAddress);
    return true;
}

// --- VerifyResult ---

std::string VerifyResult::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"valid\":" << (valid ? "true" : "false") << ",";
    oss << "\"reason\":\"" << EscapeJSON(reason) << "\",";
    oss << "\"payerAddress\":\"" << EscapeJSON(payerAddress) << "\",";
    oss << "\"amount\":" << amount;
    oss << "}";
    return oss.str();
}

// --- SettlementResult ---

std::string SettlementResult::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"success\":" << (success ? "true" : "false") << ",";
    oss << "\"error\":\"" << EscapeJSON(error) << "\",";
    oss << "\"txHash\":\"" << EscapeJSON(txHash) << "\",";
    oss << "\"payerAddress\":\"" << EscapeJSON(payerAddress) << "\",";
    oss << "\"network\":\"" << EscapeJSON(network) << "\",";
    oss << "\"confirmations\":" << confirmations;
    oss << "}";
    return oss.str();
}

// --- FacilitatorInfo ---

std::string FacilitatorInfo::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"version\":\"" << EscapeJSON(version) << "\",";
    oss << "\"schemes\":[";
    for (size_t i = 0; i < schemes.size(); i++) {
        if (i > 0) oss << ",";
        oss << "\"" << EscapeJSON(schemes[i]) << "\"";
    }
    oss << "],";
    oss << "\"networks\":[";
    for (size_t i = 0; i < networks.size(); i++) {
        if (i > 0) oss << ",";
        oss << "\"" << EscapeJSON(networks[i]) << "\"";
    }
    oss << "],";
    oss << "\"assets\":[";
    for (size_t i = 0; i < assets.size(); i++) {
        if (i > 0) oss << ",";
        oss << "\"" << EscapeJSON(assets[i]) << "\"";
    }
    oss << "],";
    oss << "\"micropaymentThreshold\":" << micropaymentThreshold << ",";
    oss << "\"vmaEnabled\":" << (vmaEnabled ? "true" : "false");
    oss << "}";
    return oss.str();
}

} // namespace x402
