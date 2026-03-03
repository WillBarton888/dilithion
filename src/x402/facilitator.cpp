// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <x402/facilitator.h>
#include <iostream>
#include <sstream>

namespace x402 {

CFacilitator::CFacilitator() {}

void CFacilitator::RegisterUTXOSet(CUTXOSet* utxo_set) {
    m_vma.RegisterUTXOSet(utxo_set);
}

void CFacilitator::RegisterMempool(CTxMemPool* mempool) {
    m_vma.RegisterMempool(mempool);
}

void CFacilitator::RegisterChainState(CChainState* chainstate) {
    m_vma.RegisterChainState(chainstate);
}

bool CFacilitator::IsX402Request(const std::string& path) {
    return path.find("/x402/") == 0;
}

std::string CFacilitator::HandleRequest(const std::string& method,
                                         const std::string& path,
                                         const std::string& body,
                                         const std::string& clientIP) {
    // Remove /x402/ prefix
    std::string subpath = path.substr(6);  // Skip "/x402/"

    // Find first slash to separate endpoint from parameter
    std::string endpoint;
    std::string param;
    size_t slash = subpath.find('/');
    if (slash != std::string::npos) {
        endpoint = subpath.substr(0, slash);
        param = subpath.substr(slash + 1);
    } else {
        endpoint = subpath;
    }

    // Route to handlers
    if (endpoint == "verify" && method == "POST") {
        return HandleVerify(body, clientIP);
    }
    else if (endpoint == "settle" && method == "POST") {
        return HandleSettle(body, clientIP);
    }
    else if (endpoint == "supported" && method == "GET") {
        return HandleSupported(clientIP);
    }
    else if (endpoint == "status" && method == "GET") {
        if (param.empty()) {
            return BuildErrorResponse(400, "Missing txid parameter");
        }
        return HandleStatus(param, clientIP);
    }
    else {
        return BuildHTTPResponse(404, "{\"error\":\"Not found\",\"path\":\"" + path + "\"}");
    }
}

std::string CFacilitator::HandleVerify(const std::string& body, const std::string& clientIP) {
    // Parse request body
    std::string rawTx, recipient;
    int64_t amount = 0;

    if (!ExtractString(body, "rawTransaction", rawTx)) {
        return BuildErrorResponse(400, "Missing rawTransaction field");
    }
    if (!ExtractString(body, "recipient", recipient)) {
        return BuildErrorResponse(400, "Missing recipient field");
    }
    if (!ExtractInt(body, "amount", amount)) {
        return BuildErrorResponse(400, "Missing or invalid amount field");
    }
    if (amount <= 0) {
        return BuildErrorResponse(400, "Amount must be positive");
    }

    // Run VMA verification
    VerifyResult result;
    if (!m_vma.VerifyPayment(rawTx, recipient, amount, result)) {
        return BuildErrorResponse(500, "Verification engine error");
    }

    // Return result with acceptance tier info
    std::ostringstream oss;
    oss << "{";
    oss << "\"valid\":" << (result.valid ? "true" : "false") << ",";
    oss << "\"reason\":\"" << result.reason << "\",";
    oss << "\"payerAddress\":\"" << result.payerAddress << "\",";
    oss << "\"amount\":" << result.amount << ",";
    oss << "\"tier\":\"" << (m_vma.IsMicropayment(amount) ? "micropayment" : "standard") << "\",";
    oss << "\"confirmationsRequired\":" << (m_vma.IsMicropayment(amount) ? 0 : 1);
    oss << "}";

    return BuildHTTPResponse(result.valid ? 200 : 400, oss.str());
}

std::string CFacilitator::HandleSettle(const std::string& body, const std::string& clientIP) {
    // Parse request body
    std::string rawTx, recipient;
    int64_t amount = 0;

    if (!ExtractString(body, "rawTransaction", rawTx)) {
        return BuildErrorResponse(400, "Missing rawTransaction field");
    }
    if (!ExtractString(body, "recipient", recipient)) {
        return BuildErrorResponse(400, "Missing recipient field");
    }
    if (!ExtractInt(body, "amount", amount)) {
        return BuildErrorResponse(400, "Missing or invalid amount field");
    }
    if (amount <= 0) {
        return BuildErrorResponse(400, "Amount must be positive");
    }

    // Run VMA settlement (verify + broadcast)
    SettlementResult result;
    if (!m_vma.SettlePayment(rawTx, recipient, amount, result)) {
        return BuildErrorResponse(500, "Settlement engine error");
    }

    return BuildHTTPResponse(result.success ? 200 : 400, result.ToJSON());
}

std::string CFacilitator::HandleSupported(const std::string& clientIP) {
    FacilitatorInfo info;
    info.version = "2.0";
    info.schemes = {"exact"};
    info.networks = {NETWORK_ID};
    info.assets = {ASSET_ID};
    info.micropaymentThreshold = m_vma.GetMicropaymentThreshold();
    info.vmaEnabled = true;

    return BuildHTTPResponse(200, info.ToJSON());
}

std::string CFacilitator::HandleStatus(const std::string& txid, const std::string& clientIP) {
    int confirmations = m_vma.GetConfirmations(txid);

    std::ostringstream oss;
    oss << "{";
    oss << "\"txid\":\"" << txid << "\",";
    oss << "\"confirmations\":" << confirmations << ",";
    if (confirmations >= 0) {
        oss << "\"status\":\"" << (confirmations == 0 ? "mempool" : "confirmed") << "\"";
    } else {
        oss << "\"status\":\"not_found\"";
    }
    oss << "}";

    return BuildHTTPResponse(confirmations >= 0 ? 200 : 404, oss.str());
}

std::string CFacilitator::BuildHTTPResponse(int statusCode, const std::string& body) {
    std::ostringstream oss;
    std::string statusText;
    switch (statusCode) {
        case 200: statusText = "OK"; break;
        case 400: statusText = "Bad Request"; break;
        case 404: statusText = "Not Found"; break;
        case 500: statusText = "Internal Server Error"; break;
        default: statusText = "Unknown"; break;
    }

    oss << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    oss << "Content-Type: application/json\r\n";
    oss << "Access-Control-Allow-Origin: *\r\n";
    oss << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    oss << "Access-Control-Allow-Headers: Content-Type, PAYMENT-SIGNATURE, PAYMENT-REQUIRED\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "\r\n";
    oss << body;
    return oss.str();
}

std::string CFacilitator::BuildErrorResponse(int httpCode, const std::string& message) {
    std::ostringstream oss;
    oss << "{\"error\":\"" << message << "\"}";
    return BuildHTTPResponse(httpCode, oss.str());
}

bool CFacilitator::ExtractString(const std::string& json, const std::string& key, std::string& value) {
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

bool CFacilitator::ExtractInt(const std::string& json, const std::string& key, int64_t& value) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return false;

    size_t colon = json.find(':', pos + search.size());
    if (colon == std::string::npos) return false;

    size_t numStart = json.find_first_not_of(" \t\n\r", colon + 1);
    if (numStart == std::string::npos) return false;

    try {
        value = std::stoll(json.substr(numStart));
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace x402
