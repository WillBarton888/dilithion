// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <attestation/seed_attestation.h>
#include <crypto/sha3.h>
#include <util/strencodings.h>
#include <wallet/crypter.h>  // For memory_cleanse()

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif

// Dilithium3 reference implementation
extern "C" {
    int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
    int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *sk);
    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

namespace Attestation {

// File format magic and version
static constexpr uint32_t KEY_FILE_MAGIC = 0x444C4154;  // "DLAT" (Dilithion Attestation)
static constexpr uint8_t KEY_FILE_VERSION = 1;

// ============================================================================
// CSeedAttestationKey
// ============================================================================

CSeedAttestationKey::~CSeedAttestationKey() {
    Clear();
}

void CSeedAttestationKey::Clear() {
    if (!m_privkey.empty()) {
        memory_cleanse(m_privkey.data(), m_privkey.size());
    }
    m_privkey.clear();
    m_pubkey.clear();
}

bool CSeedAttestationKey::Generate() {
    m_pubkey.resize(DFMP::MIK_PUBKEY_SIZE);
    m_privkey.resize(DFMP::MIK_PRIVKEY_SIZE);

    int result = pqcrystals_dilithium3_ref_keypair(m_pubkey.data(), m_privkey.data());
    if (result != 0) {
        Clear();
        return false;
    }
    return true;
}

bool CSeedAttestationKey::Load(const std::string& dataDir) {
    std::string path = dataDir + "/" + SEED_KEY_FILENAME;
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // Read and verify magic
    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), 4);
    if (magic != KEY_FILE_MAGIC) {
        std::cerr << "[Attestation] Invalid key file magic" << std::endl;
        return false;
    }

    // Read and verify version
    uint8_t version = 0;
    file.read(reinterpret_cast<char*>(&version), 1);
    if (version != KEY_FILE_VERSION) {
        std::cerr << "[Attestation] Unsupported key file version: " << (int)version << std::endl;
        return false;
    }

    // Read public key
    m_pubkey.resize(DFMP::MIK_PUBKEY_SIZE);
    file.read(reinterpret_cast<char*>(m_pubkey.data()), DFMP::MIK_PUBKEY_SIZE);

    // Read private key
    m_privkey.resize(DFMP::MIK_PRIVKEY_SIZE);
    file.read(reinterpret_cast<char*>(m_privkey.data()), DFMP::MIK_PRIVKEY_SIZE);

    if (!file.good()) {
        std::cerr << "[Attestation] Key file read error" << std::endl;
        Clear();
        return false;
    }

    std::cout << "[Attestation] Loaded seed attestation key: " << GetPubKeyHex().substr(0, 16) << "..." << std::endl;
    return true;
}

bool CSeedAttestationKey::Save(const std::string& dataDir) const {
    if (!IsValid()) return false;

    std::string path = dataDir + "/" + SEED_KEY_FILENAME;
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "[Attestation] Failed to open key file for writing: " << path << std::endl;
        return false;
    }

    // Write magic
    uint32_t magic = KEY_FILE_MAGIC;
    file.write(reinterpret_cast<const char*>(&magic), 4);

    // Write version
    uint8_t version = KEY_FILE_VERSION;
    file.write(reinterpret_cast<const char*>(&version), 1);

    // Write public key
    file.write(reinterpret_cast<const char*>(m_pubkey.data()), m_pubkey.size());

    // Write private key
    file.write(reinterpret_cast<const char*>(m_privkey.data()), m_privkey.size());

    if (!file.good()) {
        std::cerr << "[Attestation] Key file write error" << std::endl;
        return false;
    }

    std::cout << "[Attestation] Saved seed attestation key to: " << path << std::endl;
    return true;
}

bool CSeedAttestationKey::LoadOrGenerate(const std::string& dataDir) {
    if (Load(dataDir)) {
        return true;
    }

    std::cout << "[Attestation] No existing attestation key found, generating new keypair..." << std::endl;
    if (!Generate()) {
        std::cerr << "[Attestation] Failed to generate attestation keypair" << std::endl;
        return false;
    }

    if (!Save(dataDir)) {
        std::cerr << "[Attestation] WARNING: Generated key but failed to save to disk" << std::endl;
        // Key is still valid in memory, so don't fail
    }

    std::cout << "[Attestation] Generated new seed attestation key: " << GetPubKeyHex().substr(0, 16) << "..." << std::endl;
    return true;
}

bool CSeedAttestationKey::Sign(const std::vector<uint8_t>& message,
                                std::vector<uint8_t>& signature) const {
    if (!IsValid() || m_privkey.empty()) return false;

    signature.resize(DFMP::MIK_SIGNATURE_SIZE);
    size_t siglen = 0;

    int result = pqcrystals_dilithium3_ref_signature(
        signature.data(), &siglen,
        message.data(), message.size(),
        nullptr, 0,
        m_privkey.data()
    );

    if (result != 0 || siglen != DFMP::MIK_SIGNATURE_SIZE) {
        signature.clear();
        return false;
    }
    return true;
}

bool CSeedAttestationKey::IsValid() const {
    return m_pubkey.size() == DFMP::MIK_PUBKEY_SIZE;
}

std::string CSeedAttestationKey::GetPubKeyHex() const {
    return HexStr(m_pubkey);
}

// ============================================================================
// MESSAGE BUILDING
// ============================================================================

std::vector<uint8_t> BuildAttestationMessage(
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    uint32_t timestamp,
    uint8_t seedId)
{
    // Build: "DILV_ATTEST" || mikPubkey || dnaHash || timestamp_le32 || seedId
    std::vector<uint8_t> preimage;
    preimage.reserve(ATTESTATION_DOMAIN_LEN + mikPubkey.size() + 32 + 4 + 1);

    // Domain separator
    preimage.insert(preimage.end(),
        reinterpret_cast<const uint8_t*>(ATTESTATION_DOMAIN),
        reinterpret_cast<const uint8_t*>(ATTESTATION_DOMAIN) + ATTESTATION_DOMAIN_LEN);

    // MIK pubkey
    preimage.insert(preimage.end(), mikPubkey.begin(), mikPubkey.end());

    // DNA hash
    preimage.insert(preimage.end(), dnaHash.begin(), dnaHash.end());

    // Timestamp (little-endian)
    preimage.push_back(static_cast<uint8_t>(timestamp & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 8) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 16) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 24) & 0xFF));

    // Seed ID
    preimage.push_back(seedId);

    // Hash to 32 bytes
    std::vector<uint8_t> hash(32);
    SHA3_256(preimage.data(), preimage.size(), hash.data());
    return hash;
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

bool VerifyAttestation(
    const CAttestation& attestation,
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    const std::vector<uint8_t>& seedPubkey)
{
    if (!attestation.IsValid()) return false;
    if (seedPubkey.size() != DFMP::MIK_PUBKEY_SIZE) return false;

    // Reconstruct the signed message
    std::vector<uint8_t> message = BuildAttestationMessage(
        mikPubkey, dnaHash, attestation.timestamp, attestation.seedId);

    // Verify Dilithium3 signature
    int result = pqcrystals_dilithium3_ref_verify(
        attestation.signature.data(), attestation.signature.size(),
        message.data(), message.size(),
        nullptr, 0,
        seedPubkey.data()
    );

    return (result == 0);
}

bool VerifyAttestationSet(
    const CAttestationSet& attestations,
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    const std::vector<std::vector<uint8_t>>& seedPubkeys,
    int64_t blockTimestamp,
    std::string& error)
{
    if (seedPubkeys.size() != NUM_SEEDS) {
        error = "Invalid seed pubkey count";
        return false;
    }

    int validCount = 0;
    bool usedSeed[NUM_SEEDS] = {};  // Track which seeds have been used (no duplicates)

    for (const auto& att : attestations.attestations) {
        if (att.seedId >= NUM_SEEDS) {
            continue;  // Skip invalid seed IDs
        }

        if (usedSeed[att.seedId]) {
            continue;  // Skip duplicate seed attestations
        }

        // Check freshness: attestation timestamp within validity window of block timestamp
        int64_t timeDiff = blockTimestamp - static_cast<int64_t>(att.timestamp);
        if (timeDiff < 0 || timeDiff > ATTESTATION_VALIDITY_WINDOW) {
            continue;  // Too old or in the future
        }

        // Verify signature
        if (VerifyAttestation(att, mikPubkey, dnaHash, seedPubkeys[att.seedId])) {
            usedSeed[att.seedId] = true;
            validCount++;
        }
    }

    if (validCount < MIN_ATTESTATIONS) {
        error = "Insufficient valid attestations: " + std::to_string(validCount) +
                " of " + std::to_string(MIN_ATTESTATIONS) + " required";
        return false;
    }

    return true;
}

// ============================================================================
// SERIALIZATION
// ============================================================================

bool BuildAttestationScriptData(
    const CAttestationSet& attestations,
    std::vector<uint8_t>& data)
{
    if (attestations.attestations.empty()) return false;
    if (attestations.attestations.size() > 255) return false;  // Count fits in 1 byte

    // Marker
    data.push_back(ATTESTATION_MARKER);

    // Count
    data.push_back(static_cast<uint8_t>(attestations.attestations.size()));

    // Each attestation entry
    for (const auto& att : attestations.attestations) {
        if (!att.IsValid()) return false;

        // Seed ID
        data.push_back(att.seedId);

        // Timestamp (little-endian)
        data.push_back(static_cast<uint8_t>(att.timestamp & 0xFF));
        data.push_back(static_cast<uint8_t>((att.timestamp >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>((att.timestamp >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((att.timestamp >> 24) & 0xFF));

        // Signature
        data.insert(data.end(), att.signature.begin(), att.signature.end());
    }

    return true;
}

bool ParseAttestationScriptData(
    const uint8_t* data,
    size_t dataLen,
    CAttestationSet& attestations,
    size_t& consumed)
{
    consumed = 0;
    attestations.attestations.clear();

    if (dataLen < 2) return false;  // Need at least marker + count

    // Verify marker
    if (data[0] != ATTESTATION_MARKER) return false;

    uint8_t count = data[1];
    size_t expectedSize = 2 + (count * ATTESTATION_ENTRY_SIZE);
    if (dataLen < expectedSize) return false;

    size_t offset = 2;
    for (uint8_t i = 0; i < count; i++) {
        CAttestation att;

        // Seed ID
        att.seedId = data[offset++];

        // Timestamp (little-endian)
        att.timestamp = static_cast<uint32_t>(data[offset]) |
                       (static_cast<uint32_t>(data[offset + 1]) << 8) |
                       (static_cast<uint32_t>(data[offset + 2]) << 16) |
                       (static_cast<uint32_t>(data[offset + 3]) << 24);
        offset += 4;

        // Signature
        att.signature.assign(data + offset, data + offset + DFMP::MIK_SIGNATURE_SIZE);
        offset += DFMP::MIK_SIGNATURE_SIZE;

        attestations.attestations.push_back(std::move(att));
    }

    consumed = offset;
    return true;
}

// ============================================================================
// RPC HELPERS — Request attestation from seed nodes
// ============================================================================

// Simple synchronous HTTP POST for JSON-RPC (no external dependencies)
static bool HttpJsonRpcCall(
    const std::string& host,
    uint16_t port,
    const std::string& jsonBody,
    std::string& response,
    std::string& error,
    int timeoutSec = 10)
{
    // Create socket
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        error = "Failed to create socket";
        return false;
    }
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        error = "Failed to create socket";
        return false;
    }
#endif

    // Set timeout
    struct timeval tv;
    tv.tv_sec = timeoutSec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

    // Resolve and connect
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        error = "Invalid IP address: " + host;
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        error = "Connection failed to " + host + ":" + std::to_string(port);
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    // Build HTTP request with auth header (rpc:rpc)
    std::string httpRequest =
        "POST / HTTP/1.1\r\n"
        "Host: " + host + ":" + std::to_string(port) + "\r\n"
        "Content-Type: application/json\r\n"
        "X-Dilithion-RPC: 1\r\n"
        "Authorization: Basic cnBjOnJwYw==\r\n"  // base64("rpc:rpc")
        "Content-Length: " + std::to_string(jsonBody.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" + jsonBody;

    // Send
    int sent = send(sock, httpRequest.c_str(), static_cast<int>(httpRequest.size()), 0);
    if (sent <= 0) {
        error = "Failed to send request";
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    // Receive response
    response.clear();
    char buf[4096];
    int received;
    while ((received = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[received] = '\0';
        response += buf;
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    if (response.empty()) {
        error = "Empty response from " + host;
        return false;
    }

    // Strip HTTP headers — find the JSON body after \r\n\r\n
    size_t bodyStart = response.find("\r\n\r\n");
    if (bodyStart != std::string::npos) {
        response = response.substr(bodyStart + 4);
    }

    return true;
}

// Simple JSON string value extractor (avoid external JSON library dependency)
static std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";
    pos += searchKey.size();
    size_t endPos = json.find("\"", pos);
    if (endPos == std::string::npos) return "";
    return json.substr(pos, endPos - pos);
}

static std::string ExtractJsonNumber(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";
    pos += searchKey.size();
    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    size_t endPos = pos;
    while (endPos < json.size() && (json[endPos] >= '0' && json[endPos] <= '9')) endPos++;
    if (endPos == pos) return "";
    return json.substr(pos, endPos - pos);
}

bool RequestAttestation(
    const std::string& seedIP,
    uint16_t rpcPort,
    const std::string& mikPubkeyHex,
    const std::string& dnaHashHex,
    CAttestation& attestation,
    std::string& error)
{
    // Build JSON-RPC request
    std::string jsonBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getmikattestation\","
                           "\"params\":{\"mik_pubkey\":\"" + mikPubkeyHex + "\","
                           "\"dna_hash\":\"" + dnaHashHex + "\"}}";

    std::string response;
    if (!HttpJsonRpcCall(seedIP, rpcPort, jsonBody, response, error)) {
        return false;
    }

    // Check for error in response
    if (response.find("\"error\"") != std::string::npos &&
        response.find("\"error\":null") == std::string::npos) {
        // Extract error message
        std::string errMsg = ExtractJsonString(response, "message");
        if (!errMsg.empty()) {
            error = "Seed " + seedIP + ": " + errMsg;
        } else {
            error = "Seed " + seedIP + " returned error: " + response.substr(0, 200);
        }
        return false;
    }

    // Extract result fields
    std::string seedIdStr = ExtractJsonNumber(response, "seed_id");
    std::string timestampStr = ExtractJsonNumber(response, "timestamp");
    std::string signatureHex = ExtractJsonString(response, "signature");

    if (seedIdStr.empty() || timestampStr.empty() || signatureHex.empty()) {
        error = "Missing fields in attestation response from " + seedIP;
        return false;
    }

    attestation.seedId = static_cast<uint8_t>(std::stoi(seedIdStr));
    attestation.timestamp = static_cast<uint32_t>(std::stoul(timestampStr));
    attestation.signature = ParseHex(signatureHex);

    if (attestation.signature.size() != DFMP::MIK_SIGNATURE_SIZE) {
        error = "Invalid signature size from " + seedIP + ": " +
                std::to_string(attestation.signature.size());
        attestation.signature.clear();
        return false;
    }

    return true;
}

bool CollectAttestations(
    const std::vector<std::string>& seedIPs,
    uint16_t rpcPort,
    const std::string& mikPubkeyHex,
    const std::string& dnaHashHex,
    CAttestationSet& attestations,
    std::string& error)
{
    attestations.attestations.clear();
    int failures = 0;

    for (size_t i = 0; i < seedIPs.size(); i++) {
        std::cout << "  [Attestation] Requesting from seed " << i << " (" << seedIPs[i] << ")..." << std::flush;

        CAttestation att;
        std::string seedError;
        if (RequestAttestation(seedIPs[i], rpcPort, mikPubkeyHex, dnaHashHex, att, seedError)) {
            std::cout << " OK" << std::endl;
            attestations.attestations.push_back(std::move(att));

            if (attestations.HasMinimum()) {
                std::cout << "  [Attestation] Collected " << attestations.Count()
                          << " attestations (minimum " << MIN_ATTESTATIONS << " met)" << std::endl;
                return true;
            }
        } else {
            std::cout << " FAILED: " << seedError << std::endl;
            failures++;
        }
    }

    if (!attestations.HasMinimum()) {
        error = "Only " + std::to_string(attestations.Count()) + " of " +
                std::to_string(MIN_ATTESTATIONS) + " required attestations collected (" +
                std::to_string(failures) + " seeds failed)";
        return false;
    }

    return true;
}

} // namespace Attestation
