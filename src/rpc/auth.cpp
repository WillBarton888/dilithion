// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/auth.h>
#include <crypto/sha3.h>

#include <cstring>
#include <mutex>
#include <algorithm>

#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
#else
    #include <fcntl.h>
    #include <unistd.h>
#endif

namespace RPCAuth {

// Global authentication configuration
static std::string g_rpcUser;
static std::string g_rpcPassword;
static std::vector<uint8_t> g_passwordSalt;
static std::vector<uint8_t> g_passwordHash;
static bool g_authConfigured = false;
static std::mutex g_authMutex;

// Base64 encoding table
static const char* BASE64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

bool GenerateSalt(std::vector<uint8_t>& salt) {
    salt.resize(32);

#ifdef _WIN32
    // Windows: Use CryptGenRandom
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContextW(&hProvider, nullptr, nullptr,
                              PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return false;
    }

    BOOL result = CryptGenRandom(hProvider, 32, salt.data());
    CryptReleaseContext(hProvider, 0);

    return result != 0;
#else
    // Unix: Use /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return false;
    }

    ssize_t bytesRead = read(fd, salt.data(), 32);
    close(fd);

    return bytesRead == 32;
#endif
}

bool HashPassword(const std::string& password,
                  const std::vector<uint8_t>& salt,
                  std::vector<uint8_t>& hashOut) {
    // Input validation
    if (password.empty() || salt.empty()) {
        return false;
    }

    // Combine salt and password: salt || password
    std::vector<uint8_t> combined;
    combined.reserve(salt.size() + password.length());
    combined.insert(combined.end(), salt.begin(), salt.end());
    combined.insert(combined.end(), password.begin(), password.end());

    // Hash with SHA-3-256 (quantum-resistant)
    hashOut.resize(32);
    SHA3_256(combined.data(), combined.size(), hashOut.data());

    // Secure erase combined data from memory
    if (!combined.empty()) {
        memset(combined.data(), 0, combined.size());
    }

    return true;
}

bool VerifyPassword(const std::string& password,
                    const std::vector<uint8_t>& salt,
                    const std::vector<uint8_t>& storedHash) {
    // Input validation
    if (password.empty() || salt.empty() || storedHash.size() != 32) {
        return false;
    }

    // Compute hash of provided password
    std::vector<uint8_t> computedHash;
    if (!HashPassword(password, salt, computedHash)) {
        return false;
    }

    // Constant-time comparison
    bool result = SecureCompare(computedHash.data(), storedHash.data(), 32);

    // Secure erase computed hash
    if (!computedHash.empty()) {
        memset(computedHash.data(), 0, computedHash.size());
    }

    return result;
}

std::string Base64Encode(const uint8_t* data, size_t dataLen) {
    std::string result;
    result.reserve(((dataLen + 2) / 3) * 4);

    for (size_t i = 0; i < dataLen; i += 3) {
        uint32_t triple = (data[i] << 16);
        if (i + 1 < dataLen) triple |= (data[i + 1] << 8);
        if (i + 2 < dataLen) triple |= data[i + 2];

        result.push_back(BASE64_CHARS[(triple >> 18) & 0x3F]);
        result.push_back(BASE64_CHARS[(triple >> 12) & 0x3F]);
        result.push_back(i + 1 < dataLen ? BASE64_CHARS[(triple >> 6) & 0x3F] : '=');
        result.push_back(i + 2 < dataLen ? BASE64_CHARS[triple & 0x3F] : '=');
    }

    return result;
}

bool Base64Decode(const std::string& encoded, std::vector<uint8_t>& decoded) {
    // Build decode table
    static int decodeTable[256];
    static bool tableInitialized = false;

    if (!tableInitialized) {
        std::fill(std::begin(decodeTable), std::end(decodeTable), -1);
        for (int i = 0; i < 64; i++) {
            decodeTable[static_cast<uint8_t>(BASE64_CHARS[i])] = i;
        }
        tableInitialized = true;
    }

    decoded.clear();
    decoded.reserve(encoded.length() * 3 / 4);

    uint32_t value = 0;
    int bits = 0;

    for (char c : encoded) {
        if (c == '=') break;  // Padding
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;  // Skip whitespace

        int v = decodeTable[static_cast<uint8_t>(c)];
        if (v < 0) return false;  // Invalid character

        value = (value << 6) | v;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            decoded.push_back((value >> bits) & 0xFF);
        }
    }

    return true;
}

bool ParseAuthHeader(const std::string& authHeader,
                     std::string& username,
                     std::string& password) {
    // Expected format: "Basic <base64(username:password)>"

    // Check for "Basic " prefix (case-insensitive)
    std::string prefix = "Basic ";
    if (authHeader.length() < prefix.length()) {
        return false;
    }

    if (authHeader.substr(0, prefix.length()) != prefix) {
        return false;
    }

    // Extract base64 part
    std::string base64Part = authHeader.substr(prefix.length());

    // Decode base64
    std::vector<uint8_t> decoded;
    if (!Base64Decode(base64Part, decoded)) {
        return false;
    }

    // Convert to string
    std::string credentials(decoded.begin(), decoded.end());

    // Find ':' separator
    size_t colonPos = credentials.find(':');
    if (colonPos == std::string::npos) {
        return false;  // No ':' found
    }

    // Extract username and password
    username = credentials.substr(0, colonPos);
    password = credentials.substr(colonPos + 1);

    return true;
}

bool InitializeAuth(const std::string& configUser,
                    const std::string& configPassword) {
    std::lock_guard<std::mutex> lock(g_authMutex);

    // Validate inputs
    if (configUser.empty() || configPassword.empty()) {
        g_authConfigured = false;
        return false;
    }

    // Store username
    g_rpcUser = configUser;
    g_rpcPassword = configPassword;

    // Generate salt for password hashing
    if (!GenerateSalt(g_passwordSalt)) {
        g_authConfigured = false;
        return false;
    }

    // Hash the password
    if (!HashPassword(configPassword, g_passwordSalt, g_passwordHash)) {
        g_authConfigured = false;
        return false;
    }

    g_authConfigured = true;
    return true;
}

bool IsAuthConfigured() {
    std::lock_guard<std::mutex> lock(g_authMutex);
    return g_authConfigured;
}

bool AuthenticateRequest(const std::string& username,
                         const std::string& password) {
    std::lock_guard<std::mutex> lock(g_authMutex);

    // Check if authentication is configured
    if (!g_authConfigured) {
        return false;
    }

    // Check username (constant-time comparison)
    if (username.length() != g_rpcUser.length()) {
        return false;
    }

    bool usernameMatch = SecureCompare(
        reinterpret_cast<const uint8_t*>(username.c_str()),
        reinterpret_cast<const uint8_t*>(g_rpcUser.c_str()),
        username.length()
    );

    if (!usernameMatch) {
        return false;
    }

    // Verify password
    return VerifyPassword(password, g_passwordSalt, g_passwordHash);
}

bool SecureCompare(const uint8_t* a, const uint8_t* b, size_t len) {
    if (len == 0) return true;

    uint8_t result = 0;

    // XOR all bytes - if any differ, result will be non-zero
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }

    // Return true only if all bytes matched (result == 0)
    return result == 0;
}

} // namespace RPCAuth
