// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/protocol.h>
#include <core/version.h>
#include <util/strencodings.h>
#include <ctime>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace NetProtocol {

/** Global network magic (defaults to mainnet) */
uint32_t g_network_magic = MAINNET_MAGIC;

std::string CInv::ToString() const {
    const char* type_str = "unknown";
    switch (type) {
        case MSG_TX_INV: type_str = "TX"; break;
        case MSG_BLOCK_INV: type_str = "BLOCK"; break;
        case MSG_FILTERED_BLOCK: type_str = "FILTERED_BLOCK"; break;
        case MSG_CMPCT_BLOCK: type_str = "CMPCT_BLOCK"; break;
    }
    return strprintf("CInv(%s %s)", type_str, hash.GetHex().c_str());
}

std::string CAddress::ToStringIP() const {
    if (IsIPv4()) {
        return strprintf("%d.%d.%d.%d",
                        ip[12], ip[13], ip[14], ip[15]);
    }
    // IPv6: use inet_ntop for proper compressed format (e.g., ::1, 2001:db8::1)
    struct in6_addr ipv6_addr;
    memcpy(&ipv6_addr, ip, 16);
    char buf[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &ipv6_addr, buf, sizeof(buf)) != nullptr) {
        return std::string(buf);
    }
    return "unknown";
}

std::string CAddress::ToString() const {
    std::ostringstream oss;
    if (IsIPv4()) {
        oss << ToStringIP() << ":" << static_cast<unsigned int>(port);
    } else {
        oss << "[" << ToStringIP() << "]:" << static_cast<unsigned int>(port);
    }
    oss << " (services=0x" << std::hex << std::setfill('0') << std::setw(16)
        << static_cast<unsigned long long>(services) << std::dec
        << ", time=" << static_cast<unsigned int>(time) << ")";
    return oss.str();
}

bool CAddress::SetFromString(const std::string& ipStr) {
    // Try IPv4 first
    struct in_addr ipv4_addr;
    if (inet_pton(AF_INET, ipStr.c_str(), &ipv4_addr) == 1) {
        uint32_t ipv4 = ntohl(ipv4_addr.s_addr);
        SetIPv4(ipv4);
        return true;
    }
    // Try IPv6
    struct in6_addr ipv6_addr;
    if (inet_pton(AF_INET6, ipStr.c_str(), &ipv6_addr) == 1) {
        memcpy(ip, &ipv6_addr, 16);
        return true;
    }
    return false;
}

// BUG #50 FIX: Accept blockchain height parameter following Bitcoin Core pattern
// This enables proper Initial Block Download (IBD) detection by remote peers
CVersionMessage::CVersionMessage(int32_t blockchain_height)
    : version(PROTOCOL_VERSION),
      services(NODE_NETWORK),
      timestamp(std::time(nullptr)),
      nonce(0),
      user_agent("/Dilithion:" + GetVersionString() + "/"),
      start_height(blockchain_height),  // Use actual blockchain height, not hardcoded 0
      relay(true)
{
}

std::string CVersionMessage::ToString() const {
    // CID 1675294 FIX: Use std::ostringstream to completely eliminate printf format specifiers
    // This ensures type safety: version (int32_t), services (uint64_t), timestamp (int64_t),
    // start_height (int32_t), relay (bool)
    std::ostringstream oss;
    oss << "CVersionMessage(version=" << static_cast<int>(version)
        << ", services=0x" << std::hex << std::setfill('0') << std::setw(16)
        << static_cast<unsigned long long>(services) << std::dec
        << ", timestamp=" << static_cast<long long>(timestamp)
        << ", user_agent=" << user_agent
        << ", start_height=" << static_cast<int>(start_height)
        << ", relay=" << (relay ? "true" : "false") << ")";
    return oss.str();
}

} // namespace NetProtocol
