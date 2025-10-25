// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/dns.h>
#include <util/time.h>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

std::vector<NetProtocol::CAddress> CDNSResolver::QuerySeed(
    const std::string& seed_hostname,
    uint16_t default_port)
{
    std::vector<NetProtocol::CAddress> addresses;

    // Resolve all IPs for the seed hostname
    std::vector<std::string> ips = ResolveAll(seed_hostname);

    // Convert to CAddress structures
    for (const auto& ip : ips) {
        NetProtocol::CAddress addr = MakeAddress(ip, default_port);
        addresses.push_back(addr);
    }

    return addresses;
}

std::string CDNSResolver::ResolveHostname(const std::string& hostname) {
    // If it's already an IP, return it
    if (IsIPv4(hostname)) {
        return hostname;
    }

    struct addrinfo hints, *result = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // IPv4
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0) {
        return "";
    }

    std::string ip_str;
    if (result && result->ai_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
        char ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip_buf, INET_ADDRSTRLEN);
        ip_str = ip_buf;
    }

    freeaddrinfo(result);
    return ip_str;
}

std::vector<std::string> CDNSResolver::ResolveAll(const std::string& hostname) {
    std::vector<std::string> ips;

    // If it's already an IP, return it
    if (IsIPv4(hostname)) {
        ips.push_back(hostname);
        return ips;
    }

    struct addrinfo hints, *result = nullptr, *ptr = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // IPv4 only for now
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0) {
        return ips;
    }

    // Iterate through all results
    for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        if (ptr->ai_family == AF_INET) {
            struct sockaddr_in* addr = (struct sockaddr_in*)ptr->ai_addr;
            char ip_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ip_buf, INET_ADDRSTRLEN);
            ips.push_back(ip_buf);
        }
    }

    freeaddrinfo(result);

    // Remove duplicates
    std::sort(ips.begin(), ips.end());
    ips.erase(std::unique(ips.begin(), ips.end()), ips.end());

    return ips;
}

bool CDNSResolver::IsIPv4(const std::string& str) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str.c_str(), &sa.sin_addr) == 1;
}

bool CDNSResolver::IsIPv6(const std::string& str) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, str.c_str(), &sa.sin6_addr) == 1;
}

NetProtocol::CAddress CDNSResolver::MakeAddress(
    const std::string& ip_str,
    uint16_t port,
    uint64_t services)
{
    NetProtocol::CAddress addr;
    addr.time = GetTime();
    addr.services = services;
    addr.port = port;

    // Parse IPv4 address
    if (IsIPv4(ip_str)) {
        struct in_addr ipv4_addr;
        if (inet_pton(AF_INET, ip_str.c_str(), &ipv4_addr) == 1) {
            // Convert to uint32_t in network byte order
            uint32_t ipv4 = ntohl(ipv4_addr.s_addr);
            addr.SetIPv4(ipv4);
        }
    }

    return addr;
}
