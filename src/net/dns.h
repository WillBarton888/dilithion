// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_DNS_H
#define DILITHION_NET_DNS_H

#include <net/protocol.h>
#include <string>
#include <vector>

/**
 * DNS seed query for peer discovery
 */
class CDNSResolver {
public:
    /**
     * Query DNS seed and return list of peer addresses
     *
     * @param seed_hostname DNS seed hostname (e.g., "seed.dilithion.com")
     * @param default_port Default port to use if not specified
     * @return Vector of resolved addresses
     */
    static std::vector<NetProtocol::CAddress> QuerySeed(
        const std::string& seed_hostname,
        uint16_t default_port = NetProtocol::DEFAULT_PORT);

    /**
     * Resolve a single hostname to IP address
     *
     * @param hostname Hostname to resolve
     * @return IP address string, or empty on failure
     */
    static std::string ResolveHostname(const std::string& hostname);

    /**
     * Resolve hostname and return all IP addresses
     *
     * @param hostname Hostname to resolve
     * @return Vector of IP address strings
     */
    static std::vector<std::string> ResolveAll(const std::string& hostname);

    /**
     * Check if a string is a valid IPv4 address
     */
    static bool IsIPv4(const std::string& str);

    /**
     * Check if a string is a valid IPv6 address
     */
    static bool IsIPv6(const std::string& str);

    /**
     * Convert IP address string to CAddress
     *
     * @param ip_str IP address string (e.g., "192.168.1.1")
     * @param port Port number
     * @param services Service flags
     * @return CAddress structure
     */
    static NetProtocol::CAddress MakeAddress(
        const std::string& ip_str,
        uint16_t port,
        uint64_t services = NetProtocol::NODE_NETWORK);
};

#endif // DILITHION_NET_DNS_H
