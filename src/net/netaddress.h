// Copyright (c) 2009-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DILITHION_NET_NETADDRESS_H
#define DILITHION_NET_NETADDRESS_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <functional>

/**
 * @file netaddress.h
 * @brief Network address classes ported from Bitcoin Core
 *
 * Provides CNetAddr (IP address) and CService (IP + port) classes
 * for use in AddrMan and peer management.
 *
 * Key features:
 * - Network type classification (IPv4, IPv6, Tor, I2P)
 * - Network group calculation for eclipse attack protection
 * - Routability and validity checks
 * - Serialization support
 */

/**
 * Network types supported by Dilithion
 */
enum Network {
    NET_UNROUTABLE = 0,  ///< Unroutable (localhost, private, etc.)
    NET_IPV4 = 1,        ///< IPv4 addresses
    NET_IPV6 = 2,        ///< IPv6 addresses
    NET_ONION = 3,       ///< Tor v3 onion addresses (future)
    NET_I2P = 4,         ///< I2P addresses (future)
    NET_CJDNS = 5,       ///< CJDNS addresses (future)
    NET_INTERNAL = 6,    ///< Internal use only
    NET_MAX = 7,
};

/**
 * @class CNetAddr
 * @brief Network address (IP address without port)
 *
 * Stores IP addresses in IPv6 format (IPv4 addresses are mapped to IPv6).
 * Provides network type detection, group calculation, and validation.
 */
class CNetAddr {
protected:
    uint8_t m_addr[16];  ///< IPv6 address (IPv4 mapped if applicable)
    Network m_net;       ///< Network type
    uint32_t m_scope_id; ///< IPv6 scope ID (for link-local)

public:
    CNetAddr();
    explicit CNetAddr(const uint8_t ipv6[16], Network net = NET_IPV6);

    /**
     * @brief Create from IPv4 address (host byte order)
     */
    static CNetAddr FromIPv4(uint32_t ipv4);

    /**
     * @brief Create from string (e.g., "192.168.1.1" or "::1")
     */
    static bool FromString(const std::string& str, CNetAddr& addr);

    /**
     * @brief Get network type
     */
    Network GetNetwork() const { return m_net; }

    /**
     * @brief Check if address is IPv4
     */
    bool IsIPv4() const { return m_net == NET_IPV4; }

    /**
     * @brief Check if address is IPv6
     */
    bool IsIPv6() const { return m_net == NET_IPV6; }

    /**
     * @brief Check if address is valid (not unroutable)
     */
    bool IsValid() const;

    /**
     * @brief Check if address is routable (publicly reachable)
     *
     * Rejects: localhost, private networks, multicast, etc.
     */
    bool IsRoutable() const;

    /**
     * @brief Check if address is local (127.0.0.0/8 or ::1)
     */
    bool IsLocal() const;

    /**
     * @brief Check if address is RFC1918 private (10.x, 172.16-31.x, 192.168.x)
     */
    bool IsRFC1918() const;

    /**
     * @brief Check if address is RFC2544 benchmark (198.18.0.0/15)
     */
    bool IsRFC2544() const;

    /**
     * @brief Check if address is RFC3927 link-local (169.254.0.0/16)
     */
    bool IsRFC3927() const;

    /**
     * @brief Check if address is RFC6598 CGN (100.64.0.0/10)
     */
    bool IsRFC6598() const;

    /**
     * @brief Check if address is RFC5737 documentation (192.0.2.0/24, etc.)
     */
    bool IsRFC5737() const;

    /**
     * @brief Check if address is RFC3849 IPv6 documentation (2001:db8::/32)
     */
    bool IsRFC3849() const;

    /**
     * @brief Check if address is RFC4862 IPv6 link-local (fe80::/10)
     */
    bool IsRFC4862() const;

    /**
     * @brief Check if address is RFC4193 IPv6 unique local (fc00::/7)
     */
    bool IsRFC4193() const;

    /**
     * @brief Check if address is RFC4843 ORCHID (2001:10::/28)
     */
    bool IsRFC4843() const;

    /**
     * @brief Check if address is RFC7343 ORCHIDv2 (2001:20::/28)
     */
    bool IsRFC7343() const;

    /**
     * @brief Get network group for bucket assignment
     *
     * Returns bytes that represent the "network group" of this address.
     * Addresses in the same group are likely controlled by the same entity.
     *
     * For IPv4: Returns /16 prefix (first 2 bytes)
     * For IPv6: Returns /32 prefix (first 4 bytes)
     *
     * This is critical for eclipse attack protection - we want addresses
     * from different network groups in our peer table.
     */
    std::vector<uint8_t> GetGroup() const;

    /**
     * @brief Get address as bytes
     */
    const uint8_t* GetAddrBytes() const { return m_addr; }

    /**
     * @brief Get IPv4 address (0 if not IPv4)
     */
    uint32_t GetIPv4() const;

    /**
     * @brief Convert to string representation
     */
    std::string ToString() const;

    /**
     * @brief Convert to string (IP only, no port)
     */
    std::string ToStringIP() const;

    /**
     * @brief Set IPv4 address (stored as IPv4-mapped IPv6)
     */
    void SetIPv4(uint32_t ipv4);

    /**
     * @brief Set raw IPv6 address
     */
    void SetIPv6(const uint8_t ipv6[16]);

    // Comparison operators
    bool operator==(const CNetAddr& other) const;
    bool operator!=(const CNetAddr& other) const { return !(*this == other); }
    bool operator<(const CNetAddr& other) const;

    // Hash support for std::unordered_map
    friend struct std::hash<CNetAddr>;

    // Serialization
    template<typename Stream>
    void Serialize(Stream& s) const {
        s.write(reinterpret_cast<const char*>(m_addr), 16);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s.read(reinterpret_cast<char*>(m_addr), 16);
        // Determine network type from address
        DetectNetwork();
    }

private:
    void DetectNetwork();  ///< Set m_net based on m_addr contents
};

/**
 * @class CService
 * @brief Network address with port (CNetAddr + port)
 *
 * Extends CNetAddr to include a port number. This is the primary
 * address type used for peer connections.
 */
class CService : public CNetAddr {
protected:
    uint16_t m_port;  ///< Port number (host byte order)

public:
    CService();
    CService(const CNetAddr& addr, uint16_t port);
    explicit CService(const uint8_t ipv6[16], uint16_t port, Network net = NET_IPV6);

    /**
     * @brief Create from IPv4 address and port
     */
    static CService FromIPv4(uint32_t ipv4, uint16_t port);

    /**
     * @brief Create from string (e.g., "192.168.1.1:8444")
     */
    static bool FromString(const std::string& str, CService& addr);

    /**
     * @brief Get port number
     */
    uint16_t GetPort() const { return m_port; }

    /**
     * @brief Set port number
     */
    void SetPort(uint16_t port) { m_port = port; }

    /**
     * @brief Convert to string (IP:port format)
     */
    std::string ToString() const;

    /**
     * @brief Convert to string suitable for map key
     *
     * Format: "ip:port" for reliable hashing
     */
    std::string ToStringKey() const;

    // Comparison operators
    bool operator==(const CService& other) const;
    bool operator!=(const CService& other) const { return !(*this == other); }
    bool operator<(const CService& other) const;

    // Hash support for std::unordered_map
    friend struct std::hash<CService>;

    // Serialization
    template<typename Stream>
    void Serialize(Stream& s) const {
        CNetAddr::Serialize(s);
        // Port in network byte order (big-endian)
        uint8_t portBytes[2];
        portBytes[0] = (m_port >> 8) & 0xFF;
        portBytes[1] = m_port & 0xFF;
        s.write(reinterpret_cast<const char*>(portBytes), 2);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        CNetAddr::Unserialize(s);
        uint8_t portBytes[2];
        s.read(reinterpret_cast<char*>(portBytes), 2);
        m_port = (static_cast<uint16_t>(portBytes[0]) << 8) | portBytes[1];
    }
};

// Hash specializations for use in std::unordered_map
namespace std {
    template<>
    struct hash<CNetAddr> {
        size_t operator()(const CNetAddr& addr) const {
            size_t h = 0;
            const uint8_t* bytes = addr.GetAddrBytes();
            for (int i = 0; i < 16; ++i) {
                h ^= static_cast<size_t>(bytes[i]) << ((i % 8) * 8);
            }
            return h;
        }
    };

    template<>
    struct hash<CService> {
        size_t operator()(const CService& addr) const {
            size_t h = hash<CNetAddr>()(addr);
            h ^= static_cast<size_t>(addr.GetPort()) << 16;
            return h;
        }
    };
}

#endif // DILITHION_NET_NETADDRESS_H
